# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Kerberos for LDAP (port 389, encrypted – see ldapseal) and for SMB (SYSVOL).

Kerberos is preferred over NTLM: the DC proves its identity, the traffic is encrypted with AES, and it also works
in domains in which NTLM is switched off. It needs:
- the DC's DNS name in DC_HOSTS (the ticket is issued for ldap/<that name>). With an IP address there is no
  Kerberos: the name must come from the configuration – a name read from the network (RootDSE) could be chosen by
  an attacker, who would then get a ticket for a service whose key they hold.
- the KDC on the DC (port 88, TCP) and a clock within 5 minutes of the DC.
- the MIT Kerberos libraries and the Python packages gssapi and krb5 (in the image since 2.7.0).

The configuration (krb5.conf) is written by the program itself from DOMAIN_FQDN and DC_HOSTS – no DNS lookups for
KDCs or realms, no file on the host. Only AES is allowed. The ticket of a sign-in is fetched into its own in-memory
credential cache (new_ticket) and destroyed as soon as it is no longer needed (destroy_ticket) – never written to
disk.

Note on the egress guard (app/egress.py): the MIT library opens its connections to the KDC itself, outside
Python's socket module. It only ever talks to the KDCs written into krb5.conf – the DCs from DC_HOSTS.
"""
from __future__ import annotations

import atexit
import contextlib
import ipaddress
import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from typing import Any

from .config import settings

log = logging.getLogger("samaudit.kerberos")

_lock = threading.Lock()
_written: dict = {"key": None, "path": ""}

# MIT error codes (krb5 base -1765328384 + KDC error number) that mean: this account or password is not accepted.
# Then NTLM must not be tried as well – the same wrong password would count twice towards the account lockout.
_BASE = -1765328384
CREDENTIAL_ERRORS = {
    _BASE + 6: "bad_credentials",     # KDC_ERR_C_PRINCIPAL_UNKNOWN
    _BASE + 18: "account_locked",     # KDC_ERR_CLIENT_REVOKED (locked or disabled)
    _BASE + 23: "account_unusable",   # KDC_ERR_KEY_EXPIRED (password expired)
    _BASE + 24: "bad_credentials",    # KDC_ERR_PREAUTH_FAILED
    _BASE + 31: "bad_credentials",    # KRB5KRB_AP_ERR_BAD_INTEGRITY: wrong password, account without pre-auth
}
# Other errors: why Kerberos was not possible (shown as a hint on the connection page and in the diagnostics)
_REASONS = {
    _BASE + 7: "spn",                 # KDC_ERR_S_PRINCIPAL_UNKNOWN: no ldap/<name> – name is not the DC's name
    _BASE + 14: "enctype",            # KDC_ERR_ETYPE_NOSUPP: no AES key for the account
    _BASE + 37: "skew",               # KRB5KRB_AP_ERR_SKEW
    -1765328228: "kdc_unreachable",   # KRB5_KDC_UNREACH
    -1765328230: "realm",             # KRB5_REALM_CANT_RESOLVE
}
REASON_KEYS = ("ip", "upn", "spn", "enctype", "skew", "kdc_unreachable", "realm", "missing", "backoff", "off", "other")


def libraries() -> bool:
    """Are the Kerberos libraries there (always in the image; maybe not in a development environment)?"""
    try:
        import gssapi  # noqa: F401
        import krb5  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def available() -> bool:
    return settings.ldap_kerberos and libraries()


def is_dns_name(host: str) -> bool:
    host = str(host or "").strip()
    if not host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host))


def realm_of(domain: str) -> str:
    return str(domain or "").strip().upper()


def principal(bind_name: str, domain: str) -> str | None:
    """'anna@firma.local' or 'FIRMA\\anna' -> 'anna@FIRMA.LOCAL' (the realm is case-sensitive). A UPN with another
    suffix gives None: Kerberos is not possible for it here (NTLM, not a downgrade)."""
    user = str(bind_name or "")
    realm = realm_of(domain)
    if not realm:
        return None
    if "\\" in user:
        user = user.split("\\", 1)[1]
    if "@" in user:
        name, suffix = user.rsplit("@", 1)
        return f"{name}@{realm}" if suffix.lower() == str(domain).strip().lower() and name else None
    return f"{user}@{realm}" if user else None


def kdcs() -> list[str]:
    """The KDCs: every DC from DC_HOSTS given by its DNS name (IP addresses are skipped)."""
    out = [h.strip().lower() for h in settings.dc_hosts if is_dns_name(h)]
    return list(dict.fromkeys(out))


_SAFE = re.compile(r"[A-Za-z0-9.-]+")


def config_text(domain: str, kdc_names: list[str]) -> str:
    if not _SAFE.fullmatch(str(domain or "")) or not kdc_names or \
            not all(_SAFE.fullmatch(str(k or "")) for k in kdc_names):
        raise ValueError("invalid domain or DC name for Kerberos")
    realm = realm_of(domain)
    dom = str(domain).strip().lower()
    kdc_lines = "".join(f"        kdc = {k}\n" for k in kdc_names)
    return (
        "# Written by SAMAUDIT (app/kerberos.py) from DOMAIN_FQDN and DC_HOSTS – do not edit\n"
        "[libdefaults]\n"
        f"    default_realm = {realm}\n"
        "    dns_lookup_kdc = false\n"
        "    dns_lookup_realm = false\n"
        "    rdns = false\n"
        "    dns_canonicalize_hostname = false\n"
        "    udp_preference_limit = 0\n"
        "    forwardable = false\n"
        "    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
        "    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
        "    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
        "    default_ccache_name = MEMORY:samaudit\n"
        "[realms]\n"
        f"    {realm} = {{\n"
        f"{kdc_lines}"
        "    }\n"
        "[domain_realm]\n"
        f"    .{dom} = {realm}\n"
        f"    {dom} = {realm}\n"
    )


def ensure_config(domain: str, kdc_names: list[str]) -> str:
    """Write krb5.conf (once per domain/KDC list) and point KRB5_CONFIG to it. Returns the path."""
    key = (realm_of(domain), tuple(kdc_names))
    with _lock:
        if _written["key"] == key and os.path.exists(_written["path"]):
            return _written["path"]
        text = config_text(domain, kdc_names)
        fd, path = tempfile.mkstemp(prefix="samaudit-krb5-", suffix=".conf")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        old = _written["path"]
        os.environ["KRB5_CONFIG"] = path
        _written.update(key=key, path=path)
        if old and old != path:
            with contextlib.suppress(OSError):
                os.unlink(old)
        return path


def _codes(error: BaseException | None):
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        for arg in getattr(error, "args", ()) or ():
            if isinstance(arg, int):
                yield arg
        for m in re.finditer(r"(-17653\d{5})", str(error)):
            yield int(m.group(1))
        for attr in ("err_code", "min_code", "maj_code"):
            code = getattr(error, attr, None)
            if isinstance(code, int):
                yield code
        error = getattr(error, "base_error", None) or error.__cause__ or error.__context__


def credential_error(error: BaseException | None) -> str:
    """AuthError code if a Kerberos error means 'wrong password / locked / expired / unknown account', else ''."""
    for code in _codes(error):
        if code in CREDENTIAL_ERRORS:
            return CREDENTIAL_ERRORS[code]
    return ""


def reason(error: BaseException | None) -> str:
    """Short reason why Kerberos was not possible (one of REASON_KEYS)."""
    for code in _codes(error):
        if code in _REASONS:
            return _REASONS[code]
    text = str(error or "").lower()
    if "clock skew" in text:
        return "skew"
    if "cannot contact any kdc" in text or "unable to reach any kdc" in text:
        return "kdc_unreachable"
    if "server not found" in text:
        return "spn"
    return "other"


def remove_config() -> None:
    """At exit: the generated krb5.conf is not left behind in /tmp."""
    path = _written.get("path")
    if path:
        with contextlib.suppress(OSError):
            os.unlink(path)


atexit.register(remove_config)


@dataclass
class Ticket:
    context: Any
    ccache: Any
    name: str        # "MEMORY:<unique>" for pyspnego (KerberosCCache)
    principal: str


def new_ticket(principal_name: str, password: str) -> Ticket:
    """Kerberos ticket (TGT) for one sign-in, in its own in-memory credential cache. Raises the krb5 error (wrong
    password: see credential_error)."""
    import krb5

    ctx = krb5.init_context()
    princ = krb5.parse_name_flags(ctx, principal_name.encode("utf-8"))
    opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_forwardable(opt, False)
    cred = krb5.get_init_creds_password(ctx, princ, opt, password=password.encode("utf-8"))
    ccache = krb5.cc_new_unique(ctx, b"MEMORY")
    try:
        krb5.cc_initialize(ctx, ccache, cred.client)
        krb5.cc_store_cred(ctx, ccache, cred)
    except Exception:
        krb5.cc_destroy(ctx, ccache)
        raise
    name = ccache.name
    return Ticket(ctx, ccache, "MEMORY:" + (name.decode("utf-8") if isinstance(name, bytes) else str(name)),
                  principal_name)


def destroy_ticket(ticket: Ticket | None) -> None:
    """Remove the credential cache with the user's tickets (an established connection keeps only its session key)."""
    if ticket is None:
        return
    try:
        import krb5
        krb5.cc_destroy(ticket.context, ticket.ccache)
    except Exception as e:  # noqa: BLE001 – never stop a sign-in because of this, but say so
        log.warning("Kerberos ticket not removed: %s", type(e).__name__)


def remember_reason(key: str) -> None:
    """Why Kerberos was not used the last time ('' = it was used). Connection page and diagnostics."""
    try:
        from . import db
        db.set_kv("kerberos_reason", key if key in REASON_KEYS else ("" if not key else "other"))
    except Exception as e:  # noqa: BLE001
        log.debug("kv: %s", e)
