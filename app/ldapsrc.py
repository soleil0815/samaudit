# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""LDAP access: sign-in (bind with the user's own credentials, no service account),
authorisation check and collection of the domain data."""
from __future__ import annotations

import logging
import os
import re
import ssl
import uuid
from dataclasses import dataclass
from typing import Any

from .adutil import (
    UAC_ACCOUNTDISABLE, UAC_PARTIAL_SECRETS_ACCOUNT, UAC_SERVER_TRUST_ACCOUNT,
    as_int, as_str, as_strs, filetime_to_dt, gentime_to_dt, parse_sd, sid_rid, sid_to_str,
)
from .config import settings

log = logging.getLogger("samaudit.ldap")


class AuthError(Exception):
    """Sign-in error. `code` is translated in the user interface."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass
class AuthResult:
    sam: str
    upn: str
    display_name: str
    dn: str
    sid: str
    matched_groups: list[str]
    bind_name: str


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def _ldap3():
    try:
        import ldap3  # noqa: F401
        return ldap3
    except ImportError as e:  # pragma: no cover - always present in the container
        raise AuthError("ldap_missing", str(e)) from e


def _tls():
    ldap3 = _ldap3()
    verify = settings.ldap_cert_mode == "verify"
    kwargs = {"validate": ssl.CERT_REQUIRED if verify else ssl.CERT_NONE,
              "version": ssl.PROTOCOL_TLS_CLIENT}
    if verify and settings.ldap_ca_file and os.path.isfile(settings.ldap_ca_file):
        kwargs["ca_certs_file"] = settings.ldap_ca_file
    return ldap3.Tls(**kwargs)


def _server(host: str):
    ldap3 = _ldap3()
    use_tls = settings.ldap_ssl or settings.ldap_starttls
    return ldap3.Server(host, port=settings.ldap_port, use_ssl=settings.ldap_ssl,
                        tls=_tls() if use_tls else None, get_info=ldap3.NONE,
                        connect_timeout=settings.ldap_timeout)


def _targets() -> list[tuple[str, str, str]]:
    """Connection targets as (name, address, pin key).

    In "auto" mode a name that points to several DCs (e.g. the domain name) is resolved into the individual
    addresses – in a fixed order. That way each DC is trusted individually, instead of alternating
    DCs (DNS round robin) being reported as "certificate changed"."""
    import socket
    out: list[tuple[str, str, str]] = []
    for host in settings.dc_hosts:
        addrs: list[str] = []
        if settings.ldap_cert_mode == "auto":
            try:
                addrs = sorted({str(i[4][0]) for i in socket.getaddrinfo(host, settings.ldap_port, socket.AF_INET,
                                                                    socket.SOCK_STREAM)})
            except OSError:
                addrs = []
        if len(addrs) > 1:
            out += [(host, a, f"{host} [{a}]") for a in addrs]
        else:
            out.append((host, host, host))
    return out


def _check_pin(host: str, conn) -> None:
    """LDAPS auto-trust: remember the certificate chain on first contact, compare it afterwards."""
    if settings.ldap_cert_mode != "auto" or not (settings.ldap_ssl or settings.ldap_starttls):
        return
    from . import pins
    sock = getattr(conn, "socket", None)
    if sock is None or not hasattr(sock, "getpeercert"):
        raise AuthError("tls_failed", "no TLS connection")
    try:
        pins.check(host, pins.peer_chain(sock))
    except pins.PinMismatch as e:
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001
            pass
        raise AuthError("cert_changed", str(e)) from e


def _remember_type(dtype: str, vendor: str | None) -> None:
    try:
        from . import db
        db.set_kv("domain_type", dtype)
        db.set_kv("domain_vendor", vendor or "")
    except Exception as e:  # noqa: BLE001
        log.debug("kv: %s", e)


def normalize_username(username: str) -> tuple[str, str]:
    """Returns (bind_name, sam_or_upn). Accepts user, DOMAIN\\user and user@domain."""
    u = (username or "").strip()
    if not u or len(u) > 256 or any(c in u for c in "()*\x00\r\n"):
        raise AuthError("invalid_user")
    if "\\" in u:
        u = u.split("\\", 1)[1]
    if not u or u.startswith("@") or u.endswith("@") or u.count("@") > 1:
        raise AuthError("invalid_user")
    if "@" in u:
        return u, u
    # implicit UPN (sAMAccountName@DNS domain) works in AD and Samba
    return f"{u}@{settings.domain_fqdn}", u


def open_connection(bind_name: str, password: str):
    """Bind against the first reachable DC. Returns a bound connection."""
    ldap3 = _ldap3()
    from ldap3.core import exceptions as lexc

    if not password:
        raise AuthError("bad_credentials")
    if not (settings.ldap_ssl or settings.ldap_starttls) and not settings.ldap_allow_plain:
        raise AuthError("insecure_config")

    last_err: AuthError | None = None
    for host, addr, pin_key in _targets():
        try:
            conn = ldap3.Connection(
                _server(addr), user=bind_name, password=password,
                authentication=ldap3.SIMPLE, auto_bind=ldap3.AUTO_BIND_NONE,
                read_only=True, raise_exceptions=False, auto_range=False,
                auto_referrals=False,          # never follow a referral (would send the password again)
                receive_timeout=max(settings.ldap_timeout, 30),
            )
            conn.open()
            if settings.ldap_starttls and not settings.ldap_ssl:
                if not conn.start_tls():
                    raise AuthError("tls_failed", str(conn.result))
            _check_pin(pin_key, conn)  # before sending the password
            if not conn.bind():
                res = conn.result or {}
                desc = (res.get("description") or "").lower()
                msg = res.get("message") or ""
                if desc == "invalidcredentials" or "52e" in msg:
                    raise AuthError("bad_credentials")
                if "775" in msg:
                    raise AuthError("account_locked")
                if "533" in msg or "532" in msg or "701" in msg or "773" in msg:
                    raise AuthError("account_unusable", msg)
                if desc in ("strongerauthrequired", "confidentialityrequired"):
                    raise AuthError("tls_required", msg)
                raise AuthError("bind_failed", f"{desc} {msg}".strip())
            conn._samaudit_host = host
            return conn
        except AuthError as e:
            if e.code in ("bad_credentials", "account_locked", "account_unusable", "cert_changed"):
                raise
            last_err = e
        except lexc.LDAPSocketOpenError as e:
            text = str(e)
            if "certificate" in text.lower() or "ssl" in text.lower():
                last_err = AuthError("tls_cert", text)
            else:
                last_err = AuthError("dc_unreachable", f"{pin_key}: {text}")
        except lexc.LDAPException as e:
            last_err = AuthError("bind_failed", f"{pin_key}: {e}")
        except OSError as e:
            last_err = AuthError("dc_unreachable", f"{pin_key}: {e}")
    raise last_err or AuthError("dc_unreachable", "no DC configured")


# ---------------------------------------------------------------------------
# Search helpers
# ---------------------------------------------------------------------------

class Entry(dict):
    """Case-insensitive access to the raw_attributes of a search result."""

    def __init__(self, dn: str, raw: dict):
        super().__init__({k.lower(): v for k, v in (raw or {}).items()})
        self.dn = dn

    def get(self, key, default=None):
        return super().get(key.lower(), default)


def _escape(v: str) -> str:
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(v)


def search(conn, base: str, flt: str, attrs: list[str], scope: str = "SUBTREE", sd: bool = False,
           paged: bool = True) -> list[Entry]:
    ldap3 = _ldap3()
    sc = {"SUBTREE": ldap3.SUBTREE, "BASE": ldap3.BASE, "LEVEL": ldap3.LEVEL}[scope]
    controls = None
    if sd:
        from ldap3.protocol.microsoft import security_descriptor_control
        controls = security_descriptor_control(sdflags=0x05)  # OWNER + DACL
    out: list[Entry] = []
    if paged and scope != "BASE":
        gen = conn.extend.standard.paged_search(base, flt, search_scope=sc, attributes=attrs,
                                                paged_size=500, generator=True, controls=controls)
        for e in gen:
            if e.get("type") == "searchResEntry":
                out.append(Entry(e.get("dn", ""), e.get("raw_attributes", {})))
    else:
        conn.search(base, flt, search_scope=sc, attributes=attrs, controls=controls)
        for e in conn.response or []:
            if e.get("type") == "searchResEntry":
                out.append(Entry(e.get("dn", ""), e.get("raw_attributes", {})))
    _check_result(conn, base)
    return out


class SearchFailed(Exception):
    """Search aborted or incomplete – the result must not count as "empty = passed"."""


def _check_result(conn, base: str) -> None:
    res = getattr(conn, "result", None) or {}
    code = res.get("result", 0)
    if code in (0, None):
        return
    if code == 32:                       # noSuchObject: base does not exist → really empty
        return
    raise SearchFailed(f"{base}: {res.get('description')} ({code}) {res.get('message') or ''}".strip())


def base_entry(conn, dn: str, attrs: list[str], sd: bool = False) -> Entry | None:
    try:
        res = search(conn, dn, "(objectClass=*)", attrs, scope="BASE", sd=sd, paged=False)
    except Exception as e:  # noqa: BLE001
        log.debug("base_entry %s: %s", dn, e)
        return None
    return res[0] if res else None


def _full_members(conn, e: Entry) -> list[str]:
    """Reads 'member' including range retrieval (>1500 members)."""
    members = as_strs(e.get("member"))
    range_key = next((k for k in e.keys() if k.startswith("member;range=")), None)
    rounds = 0
    while range_key and rounds < 2000:
        rounds += 1
        members += as_strs(e.get(range_key))
        m = re.match(r"member;range=(\d+)-(\*|\d+)", range_key)
        if not m or m.group(2) == "*":
            break
        nxt = int(m.group(2)) + 1
        if nxt <= int(m.group(1)):
            break                          # range does not advance – stop instead of looping forever
        e2 = base_entry(conn, e.dn, [f"member;range={nxt}-*"])
        if not e2:
            break
        e = e2
        range_key = next((k for k in e.keys() if k.startswith("member;range=")), None)
    return members


# ---------------------------------------------------------------------------
# Authentication + admin check
# ---------------------------------------------------------------------------

def root_dse(conn) -> dict:
    e = base_entry(conn, "", ["defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
                              "schemaNamingContext", "dnsHostName", "domainFunctionality",
                              "forestFunctionality", "domainControllerFunctionality", "serverName",
                              "vendorName", "vendorVersion"])
    if not e:
        return {}
    vendor = " ".join(x for x in (as_str(e.get("vendorName")), as_str(e.get("vendorVersion"))) if x)
    return {
        "vendor": vendor,
        "detected_type": "samba" if "samba" in vendor.lower() else "windows",
        "default_nc": as_str(e.get("defaultNamingContext")) or settings.base_dn,
        "root_nc": as_str(e.get("rootDomainNamingContext")),
        "config_nc": as_str(e.get("configurationNamingContext")),
        "schema_nc": as_str(e.get("schemaNamingContext")),
        "dns_host": as_str(e.get("dnsHostName")),
        "domain_level": as_int(e.get("domainFunctionality")),
        "forest_level": as_int(e.get("forestFunctionality")),
        "dc_level": as_int(e.get("domainControllerFunctionality")),
    }


def _object_sid(conn, dn: str) -> str | None:
    e = base_entry(conn, dn, ["objectSid"])
    return sid_to_str((e.get("objectSid") or [None])[0]) if e else None


BUILTIN = {544, 545, 546, 548, 549, 550, 551, 552, 554, 557, 560, 561}
# Admin groups that lead to rejection in EVERY domain of the forest
FOREST_PRIV_RIDS = {"512", "516", "518", "519", "520", "521", "526", "527"}


def domain_type_for(dse: dict) -> str:
    """Configured type or the automatically detected one (rootDSE vendorName)."""
    if settings.domain_type in ("windows", "samba"):
        return settings.domain_type
    return dse.get("detected_type") or "windows"


def resolve_group_sids(conn, specs: list[str], domain_sid: str, root_sid: str, base_dn: str,
                       strict: bool = False) -> dict[str, str]:
    """Group specs (RID:x, SID, name, DN) → {SID: display name}.
    strict: abort on search errors (for deny lists – there an error must never mean "let through")."""
    out: dict[str, str] = {}
    for item in specs:
        it = item.strip()
        if not it:
            continue
        if it.upper().startswith("RID:"):
            try:
                rid = int(it[4:])
            except ValueError:
                continue
            if rid in BUILTIN:
                out[f"S-1-5-32-{rid}"] = it
            else:
                dom = root_sid if rid in (518, 519, 527, 498) else domain_sid
                out[f"{dom}-{rid}"] = it
        elif it.upper().startswith("S-1-"):
            out[it.upper()] = it
        else:
            flt = f"(&(objectClass=group)(distinguishedName={_escape(it)}))" if "=" in it else \
                f"(&(objectClass=group)(sAMAccountName={_escape(it)}))"
            try:
                for g in search(conn, base_dn, flt, ["objectSid"], paged=False):
                    sid = sid_to_str(g.get("objectSid", [None])[0])
                    if sid:
                        out[sid] = it
            except Exception as e:  # noqa: BLE001
                if strict:
                    raise AuthError("bind_failed", f"cannot resolve group {it}: {e}") from e
                log.warning("Cannot resolve group %s: %s", it, e)
    return out


def _netbios(conn, dse: dict, base_dn: str) -> str:
    """NetBIOS name of the domain – preferably from the directory (DOMAIN_NETBIOS only as a fallback)."""
    try:
        res = search(conn, f"CN=Partitions,{dse.get('config_nc') or ''}",
                     f"(&(objectClass=crossRef)(nCName={_escape(base_dn)}))", ["nETBIOSName"], paged=False)
        nb = (as_str(res[0].get("nETBIOSName")) or "") if res else ""
    except Exception:  # noqa: BLE001
        nb = ""
    return nb or settings.netbios


def _verify_identity(conn, me: Entry, dse: dict, base_dn: str) -> None:
    """Cross-check with LDAP "Who am I?" (RFC 4532): does the bound account – including its domain – match the
    one found? Windows DCs always support the operation; if the answer is missing there, sign-in is rejected."""
    must = dse.get("detected_type") == "windows"
    try:
        who = conn.extend.standard.who_am_i()
    except Exception as e:  # noqa: BLE001
        if must:
            raise AuthError("user_not_found", f"whoami: {e}") from e
        log.debug("whoami not available: %s", e)
        return
    if not who:
        if must:
            raise AuthError("user_not_found", "whoami empty")
        return
    who = str(who)
    if who.lower().startswith("dn:"):
        ok = who[3:].strip().lower() == (me.dn or "").lower()
    elif who.lower().startswith("u:"):
        acct = who[2:]
        dom, _, name = acct.rpartition("\\")
        ok = name.split("@")[0].lower() == (as_str(me.get("sAMAccountName")) or "").lower()
        nb = _netbios(conn, dse, base_dn)
        if ok and dom and nb and dom.lower() != nb.lower():
            ok = False                     # same account, but a different domain of the forest
    else:
        return
    if not ok:
        log.warning("Bound account (%s) does not match the one found (%s) – rejected", who, me.dn)
        raise AuthError("user_not_found")


def authenticate(username: str, password: str) -> AuthResult:
    """Binds with the user's credentials and checks authorisation:
    member of an auditor group (ALLOWED_GROUPS) and NOT a member of a privileged group.
    Raises AuthError otherwise."""
    bind_name, ident = normalize_username(username)
    conn = open_connection(bind_name, password)
    try:
        dse = root_dse(conn)
        base_dn = dse.get("default_nc") or settings.base_dn
        # The bind used a UPN. Look for every account this name can match
        # (explicit UPN or sAMAccountName@domain) – if ambiguous, reject, so that the rights of an account
        # other than the one that was bound are never checked.
        if "@" in ident and not ident.lower().endswith("@" + settings.domain_fqdn):
            flt = f"(&(objectCategory=person)(objectClass=user)(userPrincipalName={_escape(ident)}))"
        else:
            sam = ident.split("@", 1)[0]
            flt = (f"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={_escape(sam)})"
                   f"(userPrincipalName={_escape(sam + '@' + settings.domain_fqdn)})))")
        res = search(conn, base_dn, flt, ["sAMAccountName", "userPrincipalName", "displayName",
                                          "objectSid", "userAccountControl", "sIDHistory"], paged=False)
        if len(res) != 1:
            if len(res) > 1:
                log.warning("Sign-in name %s is ambiguous (%d accounts) – rejected", ident, len(res))
            raise AuthError("user_not_found")
        me = res[0]
        _verify_identity(conn, me, dse, base_dn)
        uac = as_int(me.get("userAccountControl"), 0) or 0
        if uac & UAC_ACCOUNTDISABLE:
            raise AuthError("account_unusable")
        my_sid = sid_to_str(me.get("objectSid", [None])[0]) or ""
        if not my_sid.startswith("S-1-5-21-"):
            raise AuthError("user_not_found", "objectSid missing")
        domain_sid = my_sid.rsplit("-", 1)[0]
        history = {s for s in (sid_to_str(x) for x in (me.get("sIDHistory") or [])) if s}

        # Effective groups (recursive, including the primary group) via tokenGroups
        tg = base_entry(conn, me.dn, ["tokenGroups"])
        token_sids = {s for s in (sid_to_str(x) for x in (tg.get("tokenGroups") or [] if tg else [])) if s}
        token_sids.discard(None)
        if not token_sids:
            raise AuthError("no_token_groups")

        root_sid = domain_sid
        if dse.get("root_nc") and dse["root_nc"].lower() != base_dn.lower():
            root_sid = _object_sid(conn, dse["root_nc"]) or domain_sid

        # 1) Always reject privileged accounts (including the built-in Administrator account).
        #    Group SIDs and the SID history are checked. In addition, the admin groups of EVERY domain
        #    of the forest apply (Enterprise/Schema Admins live in the root domain, whose SID a
        #    child-domain DC does not always return).
        check_sids = token_sids | history
        denied = resolve_group_sids(conn, settings.denied_groups, domain_sid, root_sid, base_dn, strict=True)
        hit = sorted({denied[s] for s in check_sids if s in denied})
        hit += sorted({f"RID:{s.rsplit('-', 1)[1]} ({s})" for s in check_sids
                       if s not in denied and s.startswith("S-1-5-21-") and s.rsplit("-", 1)[1] in FOREST_PRIV_RIDS})
        if history & {f"S-1-5-32-{r}" for r in (544, 548, 549, 550, 551)}:
            hit.append("SID history: BUILTIN")
        if hit or my_sid.endswith(("-500", "-502")) or any(h.endswith(("-500", "-502")) for h in history):
            log.warning("Sign-in of %s rejected: privileged account (%s)", ident, ", ".join(hit) or "RID 500")
            raise AuthError("privileged_denied", ", ".join(hit))
        # 2) Member of an auditor group?
        allowed = resolve_group_sids(conn, settings.accepted_groups, domain_sid, root_sid, base_dn)
        if not allowed:
            raise AuthError("group_missing", ", ".join(settings.accepted_groups))
        matched = [allowed[s] for s in token_sids if s in allowed]
        if not matched:
            raise AuthError("not_allowed")
        _remember_type(domain_type_for(dse), dse.get("vendor"))
        sam = as_str(me.get("sAMAccountName")) or ident
        return AuthResult(
            sam=sam,
            upn=as_str(me.get("userPrincipalName")) or bind_name,
            display_name=as_str(me.get("displayName")) or sam,
            dn=me.dn, sid=my_sid, matched_groups=sorted(set(matched)), bind_name=bind_name,
        )
    finally:
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
USER_ATTRS = ["sAMAccountName", "userPrincipalName", "displayName", "userAccountControl", "lastLogonTimestamp",
              "pwdLastSet", "whenCreated", "adminCount", "servicePrincipalName", "primaryGroupID", "sIDHistory",
              "objectSid", "msDS-SupportedEncryptionTypes", "msDS-AllowedToDelegateTo",
              "msDS-AllowedToActOnBehalfOfOtherIdentity", "userPassword", "unixUserPassword", "objectClass",
              "msDS-KeyCredentialLink", "altSecurityIdentities", "msDS-GroupMSAMembership"]
COMPUTER_ATTRS = ["sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                  "userAccountControl", "lastLogonTimestamp", "pwdLastSet", "whenCreated", "servicePrincipalName",
                  "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                  "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "primaryGroupID",
                  "sIDHistory", "objectSid", "msDS-SupportedEncryptionTypes", "objectClass",
                  "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup", "msDS-RevealedUsers",
                  "altSecurityIdentities"]


def _account(e: Entry, computer: bool) -> dict:
    sid = sid_to_str((e.get("objectSid") or [None])[0])
    uac = as_int(e.get("userAccountControl"), 0) or 0
    d: dict[str, Any] = {
        "dn": e.dn,
        "sam": as_str(e.get("sAMAccountName")) or "",
        "sid": sid,
        "rid": sid_rid(sid),
        "uac": uac,
        "enabled": not (uac & UAC_ACCOUNTDISABLE),
        "last_logon": filetime_to_dt(e.get("lastLogonTimestamp")),
        "pwd_last_set": filetime_to_dt(e.get("pwdLastSet")),
        "created": gentime_to_dt(e.get("whenCreated")),
        "spns": as_strs(e.get("servicePrincipalName")),
        "primary_gid": as_int(e.get("primaryGroupID")),
        "sid_history": [s for s in (sid_to_str(x) for x in (e.get("sIDHistory") or [])) if s],
        "enc_types": as_int(e.get("msDS-SupportedEncryptionTypes")),
        "delegate_to": as_strs(e.get("msDS-AllowedToDelegateTo")),
        "rbcd": bool(e.get("msDS-AllowedToActOnBehalfOfOtherIdentity")),
        "classes": [c.lower() for c in as_strs(e.get("objectClass"))],
        "key_cred": bool(e.get("msDS-KeyCredentialLink")),
        "alt_sec_ids": as_strs(e.get("altSecurityIdentities")),
    }
    if computer:
        legacy = e.get("ms-Mcs-AdmPwdExpirationTime")
        winlaps = e.get("msLAPS-PasswordExpirationTime")
        d.update({
            "dns": as_str(e.get("dNSHostName")) or "",
            "os": as_str(e.get("operatingSystem")) or "",
            "os_version": as_str(e.get("operatingSystemVersion")) or "",
            "laps": bool(legacy or winlaps),
            "is_dc": bool(uac & UAC_SERVER_TRUST_ACCOUNT) or d["primary_gid"] == 516,
            "is_rodc": bool(uac & UAC_PARTIAL_SECRETS_ACCOUNT) or d["primary_gid"] == 521,
            "reveal_on_demand": as_strs(e.get("msDS-RevealOnDemandGroup")),
            "never_reveal": as_strs(e.get("msDS-NeverRevealGroup")),
            "revealed": sorted({x.rsplit(":", 1)[-1] for x in as_strs(e.get("msDS-RevealedUsers"))}),
        })
    else:
        d.update({
            "upn": as_str(e.get("userPrincipalName")) or "",
            "display": as_str(e.get("displayName")) or "",
            "has_userpassword": bool(e.get("userPassword") or e.get("unixUserPassword")),
            # managed service accounts (gMSA and sMSA): random, automatically rotated passwords
            "is_gmsa": bool({"msds-groupmanagedserviceaccount", "msds-managedserviceaccount",
                             "msds-delegatedmanagedserviceaccount"} & set(d["classes"])),
            "admin_count": as_int(e.get("adminCount"), 0) or 0,
        })
        if d["is_gmsa"]:
            # who may retrieve the gMSA password (security descriptor, as for permissions)
            d["gmsa_readers"] = parse_sd(e.get("msDS-GroupMSAMembership"))
    return d


def _parse_gplink(v: str | None) -> list[dict]:
    out = []
    for m in re.finditer(r"\[LDAP://([^;\]]+);(\d+)\]", v or "", re.IGNORECASE):
        dn, opt = m.group(1), int(m.group(2))
        g = re.search(r"\{[0-9A-Fa-f-]{36}\}", dn)
        if g:
            out.append({"guid": g.group(0).upper(), "enabled": not (opt & 1), "enforced": bool(opt & 2)})
    return out


def collect(conn, progress) -> dict:
    """Collects all data for the check rules. `progress(pct, phase)`."""
    warnings: list[str] = []

    failed: set[str] = set()

    def safe(label, fn, default=None):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            log.warning("Section %s failed: %s", label, e)
            warnings.append(f"{label}: {e}")
            failed.add(label)
            return default

    progress(5, "phase_domain")
    dse = root_dse(conn)
    dn = dse.get("default_nc") or settings.base_dn
    config_nc = dse.get("config_nc") or f"CN=Configuration,{dn}"
    schema_nc = dse.get("schema_nc") or f"CN=Schema,{config_nc}"

    d = base_entry(conn, dn, ["objectSid", "msDS-Behavior-Version", "minPwdLength", "minPwdAge", "maxPwdAge",
                              "pwdHistoryLength", "pwdProperties", "lockoutThreshold", "lockoutDuration",
                              "lockOutObservationWindow", "ms-DS-MachineAccountQuota", "whenCreated", "gPLink",
                              "nTSecurityDescriptor"], sd=True)
    if d is None:
        raise RuntimeError("domain_unreadable")  # error code, translated in the UI (err_domain_unreadable)
    from .adutil import interval_days, interval_minutes
    domain_sid = sid_to_str((d.get("objectSid") or [None])[0])
    root_sid = domain_sid
    if dse.get("root_nc") and dse["root_nc"].lower() != dn.lower():
        root_sid = safe("root_sid", lambda: _object_sid(conn, dse["root_nc"])) or domain_sid

    netbios = settings.netbios or safe("netbios", lambda: as_str((search(
        conn, f"CN=Partitions,{config_nc}", f"(&(objectClass=crossRef)(nCName={_escape(dn)}))",
        ["nETBIOSName"], paged=False) or [Entry("", {})])[0].get("nETBIOSName"))) or ""

    domain = {
        "dn": dn, "fqdn": settings.domain_fqdn or ".".join(p.split("=", 1)[1] for p in dn.split(",")),
        "netbios": netbios, "sid": domain_sid, "root_sid": root_sid,
        "is_root": root_sid == domain_sid,
        "domain_level": dse.get("domain_level"), "forest_level": dse.get("forest_level"),
        "created": gentime_to_dt(d.get("whenCreated")),
        "maq": as_int(d.get("ms-DS-MachineAccountQuota")),
        "policy": {
            "min_length": as_int(d.get("minPwdLength"), 0),
            "history": as_int(d.get("pwdHistoryLength"), 0),
            "max_age_days": interval_days(d.get("maxPwdAge")),
            "min_age_days": interval_days(d.get("minPwdAge")),
            "complexity": bool((as_int(d.get("pwdProperties"), 0) or 0) & 1),
            "reversible": bool((as_int(d.get("pwdProperties"), 0) or 0) & 16),
            "lockout_threshold": as_int(d.get("lockoutThreshold"), 0),
            "lockout_duration_min": interval_minutes(d.get("lockoutDuration")),
            "lockout_window_min": interval_minutes(d.get("lockOutObservationWindow")),
        },
        "gplink": _parse_gplink(as_str(d.get("gPLink"))),
    }
    acl = {"domain_root": parse_sd(d.get("nTSecurityDescriptor"))}

    progress(12, "phase_users")
    # without trust accounts (INTERDOMAIN_TRUST_ACCOUNT, 0x800) – they never sign in
    users = [_account(e, False) for e in search(
        conn, dn, "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2048)))",
        USER_ATTRS)]
    # (Group) Managed Service Accounts
    users += safe("gmsa", lambda: [_account(e, False) for e in search(
        conn, dn, "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount)"
                  "(objectClass=msDS-DelegatedManagedServiceAccount))",
        USER_ATTRS)], []) or []

    progress(35, "phase_computers")
    computers = [_account(e, True) for e in search(conn, dn, "(objectCategory=computer)", COMPUTER_ATTRS)]
    # gMSAs are technically computer object classes too – avoid duplicates
    gmsa_dns = {u["dn"].lower() for u in users if u.get("is_gmsa")}
    computers = [c for c in computers if c["dn"].lower() not in gmsa_dns and
                 "msds-groupmanagedserviceaccount" not in c["classes"]]

    dtype = domain_type_for(dse)
    if settings.domain_type == "auto" and dtype == "windows" and any(
            "samba" in (c.get("os") or "").lower() for c in computers if c.get("is_dc")):
        dtype = "samba"
    _remember_type(dtype, dse.get("vendor"))

    progress(55, "phase_groups")
    groups = []
    for e in search(conn, dn, "(objectClass=group)", ["sAMAccountName", "objectSid", "member", "groupType",
                                                     "whenCreated"]):
        sid = sid_to_str((e.get("objectSid") or [None])[0])
        groups.append({"dn": e.dn, "sam": as_str(e.get("sAMAccountName")) or "", "sid": sid,
                       "rid": sid_rid(sid), "members": _full_members(conn, e),
                       "created": gentime_to_dt(e.get("whenCreated")),
                       "group_type": as_int(e.get("groupType"))})
    if root_sid != domain_sid:
        # Enterprise/Schema Admins live in the root domain
        for e in safe("root_groups", lambda: search(
                conn, dse["root_nc"], f"(|(objectSid={root_sid}-519)(objectSid={root_sid}-518)(objectSid={root_sid}-527))",
                ["sAMAccountName", "objectSid", "member"], paged=False), []) or []:
            sid = sid_to_str((e.get("objectSid") or [None])[0])
            groups.append({"dn": e.dn, "sam": as_str(e.get("sAMAccountName")) or "", "sid": sid,
                           "rid": sid_rid(sid), "members": _full_members(conn, e)})

    progress(65, "phase_trusts")
    trusts = []
    for e in safe("trusts", lambda: search(conn, f"CN=System,{dn}", "(objectClass=trustedDomain)",
                                           ["name", "flatName", "trustDirection", "trustType", "trustAttributes",
                                            "securityIdentifier", "whenCreated", "whenChanged",
                                            "msDS-SupportedEncryptionTypes"]), []) or []:
        trusts.append({
            "name": as_str(e.get("name")) or "", "flat": as_str(e.get("flatName")) or "",
            "direction": as_int(e.get("trustDirection"), 0), "type": as_int(e.get("trustType"), 0),
            "attributes": as_int(e.get("trustAttributes"), 0) or 0,
            "sid": sid_to_str((e.get("securityIdentifier") or [None])[0]),
            "created": gentime_to_dt(e.get("whenCreated")), "changed": gentime_to_dt(e.get("whenChanged")),
            "enc_types": as_int(e.get("msDS-SupportedEncryptionTypes")),
        })

    progress(72, "phase_config")
    sdh = safe("adminsdholder", lambda: base_entry(conn, f"CN=AdminSDHolder,CN=System,{dn}",
                                                    ["nTSecurityDescriptor"], sd=True))
    acl["adminsdholder"] = parse_sd(sdh.get("nTSecurityDescriptor")) if sdh else None

    ds = safe("dsheuristics", lambda: base_entry(
        conn, f"CN=Directory Service,CN=Windows NT,CN=Services,{config_nc}", ["dSHeuristics", "tombstoneLifetime"]))
    rb = safe("recyclebin", lambda: base_entry(
        conn, f"CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{config_nc}",
        ["msDS-EnabledFeatureBL"]))
    schema = safe("schema", lambda: base_entry(conn, schema_nc, ["objectVersion"]))
    laps_attrs = safe("laps_schema", lambda: [as_str(x.get("lDAPDisplayName")) for x in search(
        conn, schema_nc, "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))",
        ["lDAPDisplayName"], paged=False)], []) or []
    config = {
        "dsheuristics": as_str(ds.get("dSHeuristics")) if ds else None,
        "recycle_bin": (bool(rb.get("msDS-EnabledFeatureBL")) if rb is not None else None),
        "schema_version": as_int(schema.get("objectVersion")) if schema else None,
        "laps_legacy_schema": "ms-Mcs-AdmPwd" in laps_attrs,
        "laps_windows_schema": "msLAPS-Password" in laps_attrs,
        "tombstone_lifetime": as_int(ds.get("tombstoneLifetime")) if ds else None,
    }
    config.update(safe("extras", lambda: _collect_extras(conn, dn, config_nc, dse), {}) or {})
    config["dmsa"] = safe("dmsa", lambda: _collect_dmsa(conn, dn, schema_nc))
    config["kds"] = safe("kds", lambda: _collect_kds(conn, config_nc, schema_nc))

    psos = []
    for e in safe("psos", lambda: search(conn, f"CN=Password Settings Container,CN=System,{dn}",
                                         "(objectClass=msDS-PasswordSettings)",
                                         ["name", "msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled",
                                          "msDS-LockoutThreshold", "msDS-PSOAppliesTo",
                                          "msDS-PasswordReversibleEncryptionEnabled",
                                          "msDS-PasswordSettingsPrecedence"], paged=False), []) or []:
        psos.append({"name": as_str(e.get("name")), "min_length": as_int(e.get("msDS-MinimumPasswordLength"), 0),
                     "complexity": (as_str(e.get("msDS-PasswordComplexityEnabled")) or "").upper() == "TRUE",
                     "reversible": (as_str(e.get("msDS-PasswordReversibleEncryptionEnabled")) or "").upper() == "TRUE",
                     "lockout_threshold": as_int(e.get("msDS-LockoutThreshold"), 0),
                     "applies_to": as_strs(e.get("msDS-PSOAppliesTo")),
                     "precedence": as_int(e.get("msDS-PasswordSettingsPrecedence"))})

    progress(78, "phase_pki")
    pki_base = f"CN=Public Key Services,CN=Services,{config_nc}"
    published: set[str] = set()
    cas = []
    for e in safe("pki_cas", lambda: search(conn, f"CN=Enrollment Services,{pki_base}",
                                            "(objectClass=pKIEnrollmentService)",
                                            ["name", "dNSHostName", "certificateTemplates", "cACertificate",
                                             "msPKI-Enrollment-Servers", "nTSecurityDescriptor"],
                                            sd=True, paged=False), []) or []:
        tpls = as_strs(e.get("certificateTemplates"))
        published.update(t.lower() for t in tpls)
        cas.append({"name": as_str(e.get("name")), "host": as_str(e.get("dNSHostName")), "templates": tpls,
                    "certs": [bytes(c) for c in (e.get("cACertificate") or []) if isinstance(c, (bytes, bytearray))],
                    "enroll_servers": as_strs(e.get("msPKI-Enrollment-Servers")),
                    "sd": parse_sd(e.get("nTSecurityDescriptor")), "dn": e.dn})
    templates = []
    for e in safe("pki_templates", lambda: search(conn, f"CN=Certificate Templates,{pki_base}",
                                                  "(objectClass=pKICertificateTemplate)",
                                                  ["name", "displayName", "msPKI-Certificate-Name-Flag",
                                                   "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                                                   "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                                                   "msPKI-Template-Schema-Version", "msPKI-Certificate-Policy",
                                                   "nTSecurityDescriptor"], sd=True, paged=False), []) or []:
        name = as_str(e.get("name")) or ""
        templates.append({
            "name": name, "display": as_str(e.get("displayName")) or name,
            "name_flag": (as_int(e.get("msPKI-Certificate-Name-Flag"), 0) or 0) & 0xFFFFFFFF,
            "enroll_flag": (as_int(e.get("msPKI-Enrollment-Flag"), 0) or 0) & 0xFFFFFFFF,
            "ra_signature": as_int(e.get("msPKI-RA-Signature"), 0) or 0,
            "ekus": as_strs(e.get("pKIExtendedKeyUsage")) + as_strs(e.get("msPKI-Certificate-Application-Policy")),
            "published": name.lower() in published,
            "schema_version": as_int(e.get("msPKI-Template-Schema-Version"), 0),
            "policies": as_strs(e.get("msPKI-Certificate-Policy")),
            "sd": parse_sd(e.get("nTSecurityDescriptor")),
        })
    # Issuance policies linked to a group (ESC13)
    oids = [{"oid": as_str(e.get("msPKI-Cert-Template-OID")) or "", "name": as_str(e.get("displayName")) or "",
             "group": as_str(e.get("msDS-OIDToGroupLink")) or ""}
            for e in safe("pki_oids", lambda: search(conn, f"CN=OID,{pki_base}", "(msDS-OIDToGroupLink=*)",
                                                     ["msPKI-Cert-Template-OID", "displayName", "msDS-OIDToGroupLink"],
                                                     paged=False), []) or []]

    pki_objects = []
    for odn in (pki_base, f"CN=Certificate Templates,{pki_base}", f"CN=NTAuthCertificates,{pki_base}",
                f"CN=Enrollment Services,{pki_base}", f"CN=Certification Authorities,{pki_base}"):
        e = safe("pki_obj", lambda odn=odn: base_entry(conn, odn, ["nTSecurityDescriptor", "cACertificate"], sd=True))
        if e is not None:
            pki_objects.append({"dn": odn, "sd": parse_sd(e.get("nTSecurityDescriptor")),
                                "certs": [bytes(c) for c in (e.get("cACertificate") or [])
                                          if isinstance(c, (bytes, bytearray))]})

    progress(82, "phase_gpo")
    gpos = []
    for e in safe("gpos", lambda: search(conn, f"CN=Policies,CN=System,{dn}", "(objectClass=groupPolicyContainer)",
                                         ["cn", "displayName", "gPCFileSysPath", "flags", "whenChanged",
                                          "nTSecurityDescriptor"], sd=True), []) or []:
        gpos.append({"guid": (as_str(e.get("cn")) or "").upper(), "name": as_str(e.get("displayName")) or "",
                     "path": as_str(e.get("gPCFileSysPath")) or "", "flags": as_int(e.get("flags"), 0),
                     "changed": gentime_to_dt(e.get("whenChanged")), "sd": parse_sd(e.get("nTSecurityDescriptor"))})
    dc_ou = safe("dc_ou", lambda: base_entry(conn, f"OU=Domain Controllers,{dn}", ["gPLink", "nTSecurityDescriptor"],
                                             sd=True))
    acl["dc_ou"] = parse_sd(dc_ou.get("nTSecurityDescriptor")) if dc_ou else None
    all_links: list[dict] = []
    for e in (safe("all_links", lambda: search(conn, dn, "(gPLink=*)", ["gPLink"]), []) or []) + \
            (safe("site_links", lambda: search(conn, f"CN=Sites,{config_nc}", "(&(objectClass=site)(gPLink=*))",
                                               ["gPLink"], paged=False), []) or []):
        all_links += _parse_gplink(as_str(e.get("gPLink")))
    gpo_links = {"domain": domain["gplink"], "dc_ou": _parse_gplink(as_str(dc_ou.get("gPLink"))) if dc_ou else [],
                 "all": all_links}

    # Owners of the DC objects
    for e in safe("dc_owner", lambda: search(conn, dn, "(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))",
                                             ["nTSecurityDescriptor"], sd=True), []) or []:
        sdd = parse_sd(e.get("nTSecurityDescriptor"))
        for c in computers:
            if c["dn"].lower() == e.dn.lower():
                c["owner"] = (sdd or {}).get("owner")

    return {
        "meta": {"domain_type": dtype, "vendor": dse.get("vendor") or "", "unprivileged": True,
                 "dc_host": getattr(conn, "_samaudit_host", ""), "warnings": warnings, "demo": False,
                 "failed_sections": sorted(failed)},
        "rootdse": dse, "domain": domain, "users": users, "computers": computers, "groups": groups,
        "trusts": trusts, "acl": acl, "config": config, "psos": psos, "pki": {"cas": cas, "templates": templates, "objects": pki_objects, "oids": oids},
        "gpos": gpos, "gpo_links": gpo_links,
    }


# ---------------------------------------------------------------------------
# Additional data sources
# ---------------------------------------------------------------------------

def parse_dns_property(values) -> dict:
    """dNSProperty → {id: data}. Relevant: 2 = ZONE_ALLOW_UPDATE (0 none, 1 nonsecure, 2 secure only)."""
    out = {}
    for raw in values or []:
        if not isinstance(raw, (bytes, bytearray)) or len(raw) < 20:
            continue
        import struct
        data_len, _name_len, _flag, _ver, pid = struct.unpack_from("<IIIII", raw, 0)
        data = bytes(raw[20:20 + data_len])
        out[pid] = data[0] if pid == 2 and data else data
    return out


def _last_backup(conn, dn: str):
    """Last backup according to the replication metadata (dSASignature)."""
    e = base_entry(conn, dn, ["msDS-ReplAttributeMetaData"])
    vals = as_strs(e.get("msDS-ReplAttributeMetaData")) if e else []
    if not vals:
        return None  # not supported (e.g. Samba)
    for v in vals:
        if "<pszAttributeName>dSASignature</pszAttributeName>" in v:
            m = re.search(r"<ftimeLastOriginatingChange>([^<]+)</ftimeLastOriginatingChange>", v)
            if m:
                from datetime import datetime, timezone
                try:
                    d = datetime.fromisoformat(m.group(1).strip().replace("Z", "+00:00"))
                    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
                except ValueError:
                    return gentime_to_dt(m.group(1))
    return "never"


DMSA_CLASS = "msDS-DelegatedManagedServiceAccount"


def _collect_dmsa(conn, dn: str, schema_nc: str) -> dict:
    """Delegated MSAs (Windows Server 2025): who may create them, and whom do existing ones point to?"""
    cls = search(conn, schema_nc, f"(&(objectClass=classSchema)(lDAPDisplayName={DMSA_CLASS}))",
                 ["schemaIDGUID"], paged=False)
    if not cls:
        return {"schema": False}
    raw = (cls[0].get("schemaIDGUID") or [None])[0]
    guid = str(uuid.UUID(bytes_le=bytes(raw))) if isinstance(raw, (bytes, bytearray)) and len(raw) == 16 else None
    containers = []
    flt = ("(|(objectClass=organizationalUnit)(distinguishedName=CN=Users,{0})(distinguishedName=CN=Computers,{0})"
           "(distinguishedName=CN=Managed Service Accounts,{0}))").format(_escape(dn))
    for e in search(conn, dn, flt, ["nTSecurityDescriptor"], sd=True):
        containers.append({"dn": e.dn, "sd": parse_sd(e.get("nTSecurityDescriptor"))})
    accounts = []
    for e in search(conn, dn, f"(objectClass={DMSA_CLASS})",
                    ["sAMAccountName", "msDS-ManagedAccountPrecededByLink", "msDS-DelegatedMSAState"]):
        accounts.append({"dn": e.dn, "sam": as_str(e.get("sAMAccountName")) or "",
                         "preceded_by": as_strs(e.get("msDS-ManagedAccountPrecededByLink")),
                         "state": as_int(e.get("msDS-DelegatedMSAState"))})
    return {"schema": True, "guid": guid, "containers": containers, "accounts": accounts}


def _collect_kds(conn, config_nc: str, schema_nc: str) -> dict:
    """KDS root key (basis of all gMSA/dMSA passwords): who may read it?
    The key itself is never retrieved – only whether the filter matches it (then it is readable)."""
    base = f"CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,{config_nc}"
    cont = base_entry(conn, base, ["nTSecurityDescriptor"], sd=True)
    keys = search(conn, base, "(objectClass=msKds-ProvRootKey)", ["cn", "nTSecurityDescriptor"], sd=True, paged=False)
    if cont is None and not keys:
        return {"present": False}
    readable = bool(search(conn, base, "(&(objectClass=msKds-ProvRootKey)(msKds-RootKeyData=*))", ["cn"], paged=False))
    attr = search(conn, schema_nc, "(lDAPDisplayName=msKds-RootKeyData)", ["schemaIDGUID"], paged=False)
    raw = (attr[0].get("schemaIDGUID") or [None])[0] if attr else None
    guid = str(uuid.UUID(bytes_le=bytes(raw))) if isinstance(raw, (bytes, bytearray)) and len(raw) == 16 else None
    return {"present": True, "dn": base, "container_sd": parse_sd(cont.get("nTSecurityDescriptor")) if cont else None,
            "keys": [{"dn": e.dn, "sd": parse_sd(e.get("nTSecurityDescriptor"))} for e in keys],
            "readable": readable, "attr_guid": guid}


def _collect_extras(conn, dn: str, config_nc: str, dse: dict) -> dict:
    out: dict = {}
    try:
        out["sites"] = len(search(conn, f"CN=Sites,{config_nc}", "(objectClass=site)", ["cn"], paged=False))
        out["subnets"] = len(search(conn, f"CN=Subnets,CN=Sites,{config_nc}", "(objectClass=subnet)", ["cn"]))
    except Exception as e:  # noqa: BLE001
        log.debug("sites: %s", e)
    try:
        out["duplicates"] = [x.dn for x in search(conn, dn, "(|(cn=*CNF:*)(sAMAccountName=$DUPLICATE-*))", ["cn"])]
    except Exception as e:  # noqa: BLE001
        log.debug("duplicates: %s", e)
    zones = []
    root_nc = dse.get("root_nc") or dn
    for part in (f"DC=DomainDnsZones,{dn}", f"DC=ForestDnsZones,{root_nc}", f"CN=MicrosoftDNS,CN=System,{dn}"):
        try:
            for z in search(conn, part, "(objectClass=dnsZone)", ["name", "dNSProperty", "nTSecurityDescriptor"],
                            sd=True, paged=False):
                name = as_str(z.get("name")) or ""
                if name.lower() in ("rootdnsservers", "..trustanchors"):
                    continue
                props = parse_dns_property(z.get("dNSProperty"))
                zones.append({"name": name, "dn": z.dn, "allow_update": props.get(2),
                              "sd": parse_sd(z.get("nTSecurityDescriptor"))})
        except Exception as e:  # noqa: BLE001
            log.debug("dns %s: %s", part, e)
    out["dns_zones"] = zones
    try:
        out["last_backup"] = _last_backup(conn, dn)
    except Exception as e:  # noqa: BLE001
        log.debug("backup: %s", e)
    try:
        dfsr = search(conn, dn, "(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))", ["name"])
        frs = search(conn, f"CN=File Replication Service,CN=System,{dn}", "(objectClass=nTFRSReplicaSet)", ["name"],
                     paged=False)
        out["sysvol_repl"] = "dfsr" if dfsr else ("frs" if frs else None)
    except Exception as e:  # noqa: BLE001
        log.debug("sysvol repl: %s", e)
    return out
