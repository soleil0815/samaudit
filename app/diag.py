# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Anonymous diagnostics package.

One readable JSON file for troubleshooting: program and settings state, reachability of the DCs,
certificate state, the last scans (rule results only, never their contents), recent warnings
and errors, and counts from the activity log.

How it stays anonymous:
  1. Allowlist: only fields named in the *_POLICY tables below are exported. New settings, database
     columns, overview fields and item keys must be classified there – tests/test_diag.py fails otherwise.
  2. Pseudonyms: every name from the database and the settings (domain, DCs, users, groups, CAs, trusts,
     GPOs …) is replaced by a fixed placeholder (domain-1, dc-1, user-1 …), consistently within one
     package. IPv4 addresses, e-mail addresses, distinguished names and domain SIDs are replaced by pattern.
  3. Final check: after building, every string in the package is checked again against all real names;
     if one is left, no package is produced (LeakError).
Passwords, tokens, certificates and the contents of findings (items) are never read into the package.

Command line (also works when the web interface does not):
  docker compose run --rm -T samaudit diag > samaudit-diagnose.json
  docker compose logs --no-color --tail 500 samaudit | docker compose run --rm -T samaudit diag --log - > samaudit-diagnose.json
"""
from __future__ import annotations

import collections
import json
import logging
import os
import platform
import re
import socket
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Any

DIAG_FORMAT = 2          # increase when the structure of the package changes
MAX_SCANS = 5
MAX_EVENTS = 200
MAX_LOG_LINES = 300

# --------------------------------------------------------------------------- allowlists
# Settings attributes (app/config.py):
#   value  exported as is          bool  only whether it is set / true
#   count  only the number         omit  never exported
SETTINGS_POLICY: dict[str, str] = {
    "domain_type": "value", "domain_fqdn": "bool", "netbios": "bool", "dc_hosts": "count", "base_dn": "omit",
    "ldap_ssl": "value", "ldap_starttls": "value", "ldap_port": "value", "ldap_cert_mode": "value",
    "pin_reset_web": "value", "ldap_timeout": "value", "ldap_allow_plain": "value",
    "pin_new_dc": "value", "ldap_ntlm": "value", "ldap_kerberos": "value",
    "allowed_groups": "count", "legacy_groups": "count", "denied_groups": "count",
    "session_timeout_min": "value", "max_login_attempts": "value", "lockout_min": "value",
    "tls_enabled": "value", "certs_dir": "omit", "ldap_ca_file": "bool", "cookie_secure": "value",
    "port": "value", "trusted_proxies": "bool",
    "data_dir": "omit", "db_path": "omit",
    "inactive_days": "value", "admin_inactive_days": "value", "krbtgt_max_days": "value",
    "smb_checks": "value", "smb_timeout": "value",
    "egress_guard": "value", "egress_allow": "count", "update_check": "value", "update_hint_days": "value",
    "report_retention_days": "value", "audit_retention_days": "value", "privacy_contact": "bool",
    "default_lang": "value", "org_name": "bool", "tz": "value",
    "demo_mode": "value",
}

# Database columns (app/db.py SCHEMA): value | pseudo (name → placeholder) | text (free text, pseudonymised)
# | derived (only used inside the package, e.g. counted) | omit
DB_POLICY: dict[str, dict[str, str]] = {
    "scans": {"id": "value", "domain": "pseudo", "domain_type": "value", "status": "value", "progress": "value",
              "phase": "value", "started_at": "value", "finished_at": "value", "duration": "value",
              "started_by": "pseudo", "score_global": "value", "score_stale": "value", "score_privileged": "value",
              "score_trusts": "value", "score_anomalies": "value", "overview_json": "derived", "error": "text",
              "demo": "value"},
    "findings": {"id": "omit", "scan_id": "derived", "rule_id": "value", "category": "omit", "state": "value",
                 "severity": "value", "points": "value", "count": "value", "note": "text",
                 "items_json": "derived"},   # items: never exported, only their names feed the pseudonyms
    "cert_pins": {"host": "pseudo", "fingerprint": "omit", "subject": "derived", "not_after": "value",
                  "is_ca": "value", "der": "omit", "first_seen": "value", "last_seen": "value", "names": "derived"},
    "kv": {"key": "derived", "value": "derived"},     # see KV_POLICY
    "audit_log": {"id": "omit", "ts": "derived", "user": "derived", "ip": "derived", "action": "derived",
                  "detail": "omit"},                 # only counts per action
}

# Environment variables read outside app/config.py: value | bool | pseudo (a name) | omit (never, e.g. passwords)
ENV_POLICY: dict[str, str] = {
    "TZ": "value", "BACKUP_KEEP": "value", "SAMAUDIT_COMPOSE": "value", "SAMAUDIT_IMAGE_VERSION": "value",
    "LOG_LEVEL": "value", "TLS_PFX": "bool", "TLS_CERT": "bool", "TLS_KEY": "bool",
    "TLS_PFX_PASSWORD": "omit", "TLS_KEY_PASSWORD": "omit", "PUBLIC_HOSTNAME": "pseudo",
}

# Keys of the key/value table (db.set_kv / datastate): value | sensitive (names, never exported) | omit
KV_POLICY: dict[str, str] = {"app_version": "value", "schema_version": "value", "domain_type": "value",
                             "domain_vendor": "value", "dc_names": "sensitive", "ldap_mode": "value",
                             "pins_pending": "sensitive", "kerberos_reason": "value"}

# Fields of the scan overview (scanner.build_overview)
OVERVIEW_POLICY: dict[str, str] = {
    "fqdn": "pseudo", "netbios": "pseudo", "sid": "omit", "dn": "omit", "domain_type": "value",
    "dc_host": "pseudo", "ldap_mode": "value", "domain_level": "value", "forest_level": "value", "created": "omit", "is_root": "value",
    "users": "value", "computers": "value", "groups": "value", "admins": "value", "laps": "value",
    "dcs": "special", "os_dist": "value", "trusts": "special", "policy": "value", "maq": "value",
    "priv_groups": "special", "sysvol": "special", "pki_cas": "count", "warnings": "text",
    "last_backup": "value", "dns_zones": "value", "demo": "value", "unprivileged": "value", "vendor": "value",
}

# Keys inside finding items (rules*.py). Items are never exported; "sensitive" values are names that
# are replaced wherever they show up in free text (warnings, errors, log lines) and checked at the end.
ITEM_KEYS: dict[str, str] = {
    "account": "sensitive", "principal": "sensitive", "gpo": "sensitive", "template": "sensitive",
    "dn": "sensitive", "group": "sensitive", "file": "sensitive", "trust": "sensitive", "ca": "sensitive",
    "sid_history": "sensitive", "name": "sensitive", "sam": "sensitive", "dns": "sensitive", "host": "sensitive",
    "member": "sensitive", "spn": "sensitive", "owner": "sensitive", "target": "sensitive", "server": "sensitive", "line": "sensitive",
    "value": "safe", "detail": "safe", "recommended": "safe", "rights": "safe", "type": "safe",
    "pwd_last_set": "safe", "os": "safe", "days": "safe", "sd": "safe", "privilege": "safe",
    "last_logon": "safe", "kind": "safe", "direction": "safe", "changed": "safe", "since": "safe",
    "created": "safe", "flags": "safe", "attribute": "safe", "setting": "safe", "state": "safe",
}

# Well-known names and the words the package itself uses – never treated as private names
RESERVED = {
    "administrator", "administrators", "administratoren", "guest", "gast", "gäste", "guests", "krbtgt",
    "domain admins", "domänen-admins", "enterprise admins", "organisations-admins", "schema admins",
    "schema-admins", "users", "benutzer", "domain users", "domänen-benutzer", "domain computers",
    "domänencomputer", "domain controllers", "domänencontroller", "computers", "builtin", "system", "everyone",
    "jeder", "authenticated users", "authentifizierte benutzer", "account operators", "kontenoperatoren",
    "server operators", "serveroperatoren", "backup operators", "sicherungs-operatoren", "print operators",
    "druck-operatoren", "dnsadmins", "group policy creator owners", "key admins", "enterprise key admins",
    "cert publishers", "zertifikatherausgeber", "read-only domain controllers", "protected users",
    "default domain policy", "default domain controllers policy", "samaudit-users", "samaudit-benutzer",
    "creator owner", "ersteller-besitzer", "self", "selbst", "local system", "network service",
    "samba", "windows", "auto", "pass", "fail", "done", "running", "error", "disabled", "unknown", "demo",
    "low", "medium", "high", "critical", "info", "true", "false", "none", "null", "inbound", "outbound",
    "bidirectional", "trust", "trusts", "domain", "forest", "external", "policies", "sysvol", "netlogon",
    "configuration", "schema", "localhost", "example", "admin", "test", "user",
    # the program's own name (host names like samaudit.firma.local would otherwise mask it)
    "samaudit",
    # words of operating system names (shown as they are)
    "server", "standard", "datacenter", "enterprise", "professional", "pro", "home", "education", "workstation",
    "edition", "essentials", "foundation", "storage", "embedded", "ltsc", "iot",
}
_PLACEHOLDER = re.compile(r"^(?:domain|netbios|dc|host|user|group|name|ca|trust|gpo|ip|mail|dn|sid|net)-\d+$")
_WORD = re.compile(r"[A-Za-z0-9ÄÖÜäöüß_$][A-Za-z0-9ÄÖÜäöüß_$.-]*")
_IPV4 = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d|\.\d)")
_MAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# values may contain escaped characters ("CN=Mustermann\\, Lieselotte" – usual in German directories)
_DNV = r"(?:\\.|[^,;:\"'\n=()\[\]\\]){1,64}"
_DN = re.compile(r"(?i)\b(?:CN|OU|DC)=" + _DNV + r"(?:\s*,\s*(?:CN|OU|DC|O|L|ST|C)=" + _DNV + r")*")
_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+")
_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?![\w:])")
_KEEP_IP = {"0.0.0.0", "127.0.0.1"}  # noqa: S104 – literal addresses that identify nothing


def _is_ipv6(v: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.IPv6Address(v)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified)


class LeakError(Exception):
    """A real name would have remained in the package – nothing is produced."""


class Pseudo:
    """Replaces names by placeholders, consistently within one package."""

    def __init__(self) -> None:
        self.map: dict[str, str] = {}       # lower-case name → placeholder
        self.multi: dict[str, str] = {}     # names containing spaces
        self.domains: set[str] = set()
        self.netbios: set[str] = set()
        self._n: collections.Counter[str] = collections.Counter()
        self._multi_re: re.Pattern | None = None

    @staticmethod
    def _usable(v: str) -> bool:
        lv = v.lower()
        return (len(v) >= 3 and not v.isdigit() and lv not in RESERVED and not _PLACEHOLDER.match(lv)
                and not _IPV4.fullmatch(v))

    def _new(self, kind: str) -> str:
        self._n[kind] += 1
        return f"{kind}-{self._n[kind]}"

    def add(self, value: Any, kind: str) -> str:
        """Register a name; returns its placeholder (or the value itself for well-known names)."""
        v = str(value or "").strip().rstrip(".")
        if not v:
            return ""
        if _IPV4.fullmatch(v):
            return self.text(v)
        if not self._usable(v):
            return v
        key = v.lower()
        # names the word pattern cannot match as one token (spaces, é, apostrophes, "!") are matched literally
        tbl = self.map if _WORD.fullmatch(v) and not v.endswith(("-", ".")) else self.multi
        if key not in tbl:
            tbl[key] = self._new(kind)
            if kind == "user" and ("\\" in v or "@" in v):        # FIRMA\hmeier, hmeier@x: the bare name as well
                bare = v.split("\\")[-1].split("@")[0]
                if bare and bare.lower() != key and self._usable(bare):
                    (self.map if _WORD.fullmatch(bare) else self.multi).setdefault(bare.lower(), tbl[key])
            self._multi_re = None
            if kind in ("dc", "host") and "." in v:                 # dc1.firma.local → also "dc1"
                short = v.split(".")[0]
                if self._usable(short) and len(short) >= 3:
                    self.map.setdefault(short.lower(), tbl[key])
            if kind == "domain":
                self.domains.add(key)
            if kind == "netbios":
                self.netbios.add(key)
        return tbl[key]

    def add_dn(self, dn: str) -> None:
        """The object's own name (first CN) is a name; whole DNs are replaced by pattern anyway."""
        k, _, v = re.split(r"(?<!\\),", dn or "")[0].partition("=")
        if v and k.strip().upper() == "CN":
            v = re.sub(r"\\(.)", r"\1", v.strip())          # "Mustermann\, Lieselotte" → "Mustermann, Lieselotte"
            self.add(v, "name")
            for part in re.split(r",\s*", v) if "," in v else []:   # both halves on their own as well
                self.add(part, "name")

    def tokens(self) -> list[str]:
        return list(self.map) + list(self.multi)

    def _sub_word(self, m: re.Match) -> str:
        w = m.group(0)
        core = w.rstrip(".-")
        tail = w[len(core):]
        ph = self.map.get(core.lower())
        if ph:
            return ph + tail
        low = core.lower()
        for d in self.domains:                                 # unknown host inside a known domain
            if low.endswith("." + d):
                return self.add(core, "host") + tail
        return w

    def harvest(self, s: Any) -> Any:
        """First pass over all strings: learn names that only show up inside patterns (the object of a DN,
        the user in user@domain and in NETBIOS\\user), so they are also replaced where they stand alone."""
        if not isinstance(s, str) or not s:
            return s
        for m in _DN.finditer(s):
            self.add_dn(m.group(0))
        for m in _MAIL.finditer(s):
            self.add(m.group(0).split("@")[0], "user")
        for nb in self.netbios:
            for m in re.finditer(r"(?i)(?<![\w-])" + re.escape(nb) + r"\\([\w.$-]+)", s):
                self.add(m.group(1), "user")
        return s

    def text(self, s: Any) -> Any:
        if not isinstance(s, str) or not s:
            return s
        s = _MAIL.sub(lambda m: self._pattern(m.group(0), "mail"), s)
        s = _DN.sub(lambda m: self._pattern(m.group(0).rstrip(), "dn") + m.group(0)[len(m.group(0).rstrip()):], s)
        s = _SID.sub(lambda m: self._pattern(m.group(0), "sid"), s)
        s = _IPV4.sub(lambda m: m.group(0) if m.group(0) in _KEEP_IP else self._pattern(m.group(0), "ip"), s)
        s = _IPV6.sub(lambda m: self._pattern(m.group(0), "ip") if _is_ipv6(m.group(0)) else m.group(0), s)
        if self.multi:
            if self._multi_re is None:
                alts = sorted(self.multi, key=len, reverse=True)
                self._multi_re = re.compile(r"(?i)(?<![\w.-])(" + "|".join(re.escape(a) for a in alts) + r")(?![\w-])")
            s = self._multi_re.sub(lambda m: self.multi[m.group(0).lower()], s)
        return _WORD.sub(self._sub_word, s)

    def _pattern(self, v: str, kind: str) -> str:
        key = v.lower()
        if key not in self.map:
            self.map[key] = self._new(kind)
        return self.map[key]


# --------------------------------------------------------------------------- recent warnings and errors
_events: collections.deque = collections.deque(maxlen=MAX_EVENTS)
_started = time.time()


class _EventBuffer(logging.Handler):
    """Keeps the last warnings and errors in memory (never on disk); pseudonymised only on export."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            exc = None
            if record.exc_info and record.exc_info[1] is not None:
                e = record.exc_info[1]
                frames = traceback.extract_tb(record.exc_info[2])[-4:]
                exc = {"type": type(e).__name__, "message": str(e)[:300],
                       "where": [f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in frames]}
            _events.append({"ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="seconds"),
                            "level": record.levelname, "logger": record.name,
                            "message": record.getMessage()[:500], "exception": exc})
        except Exception:  # noqa: BLE001 – logging must never fail
            pass


_installed = False


def install_log_buffer() -> None:
    global _installed, _started
    if _installed:
        return
    _installed = True
    _started = time.time()
    h = _EventBuffer(level=logging.WARNING)
    logging.getLogger().addHandler(h)


# --------------------------------------------------------------------------- collecting
def _settings_part(settings) -> dict:
    out: dict[str, Any] = {}
    for name, kind in SETTINGS_POLICY.items():
        v = getattr(settings, name, None)
        if kind == "value":
            out[name] = v
        elif kind == "bool":
            out[name] = bool(v)
        elif kind == "count":
            out[name] = len(v or [])
    out["allowed_groups_default"] = settings.allowed_groups == ["SAMAUDIT-Users"]
    return out


def _register_settings(p: Pseudo, settings) -> None:
    if settings.domain_fqdn:
        p.add(settings.domain_fqdn, "domain")
    if settings.netbios:
        p.add(settings.netbios, "netbios")
    for h in settings.dc_hosts:
        p.add(h, "domain" if h.lower() == settings.domain_fqdn else "dc")
    for g in settings.allowed_groups + settings.legacy_groups + settings.denied_groups:
        if g.upper().startswith("RID:"):
            continue
        if "=" in g:
            p.add_dn(g)
        else:
            p.add(g, "group")
    for e in settings.egress_allow:
        p.add(e, "host")
    if settings.org_name:
        p.add(settings.org_name, "name")
    if settings.privacy_contact:
        p.add(settings.privacy_contact, "name")
        for w in re.split(r"[\s,;]+", settings.privacy_contact):
            if len(w) >= 4:
                p.add(w, "name")


def _env_part(p: Pseudo) -> dict:
    out: dict[str, Any] = {}
    for name, kind in ENV_POLICY.items():
        v = os.environ.get(name, "").strip()
        if kind == "value":
            out[name] = v or None
        elif kind == "bool":
            out[name] = bool(v)
        elif kind == "pseudo":
            out[name] = p.add(v, "host") if v else None
    p.add(socket.gethostname(), "host")
    return out


def _register_items(p: Pseudo, items: Any) -> None:
    for it in items or []:
        if not isinstance(it, dict):
            continue
        for k, v in it.items():
            if ITEM_KEYS.get(k, "sensitive") != "sensitive" or v in (None, ""):   # unknown keys: treat as names
                continue
            for s in (v if isinstance(v, list) else [v]):
                s = str(s)
                if "=" in s and "," in s:
                    p.add_dn(s)
                if len(s) <= 256:
                    p.add(s, "name")


def _overview_part(p: Pseudo, ov: dict) -> dict:
    out: dict[str, Any] = {}
    for k, kind in OVERVIEW_POLICY.items():
        if k not in ov:
            continue
        v = ov[k]
        if kind == "value":
            out[k] = v
        elif kind == "pseudo":
            out[k] = p.add(v, "domain" if k == "fqdn" else "netbios" if k == "netbios" else "dc") if v else v
        elif kind == "count":
            out[k] = len(v or [])
        elif kind == "text":
            out[k] = v
        elif kind == "special" and k == "dcs":
            out[k] = [{"name": p.add(d.get("name"), "dc"), "os": d.get("os"), "rodc": d.get("rodc")} for d in v or []]
        elif kind == "special" and k == "trusts":
            out[k] = [{"name": p.add(t.get("name"), "trust"), "direction": t.get("direction"), "type": t.get("type"),
                       "attributes": t.get("attributes")} for t in v or []]
        elif kind == "special" and k == "priv_groups":
            out[k] = [{"name": p.add(g.get("name"), "group"), "count": g.get("count"), "enabled": g.get("enabled")}
                      for g in v or []]
        elif kind == "special" and k == "sysvol":
            out[k] = {"status": (v or {}).get("status"), "error": (v or {}).get("error"), "files": (v or {}).get("files"),
                      "auth": (v or {}).get("auth"), "kerberos_error": (v or {}).get("kerberos_error")}
    return out


def _register_overview(p: Pseudo, ov: dict) -> None:
    if ov.get("fqdn"):
        p.add(ov["fqdn"], "domain")
    if ov.get("netbios"):
        p.add(ov["netbios"], "netbios")
    for d in ov.get("dcs") or []:
        p.add(d.get("name"), "dc")
    for t in ov.get("trusts") or []:
        p.add(t.get("name"), "trust")
    for c in ov.get("pki_cas") or []:
        p.add(c, "ca")
    for g in ov.get("priv_groups") or []:
        p.add(g.get("name"), "group")
        for m in g.get("members") or []:
            p.add(m, "user")
    if ov.get("dn"):
        p.add_dn(ov["dn"])


_NOTE = re.compile(r"^@?[a-z][a-z0-9_]*(?:\|[-0-9.]+)?$|^[-0-9.]+ ?%?$")


def _note(v: Any) -> Any:
    """Notes are codes ("@n_days_left|30", "na_acl") or numbers – anything else is not exported."""
    if v is None:
        return None
    return v if _NOTE.match(str(v)) else "(text)"


def _probe(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "ok"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except socket.gaierror:
        return "dns"
    except OSError as e:
        return f"error:{e.errno}"


def _connection_part(p: Pseudo, settings, probe: bool) -> dict:
    from . import db
    out: dict[str, Any] = {"cert_mode": settings.ldap_cert_mode, "targets": [], "pins": []}
    ports = sorted({settings.ldap_port, 389, 636} | ({445} if settings.smb_checks else set()) |
                   ({88} if settings.ldap_kerberos else set()))
    if probe and not settings.demo_mode:
        from concurrent.futures import ThreadPoolExecutor

        def one(host: str) -> dict:
            try:
                addrs = {str(i[4][0]) for i in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)}
            except OSError:
                addrs = set()
            with ThreadPoolExecutor(len(ports)) as ex:
                res = dict(zip(ports, ex.map(lambda port: _probe(host, port), ports), strict=True))
            return {"host": host, "addresses": len(addrs), "ports": {str(k): v for k, v in res.items()}}

        hosts = settings.dc_hosts[:4]
        with ThreadPoolExecutor(max(1, len(hosts))) as ex:
            for t in ex.map(one, hosts):
                p.add(t["host"], "domain" if t["host"].lower() == settings.domain_fqdn else "dc")
                out["targets"].append(t)
    else:
        out["targets_note"] = "not probed (demo mode)" if settings.demo_mode else "not probed"
    for pin in db.list_pins():
        host = pin["host"]
        name, _, addr = host.partition(" [")
        p.add(name, "domain" if name == settings.domain_fqdn else "dc")
        if pin.get("subject"):
            p.text(pin["subject"])
        out["pins"].append({"host": host, "is_ca": bool(pin["is_ca"]), "not_after": pin["not_after"],
                            "first_seen": pin["first_seen"], "last_seen": pin["last_seen"]})
    return out


def _web_cert_part() -> dict:
    try:
        from . import webcert
        info = webcert.INFO or {}
    except Exception:  # noqa: BLE001
        info = {}
    out = {k: info.get(k) for k in ("source", "chain", "not_after", "warnings") if k in info}
    if info.get("error") is not None:                  # the code only – the text may contain file and host names
        out["error"] = getattr(info["error"], "key", "error")
    return out


def _runtime_part(settings) -> dict:
    from . import db
    out: dict[str, Any] = {"python": platform.python_version(), "machine": platform.machine(),
                           "uptime_s": int(time.time() - _started) if _installed else None,
                           "user_id": os.getuid() if hasattr(os, "getuid") else None}
    try:
        from . import kerberos
        out["kerberos_libraries"] = kerberos.libraries()
    except Exception:  # noqa: BLE001
        out["kerberos_libraries"] = False
    try:
        out["db_size_kb"] = os.path.getsize(settings.db_path) // 1024
        st = os.statvfs(settings.data_dir)
        out["data_free_mb"] = st.f_bavail * st.f_frsize // (1024 * 1024)
        bdir = os.path.join(settings.data_dir, "backups")
        out["backups"] = len([f for f in os.listdir(bdir) if f.endswith(".db")]) if os.path.isdir(bdir) else 0
    except OSError as e:
        out["data_error"] = type(e).__name__
    with db.conn() as c:
        out["scans_total"] = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return out


def _update_part() -> dict:
    from . import updatecheck
    return updatecheck.diag_part()


def _activity_part(p: Pseudo) -> dict:
    from . import db
    with db.conn() as c:
        rows = c.execute("SELECT action, COUNT(*) AS n, MAX(ts) AS last FROM audit_log GROUP BY action").fetchall()
        for r in c.execute("SELECT DISTINCT user FROM audit_log WHERE user IS NOT NULL").fetchall():
            p.add(r["user"], "user")
        users = c.execute("SELECT COUNT(DISTINCT user) FROM audit_log").fetchone()[0]
    return {"actions": {r["action"]: {"count": r["n"], "last": r["last"]} for r in rows}, "distinct_users": users}


def _scans_part(p: Pseudo) -> tuple[list, dict | None]:
    from . import db
    with db.conn() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (MAX_SCANS,)).fetchall()]
    out, latest_ov = [], None
    for r in rows:
        ov = json.loads(r.get("overview_json") or "{}")
        _register_overview(p, ov)
        findings = db.get_findings(r["id"])
        for f in findings:
            _register_items(p, f.get("items"))
        if r.get("status") == "done" and latest_ov is None:
            latest_ov = ov
        entry: dict[str, Any] = {}
        for col, kind in DB_POLICY["scans"].items():
            if kind == "value":
                entry[col] = r.get(col)
            elif kind == "pseudo":
                entry[col] = p.add(r.get(col), "domain" if col == "domain" else "user") if r.get(col) else None
            elif kind == "text":
                entry[col] = r.get(col)
        res: dict[str, list] = {}
        errors = []
        for f in sorted(findings, key=lambda f: f["rule_id"]):
            res[f["rule_id"]] = [f["state"], f["severity"], f["points"], f["count"], _note(f.get("note"))]
            if f.get("note") == "na_error":
                errors.append({"rule": f["rule_id"], "detail": [i.get("detail") for i in f.get("items") or []][:3]})
        entry["warnings"] = ov.get("warnings") or []
        entry["sysvol"] = ov.get("sysvol")
        entry["rule_errors"] = errors
        entry["summary"] = dict(collections.Counter(f["state"] for f in findings))
        entry["results"] = res
        out.append(entry)
    return out, latest_ov


def _walk(o: Any, fn) -> Any:
    if isinstance(o, dict):
        return {str(k): _walk(v, fn) for k, v in o.items()}   # keys are field names, rule ids, action codes
    if isinstance(o, list):
        return [_walk(v, fn) for v in o]
    if o is None or isinstance(o, (bool, int, float)):
        return o
    return fn(o if isinstance(o, str) else str(o))   # objects (e.g. exceptions) are text too – never pass them by


def _strings(o: Any):
    if isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)
    elif isinstance(o, str):
        yield o
    elif o is not None and not isinstance(o, (bool, int, float)):
        yield str(o)


def check_leaks(pkg: dict, p: Pseudo) -> None:
    """Every real name known to the package builder must be gone; raise LeakError otherwise."""
    single = set(p.map)
    multi = None
    if p.multi:
        alts = sorted(p.multi, key=len, reverse=True)
        multi = re.compile(r"(?i)(?<![\w.-])(" + "|".join(re.escape(a) for a in alts) + r")(?![\w-])")
    for s in _strings(pkg):
        for m in _WORD.finditer(s):
            w = m.group(0).rstrip(".-").lower()
            if w in single and not _PLACEHOLDER.match(w):
                raise LeakError(f"a name ({p.map[w].split('-')[0]}) remained")
        if multi is not None:
            m2 = multi.search(s)
            if m2:
                raise LeakError(f"a name ({p.multi[m2.group(0).lower()].split('-')[0]}) remained")
        for ip in _IPV4.findall(s):
            if ip not in _KEEP_IP:
                raise LeakError("an IP address remained")
        if any(_is_ipv6(m.group(0)) for m in _IPV6.finditer(s)):
            raise LeakError("an IP address remained")
        if _DN.search(s) or _MAIL.search(s) or _SID.search(s):
            raise LeakError("a directory name, e-mail address or SID remained")


def build(source: str = "web", probe: bool = True, log_lines: list[str] | None = None) -> dict:
    """Builds the package. Raises LeakError if the final check finds a real name."""
    from . import datastate, db
    from .config import settings
    from .version import APP_NAME, IMAGE_VERSION, VERSION

    p = Pseudo()
    _register_settings(p, settings)
    for n in (db.get_kv("dc_names") or "").split(","):
        if n.strip():
            p.add(n.strip(), "dc")

    scans, latest_ov = _scans_part(p)
    kv = {k: db.get_kv(k) for k, kind in KV_POLICY.items() if kind == "value"}
    pkg: dict[str, Any] = {
        "samaudit_diagnostics": DIAG_FORMAT,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "notice": ("Anonymised: names, addresses and IDs are replaced by placeholders (domain-1, dc-1, ip-1, "
                   "user-1 …). No passwords, certificates or report contents."),
        "program": {"name": APP_NAME, "version": VERSION, "image_version": IMAGE_VERSION,
                    "schema_version": datastate.SCHEMA_VERSION, "db": kv,
                    "compose": {"have": os.environ.get("SAMAUDIT_COMPOSE", ""), "need": datastate.COMPOSE_REQUIRED},
                    "config_problems": settings.validate()},
        "settings": _settings_part(settings),
        "environment": _env_part(p),
        "runtime": _runtime_part(settings),
        "update": _update_part(),
        "web_certificate": _web_cert_part(),
        "connection": _connection_part(p, settings, probe),
        "domain": {"detected_type": kv.get("domain_type"), "vendor": kv.get("domain_vendor"),
                   "dc_names_known": len([n for n in (db.get_kv("dc_names") or "").split(",") if n.strip()]),
                   "latest_scan": _overview_part(p, latest_ov) if latest_ov else None},
        "scans": scans,
        "activity": _activity_part(p),
        "events": list(_events) if source == "web" else "only in the web interface (use --log for the server log)",
    }
    if log_lines is not None:
        pkg["server_log"] = [ln.rstrip()[:400] for ln in log_lines[-MAX_LOG_LINES:]]
    _walk(pkg, p.harvest)
    pkg = _walk(pkg, p.text)
    check_leaks(pkg, p)
    return pkg


def dumps(pkg: dict) -> str:
    return json.dumps(pkg, ensure_ascii=False, indent=2, default=str) + "\n"


def filename(pkg: dict) -> str:
    stamp = re.sub(r"[^0-9]", "", str(pkg.get("created", "")))[:12]
    return f"samaudit-diagnose-{pkg['program']['version']}-{stamp}.json"


def _drop_root() -> None:
    """`docker compose exec` runs as root: read the data as its owner (the program user), like the server."""
    from .config import settings
    if not hasattr(os, "getuid") or os.getuid() != 0:
        return
    try:
        st = os.stat(settings.data_dir)
    except OSError:
        return
    if st.st_uid != 0:
        os.setgroups([])
        os.setgid(st.st_gid)
        os.setuid(st.st_uid)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="diag", description="Anonymous SAMAUDIT diagnostics package (JSON on stdout).")
    ap.add_argument("--log", help="server log to include, '-' = stdin (e.g. piped from docker compose logs)")
    ap.add_argument("--no-probe", action="store_true", help="do not test the connection to the DCs")
    ap.add_argument("-o", "--output", help="write to this file instead of stdout")
    a = ap.parse_args(argv)
    lines = None
    _drop_root()                         # before reading --log: the file is read with the program user's rights
    if a.log:
        src = sys.stdin if a.log == "-" else open(a.log, encoding="utf-8", errors="replace")  # noqa: SIM115
        with src:
            lines = collections.deque(src, maxlen=MAX_LOG_LINES)
    from .config import settings
    if not os.path.exists(settings.db_path):
        print("SAMAUDIT has not been started yet (no database) – start it once, then create the package.",
              file=sys.stderr)
        return 2
    try:
        pkg = build("cli", probe=not a.no_probe, log_lines=list(lines) if lines is not None else None)
    except LeakError as e:
        print(f"No package produced: {e}. Please report this as a bug (without the package).", file=sys.stderr)
        return 3
    text = dumps(pkg)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"written: {a.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
