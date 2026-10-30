# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Hilfsfunktionen für Active-Directory-Datenformate (SIDs, Zeitstempel,
userAccountControl, Security Descriptors)."""
from __future__ import annotations

import re
import struct
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# userAccountControl
# ---------------------------------------------------------------------------
UAC_SCRIPT = 0x0001
UAC_ACCOUNTDISABLE = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
UAC_NORMAL_ACCOUNT = 0x0200
UAC_WORKSTATION_TRUST_ACCOUNT = 0x1000
UAC_SERVER_TRUST_ACCOUNT = 0x2000
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_SMARTCARD_REQUIRED = 0x40000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UAC_PARTIAL_SECRETS_ACCOUNT = 0x4000000  # RODC

# ---------------------------------------------------------------------------
# Well-known SIDs / RIDs
# ---------------------------------------------------------------------------
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone / Jeder",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "SELF",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicator",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
}

DOMAIN_RIDS = {
    498: "Enterprise Read-only Domain Controllers",
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

# Extended Rights / Objekt-GUIDs
GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
GUID_CERT_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_CERT_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Access mask bits
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000
ADS_RIGHT_WRITE_DAC = 0x00040000
ADS_RIGHT_WRITE_OWNER = 0x00080000
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_SELF = 0x00000008
FULL_CONTROL_AD = 0x000F01FF

# ---------------------------------------------------------------------------
# Werte-Normalisierung (ldap3 liefert je nach Schema-Info Listen, Strings, Bytes)
# ---------------------------------------------------------------------------

def as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def first(v):
    lst = as_list(v)
    return lst[0] if lst else None


def as_str(v) -> str | None:
    v = first(v)
    if v is None:
        return None
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.decode("latin-1")
    return str(v)


def as_int(v, default: int | None = None) -> int | None:
    v = first(v)
    if v is None:
        return default
    if isinstance(v, datetime):
        return default
    try:
        if isinstance(v, bytes):
            v = v.decode()
        return int(v)
    except (TypeError, ValueError):
        return default


def as_strs(v) -> list[str]:
    out = []
    for x in as_list(v):
        if isinstance(x, bytes):
            try:
                x = x.decode("utf-8")
            except UnicodeDecodeError:
                continue
        out.append(str(x))
    return out


# ---------------------------------------------------------------------------
# SIDs
# ---------------------------------------------------------------------------

def sid_to_str(raw) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw if raw.startswith("S-") else None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        return None
    revision = raw[0]
    sub_count = raw[1]
    if len(raw) < 8 + 4 * sub_count:
        return None
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack("<" + "I" * sub_count, raw[8:8 + 4 * sub_count])
    return "S-%d-%d" % (revision, authority) + "".join("-%d" % s for s in subs)


def sid_rid(sid: str | None) -> int | None:
    if not sid:
        return None
    try:
        return int(sid.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return None


def sid_domain(sid: str | None) -> str | None:
    if not sid or sid.count("-") < 4:
        return None
    return sid.rsplit("-", 1)[0]


# ---------------------------------------------------------------------------
# Zeit
# ---------------------------------------------------------------------------
_EPOCH_AD = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_dt(v) -> datetime | None:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    n = as_int(v)
    if n is None:
        # ldap3 kann Zeitwerte bereits als String formatiert liefern
        s = as_str(v)
        if s:
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _EPOCH_AD + timedelta(microseconds=n // 10)
    except OverflowError:
        return None


def gentime_to_dt(v) -> datetime | None:
    v = first(v)
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    s = as_str(v)
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y%m%d%H%M%S.%fZ", "%Y%m%d%H%M%S.0Z", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def interval_days(v) -> float | None:
    """Negative 100ns-Intervalle (maxPwdAge, lockoutDuration …) → Tage."""
    n = as_int(v)
    if n is None:
        return None
    if n in (-9223372036854775808, 0):
        return 0.0
    return abs(n) / 10_000_000 / 86400


def interval_minutes(v) -> float | None:
    n = as_int(v)
    if n is None:
        return None
    if n == -9223372036854775808:
        return 0.0
    return abs(n) / 10_000_000 / 60


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def days_since(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    return (now_utc() - dt).days


def local_tz():
    """Zeitzone der Anzeige (TZ, Standard Europe/Berlin)."""
    import os
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(os.environ.get("TZ") or "Europe/Berlin")
    except Exception:  # noqa: BLE001 – ohne tzdata: UTC
        return timezone.utc


LOCAL_TZ = local_tz()


def fmt_date(dt: datetime | None) -> str:
    return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d") if dt else "–"


# ---------------------------------------------------------------------------
# Security Descriptor (self-relative) – minimaler DACL-Parser
# ---------------------------------------------------------------------------

def _guid(b: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(b)))


def parse_sd(raw) -> dict | None:
    """Liefert {'owner': sid, 'aces': [{type, flags, mask, sid, object_type, inherited_object_type, inherited}]}."""
    raw = first(raw)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 20:
        return None
    try:
        _rev, _sbz, _control, off_owner, _off_group, _off_sacl, off_dacl = struct.unpack_from("<BBHIIII", raw, 0)
        owner = None
        if off_owner:
            owner = _sid_at(raw, off_owner)
        aces = []
        if off_dacl:
            _arev, _s1, _size, count, _s2 = struct.unpack_from("<BBHHH", raw, off_dacl)
            pos = off_dacl + 8
            for _ in range(count):
                ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", raw, pos)
                body = pos + 4
                ace = {"type": ace_type, "flags": ace_flags, "inherited": bool(ace_flags & 0x10),
                       "object_type": None, "inherited_object_type": None}
                if ace_type in (0x00, 0x01):  # ACCESS_ALLOWED / ACCESS_DENIED
                    ace["mask"] = struct.unpack_from("<I", raw, body)[0]
                    ace["sid"] = _sid_at(raw, body + 4)
                    ace["allow"] = ace_type == 0x00
                    aces.append(ace)
                elif ace_type in (0x05, 0x06):  # ACCESS_ALLOWED_OBJECT / DENIED_OBJECT
                    mask, oflags = struct.unpack_from("<II", raw, body)
                    p = body + 8
                    if oflags & 0x1:
                        ace["object_type"] = _guid(raw[p:p + 16])
                        p += 16
                    if oflags & 0x2:
                        ace["inherited_object_type"] = _guid(raw[p:p + 16])
                        p += 16
                    ace["mask"] = mask
                    ace["sid"] = _sid_at(raw, p)
                    ace["allow"] = ace_type == 0x05
                    aces.append(ace)
                pos += ace_size
                if ace_size == 0:
                    break
        return {"owner": owner, "aces": aces}
    except (struct.error, IndexError, ValueError):
        return None


def _sid_at(raw: bytes, off: int) -> str | None:
    if off + 8 > len(raw):
        return None
    sub_count = raw[off + 1]
    return sid_to_str(bytes(raw[off:off + 8 + 4 * sub_count]))


def ace_grants_control(ace: dict) -> list[str]:
    """Welche gefährlichen Rechte gewährt eine ACE? (für Berichte)"""
    out = []
    m = ace.get("mask", 0)
    if not ace.get("allow"):
        return out
    if m & ADS_RIGHT_GENERIC_ALL or (m & FULL_CONTROL_AD) == FULL_CONTROL_AD:
        out.append("GenericAll")
    if m & ADS_RIGHT_GENERIC_WRITE:
        out.append("GenericWrite")
    if m & ADS_RIGHT_WRITE_DAC:
        out.append("WriteDacl")
    if m & ADS_RIGHT_WRITE_OWNER:
        out.append("WriteOwner")
    if (m & ADS_RIGHT_DS_WRITE_PROP) and not ace.get("object_type"):
        out.append("WriteAllProperties")
    return out


# ---------------------------------------------------------------------------
# Betriebssysteme
# ---------------------------------------------------------------------------

# Ende des erweiterten Supports von Windows Server 2016 und Windows 10 Enterprise LTSC 2021:
# letzter Patchtag 12.01.2027 – ab dem 13.01.2027 ohne Sicherheitsupdates
EXPIRING_END = datetime(2027, 1, 13, tzinfo=timezone.utc)


def classify_os(os_name: str | None, os_version: str | None = None, today: datetime | None = None) -> str:
    """Grobe Einordnung: 'obsolete', 'win10', 'expiring', 'supported', 'samba', 'other', 'unknown'.
    'expiring' wird nach EXPIRING_END automatisch zu 'obsolete'."""
    c = _classify_os(os_name, os_version)
    if c == "expiring" and (today or now_utc()) >= EXPIRING_END:
        return "obsolete"
    return c


def _classify_os(os_name: str | None, os_version: str | None = None) -> str:
    if not os_name:
        return "unknown"
    s = os_name.lower()
    if "samba" in s:
        return "samba"
    if "windows" not in s:
        return "other"
    obsolete = ("windows 2000", "windows xp", "windows vista", "windows 7", "windows 8",
                "server 2003", "server 2008", "server 2012", "windows nt")
    if any(o in s for o in obsolete):
        return "obsolete"
    if "windows 10" in s:
        if "iot" in s and ("ltsc" in s or "ltsb" in s):
            return "supported"            # IoT Enterprise LTSC 2021: Support bis 01/2032
        if "ltsc" in s or "ltsb" in s:
            # Langzeitversionen: Support je nach Build (2015/2016 beendet, 2019 bis 01/2029, 2021 bis 01/2027)
            m = re.search(r"\((\d{5})\)", os_version or "")
            build = int(m.group(1)) if m else 0
            if build and build <= 14393:
                return "obsolete"
            if build >= 19044:
                return "expiring"
            return "supported"
        return "win10"
    if "server 2016" in s:
        return "expiring"
    return "supported"
