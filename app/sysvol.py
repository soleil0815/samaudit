# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""SYSVOL-Auswertung über SMB mit den Anmeldedaten des Admins:
- Group Policy Preferences mit gespeicherten Passwörtern (cpassword, Autologon)
- Sicherheitsvorlagen (GptTmpl.inf), Administrative Vorlagen (Registry.pol),
  erweiterte Überwachungsrichtlinie (audit.csv)
- Anmeldeskripte (NETLOGON, GPO-Skripte) mit möglichen Klartext-Passwörtern"""
from __future__ import annotations

import configparser
import logging
import re
import struct

from .config import settings

log = logging.getLogger("samaudit.sysvol")

GPP_FILES = {"groups.xml", "services.xml", "scheduledtasks.xml", "datasources.xml", "drives.xml", "printers.xml",
             "registry.xml"}
_CPASS = re.compile(rb'cpassword="([^"]+)"', re.IGNORECASE)
_USER = re.compile(rb'(?:userName|accountName|runAs|newName)="([^"]*)"', re.IGNORECASE)
_AUTOLOGON = re.compile(rb'name="DefaultPassword"[^>]*value="([^"]+)"', re.IGNORECASE)

SCRIPT_EXT = (".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".kix", ".js", ".wsf", ".ini", ".cfg", ".txt")
MAX_SCRIPT_FILES = 1500
SECRET_PATTERNS = [
    ("net use /user", re.compile(r"net\s+use\s+.*?/user:\S+\s+(?!\*)\S+", re.I)),
    ("ConvertTo-SecureString", re.compile(r"ConvertTo-SecureString\s+[\"'][^\"']{4,}[\"']\s+-AsPlainText", re.I)),
    ("password=", re.compile(r"\b(?:password|passwd|pwd|kennwort|passwort)\s*[=:]\s*[\"']?[^\s\"'$%{]{4,}", re.I)),
    ("runas /savecred", re.compile(r"runas\s+.*?/savecred", re.I)),
    ("-Password", re.compile(r"-(?:Password|Credential)\s+[\"'][^\"']{4,}[\"']", re.I)),
]


def _decode(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def parse_gpttmpl(text: str) -> dict:
    cp = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    cp.optionxform = str  # Groß-/Kleinschreibung erhalten
    try:
        cp.read_string(text)
    except configparser.Error:
        return {}
    out: dict[str, dict] = {}
    for sec in cp.sections():
        out[sec] = {k.strip(): v.strip() for k, v in cp.items(sec)}
    return out


def parse_registry_pol(b: bytes) -> dict:
    """Registry.pol (PReg) → {'schlüssel\\wert' (klein): Wert}."""
    out: dict[str, object] = {}
    if len(b) < 8 or b[:4] != b"PReg":
        return out
    i, n = 8, len(b)

    def read_str() -> str:
        nonlocal i
        j = i
        while j + 1 < n and b[j:j + 2] != b"\x00\x00":
            j += 2
        s = b[i:j].decode("utf-16-le", "replace")
        i = j + 2
        return s

    while i + 1 < n:
        if b[i:i + 2] != b"[\x00":
            i += 2
            continue
        i += 2
        try:
            key = read_str(); i += 2               # ;
            val = read_str(); i += 2               # ;
            typ = struct.unpack_from("<I", b, i)[0]; i += 6
            size = struct.unpack_from("<I", b, i)[0]; i += 6
            data = b[i:i + size]; i += size
            i += 2                                  # ]
        except struct.error:
            break
        if typ in (1, 2):
            v: object = data.decode("utf-16-le", "replace").rstrip("\x00")
        elif typ == 4 and len(data) >= 4:
            v = struct.unpack("<I", data[:4])[0]
        elif typ == 11 and len(data) >= 8:
            v = struct.unpack("<Q", data[:8])[0]
        elif typ == 7:
            v = [x for x in data.decode("utf-16-le", "replace").split("\x00") if x]
        else:
            v = data.hex()
        if val.startswith("**del.") or val.startswith("**Del."):
            continue
        out[f"{key}\\{val}".lower()] = v
    return out


def parse_audit_csv(text: str) -> dict:
    """audit.csv → {subcategory-GUID (klein) oder Name: Setting Value}."""
    import csv
    import io
    out = {}
    for row in csv.DictReader(io.StringIO(text)):
        guid = (row.get("Subcategory GUID") or "").strip().strip("{}").lower()
        name = (row.get("Subcategory") or "").strip()
        try:
            val = int((row.get("Setting Value") or "0").strip() or 0)
        except ValueError:
            val = 0
        if guid:
            out[guid] = val
        if name:
            out[name.lower()] = val
    return out


def _scan_script(data: bytes, path: str, found: list) -> None:
    text = _decode(data[:600_000])
    for no, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        stripped = line.strip()
        if stripped.startswith(("REM ", "rem ", "::", "#", "'")) and "net use" not in stripped.lower():
            continue
        for kind, rx in SECRET_PATTERNS:
            if rx.search(line):
                found.append({"file": path, "line": no, "kind": kind})
                break
        if len(found) > 300:
            return


def scan(server: str, fqdn: str, username: str, password: str, gpos: list[dict], gpo_links: dict) -> dict:
    result = {"status": "ok", "error": None, "gpp_passwords": [], "secedit": {}, "regpol": {}, "audit": {},
              "script_secrets": [], "files_scanned": 0}
    if not settings.smb_checks:
        result["status"] = "disabled"
        return result
    try:
        import smbclient
        from smbclient import path as smbpath
    except ImportError as e:
        result.update(status="error", error=f"smbprotocol fehlt: {e}")
        return result

    try:
        smbclient.register_session(server, username=username, password=password,
                                   connection_timeout=settings.smb_timeout, require_signing=True)
    except Exception as e:  # noqa: BLE001
        result.update(status="error", error=str(e)[:300])
        return result

    def read(path: str, limit: int = 2_000_000) -> bytes | None:
        try:
            with smbclient.open_file(path, mode="rb") as fh:
                result["files_scanned"] += 1
                return fh.read(limit)
        except Exception as e:  # noqa: BLE001
            log.debug("read %s: %s", path, e)
            return None

    script_count = 0

    def scan_scripts(folder: str, label: str):
        nonlocal script_count
        try:
            if not smbpath.isdir(folder):
                return
            for dirpath, _dirs, files in smbclient.walk(folder):
                for f in files:
                    if script_count >= MAX_SCRIPT_FILES:
                        return
                    if not f.lower().endswith(SCRIPT_EXT):
                        continue
                    script_count += 1
                    full = rf"{dirpath}\{f}"
                    data = read(full, 600_000)
                    if data:
                        _scan_script(data, label + full[len(folder):], result["script_secrets"])
        except Exception as e:  # noqa: BLE001
            log.debug("scripts %s: %s", folder, e)

    sysvol = rf"\\{server}\SYSVOL\{fqdn}"
    root = rf"{sysvol}\Policies"
    names = {g["guid"].upper(): g["name"] for g in gpos}
    try:
        for entry in smbclient.scandir(root):
            guid = entry.name.upper()
            if not entry.is_dir() or not guid.startswith("{"):
                continue
            base = rf"{root}\{entry.name}"
            gname = names.get(guid, guid)
            # 1) Group Policy Preferences
            for scope in ("Machine", "User"):
                pref = rf"{base}\{scope}\Preferences"
                if smbpath.isdir(pref):
                    for dirpath, _dirs, files in smbclient.walk(pref):
                        for f in files:
                            if f.lower() not in GPP_FILES:
                                continue
                            full = rf"{dirpath}\{f}"
                            data = read(full)
                            if not data:
                                continue
                            short = full.split("\\Policies\\", 1)[-1]
                            if _CPASS.search(data):
                                users = sorted({u.decode("utf-8", "replace") for u in _USER.findall(data) if u})
                                result["gpp_passwords"].append({"gpo": gname, "guid": guid, "file": short,
                                                                "accounts": ", ".join(users) or "–"})
                            if _AUTOLOGON.search(data):
                                result["gpp_passwords"].append({"gpo": gname, "guid": guid, "file": short,
                                                                "accounts": "Autologon (DefaultPassword)"})
                # 2) Administrative Vorlagen
                pol = read(rf"{base}\{scope}\Registry.pol")
                if pol:
                    result["regpol"].setdefault(guid, {})[scope.lower()] = parse_registry_pol(pol)
                # 3) Skripte in GPOs
                scan_scripts(rf"{base}\{scope}\Scripts", rf"{gname}\{scope}\Scripts")
            # 4) Sicherheitsvorlage und erweiterte Überwachung
            inf = read(rf"{base}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf", 1_000_000)
            if inf:
                result["secedit"][guid] = parse_gpttmpl(_decode(inf))
            aud = read(rf"{base}\Machine\Microsoft\Windows NT\Audit\audit.csv", 500_000)
            if aud:
                result["audit"][guid] = parse_audit_csv(_decode(aud))
        # 5) NETLOGON
        scan_scripts(rf"{sysvol}\scripts", "NETLOGON")
    except Exception as e:  # noqa: BLE001
        result.update(status="error", error=str(e)[:300])
    finally:
        try:
            smbclient.delete_session(server)
        except Exception:  # noqa: BLE001
            pass
        try:
            smbclient.reset_connection_cache()
        except Exception:  # noqa: BLE001
            pass
    return result
