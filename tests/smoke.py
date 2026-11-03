# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rauchtest für CI (ohne Docker, ohne Domäne): Regeln mit Demo-Daten, PDF, Seiten, Parser, Pinning.
Aufruf: python tests/smoke.py   – Rückgabewert ≠ 0 bei Fehlern."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.update(DEMO_MODE="true", DOMAIN_FQDN="firma.local", PUBLIC_HOSTNAME="localhost",
                  DATA_DIR=tempfile.mkdtemp(prefix="samaudit-test-"), TLS_ENABLED="false")

failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        failures.append(msg)


# --- Regeln -------------------------------------------------------------------
from app import db, demo, scanner  # noqa: E402
from app.rules import RULES  # noqa: E402

db.init()
findings, scores = scanner.evaluate(demo.build())
check(len(RULES) == len(findings) and len(RULES) >= 110, f"{len(RULES)} Regeln ausgewertet")
errors = [f["rule_id"] for f in findings if f["note"] == "na_error"]
check(not errors, f"keine Regel mit Auswertungsfehler {errors}")
check(len({r.id for r in RULES}) == len(RULES), "Regel-IDs eindeutig")

# fehlgeschlagener Datenabschnitt → nicht prüfbar statt bestanden
m = demo.build()
m["meta"]["failed_sections"] = ["trusts"]
f2, _ = scanner.evaluate(m)
check(all(f["state"] == "na" for f in f2 if f["rule_id"].startswith("TRS-")), "Abschnittsfehler → nicht prüfbar")

# --- PDF ----------------------------------------------------------------------
from app import pdfreport  # noqa: E402
from app.main import report_data  # noqa: E402

model = demo.build()
sid = db.create_scan("firma.local", "windows", "test", True)
db.finish_scan(sid, scores, scanner.build_overview(model), findings, 1.0, "firma.local")
data = report_data(sid)
for lang in ("de", "en"):
    pdf = pdfreport.build_pdf(data, lang)
    check(pdf[:4] == b"%PDF", f"PDF erzeugt ({lang})")

# --- Seiten (ASGI direkt, ohne HTTP-Client) -------------------------------------
from app.main import app  # noqa: E402


async def get(path: str, cookie: str = "") -> int:
    return (await fetch(path, cookie))[0]


async def fetch(path: str, cookie: str = "") -> tuple[int, str]:
    scope = {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": [(b"cookie", cookie.encode())] if cookie else [], "client": ("127.0.0.1", 1), "server": ("t", 80), "scheme": "http",
             "http_version": "1.1", "root_path": ""}
    status: dict = {"body": b""}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            status["s"] = msg["status"]
        elif msg["type"] == "http.response.body":
            status["body"] += msg.get("body", b"")

    await app(scope, receive, send)
    return status.get("s", 0), status["body"].decode("utf-8", "replace")


for p in ("/login", "/help", "/news", "/privacy", "/healthz"):
    check(asyncio.run(get(p)) == 200, f"GET {p}")

# Spendenlink nur auf der Hilfe-Seite, Quellcode-Link (AGPL) auf Anmeldung und Hilfe
from app.version import DONATE_URL, SOURCE_URL  # noqa: E402

_help = asyncio.run(fetch("/help"))[1]
_login = asyncio.run(fetch("/login"))[1]
check(DONATE_URL in _help and SOURCE_URL in _help, "Hilfe: Quellcode- und Spendenlink")
check(SOURCE_URL in _login and DONATE_URL not in _login, "Anmeldung: Quellcode-Link, kein Spendenlink")
for _tpl in ("base.html", "dashboard.html", "login.html"):
    _src = open(os.path.join(ROOT, "app", "templates", _tpl), encoding="utf-8").read()
    check("DONATE_URL" not in _src and "buymeacoffee" not in _src, f"kein Spendenlink in {_tpl}")

# --- Parser und Schutzfunktionen ----------------------------------------------
from app import webcert  # noqa: E402
from app.sysvol import parse_gpttmpl  # noqa: E402

inf = parse_gpttmpl('[Service General Setting]\n"Spooler",4,""\n[privilege rights]\nSeDebugPrivilege = *S-1-1-0\njunk\n')
check(inf.get("Service General Setting", {}).get('"Spooler"', "").startswith("4"), "GptTmpl: Zeilen ohne '='")
check(inf.get("Privilege Rights", {}).get("sedebugprivilege") == "*S-1-1-0", "GptTmpl: ohne Groß-/Kleinschreibung")
check(webcert._pem_key(b"xxxxxxxx-----BEGIN PRIVATE", None, "t") is None, "PEM: keine Endlosschleife")

# --- LDAPS-Pinning ---------------------------------------------------------------
import datetime as _dt  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from app import pins  # noqa: E402

_now = _dt.datetime.now(_dt.timezone.utc)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FIRMA-CA")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
      .serial_number(1).not_valid_before(_now).not_valid_after(_now + _dt.timedelta(days=30))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))


def leaf(name: str, eku) -> bytes:
    k = ec.generate_private_key(ec.SECP256R1())
    c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
         .issuer_name(ca_name).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(_now).not_valid_after(_now + _dt.timedelta(days=30))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
         .add_extension(x509.ExtendedKeyUsage([eku]), critical=False).sign(ca_key, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


ca_der = ca.public_bytes(serialization.Encoding.DER)
SA, CA_ = ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH
check(pins.check("firma.local [10.0.0.1]", [leaf("dc01.firma.local", SA), ca_der])["first_use"], "Pin: erster Kontakt")
check(not pins.check("firma.local [10.0.0.1]", [leaf("dc01.firma.local", SA), ca_der])["first_use"], "Pin: Erneuerung ok")


def rejected(host, chain) -> bool:
    try:
        pins.check(host, chain)
        return False
    except pins.PinMismatch:
        return True


check(rejected("firma.local [10.0.0.1]", [leaf("eve.firma.local", SA), ca_der]), "Pin: fremder Name derselben CA abgewiesen")
check(rejected("firma.local [10.0.0.1]", [leaf("dc01.firma.local", CA_), ca_der]), "Pin: Client-Zertifikat abgewiesen")
db.set_kv("dc_names", "dc01.firma.local,dc02.firma.local")     # aus dem letzten Scan bekannt
check(rejected("firma.local [10.0.0.9]", [leaf("eve.firma.local", SA), ca_der]), "Pin: neue Adresse, kein DC → abgewiesen")
check(not pins.check("firma.local [10.0.0.2]", [leaf("dc02.firma.local", SA), ca_der])["first_use"],
      "Pin: zweiter DC (Ausfall des ersten) übernommen")
check(pins.check("samba.lan [10.0.1.1]", [leaf("dc1.samba.lan", SA)])["first_use"] is not None, "Pin: Samba ohne CA-Kette")
check(db.delete_pins("firma.local") >= 2, "Pin: Zurücksetzen per Name entfernt alle Adressen")

print(f"\n{len(failures)} Fehler")
sys.exit(1 if failures else 0)
