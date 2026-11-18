# SPDX-License-Identifier: AGPL-3.0-or-later
"""Diagnostics package (2.2.0): anonymous, and kept in step with the program.

The coverage tests fail as soon as a new setting, database column, key/value entry, overview field or item key
appears without a decision in app/diag.py whether and how it goes into the package."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-diag-"))

from app import diag  # noqa: E402

REAL = ["Firma Muster", "firma.local", "dc1.firma.local", "dc7", "mmuster", "Max Mustermann", "jdoe", "10.0.10.55",
        "10.0.10.66", "10.0.10.10", "FIRMA", "Vertrieb Nord", "admin.mm@firma.local", "S-1-5-21-111-222-333"]


def _seed():
    """Demo scan plus real-looking names in every free-text place."""
    from app import db, demo, scanner
    db.init()
    with db.conn() as c:
        c.execute("DELETE FROM scans")
        c.execute("DELETE FROM audit_log")
        c.execute("DELETE FROM cert_pins")
    model = demo.build()
    model["meta"]["warnings"] = ["gpos: cannot read CN=Vertrieb Nord,OU=Gruppen,DC=firma,DC=local on dc7"]
    results, scores = scanner.evaluate(model)
    ov = scanner.build_overview(model)
    sid = db.create_scan("firma.local", "windows", "Max Mustermann (mmuster)", True)
    db.finish_scan(sid, scores, ov, results, 2.5, "firma.local")
    sid2 = db.create_scan("firma.local", "windows", "mmuster", False)
    db.fail_scan(sid2, "LDAP bind to dc7.firma.local (10.0.10.10) failed for jdoe@firma.local")
    db.audit("act_login", "mmuster", "10.0.10.55", "")
    db.audit("act_login_failed", "jdoe", "10.0.10.66", "x")
    db.save_pin("dc1.firma.local [10.0.10.10]", "ab" * 32, "CN=dc1.firma.local", "2027-01-01", False, b"x",
                "dc1.firma.local")
    db.set_kv("dc_names", "dc1.firma.local,dc7.firma.local")
    diag.install_log_buffer()
    lg = logging.getLogger("samaudit.ldap")
    lg.warning("Sign-in of %s rejected: privileged account (%s)", "admin.mm@firma.local",
               "CN=Domain Admins,CN=Users,DC=firma,DC=local")
    lg.warning("Section gpos failed: dc7 timed out, user jdoe, SID S-1-5-21-111-222-333-1105, group Vertrieb Nord")
    lg.warning("Bound account FIRMA\\mmuster on dc1.firma.local")


class Coverage(unittest.TestCase):
    def test_every_setting_is_classified(self):
        from app.config import Settings
        attrs = set(vars(Settings()))
        missing = sorted(attrs - set(diag.SETTINGS_POLICY))
        self.assertEqual(missing, [], "new setting: classify it in diag.SETTINGS_POLICY")
        self.assertEqual(sorted(set(diag.SETTINGS_POLICY) - attrs), [], "SETTINGS_POLICY lists a removed setting")
        self.assertTrue(set(diag.SETTINGS_POLICY.values()) <= {"value", "bool", "count", "omit"})

    def test_every_environment_variable_is_classified(self):
        names = set()
        for f in list((ROOT / "app").glob("*.py")) + [ROOT / "run.py"]:
            if f.name in ("config.py", "diag.py"):
                continue
            names |= set(re.findall(r"os\.environ\.get\(\s*\"(\w+)\"", f.read_text(encoding="utf-8")))
        names |= {"TLS_PFX", "TLS_CERT", "TLS_KEY"}       # read in a loop in webcert.py
        self.assertEqual(sorted(names - set(diag.ENV_POLICY)), [], "new environment variable: classify it in diag.ENV_POLICY")
        self.assertEqual(diag.ENV_POLICY["TLS_PFX_PASSWORD"], "omit")
        self.assertEqual(diag.ENV_POLICY["TLS_KEY_PASSWORD"], "omit")

    def test_every_database_column_is_classified(self):
        from app import db
        tables: dict[str, set[str]] = {}
        for name, body in re.findall(r"CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\n\);", db.SCHEMA, re.S):
            cols = {ln.strip().split()[0] for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("--")}
            tables[name] = cols
        # columns added later by migrations (ALTER TABLE … ADD COLUMN)
        for name, col in re.findall(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", Path(db.__file__).read_text(encoding="utf-8")):
            tables.setdefault(name, set()).add(col)
        self.assertEqual(sorted(tables), sorted(diag.DB_POLICY), "new table: classify it in diag.DB_POLICY")
        for t, cols in tables.items():
            self.assertEqual(sorted(cols - set(diag.DB_POLICY[t])), [], f"new column in {t}: classify it in diag.DB_POLICY")

    def test_every_kv_key_is_classified(self):
        keys = set()
        for f in (ROOT / "app").glob("*.py"):
            src = f.read_text(encoding="utf-8")
            keys |= set(re.findall(r"set_kv\(\s*\"(\w+)\"", src))
            keys |= set(re.findall(r"VALUES\('(\w+)'", src))
        self.assertTrue({"dc_names", "app_version"} <= keys)
        self.assertEqual(sorted(keys - set(diag.KV_POLICY)), [], "new key/value entry: classify it in diag.KV_POLICY")

    def test_every_overview_field_is_classified(self):
        from app import demo, scanner
        ov = scanner.build_overview(demo.build())
        self.assertEqual(sorted(set(ov) - set(diag.OVERVIEW_POLICY)), [],
                         "new overview field: classify it in diag.OVERVIEW_POLICY")

    def test_every_item_key_is_classified(self):
        from app import demo, scanner
        results, _ = scanner.evaluate(demo.build())
        keys = {k for r in results for it in r["items"] if isinstance(it, dict) for k in it}
        self.assertEqual(sorted(keys - set(diag.ITEM_KEYS)), [], "new item key: classify it in diag.ITEM_KEYS")


class Pseudonyms(unittest.TestCase):
    def test_consistent_placeholders(self):
        p = diag.Pseudo()
        p.add("firma.local", "domain")
        p.add("dc1.firma.local", "dc")
        p.add("mmuster", "user")
        t = p.text("dc1.firma.local and DC1 for mmuster in firma.local, pc-0042.firma.local at 10.0.10.5 / 10.0.10.5")
        self.assertEqual(t, "dc-1 and dc-1 for user-1 in domain-1, host-1 at ip-1 / ip-1")

    def test_patterns(self):
        p = diag.Pseudo()
        t = p.text("CN=Max,OU=IT,DC=firma,DC=local; mm@firma.example; S-1-5-21-1-2-3-512; 127.0.0.1; "
                   "fe80::1c2b:3a4d at 12:34:56 from 2001:db8::7")
        self.assertNotIn("fe80", t)
        self.assertNotIn("2001:db8", t)
        self.assertIn("12:34:56", t)
        self.assertNotIn("Max", t)
        self.assertNotIn("firma", t)
        self.assertIn("sid-1-512", t)
        self.assertIn("127.0.0.1", t)

    def test_program_name_survives_host_named_after_it(self):
        p = diag.Pseudo()
        p.add("samaudit.firma.local", "host")
        self.assertEqual(p.text("SAMAUDIT 2.4.1 on samaudit.firma.local"), "SAMAUDIT 2.4.1 on host-1")

    def test_well_known_names_stay(self):
        p = diag.Pseudo()
        self.assertEqual(p.add("Domain Admins", "group"), "Domain Admins")
        self.assertEqual(p.text("Windows Server 2022 Standard"), "Windows Server 2022 Standard")

    def test_leak_check_stops_the_package(self):
        p = diag.Pseudo()
        p.add("mmuster", "user")
        with self.assertRaises(diag.LeakError):
            diag.check_leaks({"x": ["started by mmuster"]}, p)
        with self.assertRaises(diag.LeakError):
            diag.check_leaks({"x": "10.0.10.9"}, p)
        diag.check_leaks({"x": ["started by user-1"]}, p)


class _Configured(unittest.TestCase):
    """Settings like a real installation (the settings object is shared by all test modules)."""
    CONF = {"domain_fqdn": "firma.local", "netbios": "FIRMA", "dc_hosts": ["dc1.firma.local"],
            "org_name": "Firma Muster GmbH", "demo_mode": False}

    @classmethod
    def setUpClass(cls):
        from app.config import settings
        cls._old = {k: getattr(settings, k) for k in cls.CONF}
        for k, v in cls.CONF.items():
            setattr(settings, k, v)
        _seed()

    @classmethod
    def tearDownClass(cls):
        from app.config import settings
        for k, v in cls._old.items():
            setattr(settings, k, v)


class Package(_Configured):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pkg = diag.build("web", probe=False)
        cls.text = diag.dumps(cls.pkg)

    def test_no_real_names(self):
        low = self.text.lower()
        for r in REAL:
            self.assertNotIn(r.lower(), low, f"{r!r} is in the package")
        self.assertNotRegex(self.text, r"(?i)\b(?:CN|OU|DC)=")

    def test_structure(self):
        pkg = self.pkg
        self.assertEqual(pkg["samaudit_diagnostics"], diag.DIAG_FORMAT)
        self.assertEqual(pkg["program"]["version"], __import__("app.version").version.VERSION)
        self.assertEqual(len(pkg["scans"]), 2)
        done = [s for s in pkg["scans"] if s["status"] == "done"][0]
        self.assertGreater(len(done["results"]), 100)
        self.assertEqual(set(done["results"]["ANM-01"][:1]) <= {"fail", "pass", "na"}, True)
        self.assertTrue(pkg["events"], "recent warnings are included")
        self.assertIn("pins", pkg["connection"])
        self.assertEqual(json.loads(self.text)["source"], "web")

    def test_no_secrets_or_contents(self):
        for word in ("password", "items", "fingerprint", "members", "der\"", "sid\":"):
            self.assertNotIn(word, self.text.replace("passwords", ""), word)

    def test_cli(self):
        from app.config import settings
        env = dict(os.environ, DATA_DIR=settings.data_dir, DOMAIN_FQDN="firma.local", DOMAIN_NETBIOS="FIRMA", DC_HOSTS="dc1.firma.local",
                   DEMO_MODE="false", TLS_KEY_PASSWORD="Geheim-Kennwort-123", PUBLIC_HOSTNAME="samaudit.firma.local")
        r = subprocess.run([sys.executable, "-m", "app.diag", "--no-probe", "--log", "-"], cwd=ROOT, env=env,
                           input="INFO samaudit: start for firma.local\nWARNING Section x failed on dc7 (10.0.10.10)\n",
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        pkg = json.loads(r.stdout)
        self.assertEqual(pkg["source"], "cli")
        self.assertEqual(len(pkg["server_log"]), 2)
        self.assertNotIn("Geheim-Kennwort-123", r.stdout)
        self.assertNotIn("samaudit.firma", r.stdout.lower())
        self.assertEqual(pkg["program"]["name"], "SAMAUDIT")
        self.assertNotIn("TLS_KEY_PASSWORD", r.stdout)
        for real in REAL:
            self.assertNotIn(real.lower(), r.stdout.lower())


try:
    import starlette  # noqa: F401
    HAVE_WEB = True
except ImportError:  # pragma: no cover
    HAVE_WEB = False


@unittest.skipUnless(HAVE_WEB, "starlette missing")
class Web(_Configured):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from app import auth
        cls.sid = auth.create("mmuster", "Max Mustermann", "mmuster@firma.local", "mmuster", ["SAMAUDIT-Users"],
                              "x", "127.0.0.1").sid

    def _get(self, path, cookie=""):
        from tests.test_web_hardening import _call

        async def run():
            from app.main import app
            # add the session cookie to the scope via a small wrapper
            async def wrapped(scope, receive, send):
                if cookie:
                    scope = dict(scope, headers=[(b"cookie", cookie.encode())])
                await app(scope, receive, send)
            return await _call(wrapped, path)
        return asyncio.run(run())

    def test_needs_sign_in(self):
        for p in ("/audit/diag", "/audit/diag.json"):
            self.assertEqual(self._get(p)["status"], 303, p)

    def test_preview_and_download(self):
        from app import db
        ck = f"samaudit_sid={self.sid}"
        r = self._get("/audit/diag", ck)
        self.assertEqual(r["status"], 200)
        body = r["body"].decode()
        self.assertIn("samaudit_diagnostics", body)
        self.assertIn('href="/audit/diag.json"', body)
        r = self._get("/audit/diag.json", ck)
        self.assertEqual(r["status"], 200)
        cd = dict(r["headers"]).get("content-disposition", "")
        self.assertRegex(cd, r'attachment; filename="samaudit-diagnose-[\d.]+-\d{12}\.json"')
        pkg = json.loads(r["body"])
        self.assertEqual(pkg["source"], "web")
        for real in REAL:
            self.assertNotIn(real.lower(), r["body"].decode().lower())
        self.assertEqual(db.audit_entries(1)[0]["action"], "act_diag")
        self.assertIn('href="/audit/diag"', self._get("/audit", ck)["body"].decode())

    def test_entrypoint_command(self):
        src = (ROOT / "entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('set -- python -m app.diag "$@"', src)


if __name__ == "__main__":
    unittest.main()
