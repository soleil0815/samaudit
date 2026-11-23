# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""2.6.0: approval of further DCs, LDAP without a certificate (NTLM), SMB to the checked address, cooldown."""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-dc-"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

def _ldap3_standin() -> dict:
    """For local runs without ldap3: just enough for open_connection (the CI installs the real one)."""
    if importlib.util.find_spec("ldap3") is not None:
        return {}
    lib, core, exc = (types.ModuleType(n) for n in ("ldap3", "ldap3.core", "ldap3.core.exceptions"))
    exc.LDAPException = type("LDAPException", (Exception,), {})
    exc.LDAPSocketOpenError = type("LDAPSocketOpenError", (exc.LDAPException,), {})
    lib.core, core.exceptions = core, exc
    return {"ldap3": lib, "ldap3.core": core, "ldap3.core.exceptions": exc}


from app import db, ldapsrc, pins, sysvol  # noqa: E402
from app.config import settings  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def self_signed(name: str) -> bytes:
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW)
         .not_valid_after(NOW + dt.timedelta(days=30))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


def cfg():
    """The current settings object (another test may have reloaded app.config)."""
    return sys.modules["app.config"].settings


class Approval(unittest.TestCase):
    def setUp(self):
        db.init()
        db.delete_pins()
        db.set_kv("pins_pending", "{}")
        db.set_kv("dc_names", "")
        self._saved = cfg().pin_new_dc

    def tearDown(self):
        cfg().pin_new_dc = self._saved

    def test_further_samba_dc_waits_for_approval(self):
        self.assertTrue(pins.check("samba.lan [10.0.1.1]", [self_signed("samba.lan")])["first_use"])
        second = self_signed("dc2.samba.lan")
        with self.assertRaises(pins.PinPending):
            pins.check("samba.lan [10.0.1.2]", [second])
        p = pins.pending()["samba.lan [10.0.1.2]"]
        self.assertIsNone(db.get_pin("samba.lan [10.0.1.2]"))
        self.assertFalse(pins.approve("samba.lan [10.0.1.2]", "t", "00" * 32), "wrong fingerprint is refused")
        self.assertTrue(pins.approve("samba.lan [10.0.1.2]", "t", p["fingerprint"]))
        self.assertFalse(pins.check("samba.lan [10.0.1.2]", [second])["first_use"])
        self.assertEqual(pins.pending(), {})

    def test_auto_keeps_the_old_behaviour(self):
        cfg().pin_new_dc = "auto"
        pins.check("samba.lan [10.0.1.1]", [self_signed("samba.lan")])
        self.assertTrue(pins.check("samba.lan [10.0.1.2]", [self_signed("dc2.samba.lan")])["first_use"])

    def test_pending_list_is_bounded(self):
        pins.check("samba.lan [10.0.1.1]", [self_signed("samba.lan")])
        for i in range(30):
            with self.assertRaises(pins.PinPending):
                pins.check(f"samba.lan [10.0.2.{i}]", [self_signed("dc.samba.lan")])
        self.assertLessEqual(len(pins.pending()), 20)

    def test_pending_dc_is_skipped_not_weakened(self):
        calls = []

        def fake_connect(bind, pw, addr, key, mode):
            calls.append((key, mode))
            if key.endswith("[10.0.1.2]"):
                raise ldapsrc.AuthError("dc_pending", key)
            conn = types.SimpleNamespace(socket=types.SimpleNamespace(getpeername=lambda: ("10.0.1.1", 636)))
            return conn
        with mock.patch.dict(sys.modules, _ldap3_standin()), \
             mock.patch.object(ldapsrc, "_targets", lambda: [("samba.lan", "10.0.1.2", "samba.lan [10.0.1.2]"),
                                                             ("samba.lan", "10.0.1.1", "samba.lan [10.0.1.1]")]), \
             mock.patch.object(ldapsrc, "_connect", fake_connect), \
             mock.patch.object(settings, "ldap_ntlm", True):
            conn = ldapsrc.open_connection("u@samba.lan", "pw")
        self.assertEqual(conn._samaudit_addr, "10.0.1.1")
        self.assertNotIn(("samba.lan [10.0.1.2]", "ntlm"), calls)


class LdapWithoutCertificate(unittest.TestCase):
    def setUp(self):
        db.init()
        db.delete_pins()

    def _run(self, fails: dict, ntlm=True, pinned=False):
        calls = []

        def fake_connect(bind, pw, addr, key, mode):
            calls.append(mode)
            if mode in fails:
                raise fails[mode]
            return types.SimpleNamespace(socket=types.SimpleNamespace(getpeername=lambda: ("10.0.10.1", 389)))
        if pinned:
            db.save_pin("dc1.firma.local", "ab" * 32, "CN=dc1", "2030-01-01", False, b"x", "dc1.firma.local")
        with mock.patch.dict(sys.modules, _ldap3_standin()), \
             mock.patch.object(ldapsrc, "_targets", lambda: [("dc1.firma.local", "dc1.firma.local", "dc1.firma.local")]), \
             mock.patch.object(ldapsrc, "_connect", fake_connect), mock.patch.object(settings, "ldap_ntlm", ntlm), \
             mock.patch.object(settings, "ldap_ssl", True), mock.patch.object(settings, "ldap_port", 636):
            try:
                return ldapsrc.open_connection("u@firma.local", "pw"), calls
            except ldapsrc.AuthError as e:
                return e, calls

    def test_order_ldaps_starttls_ntlm(self):
        no_tls = ldapsrc.AuthError("tls_failed", "no certificate")
        conn, calls = self._run({"": no_tls, "starttls": no_tls})
        self.assertEqual(calls, ["", "starttls", "ntlm"])
        self.assertEqual(conn._samaudit_mode, "ntlm")
        self.assertEqual(db.get_kv("ldap_mode"), "ntlm")

    def test_ntlm_only_when_switched_on(self):
        no_tls = ldapsrc.AuthError("tls_failed", "no certificate")
        err, calls = self._run({"": no_tls, "starttls": no_tls}, ntlm=False)
        self.assertIsInstance(err, ldapsrc.AuthError)
        self.assertNotIn("ntlm", calls)

    def test_never_ntlm_for_a_dc_that_had_a_certificate(self):
        no_tls = ldapsrc.AuthError("tls_failed", "blocked")
        err, calls = self._run({"": no_tls, "starttls": no_tls}, pinned=True)
        self.assertIsInstance(err, ldapsrc.AuthError)
        self.assertNotIn("ntlm", calls)

    def test_never_ntlm_after_a_certificate_error_or_mismatch(self):
        err, calls = self._run({"": ldapsrc.AuthError("cert_changed", "x")})
        self.assertEqual(err.code, "cert_changed")
        self.assertEqual(calls, [""])

    def test_plain_simple_bind_never_without_allow_plain(self):
        with mock.patch.object(settings, "ldap_ssl", False), mock.patch.object(settings, "ldap_starttls", False), \
             mock.patch.object(settings, "ldap_allow_plain", False), mock.patch.object(settings, "ldap_ntlm", True):
            self.assertEqual(ldapsrc._modes(), ["ntlm"])

    @unittest.skipUnless(importlib.util.find_spec("spnego"), "pyspnego not installed")
    def test_nt_hash(self):
        self.assertEqual(ldapsrc.nt_hash_password("password"), "0" * 32 + ":8846f7eaee8fb117ad06bdd830b7586c")


class SmbToTheCheckedAddress(unittest.TestCase):
    def test_register_session_uses_the_address_and_ntlm(self):
        seen = {}
        fake = types.ModuleType("smbclient")
        fake.register_session = lambda server, **kw: seen.update(server=server, **kw)
        fake.scandir = lambda p: iter(())
        fake.delete_session = lambda s: None
        fake.reset_connection_cache = lambda: None
        fake.walk = lambda p: iter(())
        fake_path = types.ModuleType("smbclient.path")
        fake_path.isdir = lambda p: False
        fake_path.isfile = lambda p: False
        fake.path = fake_path
        with mock.patch.dict(sys.modules, {"smbclient": fake, "smbclient.path": fake_path}), \
             mock.patch.object(settings, "smb_checks", True):
            res = sysvol.scan("10.0.10.1", "firma.local", "u@firma.local", "pw", [], {})
        self.assertEqual(seen["server"], "10.0.10.1")
        self.assertTrue(seen["require_signing"])
        self.assertEqual(res["auth"], "negotiate" if importlib.util.find_spec("gssapi") else "ntlm")

    def test_scanner_passes_the_checked_address(self):
        src = (ROOT / "app" / "scanner.py").read_text(encoding="utf-8")
        self.assertIn('smb_target = model["meta"].get("dc_addr") or model["meta"]["dc_host"]', src)


class Cooldown(unittest.TestCase):
    def test_young_releases_are_held_back(self):
        import lockutil
        old = {"starlette": "1.10.0", "anyio": "4.15.1"}
        new = {"starlette": "1.11.0", "anyio": "4.16.0", "newdep": "1.0"}
        ages = {("starlette", "1.11.0"): 2, ("anyio", "4.16.0"): 30, ("newdep", "1.0"): 1}

        def up(n, v):
            return NOW - dt.timedelta(days=ages[(n, v)])
        self.assertEqual(lockutil.too_young(old, new, 7, uploaded=up, now=NOW), ["newdep<1.0", "starlette==1.10.0"])
        self.assertEqual(lockutil.too_young(old, new, 0, uploaded=up, now=NOW), [])
        self.assertEqual(lockutil.too_young(old, {"x": "1"}, 7, uploaded=lambda n, v: None, now=NOW), ["x<1"])

    def test_security_update_uses_cooldown_with_trivy_exception(self):
        import yaml
        wf = yaml.safe_load((ROOT / ".github/workflows/security-update.yml").read_text(encoding="utf-8"))
        steps = {s.get("id"): s for s in wf["jobs"]["prepare"]["steps"] if s.get("id")}
        self.assertIn("COOLDOWN_DAYS", steps["locks"]["env"])
        self.assertTrue(steps["trivy"]["continue-on-error"])
        self.assertIn("COOLDOWN_DAYS=0", steps["relock"]["run"])
        self.assertIn("trivy2", steps["upload"]["if"])
        dep = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text(encoding="utf-8"))
        self.assertGreaterEqual(dep["updates"][0]["cooldown"]["default-days"], 7)
        sh = (ROOT / "tools/update-locks.sh").read_text(encoding="utf-8")
        self.assertIn('date -u -d "-$COOLDOWN_DAYS days"', sh)


class WebApproval(unittest.TestCase):
    def setUp(self):
        db.init()
        db.delete_pins()
        db.set_kv("pins_pending", "{}")

    def test_approve_needs_csrf_and_a_still_authorised_auditor(self):
        from app import auth
        from tests.test_code_audit_2611 import _post
        pins.check("samba.lan [10.0.1.1]", [self_signed("samba.lan")])
        with self.assertRaises(pins.PinPending):
            pins.check("samba.lan [10.0.1.2]", [self_signed("dc2.samba.lan")])
        fp = pins.pending()["samba.lan [10.0.1.2]"]["fingerprint"]
        s = auth.create("mmuster", "M", "m@firma.local", "m@firma.local", ["SAMAUDIT-Users"], "x", "127.0.0.1")
        ck = f"samaudit_sid={s.sid}"
        with mock.patch.object(settings, "demo_mode", False), mock.patch.object(settings, "tls_enabled", False):
            _post("/connection/approve", {"csrf": "wrong", "host": "samba.lan [10.0.1.2]", "fingerprint": fp}, ck)
            self.assertIsNone(db.get_pin("samba.lan [10.0.1.2]"))
            with mock.patch.object(ldapsrc, "authenticate", side_effect=ldapsrc.AuthError("not_allowed")):
                _post("/connection/approve", {"csrf": s.csrf, "host": "samba.lan [10.0.1.2]", "fingerprint": fp}, ck)
            self.assertIsNone(db.get_pin("samba.lan [10.0.1.2]"), "revoked auditor cannot approve")
            s2 = auth.create("mmuster", "M", "m@firma.local", "m@firma.local", ["SAMAUDIT-Users"], "x", "127.0.0.1")
            with mock.patch.object(ldapsrc, "authenticate", return_value=None):
                r = _post("/connection/approve", {"csrf": s2.csrf, "host": "samba.lan [10.0.1.2]", "fingerprint": fp},
                          f"samaudit_sid={s2.sid}")
        self.assertEqual(r["status"], 303)
        self.assertIsNotNone(db.get_pin("samba.lan [10.0.1.2]"))

    def test_texts_exist(self):
        from app.i18n import T
        for k in ("err_dc_pending", "pins_pending_title", "ldap_mode_ntlm", "ldap_mode_ldaps", "ldap_mode_starttls",
                  "ldap_mode_plain", "smb_auth_ntlm", "act_cert_pending", "act_cert_approved"):
            self.assertIn(k, T)


if __name__ == "__main__":
    unittest.main()
