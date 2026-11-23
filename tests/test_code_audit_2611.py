# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Code audit 11/2026: confirmed findings, each test fails on the previous version."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-ca2611-"))

from app import auth, db, diag, ldapsrc, sysvol  # noqa: E402
from app.config import settings  # noqa: E402


def _post(path: str, fields: dict, cookie: str = "", client: str = "203.0.113.7") -> dict:
    from app.main import app
    body = urllib.parse.urlencode(fields).encode()
    out: dict = {"headers": {}}
    sent = {"done": False}

    async def receive():
        if sent["done"]:
            await asyncio.sleep(0.05)
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
            out["headers"] = {k.decode().lower(): v.decode() for k, v in msg.get("headers", [])}

    headers = [(b"content-type", b"application/x-www-form-urlencoded"), (b"host", b"samaudit.firma.local")]
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    scope = {"type": "http", "method": "POST", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": headers, "client": (client, 50000), "server": ("127.0.0.1", 9400), "scheme": "http",
             "http_version": "1.1", "root_path": ""}
    asyncio.run(app(scope, receive, send))
    return out


def _audit_rows(action: str) -> int:
    with db.conn() as c:
        return c.execute("SELECT COUNT(*) FROM audit_log WHERE action=?", (action,)).fetchone()[0]


class Base(unittest.TestCase):
    def setUp(self):
        db.init()
        self._saved = (settings.demo_mode, settings.pin_reset_web, settings.max_login_attempts, settings.tls_enabled)
        settings.demo_mode, settings.tls_enabled = False, False
        auth._failures.clear()
        auth._lock_logged.clear()

    def tearDown(self):
        settings.demo_mode, settings.pin_reset_web, settings.max_login_attempts, settings.tls_enabled = self._saved
        auth._failures.clear()
        auth._lock_logged.clear()


class PinResetRecheck(Base):
    def test_revoked_auditor_cannot_reset_dc_pins(self):
        settings.pin_reset_web = True
        db.save_pin("dc1.firma.local", "ab" * 32, "CN=dc1.firma.local", "2030-01-01", False, b"x", "dc1.firma.local")
        s = auth.create("mmuster", "Max Mustermann", "mmuster@firma.local", "mmuster@firma.local",
                        ["SAMAUDIT-Users"], "x", "127.0.0.1")
        with mock.patch.object(ldapsrc, "authenticate", side_effect=ldapsrc.AuthError("not_allowed")):
            r = _post("/connection/reset", {"csrf": s.csrf, "host": "dc1.firma.local"}, f"samaudit_sid={s.sid}")
        self.assertEqual(r["status"], 303)
        self.assertIn("/login", r["headers"].get("location", ""))
        self.assertTrue(db.list_pins(), "pin must survive")
        self.assertIsNone(auth.get(s.sid), "session must be revoked")


class LoginAuditFlood(Base):
    def _login(self, user: str) -> dict:
        tok = "T" * 32
        return _post("/login", {"username": user, "password": "x", "csrf_token": tok}, f"samaudit_lt={tok}")

    def test_malformed_user_names_count_towards_the_lockout(self):
        settings.max_login_attempts = 5
        before = _audit_rows("act_login_failed")
        for i in range(60):
            self._login(f"a({i}")
        written = _audit_rows("act_login_failed") - before
        self.assertTrue(auth.is_locked("someone", "203.0.113.7"), "the IP must end up locked")
        self.assertLessEqual(written, 5 * 3 + 1, written)

    def test_locked_ip_logs_once_even_with_changing_user_names(self):
        settings.max_login_attempts = 5
        for i in range(15):
            auth.record_failure(f"u{i}", "203.0.113.7")
        before = _audit_rows("act_login_failed")
        for i in range(50):
            self._login(f"victim{i}")
        self.assertEqual(_audit_rows("act_login_failed") - before, 1)
        self.assertLessEqual(len(auth._lock_logged), 1)


class LinearParsers(unittest.TestCase):
    def test_autologon_regex_is_linear(self):
        data = b'name="DefaultPassword" ' * 6000          # ~140 KB without '>'
        t = time.perf_counter()
        sysvol._AUTOLOGON.search(data)
        self.assertLess(time.perf_counter() - t, 0.5)
        ok = b'<Properties action="U" name="DefaultPassword" type="REG_SZ" value="Geheim1!"/>'
        self.assertEqual(sysvol._AUTOLOGON.search(ok).group(1), b"Geheim1!")

    def test_gplink_regex_is_linear(self):
        t = time.perf_counter()
        ldapsrc._parse_gplink("[LDAP://" * 8000)
        self.assertLess(time.perf_counter() - t, 0.5)
        g = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        v = f"[LDAP://cn={g},cn=policies,cn=system,DC=firma,DC=local;0][LDAP://cn={g.lower()},cn=x;3]"
        self.assertEqual([(x["enabled"], x["enforced"]) for x in ldapsrc._parse_gplink(v)], [(True, False), (False, True)])


class DiagLeaks(unittest.TestCase):
    def test_certificate_error_object_is_not_exported_as_text(self):
        from app import webcert
        err = webcert.CertError("certerr_pfx", name="samaudit.firma.local.pfx")
        with mock.patch.dict(webcert.INFO, {"source": "certs", "error": err}, clear=True):
            out = diag._web_cert_part()
        self.assertEqual(out["error"], "certerr_pfx")
        self.assertNotIn("firma", str(out))

    def test_objects_are_pseudonymised_and_checked(self):
        p = diag.Pseudo()
        p.add("firma.local", "domain")
        pkg = diag._walk({"x": Exception("cannot reach dc1.firma.local")}, p.text)
        self.assertNotIn("firma", str(pkg))
        with self.assertRaises(diag.LeakError):
            diag.check_leaks({"x": Exception("firma.local")}, p)

    def test_names_outside_the_word_pattern_are_replaced_and_caught(self):
        p = diag.Pseudo()
        for n in ("rené", "o'brien", "Sommer2026!"):
            p.add(n, "user")
        txt = "Login failed for 'rené', \"o'brien\" and 'Sommer2026!'"
        out = p.text(txt)
        for n in ("rené", "o'brien", "Sommer2026"):
            self.assertNotIn(n.lower(), out.lower(), out)
        with self.assertRaises(diag.LeakError):
            diag.check_leaks({"e": txt}, p)

    def test_plain_names_still_work(self):
        p = diag.Pseudo()
        ph = p.add("mmuster", "user")
        self.assertEqual(p.text("user mmuster."), f"user {ph}.")


class SecurityUpdateOnlyPublishedCode(unittest.TestCase):
    """The patchday must never publish merged but unpublished program code as "<version>-sN"."""

    def _script(self) -> str:
        import yaml
        wf = yaml.safe_load((ROOT / ".github/workflows/security-update.yml").read_text(encoding="utf-8"))
        steps = wf["jobs"]["prepare"]["steps"]
        ids = [st.get("id") for st in steps]
        self.assertLess(ids.index("published"), ids.index("locks"))
        self.assertIn("steps.published.outputs.ok == 'true'", steps[ids.index("locks")]["if"])
        return steps[ids.index("published")]["run"]

    def _run(self, repo: Path, script: str) -> str:
        import subprocess
        out = repo / "out"
        out.write_text("")
        subprocess.run(["bash", "-c", script], cwd=repo, check=True, capture_output=True,
                       env={"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(out), "HOME": str(repo)})
        return out.read_text().strip()

    def test_guard(self):
        import subprocess
        script = self._script()
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)

            def git(*a):
                subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@firma.local", *a], cwd=repo,
                               check=True, capture_output=True)
            (repo / "app" / "docs").mkdir(parents=True)
            (repo / "app" / "version.py").write_text('VERSION = "2.5.0"\n')
            (repo / "app" / "main.py").write_text("x = 1\n")
            git("init", "-q")
            git("add", ".")
            git("commit", "-qm", "r")
            git("tag", "v2.5.0")
            self.assertEqual(self._run(repo, script), "ok=true")
            (repo / "app" / "docs" / "handbuch.de.md").write_text("Doku\n")
            (repo / "requirements.txt").write_text("x==1\n")
            git("add", ".")
            git("commit", "-qm", "docs and locks")
            self.assertEqual(self._run(repo, script), "ok=true")
            (repo / "app" / "main.py").write_text("x = 2\n")
            git("commit", "-qam", "merged fix, not published")
            self.assertEqual(self._run(repo, script), "ok=false")
            (repo / "app" / "version.py").write_text('VERSION = "2.6.0"\n')
            git("commit", "-qam", "new version merged")
            self.assertEqual(self._run(repo, script), "ok=false")
            git("tag", "v2.6.0")
            self.assertEqual(self._run(repo, script), "ok=true")


class TrivyAlwaysVerified(unittest.TestCase):
    def test_no_reuse_of_an_unchecked_binary(self):
        src = (ROOT / ".github/scripts/trivy.sh").read_text(encoding="utf-8")
        self.assertNotIn('[ ! -x "$bin/trivy" ]', src)
        self.assertIn('mktemp -d', src)


class LoginAndSession(Base):
    def test_non_ascii_csrf_is_a_plain_no(self):
        self.assertFalse(auth.check_token("abc", "ä"))
        self.assertFalse(auth.check_token("ä", "abc"))
        self.assertTrue(auth.check_token("abc", "abc"))

    def test_locked_ad_account_revokes_the_session(self):
        from app.main import ACCOUNT_GONE
        self.assertIn("account_locked", ACCOUNT_GONE)

    def test_bind_sub_codes_are_told_apart(self):
        class Conn:
            def __init__(self, msg):
                self.result = {"description": "invalidCredentials", "message": msg}
        cases = {"80090308: LdapErr: DSID-0C09042A, comment: AcceptSecurityContext error, data 775, v2580": "account_locked",
                 "80090308: LdapErr: ... data 533, v2580": "account_unusable",
                 "80090308: LdapErr: ... data 52e, v2580": "bad_credentials",
                 "": "bad_credentials"}
        for msg, code in cases.items():
            with self.assertRaises(ldapsrc.AuthError) as cm:
                ldapsrc._bind_error(Conn(msg))
            self.assertEqual(cm.exception.code, code, msg)

    def test_scan_ids_beyond_sqlite_integer_are_not_found(self):
        from app.main import _scan_id

        class R:
            path_params = {"id": 10**20}
        self.assertEqual(_scan_id(R()), 0)


class Robustness(unittest.TestCase):
    def test_unusual_certificate_files_give_a_message(self):
        from app import webcert
        with mock.patch.object(webcert, "_analyze", side_effect=RuntimeError("duplicate extension")):
            with self.assertRaises(webcert.CertError) as cm:
                webcert.analyze([("x.pem", b"-----BEGIN CERTIFICATE-----")], None)
        self.assertEqual(cm.exception.key, "certerr_format")

    def test_broken_file_in_certs_folder_does_not_stop_the_start(self):
        from app import webcert
        with mock.patch.object(webcert, "_from_upload", return_value=None), \
             mock.patch.object(webcert, "_from_certs_folder", side_effect=RuntimeError("unsupported curve")):
            cert, key = webcert.prepare()
        self.assertTrue(os.path.exists(cert) and os.path.exists(key))
        self.assertEqual(webcert.INFO.get("source"), "self")

    def test_log_level_blank_or_lower_case(self):
        src = (ROOT / "run.py").read_text(encoding="utf-8")
        self.assertIn('.strip().upper()', src)

    def test_healthcheck_reads_tls_enabled_like_the_program(self):
        src = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("v=os.environ.get('TLS_ENABLED','').strip().lower(); s=(v or 'true')", src)


class DiagNames(unittest.TestCase):
    def test_domain_backslash_user_is_replaced(self):
        p = diag.Pseudo()
        ph = p.add("FIRMA\\hmeier", "user")
        out = p.text("Login failed for 'FIRMA\\\\hmeier'")
        self.assertNotIn("hmeier", out)
        self.assertIn(ph, out)

    def test_dn_with_escaped_comma(self):
        p = diag.Pseudo()
        p.add_dn("CN=Mustermann\\, Lieselotte,OU=Leute,DC=firma,DC=local")
        out = p.text("Warnung: Lieselotte Mustermann")
        self.assertNotIn("Lieselotte", out)
        self.assertNotIn("Mustermann", out)

    def test_ip_at_the_end_of_a_sentence(self):
        p = diag.Pseudo()
        self.assertNotIn("192.168.77.12", p.text("DC not reachable: 192.168.77.12."))


class BackupRetention(unittest.TestCase):
    def test_old_backups_are_deleted(self):
        from app import datastate
        os.makedirs(datastate.backup_dir(), exist_ok=True)
        old = os.path.join(datastate.backup_dir(), "samaudit-ersetzt-20240101-000000.db")
        new = os.path.join(datastate.backup_dir(), "samaudit-vor-2.5.0-20261120-000000.db")
        for f in (old, new):
            open(f, "wb").close()
        os.utime(old, (time.time() - 200 * 86400,) * 2)
        self.assertEqual(datastate.prune_by_age(90), 1)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(new))
        self.assertEqual(datastate.prune_by_age(0), 0)


class GpoPrecedence(unittest.TestCase):
    D = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    O = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"

    def ctx(self, dom_enforced=False, ou_flags=0):
        import copy
        from app import demo
        from app.analysis import Ctx
        m = copy.deepcopy(demo.build())
        m["gpo_links"]["domain"] = [{"guid": self.D, "enabled": True, "enforced": dom_enforced}]
        for g in m["gpos"]:
            if g["guid"].upper() == self.O:
                g["flags"] = ou_flags
        return Ctx(m, settings)

    def test_enforced_domain_gpo_wins(self):
        self.assertEqual(self.ctx().gpo_guids("dc"), [self.D, self.O])
        self.assertEqual(self.ctx(dom_enforced=True).gpo_guids("dc"), [self.O, self.D])

    def test_disabled_computer_settings_do_not_apply(self):
        self.assertNotIn(self.O, self.ctx(ou_flags=2).gpo_guids("dc"))
        self.assertIn(self.O, self.ctx(ou_flags=1).gpo_guids("dc"))


class SysvolCompleteness(unittest.TestCase):
    def _run(self, rid, sv):
        import copy
        from app import demo
        from app.analysis import Ctx
        from app.rules import RULES
        m = copy.deepcopy(demo.build())
        m["sysvol"].update(sv)
        rule = next(r for r in RULES if r.legacy_id == rid)
        try:
            return rule.check(Ctx(m, settings))
        except Exception as e:  # noqa: BLE001 – NotApplicable carries the note
            return str(e)

    def test_nothing_found_but_unreadable_is_not_passed(self):
        for rid, key in (("A-GPPPassword", "gpp_passwords"), ("A-ScriptPasswords", "script_secrets")):
            res = self._run(rid, {key: [], "unreadable_gpos": ["{0B7E3A55-3C1D-4E8B-A0D2-6F4C2B1E9D80}"]})
            self.assertEqual(res, "na_sysvol_partial", rid)


class ChildDomain(unittest.TestCase):
    def test_schema_enterprise_admins_not_checkable_in_child_domain(self):
        import copy
        from app import demo
        from app.analysis import Ctx
        from app.rules import RULES
        m = copy.deepcopy(demo.build())
        m["domain"]["is_root"] = False
        rule = next(r for r in RULES if r.legacy_id == "P-SchemaEnterpriseAdmins")
        from app.rules import NotApplicable
        with self.assertRaises(NotApplicable) as cm:
            rule.check(Ctx(m, settings))
        self.assertEqual(str(cm.exception), "na_child_domain")


class RecheckAndRelogin(Base):
    def test_technical_error_on_recheck_does_not_crash(self):
        from app.main import recheck
        s = auth.create("mmuster", "M", "m@firma.local", "m@firma.local", ["SAMAUDIT-Users"], "x", "127.0.0.1")

        class R:
            state = type("S", (), {"sess": s})()
            client = ("203.0.113.7", 1)
            headers: dict = {}
            url = type("U", (), {"path": "/x"})()
        with mock.patch.object(ldapsrc, "authenticate", side_effect=RuntimeError("search failed")):
            self.assertIsNone(asyncio.run(recheck(R())))
        self.assertIsNotNone(auth.get(s.sid))

    def test_signing_in_again_ends_the_old_session(self):
        settings.demo_mode = True
        old = auth.create("demo", "D", "d@firma.local", "demo", ["SAMAUDIT-Users"], "demo", "127.0.0.1")
        tok = "T" * 32
        r = _post("/login", {"username": "demo", "password": "demo", "csrf_token": tok},
                  f"samaudit_lt={tok}; samaudit_sid={old.sid}")
        self.assertEqual(r["status"], 303)
        self.assertIsNone(auth.get(old.sid))


class DiagCli(unittest.TestCase):
    def test_no_database_yet(self):
        import contextlib
        import io
        err = io.StringIO()
        with mock.patch.object(settings, "db_path", os.path.join(tempfile.mkdtemp(), "none.db")), \
             contextlib.redirect_stderr(err), mock.patch.object(diag, "_drop_root", lambda: None):
            self.assertEqual(diag.main(["--no-probe"]), 2)
        self.assertIn("not been started", err.getvalue())


class UserPasswordContent(unittest.TestCase):
    def test_values_are_never_requested(self):
        self.assertNotIn("userPassword", ldapsrc.USER_ATTRS)
        self.assertNotIn("unixUserPassword", ldapsrc.USER_ATTRS)
        self.assertIn("(|(userPassword=*)(unixUserPassword=*))", (ROOT / "app" / "ldapsrc.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
