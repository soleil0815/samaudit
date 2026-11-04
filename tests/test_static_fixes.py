# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-tests for the spots uncovered by the static checks (mypy) in 2.1.1, and for UI language handling."""
from __future__ import annotations

import ast
import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-static-"))

from app import i18n  # noqa: E402

try:
    import starlette  # noqa: F401
    HAVE_WEB = True
except ImportError:  # pragma: no cover - always present in CI
    HAVE_WEB = False


class TranslationFallback(unittest.TestCase):
    def test_entry_without_german_text_returns_the_key(self):
        i18n.T["__en_only"] = {"en": "only {x}"}
        self.addCleanup(i18n.T.pop, "__en_only")
        self.assertEqual(i18n.t("__en_only", "de", x=1), "__en_only")   # previously: AttributeError on None
        self.assertEqual(i18n.t("__en_only", "en", x=1), "only 1")

    def test_unknown_key(self):
        self.assertEqual(i18n.t("__does_not_exist"), "__does_not_exist")


class ServerSettings(unittest.TestCase):
    def test_uvicorn_gets_port_and_all_settings(self):
        # Regression: a comment in the middle of the line had commented out "port" and further settings –
        # uvicorn then ran on 8000 instead of 9400 and the health check failed.
        tree = ast.parse((ROOT / "run.py").read_text(encoding="utf-8"))
        keys = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "kwargs":
                keys = {k.value for k in node.value.keys}  # type: ignore[union-attr]
        self.assertIsNotNone(keys, "kwargs for uvicorn not found")
        for k in ("host", "port", "log_level", "access_log", "proxy_headers", "server_header"):
            self.assertIn(k, keys)


@unittest.skipUnless(HAVE_WEB, "starlette missing")
class MultipartReader(unittest.TestCase):
    def parse(self, body: bytes, boundary: str = "XyZ"):
        from starlette.requests import Request

        from app.main import multipart_of
        sent = {"done": False}

        async def receive():
            if sent["done"]:
                return {"type": "http.disconnect"}
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        scope = {"type": "http", "method": "POST", "path": "/", "headers": [
            (b"content-type", f"multipart/form-data; boundary={boundary}".encode()),
            (b"content-length", str(len(body)).encode())]}
        return asyncio.run(multipart_of(Request(scope, receive)))

    def test_plain_field_and_file(self):
        body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nabc\r\n"
                b"--XyZ\r\nContent-Disposition: form-data; name=\"cert\"; filename=\"ca.pem\"\r\n"
                b"Content-Type: application/octet-stream\r\n\r\nPEM\r\n--XyZ--\r\n")
        fields, files = self.parse(body)
        self.assertEqual(fields, {"csrf": "abc"})
        self.assertEqual(files, [("ca.pem", b"PEM")])

    def test_rfc2231_name_becomes_a_plain_string(self):
        body = (b"--XyZ\r\nContent-Disposition: form-data; name*=utf-8''csrf\r\n\r\nabc\r\n--XyZ--\r\n")
        fields, _files = self.parse(body)
        self.assertEqual(fields, {"csrf": "abc"})

    def test_nested_multipart_part_is_skipped(self):
        body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"x\"\r\n"
                b"Content-Type: multipart/mixed; boundary=In\r\n\r\n"
                b"--In\r\nContent-Type: text/plain\r\n\r\ninnen\r\n--In--\r\n"
                b"--XyZ\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nabc\r\n--XyZ--\r\n")
        fields, files = self.parse(body)
        self.assertEqual(fields.get("csrf"), "abc")
        self.assertFalse(fields.get("x"), "a nested part carries no form value")
        self.assertEqual(files, [])


class ConfigProblems(unittest.TestCase):
    def test_validate_reports_in_english_for_the_log(self):
        from app.config import Settings
        with mock.patch.dict(os.environ, {"DEMO_MODE": "false", "DOMAIN_FQDN": "", "DC_HOSTS": ""}):
            problems = Settings().validate()
        self.assertIn("DOMAIN_FQDN is not set.", problems)
        self.assertIn("DC_HOSTS is not set.", problems)


@unittest.skipUnless(HAVE_WEB, "starlette missing")
class LoginConfigNotice(unittest.TestCase):
    """The login page shows the configuration notice in the UI language and never the problem details."""

    def login_page(self, lang: str) -> str:
        from app import db, main
        db.init()
        sent: dict = {"body": b""}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.body":
                sent["body"] += msg.get("body", b"")
        scope = {"type": "http", "method": "GET", "path": "/login", "raw_path": b"/login", "query_string": b"",
                 "headers": [(b"cookie", f"{main.LANG_COOKIE}={lang}".encode())], "client": ("127.0.0.1", 1),
                 "server": ("t", 80), "scheme": "http", "http_version": "1.1", "root_path": ""}
        with mock.patch.object(main.settings, "validate", return_value=["DOMAIN_FQDN is not set."]):
            asyncio.run(main.app(scope, receive, send))
        return sent["body"].decode("utf-8")

    def test_english_ui(self):
        html = self.login_page("en")
        self.assertIn("Configuration error: details in the container log", html)
        self.assertNotIn("Konfigurationsfehler", html)
        self.assertNotIn("DOMAIN_FQDN is not set", html)

    def test_german_ui(self):
        html = self.login_page("de")
        self.assertIn("Konfigurationsfehler: Details im Container-Protokoll", html)
        self.assertNotIn("Configuration error", html)
        self.assertNotIn("DOMAIN_FQDN is not set", html)


class UiErrorTexts(unittest.TestCase):
    """Errors that reach the web interface are translated; str() is English for the log."""

    def test_cert_error_follows_the_ui_language(self):
        from app.webcert import CertError, analyze
        e = CertError("certerr_too_many", n=10)
        self.assertEqual(str(e), "At most 10 files at once.")
        self.assertEqual(e.text("de"), "Höchstens 10 Dateien auf einmal.")
        with self.assertRaises(CertError) as cm:
            analyze([("x.pfx", b"not a certificate")], None)
        self.assertEqual(cm.exception.text("de"), "x.pfx: Passwort falsch oder Datei beschädigt.")
        self.assertEqual(cm.exception.text("en"), "x.pfx: wrong password or damaged file.")
        folder = CertError("certerr_missing", folder=True, files="a.pfx")
        self.assertEqual(folder.text("de"), "Ordner certs: a.pfx nicht gefunden.")
        self.assertEqual(str(folder), "certs folder: a.pfx not found.")

    def test_scan_error_codes_are_translated(self):
        for code in ("domain_unreadable", "aborted_restart"):
            self.assertIn(f"err_{code}", i18n.T)
        self.assertEqual(i18n.tv("@err_smb_missing|No module", "en"), "smbprotocol missing: No module")
        self.assertEqual(i18n.tv("@err_smb_missing|No module", "de"), "smbprotocol fehlt: No module")


if __name__ == "__main__":
    unittest.main()
