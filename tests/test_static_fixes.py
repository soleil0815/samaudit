# SPDX-License-Identifier: AGPL-3.0-or-later
"""Selbsttests für die Stellen, die die statischen Prüfungen (mypy) in 2.1.1 aufgedeckt haben."""
from __future__ import annotations

import ast
import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-static-"))

from app import i18n  # noqa: E402

try:
    import starlette  # noqa: F401
    HAVE_WEB = True
except ImportError:  # pragma: no cover - im CI immer vorhanden
    HAVE_WEB = False


class TranslationFallback(unittest.TestCase):
    def test_entry_without_german_text_returns_the_key(self):
        i18n.T["__nur_en"] = {"en": "only {x}"}
        self.addCleanup(i18n.T.pop, "__nur_en")
        self.assertEqual(i18n.t("__nur_en", "de", x=1), "__nur_en")   # früher: AttributeError auf None
        self.assertEqual(i18n.t("__nur_en", "en", x=1), "only 1")

    def test_unknown_key(self):
        self.assertEqual(i18n.t("__gibt_es_nicht"), "__gibt_es_nicht")


class ServerSettings(unittest.TestCase):
    def test_uvicorn_gets_port_and_all_settings(self):
        # Regression: ein Kommentar mitten in der Zeile hatte "port" und weitere Einstellungen auskommentiert –
        # uvicorn lief dann auf 8000 statt 9400 und der Gesundheitscheck schlug fehl.
        tree = ast.parse((ROOT / "run.py").read_text(encoding="utf-8"))
        keys = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "kwargs":
                keys = {k.value for k in node.value.keys}  # type: ignore[union-attr]
        self.assertIsNotNone(keys, "kwargs für uvicorn nicht gefunden")
        for k in ("host", "port", "log_level", "access_log", "proxy_headers", "server_header"):
            self.assertIn(k, keys)


@unittest.skipUnless(HAVE_WEB, "starlette fehlt")
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


if __name__ == "__main__":
    unittest.main()
