# SPDX-License-Identifier: AGPL-3.0-or-later
"""Web hardening found with OWASP ZAP (2.1.9): strict style CSP, no inline styles, HttpOnly language cookie,
recognisable CSRF field on the sign-in form."""
from __future__ import annotations

import asyncio
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-web-"))

try:
    import starlette  # noqa: F401
    HAVE_WEB = True
except ImportError:  # pragma: no cover
    HAVE_WEB = False


async def _call(app, path: str, method: str = "GET"):
    out: dict = {"headers": [], "body": b""}
    sent = {"done": False}

    async def receive():
        if sent["done"]:
            await asyncio.sleep(0.05)
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
            out["headers"] = [(k.decode().lower(), v.decode()) for k, v in msg.get("headers", [])]
        elif msg["type"] == "http.response.body":
            out["body"] += msg.get("body", b"")

    scope = {"type": "http", "method": method, "path": path.split("?")[0], "raw_path": path.encode(),
             "query_string": (path.split("?", 1)[1] if "?" in path else "").encode(), "headers": [],
             "client": ("127.0.0.1", 1), "server": ("localhost", 9400), "scheme": "https", "root_path": ""}
    await app(scope, receive, send)
    return out


class Templates(unittest.TestCase):
    def test_no_inline_style_attributes(self):
        offenders = []
        for f in sorted((ROOT / "app" / "templates").glob("*.html")):
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\sstyle\s*=", line):
                    offenders.append(f"{f.name}:{n}")
        self.assertEqual(offenders, [], "inline styles are blocked by the CSP – use a class from app.css")

    def test_utility_classes_exist(self):
        css = (ROOT / "app" / "static" / "app.css").read_text(encoding="utf-8")
        used = set()
        for f in (ROOT / "app" / "templates").glob("*.html"):
            used |= set(re.findall(r"\b(u-[a-z0-9-]+)", f.read_text(encoding="utf-8")))
        missing = sorted(c for c in used if f".{c} " not in css and f".{c}{{" not in css)
        self.assertEqual(missing, [])
        for i in (0, 2, 57, 100):
            self.assertIn(f".w-{i}.w-{i} {{ width: {i}%; }}", css)
        for c in ("stale", "privileged", "trusts", "anomalies"):
            self.assertIn(f".c-{c} {{", css)
        for s in ("critical", "high", "medium", "low", "info"):
            self.assertIn(f".sevc-{s} {{", css)


@unittest.skipUnless(HAVE_WEB, "starlette missing")
class Responses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import db
        from app.main import app
        db.init()
        cls.app = app

    def test_csp_forbids_inline_styles_and_scripts(self):
        r = asyncio.run(_call(self.app, "/login"))
        csp = dict(r["headers"])["content-security-policy"]
        self.assertIn("style-src 'self';", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("script-src 'self';", csp)

    def test_rendered_pages_have_no_inline_styles(self):
        for path in ("/login", "/help", "/news", "/privacy"):
            body = asyncio.run(_call(self.app, path))["body"].decode()
            self.assertIsNone(re.search(r"<[^>]+\sstyle=", body), path)

    def test_language_cookie_is_httponly(self):
        r = asyncio.run(_call(self.app, "/lang/en?next=/login"))
        cookies = [v for k, v in r["headers"] if k == "set-cookie" and v.startswith("samaudit_lang=")]
        self.assertTrue(cookies)
        self.assertIn("httponly", cookies[0].lower())

    def test_sign_in_form_uses_a_recognisable_csrf_field(self):
        body = asyncio.run(_call(self.app, "/login"))["body"].decode()
        self.assertRegex(body, r'<input type="hidden" name="csrf_token" value="[^"]{20,}">')
        self.assertNotIn('name="token"', body)


if __name__ == "__main__":
    unittest.main()
