# SPDX-License-Identifier: AGPL-3.0-or-later
"""Update hint (2.5.0): age hint without network, optional online check with GitHub, egress exception."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-upd-"))

from app import egress, updatecheck  # noqa: E402
from app.config import settings  # noqa: E402
from app.version import IMAGE_VERSION, VERSION  # noqa: E402


def _iso(delta_s: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=delta_s)).isoformat(timespec="seconds")


class Base(unittest.TestCase):
    def setUp(self):
        self._saved = (settings.update_check, settings.update_hint_days, settings.demo_mode)
        settings.update_check, settings.update_hint_days, settings.demo_mode = False, 60, False
        updatecheck.set_state(checked_at=None, ok_at=None, latest=None, error=None)
        updatecheck._ips.update(ips=set(), ts=0.0)

    def tearDown(self):
        settings.update_check, settings.update_hint_days, settings.demo_mode = self._saved
        updatecheck.set_state(checked_at=None, ok_at=None, latest=None, error=None)


class Versions(Base):
    def test_security_updates_count(self):
        self.assertGreater(updatecheck.vkey("2.4.1-s1"), updatecheck.vkey("2.4.1"))
        self.assertGreater(updatecheck.vkey("2.5.0"), updatecheck.vkey("2.4.1-s9"))
        self.assertGreater(updatecheck.vkey("2.10.0"), updatecheck.vkey("2.9.9"))
        self.assertEqual(updatecheck.vkey("junk"), (0, 0, 0, 0))

    def test_newer_compares_with_running_image(self):
        self.assertFalse(updatecheck.newer(IMAGE_VERSION))
        self.assertFalse(updatecheck.newer("1.0.0"))
        self.assertFalse(updatecheck.newer(None))
        self.assertTrue(updatecheck.newer(IMAGE_VERSION.split("-")[0] + "-s99"))
        self.assertTrue(updatecheck.newer("99.0.0"))

    def test_parse_release(self):
        ok = json.dumps({"tag_name": "v2.6.0", "draft": False, "prerelease": False}).encode()
        self.assertEqual(updatecheck.parse_latest(ok), "2.6.0")
        self.assertEqual(updatecheck.parse_latest(json.dumps({"tag_name": "v2.6.0-s2"}).encode()), "2.6.0-s2")
        for bad in ({"tag_name": "v2.6.0", "prerelease": True}, {"tag_name": "v2.6.0", "draft": True},
                    {"tag_name": "<script>"}, {"tag_name": "v2.6.0; rm"}, {}, []):
            with self.assertRaises(ValueError):
                updatecheck.parse_latest(json.dumps(bad).encode())
        with self.assertRaises(ValueError):
            updatecheck.parse_latest(b"not json")

    def test_api_url_and_neutral_request(self):
        self.assertEqual(updatecheck.API_URL, "https://api.github.com/repos/soleil0815/samaudit/releases/latest")
        src = (ROOT / "app" / "updatecheck.py").read_text(encoding="utf-8")
        self.assertIn('"User-Agent": "SAMAUDIT-update-check"', src)
        self.assertIn("ProxyHandler({})", src)


class Check(Base):
    def test_off_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("UPDATE_CHECK", None)
            from app.config import Settings
            self.assertFalse(Settings().update_check)
            self.assertEqual(Settings().update_hint_days, 60)
        self.assertFalse(updatecheck.due())

    def test_never_fetches_when_off_or_demo(self):
        updatecheck._started -= 3600
        self.assertFalse(updatecheck.due())
        settings.update_check, settings.demo_mode = True, True
        self.assertFalse(updatecheck.due())
        settings.demo_mode = False
        self.assertTrue(updatecheck.due())

    def test_success_and_schedule(self):
        settings.update_check = True
        st = updatecheck.check_now(fetch=lambda: "99.0.0")
        self.assertEqual((st["latest"], st["error"]), ("99.0.0", None))
        self.assertFalse(updatecheck.due())
        updatecheck.set_state(checked_at=_iso(updatecheck.INTERVAL + 5))
        self.assertTrue(updatecheck.due())

    def test_failure_is_silent_and_retried_sooner(self):
        settings.update_check = True

        def boom():
            raise OSError("no route to host 203.0.113.9")
        st = updatecheck.check_now(fetch=boom)
        self.assertEqual(st["error"], "OSError")          # only the class name, no addresses
        self.assertIsNone(st["latest"])
        updatecheck.set_state(checked_at=_iso(updatecheck.RETRY + 5))
        self.assertTrue(updatecheck.due())

    def test_diag_part(self):
        settings.update_check = True
        updatecheck.check_now(fetch=lambda: "99.0.0")
        d = updatecheck.diag_part()
        self.assertTrue(d["online_check"] and d["newer_available"])
        self.assertEqual(d["latest"], "99.0.0")
        self.assertEqual(set(d), {"online_check", "hint_days", "release_date", "last_check", "last_success",
                                  "latest", "error", "newer_available"})


class DiagPackage(Base):
    def test_package_has_update_section(self):
        from app import db, diag
        db.init()
        pkg = diag.build(source="cli", probe=False)
        self.assertEqual(pkg["samaudit_diagnostics"], 2)
        self.assertFalse(pkg["update"]["online_check"])
        self.assertEqual(pkg["settings"]["update_check"], False)
        self.assertEqual(pkg["settings"]["update_hint_days"], 60)


class Notice(Base):
    def rel(self) -> date:
        r = updatecheck.release_date()
        self.assertIsNotNone(r, "news.json needs an entry with a date for the current version")
        return r

    def test_release_date_from_news(self):
        self.rel()

    def test_no_hint_while_young(self):
        self.assertIsNone(updatecheck.notice(None, today=self.rel() + timedelta(days=59)))

    def test_age_hint(self):
        n = updatecheck.notice(None, today=self.rel() + timedelta(days=61))
        self.assertEqual((n["kind"], n["version"], n["days"]), ("age", VERSION, 61))
        self.assertIsNone(updatecheck.notice(n["key"], today=self.rel() + timedelta(days=61)))
        settings.update_hint_days = 0
        self.assertIsNone(updatecheck.notice(None, today=self.rel() + timedelta(days=400)))

    def test_new_version_hint_only_with_online_check(self):
        updatecheck.set_state(latest="99.0.0", ok_at=_iso(), checked_at=_iso())
        self.assertIsNone(updatecheck.notice(None, today=self.rel()))
        settings.update_check = True
        n = updatecheck.notice(None, today=self.rel())
        self.assertEqual((n["kind"], n["version"]), ("new", "99.0.0"))
        self.assertIsNone(updatecheck.notice("new:99.0.0"))
        updatecheck.set_state(latest="99.0.1")
        self.assertIsNotNone(updatecheck.notice("new:99.0.0"), "dismissed hint returns for the next version")

    def test_confirmed_up_to_date_suppresses_age_hint(self):
        settings.update_check = True
        updatecheck.set_state(latest=VERSION, ok_at=_iso(3600), checked_at=_iso(3600))
        self.assertIsNone(updatecheck.notice(None, today=self.rel() + timedelta(days=100)))
        updatecheck.set_state(ok_at=_iso(5 * 86400))
        self.assertEqual(updatecheck.notice(None, today=self.rel() + timedelta(days=100))["kind"], "age")


class Egress(Base):
    def test_github_only_with_check_on_and_port_443(self):
        with mock.patch.object(updatecheck, "host_ips", return_value={"140.82.121.6"}):
            self.assertFalse(updatecheck.allows("140.82.121.6", 443))
            self.assertFalse(egress.is_allowed("140.82.121.6", 443))
            settings.update_check = True
            self.assertTrue(egress.is_allowed("140.82.121.6", 443))
            self.assertFalse(egress.is_allowed("140.82.121.6", 80))
            self.assertFalse(egress.is_allowed("140.82.121.7", 443))

    def test_no_dns_lookup_when_off(self):
        with mock.patch.object(egress, "_orig_getaddrinfo", side_effect=AssertionError("looked up")):
            self.assertEqual(updatecheck.host_ips(), set())


class Page(Base):
    def render(self, notice, lang="de") -> str:
        from app.main import templates
        sess = SimpleNamespace(display="Demo", groups=["SAMAUDIT-Users"], csrf="x")
        return templates.env.get_template("dashboard.html").render(
            sess=sess, path="/", lang=lang, settings=settings, news_unseen=[], request=None, latest=None,
            running=None, overview=None, compose_msg=None, update_notice=notice,
            news_headline=lambda e: None, news_text=lambda i, lang: "")

    def test_strips(self):
        html = self.render({"kind": "new", "version": "9.9.9", "key": "new:9.9.9"})
        self.assertIn("Version 9.9.9 verfügbar", html)
        self.assertIn("https://github.com/soleil0815/samaudit/releases", html)
        self.assertIn('href="/update/seen?next=/"', html)
        html = self.render({"kind": "age", "version": VERSION, "date": date(2026, 1, 2), "days": 70, "key": "x"}, "en")
        self.assertIn("Check for updates", html)
        self.assertIn("2026-01-02, i.e. 70 days old", html)
        self.assertNotIn("news-strip upd", self.render(None))

    def test_privacy_page_mentions_check_only_when_on(self):
        from app.main import templates
        tpl = templates.env.get_template("privacy.html")
        kw = dict(sess=None, path="/privacy", lang="de", news_unseen=[], request=None)
        self.assertNotIn("Update-Prüfung", tpl.render(settings=settings, **kw))
        settings.update_check = True
        self.assertIn("Update-Prüfung", tpl.render(settings=settings, **kw))


if __name__ == "__main__":
    unittest.main()
