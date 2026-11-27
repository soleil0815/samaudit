# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""2.7.2: security updates ("<version>-s<n>") get their own entry under News – written by the security update
workflow (tools/lockutil.py add-news), shown and marked as new in the program."""
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import lockutil  # noqa: E402

from app import news, updatecheck  # noqa: E402
from app.version import VERSION  # noqa: E402

ROWS = [("Base image", "python", "3.13.18-slim-trixie (sha256:aa)", "3.13.19-slim-trixie (sha256:bb)"),
        ("Debian", "libssl3t64", "3.5.9-1~deb13u1", "3.5.10-1~deb13u1"),
        ("Debian", "openssl", "3.5.9-1~deb13u1", "3.5.10-1~deb13u1"),
        ("Python", "click", "8.5.0", "8.5.1")]


class NewsEntry(unittest.TestCase):
    def test_entry_names_packages_in_both_languages(self):
        e = lockutil.news_entry(ROWS, "2.7.2-s1", "2026-12-08")
        self.assertEqual((e["version"], e["date"]), ("2.7.2-s1", "2026-12-08"))
        item = e["items"][0]
        self.assertEqual(item["type"], "security")
        self.assertIn("gleiches Programm (2.7.2)", item["de"])
        self.assertIn("Basisimage: Python 3.13.19; Debian: libssl3t64, openssl; Python-Pakete: click", item["de"])
        self.assertIn("base image: Python 3.13.19; Debian: libssl3t64, openssl; Python packages: click", item["en"])
        self.assertIn("CHANGELOG-SECURITY.md", item["en"])

    def test_long_lists_are_shortened(self):
        rows = [("Debian", f"lib{i:02d}", "1", "2") for i in range(11)]
        item = lockutil.news_entry(rows, "2.7.2-s1", "2026-12-08")["items"][0]
        self.assertIn("lib07 und 3 weitere", item["de"])
        self.assertIn("lib07 and 3 more", item["en"])
        self.assertNotIn("lib08", item["de"])

    def test_add_news_puts_entry_on_top_once(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "news.json"
            p.write_text(json.dumps([{"version": "2.7.2", "date": "2026-11-27", "items": []}]), encoding="utf-8")
            entry = lockutil.news_entry(ROWS, "2.7.2-s1", "2026-12-08")
            lockutil.add_news(p, entry)
            lockutil.add_news(p, entry)                     # a repeated run does not add it twice
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual([e["version"] for e in data], ["2.7.2-s1", "2.7.2"])

    def test_cli_needs_changes(self):
        with tempfile.TemporaryDirectory() as old, tempfile.TemporaryDirectory() as new:
            for d, ver in ((old, "8.5.0"), (new, "8.5.1")):
                (Path(d) / "requirements.txt").write_text(f"click=={ver} \\\n    --hash=sha256:{'0' * 64}\n")
            p = Path(new) / "news.json"
            p.write_text("[]", encoding="utf-8")
            self.assertEqual(lockutil.main(["add-news", old, new, "2.7.2-s1", "2026-12-08", str(p)]), 0)
            self.assertIn("click", json.loads(p.read_text())[0]["items"][0]["de"])
            self.assertEqual(lockutil.main(["add-news", new, new, "2.7.2-s2", "2026-12-09", str(p)]), 1)

    def test_shipped_news_is_valid(self):
        data = json.loads((ROOT / "app/docs/news.json").read_text(encoding="utf-8"))
        self.assertTrue(any(e["version"] == VERSION for e in data))


class Workflow(unittest.TestCase):
    def test_security_update_writes_and_commits_the_news_entry(self):
        w = (ROOT / ".github/workflows/security-update.yml").read_text(encoding="utf-8")
        self.assertIn("tools/lockutil.py add-news", w)
        add = w[w.index("git add Dockerfile"):].split("\n", 1)[0]
        self.assertIn("app/docs/news.json", add)
        self.assertLess(w.index("add-news"), w.index("git add Dockerfile"))


class ProgramShowsSecurityUpdates(unittest.TestCase):
    def load(self, image: str, entries: list[dict]) -> list[dict]:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "news.json"
            p.write_text(json.dumps(entries), encoding="utf-8")
            with mock.patch.object(news, "_PATH", str(p)), mock.patch.object(news, "IMAGE_VERSION", image):
                return news._load()

    ENTRIES = [
        {"version": "2.7.2", "date": "2026-11-27", "items": [{"type": "notice", "de": "Programm"}]},
        {"version": "2.7.2-s1", "date": "2026-12-08", "items": [{"type": "security", "de": "Pakete s1"}]},
        {"version": "2.7.2-s2", "date": "2027-01-12", "items": [{"type": "security", "de": "Pakete s2"}]},
        {"version": "2.7.1-s1", "date": "2026-11-26", "items": [{"type": "security", "de": "alt"}]},
    ]

    def test_version_key(self):
        self.assertEqual(news._vkey("2.7.1-s2"), (2, 7, 1, 2))
        self.assertEqual(news._vkey("2.7.1"), (2, 7, 1, 0))
        self.assertGreater(news._vkey("2.10.0"), news._vkey("2.9.9-s9"))

    def test_security_update_entry_shown_newest_first(self):
        got = [r["version"] for r in self.load("2.7.2-s1", self.ENTRIES)]
        self.assertEqual(got, ["2.7.2-s1", "2.7.2", "2.7.1-s1"])     # s2 is from the future for this image

    def test_new_after_seeing_the_program_version(self):
        with mock.patch.object(news, "ENTRIES", self.load("2.7.2-s1", self.ENTRIES)), \
                mock.patch.object(news, "IMAGE_VERSION", "2.7.2-s1"):
            self.assertEqual([r["version"] for r in news.unseen("2.7.2")], ["2.7.2-s1"])
            self.assertEqual(news.unseen("2.7.2-s1"), [])
            self.assertEqual([r["version"] for r in news.unseen(None)], ["2.7.2-s1"])
            self.assertTrue(news.headline(news.unseen("2.7.2"))["security"])

    def test_age_hint_counts_from_the_security_update(self):
        entries = self.load("2.7.2-s1", self.ENTRIES)
        with mock.patch.object(news, "ENTRIES", entries), mock.patch.object(updatecheck, "IMAGE_VERSION", "2.7.2-s1"), \
                mock.patch.object(updatecheck, "VERSION", "2.7.2"):
            self.assertEqual(updatecheck.release_date(), date(2026, 12, 8))
        with mock.patch.object(news, "ENTRIES", entries), mock.patch.object(updatecheck, "IMAGE_VERSION", "2.7.2-s5"), \
                mock.patch.object(updatecheck, "VERSION", "2.7.2"):
            self.assertEqual(updatecheck.release_date(), date(2026, 11, 27))   # no entry: program version

    def test_cookie_stores_the_image_version(self):
        src = (ROOT / "app/main.py").read_text(encoding="utf-8")
        self.assertIn("set_cookie(news.COOKIE, IMAGE_VERSION", src)
        self.assertIn("r.version == IMAGE_VERSION", (ROOT / "app/templates/news.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
