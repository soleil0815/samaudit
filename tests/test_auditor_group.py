# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auditor group: new default SAMAUDIT-Users, former name SAMAUDIT-Benutzer still accepted without ALLOWED_GROUPS."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-group-"))

from app.config import Settings  # noqa: E402


def settings_with(**env):
    base = {k: v for k, v in os.environ.items() if k not in ("ALLOWED_GROUPS", "DEMO_MODE")}
    with mock.patch.dict(os.environ, {**base, **env}, clear=True):
        return Settings()


class AuditorGroup(unittest.TestCase):
    def test_default_accepts_new_and_former_name(self):
        s = settings_with()
        self.assertEqual(s.allowed_groups, ["SAMAUDIT-Users"])
        self.assertEqual(s.accepted_groups, ["SAMAUDIT-Users", "SAMAUDIT-Benutzer"])

    def test_explicit_setting_means_exactly_those_groups(self):
        self.assertEqual(settings_with(ALLOWED_GROUPS="SAMAUDIT-Benutzer").accepted_groups, ["SAMAUDIT-Benutzer"])
        self.assertEqual(settings_with(ALLOWED_GROUPS="Audit-A;Audit-B").accepted_groups, ["Audit-A", "Audit-B"])

    def test_empty_setting_still_lets_nobody_in(self):
        s = settings_with(ALLOWED_GROUPS="")
        self.assertEqual(s.accepted_groups, [])
        self.assertTrue(any("ALLOWED_GROUPS" in p for p in s.validate()))

    def test_sign_in_and_pages_use_all_accepted_groups(self):
        src = (ROOT / "app" / "ldapsrc.py").read_text(encoding="utf-8")
        self.assertIn("resolve_group_sids(conn, settings.accepted_groups", src)
        self.assertNotIn("settings.allowed_groups, domain_sid", src)
        for tpl in ("login.html", "privacy.html"):
            html = (ROOT / "app" / "templates" / tpl).read_text(encoding="utf-8")
            self.assertNotIn("settings.allowed_groups", html, tpl)


if __name__ == "__main__":
    unittest.main()
