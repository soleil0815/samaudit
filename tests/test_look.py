# SPDX-License-Identifier: AGPL-3.0-or-later
"""2.3.0 look: appearance follows the system, three-way switch, no web font that is no longer shipped."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CSS = (ROOT / "app/static/app.css").read_text(encoding="utf-8")


class Look(unittest.TestCase):
    def test_theme_follows_system_by_default(self):
        init = (ROOT / "app/static/theme-init.js").read_text(encoding="utf-8")
        self.assertIn('|| "system"', init)
        self.assertIn("prefers-color-scheme: dark", init)
        js = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
        self.assertIn("data-theme-set", js)
        self.assertIn('return "system"', js)

    def test_three_way_switch(self):
        base = (ROOT / "app/templates/base.html").read_text(encoding="utf-8")
        for v in ("system", "light", "dark"):
            self.assertIn(f'data-theme-set="{v}"', base)

    def test_both_themes_defined(self):
        self.assertRegex(CSS, r":root \{[^}]*--accent: #0071E3")
        self.assertRegex(CSS, r':root\[data-theme="dark"\] \{[^}]*--accent: #0A84FF')

    def test_fonts_exist(self):
        for url in re.findall(r'url\("(fonts/[^"]+)"\)', CSS):
            self.assertTrue((ROOT / "app/static" / url).is_file(), url)
        self.assertNotIn("Poppins", CSS)

    def test_logo_without_inline_colour_on_page(self):
        base = (ROOT / "app/templates/base.html").read_text(encoding="utf-8")
        logo = base[base.index("{% macro logo"):base.index("{%- endmacro %}", base.index("{% macro logo"))]
        self.assertNotIn("fill=\"#", logo)


if __name__ == "__main__":
    unittest.main()
