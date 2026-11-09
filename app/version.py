# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Program name and version.

VERSION        program version (changes only with program changes)
IMAGE_VERSION  version of the container image: equal to VERSION or "<VERSION>-s<n>" for a
               security update (same program, newer packages). Set at build time."""
import os
import re

APP_NAME = "SAMAUDIT"
VERSION = "2.1.9"
SOURCE_URL = "https://github.com/soleil0815/samaudit"   # source code (AGPL §13)
DONATE_URL = "https://buymeacoffee.com/soleil0815"   # voluntary support (sidebar and help page)

_img = os.environ.get("SAMAUDIT_IMAGE_VERSION", "").strip()
IMAGE_VERSION = _img if re.fullmatch(re.escape(VERSION) + r"(-s\d+)?", _img) else VERSION
