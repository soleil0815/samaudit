# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Programmname und Version.

VERSION        Programmversion (ändert sich nur mit Programmänderungen)
IMAGE_VERSION  Version des Container-Images: gleich VERSION oder „<VERSION>-s<n>“ für ein
               Sicherheitsupdate (gleiches Programm, neue Paketstände). Wird beim Bau gesetzt."""
import os
import re

APP_NAME = "SAMAUDIT"
VERSION = "1.9.7"

_img = os.environ.get("SAMAUDIT_IMAGE_VERSION", "").strip()
IMAGE_VERSION = _img if re.fullmatch(re.escape(VERSION) + r"(-s\d+)?", _img) else VERSION
