# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""What's new: changes per version (features, security, fixes, notices).

The entries live in app/docs/news.json and ship with every version – nothing is loaded from
the internet. Which version a browser saw last is stored only in a cookie."""
from __future__ import annotations

import json
import logging
import os

from .version import VERSION

log = logging.getLogger("samaudit.news")

COOKIE = "samaudit_news"
TYPES = ("security", "feature", "fix", "notice")
_PATH = os.path.join(os.path.dirname(__file__), "docs", "news.json")


def _vkey(v: str) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0,)


def _load() -> list[dict]:
    try:
        with open(_PATH, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        log.warning("Could not load the news entries: %s", e)
        return []
    out = []
    for r in raw if isinstance(raw, list) else []:
        v = str(r.get("version", ""))
        items = [i for i in r.get("items", []) if i.get("type") in TYPES and (i.get("de") or i.get("en"))]
        if v and items and _vkey(v) <= _vkey(VERSION):     # show nothing from the future
            out.append({"version": v, "date": r.get("date") or "", "items": items,
                        "security": any(i["type"] == "security" for i in items)})
    return sorted(out, key=lambda r: _vkey(r["version"]), reverse=True)


ENTRIES = _load()


def unseen(seen: str | None) -> list[dict]:
    """Entries newer than the version seen last.
    Without a cookie (first visit) only the current version counts as new."""
    if not ENTRIES:
        return []
    if not seen:
        return ENTRIES[:1] if ENTRIES[0]["version"] == VERSION else []
    return [r for r in ENTRIES if _vkey(r["version"]) > _vkey(seen)]


def headline(entries: list[dict]) -> dict | None:
    """One entry for the line on the overview: security topics take precedence, otherwise the newest."""
    for r in entries:
        for i in r["items"]:
            if i["type"] == "security":
                return {"version": r["version"], "item": i, "security": True}
    if entries:
        return {"version": entries[0]["version"], "item": entries[0]["items"][0], "security": False}
    return None


def text(item: dict, lang: str) -> str:
    return item.get(lang) or item.get("de") or item.get("en") or ""
