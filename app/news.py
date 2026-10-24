# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Neuigkeiten: Änderungen je Version (Funktionen, Sicherheit, Fehlerbehebungen, Hinweise).

Die Einträge liegen in app/docs/news.json und kommen mit jeder Version mit – es wird nichts aus
dem Internet geladen. Welche Version ein Browser zuletzt gesehen hat, steht nur in einem Cookie."""
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
        log.warning("Neuigkeiten konnten nicht geladen werden: %s", e)
        return []
    out = []
    for r in raw if isinstance(raw, list) else []:
        v = str(r.get("version", ""))
        items = [i for i in r.get("items", []) if i.get("type") in TYPES and (i.get("de") or i.get("en"))]
        if v and items and _vkey(v) <= _vkey(VERSION):     # nichts aus der Zukunft anzeigen
            out.append({"version": v, "date": r.get("date") or "", "items": items,
                        "security": any(i["type"] == "security" for i in items)})
    return sorted(out, key=lambda r: _vkey(r["version"]), reverse=True)


ENTRIES = _load()


def unseen(seen: str | None) -> list[dict]:
    """Einträge, die neuer sind als die zuletzt gesehene Version.
    Ohne Cookie (erster Besuch) gilt nur die aktuelle Version als neu."""
    if not ENTRIES:
        return []
    if not seen:
        return ENTRIES[:1] if ENTRIES[0]["version"] == VERSION else []
    return [r for r in ENTRIES if _vkey(r["version"]) > _vkey(seen)]


def headline(entries: list[dict]) -> dict | None:
    """Ein Eintrag für die Zeile auf der Übersicht: Sicherheitsthemen haben Vorrang, sonst das Neueste."""
    for r in entries:
        for i in r["items"]:
            if i["type"] == "security":
                return {"version": r["version"], "item": i, "security": True}
    if entries:
        return {"version": entries[0]["version"], "item": entries[0]["items"][0], "security": False}
    return None


def text(item: dict, lang: str) -> str:
    return item.get(lang) or item.get("de") or item.get("en") or ""
