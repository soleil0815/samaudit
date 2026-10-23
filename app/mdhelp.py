# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Handbuch (app/docs/*.md) als HTML für die Hilfe-Seite.

Bewusst kleiner, eigener Markdown-Leser für genau die Elemente, die das Handbuch nutzt
(Überschriften, Absätze, Listen, Tabellen, Code, Hinweise, Fett, Code im Text, Links) –
ohne zusätzliche Bibliothek. Aller Text wird HTML-maskiert; Links nur auf http(s), # oder /."""
from __future__ import annotations

import os
import re
from functools import lru_cache
from html import escape

DOCS = os.path.join(os.path.dirname(__file__), "docs")
FILES = {"de": "handbuch.de.md", "en": "manual.en.md"}

_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*")


def _slug(text: str, used: set[str]) -> str:
    s = re.sub(r"[^a-z0-9äöüß]+", "-", text.lower()).strip("-") or "abschnitt"
    base, n = s, 2
    while s in used:
        s, n = f"{base}-{n}", n + 1
    used.add(s)
    return s


def _inline(text: str) -> str:
    """Inline-Formatierung auf bereits maskiertem Text."""
    codes: list[str] = []

    def keep_code(m):
        codes.append(f"<code>{m.group(1)}</code>")
        return f"\x00{len(codes) - 1}\x00"

    out = _CODE.sub(keep_code, escape(text, quote=True))

    def link(m):
        label, url = m.group(1), m.group(2)
        if url.startswith(("https://", "http://")):
            return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{label}</a>'
        if url.startswith(("#", "/")) and not url.startswith("//"):
            return f'<a href="{url}">{label}</a>'
        return label

    out = _LINK.sub(link, out)
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    return re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], out)


def render(md: str) -> tuple[str, list[tuple[int, str, str]]]:
    """Gibt (HTML, Inhaltsverzeichnis[(Ebene, id, Titel)]) zurück."""
    lines = md.splitlines()
    html: list[str] = []
    toc: list[tuple[int, str, str]] = []
    used: set[str] = set()
    i, n = 0, len(lines)
    para: list[str] = []

    def flush():
        if para:
            html.append(f"<p>{_inline(' '.join(para))}</p>")
            para.clear()

    while i < n:
        line = lines[i]
        s = line.strip()
        if not s:
            flush(); i += 1; continue
        if s.startswith("```"):
            flush()
            j = i + 1
            while j < n and not lines[j].strip().startswith("```"):
                j += 1
            html.append("<pre><code>" + escape("\n".join(lines[i + 1:j])) + "</code></pre>")
            i = j + 1; continue
        m = re.match(r"^(#{1,4})\s+(.*)$", s)
        if m:
            flush()
            level, title = len(m.group(1)), m.group(2).strip()
            sid = _slug(title, used)
            if level in (2, 3):
                toc.append((level, sid, re.sub(r"[*`]", "", title)))
            html.append(f'<h{level} id="{sid}">{_inline(title)}</h{level}>')
            i += 1; continue
        if s == "---":
            flush(); html.append("<hr>"); i += 1; continue
        if s.startswith(">"):
            flush()
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip()); i += 1
            html.append(f'<aside class="note">{_inline(" ".join(buf))}</aside>')
            continue
        if s.startswith("|") and i + 1 < n and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            flush()
            cells = lambda row: [c.strip() for c in row.strip().strip("|").split("|")]  # noqa: E731
            head = cells(s)
            rows = []
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                rows.append(cells(lines[i])); i += 1
            t = ["<div class=\"table-wrap\"><table><thead><tr>"] + [f"<th>{_inline(c)}</th>" for c in head] + ["</tr></thead><tbody>"]
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            html.append("".join(t)); continue
        lm = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if lm:
            flush()
            ordered = lm.group(2)[0].isdigit()
            tag = "ol" if ordered else "ul"
            items: list[list] = []   # [text, [unterpunkte]]
            while i < n:
                m2 = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", lines[i])
                if m2 and len(m2.group(1)) == 0:
                    items.append([m2.group(3), []]); i += 1
                elif m2 and items:
                    items[-1][1].append(m2.group(3)); i += 1
                elif lines[i].startswith("   ") and lines[i].strip() and items:
                    items[-1][0] += " " + lines[i].strip(); i += 1   # Fortsetzungszeile
                else:
                    break
            out = [f"<{tag}>"]
            for text, subs in items:
                sub = "".join(f"<li>{_inline(x)}</li>" for x in subs)
                out.append(f"<li>{_inline(text)}" + (f"<ul>{sub}</ul>" if sub else "") + "</li>")
            out.append(f"</{tag}>")
            html.append("".join(out)); continue
        para.append(s); i += 1
    flush()
    return "\n".join(html), toc


@lru_cache(maxsize=4)
def manual(lang: str) -> tuple[str, list[tuple[int, str, str]]]:
    path = os.path.join(DOCS, FILES.get(lang, FILES["de"]))
    with open(path, encoding="utf-8") as f:
        return render(f.read())
