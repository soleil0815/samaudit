# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Kleine SVG-Grafiken für die Weboberfläche (ohne JS-Bibliotheken).
Farben kommen aus CSS-Variablen, damit Hell/Dunkel automatisch passt."""
from __future__ import annotations

import math
from html import escape

from .i18n import level_key, t


def level_class(score: int | None) -> str:
    if score is None:
        return "lv-na"
    return f"lv-{level_key(score)}"


def seal(score: int | None, lang: str, size: int = 220) -> str:
    """Das „Prüfsiegel“: Skala mit 50 Teilstrichen, gefüllt bis zum Risikowert."""
    s = 0 if score is None else max(0, min(100, int(score)))
    cx = cy = size / 2
    r_out = size / 2 - 6
    r_tick_in = r_out - 14
    ticks = []
    n = 50
    filled = round(s / 100 * n)
    for i in range(n):
        ang = -math.pi / 2 + 2 * math.pi * i / n
        long_tick = i % 5 == 0
        r1 = r_tick_in - (4 if long_tick else 0)
        x1, y1 = cx + r1 * math.cos(ang), cy + r1 * math.sin(ang)
        x2, y2 = cx + r_out * math.cos(ang), cy + r_out * math.sin(ang)
        cls = "tick on" if i < filled else "tick"
        ticks.append(f'<line class="{cls}" x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}"/>')
    label = "–" if score is None else str(s)
    lvl = "" if score is None else t(f"level_{level_key(s)}", lang)
    return (
        f'<svg class="seal {level_class(score)}" viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
        f'role="img" aria-label="{escape(t("risk_score", lang))}: {label} – {escape(lvl)}">'
        f'<circle class="seal-face" cx="{cx}" cy="{cy}" r="{r_tick_in - 10:.1f}"/>'
        f'{"".join(ticks)}'
        f'<text class="seal-num" x="{cx}" y="{cy + size * 0.07:.1f}" text-anchor="middle">{label}</text>'
        f'<text class="seal-sub" x="{cx}" y="{cy + size * 0.2:.1f}" text-anchor="middle">{escape(lvl)}</text>'
        f'</svg>'
    )


def trend(points: list[tuple[str, int, int]], lang: str, width: int = 560, height: int = 180) -> str:
    """points: [(label, score, scan_id)] chronologisch."""
    if len(points) < 2:
        return ""
    pad_l, pad_r, pad_t, pad_b = 34, 14, 12, 26
    w, h = width - pad_l - pad_r, height - pad_t - pad_b
    step = w / (len(points) - 1)

    def xy(i, v):
        return pad_l + i * step, pad_t + h - (v / 100) * h

    grid = []
    for v in (0, 25, 50, 75, 100):
        y = pad_t + h - v / 100 * h
        grid.append(f'<line class="grid" x1="{pad_l}" x2="{width - pad_r}" y1="{y:.1f}" y2="{y:.1f}"/>'
                    f'<text class="axis" x="{pad_l - 8}" y="{y + 4:.1f}" text-anchor="end">{v}</text>')
    path = " ".join(("M" if i == 0 else "L") + f"{xy(i, v)[0]:.1f},{xy(i, v)[1]:.1f}" for i, (_, v, _) in enumerate(points))
    dots, labels = [], []
    every = max(1, math.ceil(len(points) / 6))
    for i, (lab, v, _sid) in enumerate(points):
        x, y = xy(i, v)
        dots.append(f'<g class="pt" data-tip="{escape(lab)}: {v}"><circle class="hit" cx="{x:.1f}" cy="{y:.1f}" r="12"/>'
                    f'<circle class="dot {level_class(v)}" cx="{x:.1f}" cy="{y:.1f}" r="4.5"/></g>')
        if i % every == 0 or i == len(points) - 1:
            labels.append(f'<text class="axis" x="{x:.1f}" y="{height - 6}" text-anchor="middle">{escape(lab[:5])}</text>')
    return (f'<svg class="trend" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(t("trend", lang))}">'
            f'{"".join(grid)}<path class="line" d="{path}"/>{"".join(dots)}{"".join(labels)}</svg>')


def hbars(rows: list[tuple[str, int]], width: int = 520, unit: str = "") -> str:
    """Einfache horizontale Balken (eine Farbe), Werte direkt beschriftet."""
    if not rows:
        return ""
    bar_h, gap, label_w = 14, 12, 210
    vmax = max(v for _, v in rows) or 1
    height = len(rows) * (bar_h + gap)
    out = []
    for i, (lab, v) in enumerate(rows):
        y = i * (bar_h + gap)
        bw = max(3, (width - label_w - 50) * v / vmax)
        out.append(f'<text class="blabel" x="0" y="{y + bar_h - 2}">{escape(lab[:34])}</text>'
                   f'<rect class="bar" x="{label_w}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="3"/>'
                   f'<text class="bval" x="{label_w + bw + 8:.1f}" y="{y + bar_h - 2}">{v}{unit}</text>')
    return f'<svg class="hbars" viewBox="0 0 {width} {height}" role="img">{"".join(out)}</svg>'


def login_dial() -> str:
    """Dekorative Skala für die Anmeldeseite."""
    size, n = 520, 72
    c = size / 2
    out = []
    for i in range(n):
        ang = -math.pi / 2 + 2 * math.pi * i / n
        long_tick = i % 6 == 0
        r1, r2 = (c - 44 if long_tick else c - 30), c - 8
        cls = ' class="on"' if 4 <= i <= 17 else ""
        out.append(f'<line{cls} x1="{c + r1 * math.cos(ang):.1f}" y1="{c + r1 * math.sin(ang):.1f}" '
                   f'x2="{c + r2 * math.cos(ang):.1f}" y2="{c + r2 * math.sin(ang):.1f}"/>')
    return f'<svg class="dial" viewBox="0 0 {size} {size}" aria-hidden="true">{"".join(out)}</svg>'
