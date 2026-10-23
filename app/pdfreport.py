# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""PDF-Export des Berichts (ReportLab, ohne externe Abhängigkeiten zur Laufzeit)."""
from __future__ import annotations

import io
import math
import os
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, CondPageBreak, Flowable, Frame, KeepTogether, NextPageTemplate, PageBreak, PageTemplate,
    Paragraph, Preformatted, Spacer, Table, TableStyle,
)

from .adutil import LOCAL_TZ
from .version import APP_NAME, VERSION
from .i18n import level_key, t, tv
from .rules import CATEGORIES, SEVERITIES

FONT_DIR = os.path.join(os.path.dirname(__file__), "pdf_fonts")
_fonts_ready = False


def _fonts() -> tuple[str, str, str, str]:
    global _fonts_ready
    if not _fonts_ready:
        try:
            pdfmetrics.registerFont(TTFont("Body", os.path.join(FONT_DIR, "Carlito-Regular.ttf")))
            pdfmetrics.registerFont(TTFont("Body-Bold", os.path.join(FONT_DIR, "Carlito-Bold.ttf")))
            pdfmetrics.registerFont(TTFont("Body-Italic", os.path.join(FONT_DIR, "Carlito-Italic.ttf")))
            pdfmetrics.registerFont(TTFont("Mono", os.path.join(FONT_DIR, "DejaVuSansMono.ttf")))
            pdfmetrics.registerFont(TTFont("Head", os.path.join(FONT_DIR, "Poppins-Medium.ttf")))
            pdfmetrics.registerFont(TTFont("Head-Bold", os.path.join(FONT_DIR, "Poppins-Bold.ttf")))
            from reportlab.pdfbase.pdfmetrics import registerFontFamily
            registerFontFamily("Body", normal="Body", bold="Body-Bold", italic="Body-Italic", boldItalic="Body-Bold")
            _fonts_ready = True
        except Exception:  # noqa: BLE001 – Fallback auf eingebaute Schriften
            _fonts_ready = None
    if _fonts_ready:
        return "Body", "Body-Bold", "Body-Italic", "Mono"
    return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Courier"


# Farben (heller Druck)
INK = colors.HexColor("#16202b")
INK2 = colors.HexColor("#485667")
INK3 = colors.HexColor("#758293")
LINE = colors.HexColor("#d6dce3")
LINE2 = colors.HexColor("#e6eaee")
SURF2 = colors.HexColor("#f4f6f8")
ACCENT = colors.HexColor("#5b5fe0")
ACCENT_LIGHT = colors.HexColor("#8b8ff8")
NAVY = colors.HexColor("#121729")
CAT = {"stale": colors.HexColor("#1f9d68"), "privileged": colors.HexColor("#5b5fe0"),
       "trusts": colors.HexColor("#c48a00"), "anomalies": colors.HexColor("#d23f3f")}


def head_font(bold=True) -> str:
    return ("Head-Bold" if bold else "Head") if _fonts_ready else ("Helvetica-Bold" if bold else "Helvetica")
SEV = {"critical": colors.HexColor("#b42318"), "high": colors.HexColor("#c9541a"),
       "medium": colors.HexColor("#a87d00"), "low": colors.HexColor("#3b78b0"), "info": colors.HexColor("#6b7785")}
LV = [colors.HexColor("#2e7d5b"), colors.HexColor("#6f8f2a"), colors.HexColor("#c9541a"), colors.HexColor("#b42318")]
TICK_OFF = colors.HexColor("#d3d9e0")

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


def X(s) -> str:
    return escape("" if s is None else str(s))


def lv_color(score: int | None):
    return LV[level_key(score or 0)]


# ---------------------------------------------------------------------------
# Zeichenhilfen
# ---------------------------------------------------------------------------

def draw_seal(c, cx, cy, radius, score, lang, fonts, dark_bg=False):
    body, bold, _it, _mono = fonts
    s = max(0, min(100, int(score or 0)))
    n, filled = 50, round(s / 100 * 50)
    r_out, r_in = radius, radius - 12
    c.saveState()
    c.setFillColor(colors.white if not dark_bg else colors.HexColor("#1e2a37"))
    c.setStrokeColor(LINE if not dark_bg else colors.HexColor("#2c3846"))
    c.circle(cx, cy, r_in - 8, stroke=1, fill=1)
    c.setLineCap(1)
    for i in range(n):
        ang = math.pi / 2 - 2 * math.pi * i / n
        long_tick = i % 5 == 0
        r1 = r_in - (3.5 if long_tick else 0)
        c.setLineWidth(2.6)
        c.setStrokeColor(lv_color(s) if i < filled else (TICK_OFF if not dark_bg else colors.HexColor("#2c3846")))
        c.line(cx + r1 * math.cos(ang), cy + r1 * math.sin(ang), cx + r_out * math.cos(ang), cy + r_out * math.sin(ang))
    c.setFillColor(INK if not dark_bg else colors.white)
    c.setFont(bold, radius * 0.62)
    c.drawCentredString(cx, cy - radius * 0.12, str(s))
    c.setFont(body, radius * 0.15)
    c.setFillColor(INK2 if not dark_bg else colors.HexColor("#c7d1dc"))
    c.drawCentredString(cx, cy - radius * 0.42, t(f"level_{level_key(s)}", lang))
    c.restoreState()


def draw_logo(c, x, y, size):
    """Violette Kachel mit weißem Schild (wie in der Weboberfläche)."""
    c.saveState()
    c.setFillColor(colors.HexColor("#6f72ee"))
    c.roundRect(x, y, size, size, size * 0.28, stroke=0, fill=1)
    c.setFillColor(colors.HexColor("#8b8ff8"))
    c.roundRect(x, y + size * 0.5, size, size * 0.5, size * 0.28, stroke=0, fill=1)
    c.setFillColor(colors.HexColor("#7b7ef4"))
    c.rect(x, y + size * 0.45, size, size * 0.12, stroke=0, fill=1)
    s = size / 24.0
    c.translate(x, y + size)
    c.scale(s, -s)
    p = c.beginPath()
    p.moveTo(12, 4.8); p.lineTo(6.6, 6.8); p.lineTo(6.6, 11.1)
    p.curveTo(6.6, 14.7, 8.9, 17.3, 12, 18.6); p.curveTo(15.1, 17.3, 17.4, 14.7, 17.4, 11.1)
    p.lineTo(17.4, 6.8); p.close()
    c.setFillColor(colors.white)
    c.drawPath(p, stroke=0, fill=1)
    c.setStrokeColor(colors.HexColor("#6366e6")); c.setLineWidth(1.6); c.setLineCap(1); c.setLineJoin(1)
    p2 = c.beginPath(); p2.moveTo(9.7, 11.6); p2.lineTo(11.4, 13.3); p2.lineTo(14.5, 10.1)
    c.drawPath(p2, stroke=1, fill=0)
    c.restoreState()


class Bars(Flowable):
    """Horizontale Balken (eine Farbe) mit direkter Beschriftung."""

    def __init__(self, rows, width, fonts, label_w=70 * mm):
        super().__init__()
        self.rows, self.width, self.fonts, self.label_w = rows, width, fonts, label_w
        self.bar_h, self.gap = 9, 7
        self.height = len(rows) * (self.bar_h + self.gap)

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        body, bold, *_ = self.fonts
        vmax = max([v for _, v in self.rows] or [1]) or 1
        for i, (lab, v) in enumerate(self.rows):
            y = self.height - (i + 1) * (self.bar_h + self.gap) + self.gap / 2
            c.setFont(body, 9)
            c.setFillColor(INK2)
            c.drawString(0, y + 1.5, str(lab)[:46])
            bw = max(2, (self.width - self.label_w - 30) * v / vmax)
            c.setFillColor(ACCENT)
            c.roundRect(self.label_w, y, bw, self.bar_h, 2, stroke=0, fill=1)
            c.setFillColor(INK)
            c.setFont(bold, 9)
            c.drawString(self.label_w + bw + 5, y + 1.5, str(v))


class ScoreMeter(Flowable):
    def __init__(self, score, width, height=6):
        super().__init__()
        self.score, self.width, self.height = score or 0, width, height

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(LINE2)
        c.roundRect(0, 0, self.width, self.height, 3, stroke=0, fill=1)
        c.setFillColor(lv_color(self.score))
        c.roundRect(0, 0, max(3, self.width * self.score / 100), self.height, 3, stroke=0, fill=1)


# ---------------------------------------------------------------------------
# Dokument
# ---------------------------------------------------------------------------

def build_pdf(data: dict, lang: str = "de") -> bytes:
    fonts = _fonts()
    body, bold, italic, mono = fonts
    scan, ov = data["scan"], data["ov"]
    domain = ov.get("fqdn") or "–"
    started = scan.get("started_at") or ""
    try:
        started_dt = datetime.fromisoformat(started).astimezone(LOCAL_TZ)
        date_str = started_dt.strftime("%d.%m.%Y %H:%M") if lang == "de" else started_dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        date_str = started

    st = {
        "body": ParagraphStyle("body", fontName=body, fontSize=10, leading=14, textColor=INK),
        "muted": ParagraphStyle("muted", fontName=body, fontSize=9, leading=12.5, textColor=INK3),
        "small": ParagraphStyle("small", fontName=body, fontSize=8.5, leading=11, textColor=INK),
        "cell": ParagraphStyle("cell", fontName=body, fontSize=8.5, leading=10.5, textColor=INK),
        "cellmono": ParagraphStyle("cellmono", fontName=mono, fontSize=7.2, leading=9, textColor=INK),
        "th": ParagraphStyle("th", fontName=bold, fontSize=8.5, leading=10.5, textColor=INK2),
        "h1": ParagraphStyle("h1", fontName=head_font(), fontSize=19, leading=24, textColor=INK, spaceAfter=4),
        "h2": ParagraphStyle("h2", fontName=head_font(), fontSize=13.5, leading=18, textColor=INK, spaceBefore=6, spaceAfter=6),
        "h3": ParagraphStyle("h3", fontName=bold, fontSize=11.5, leading=14.5, textColor=INK),
        "label": ParagraphStyle("label", fontName=bold, fontSize=8.5, leading=11, textColor=INK3, spaceBefore=6, spaceAfter=2),
        "code": ParagraphStyle("code", fontName=mono, fontSize=7.6, leading=10, textColor=INK),
        "right": ParagraphStyle("right", fontName=bold, fontSize=10, leading=12, textColor=INK2, alignment=TA_RIGHT),
    }
    content_w = PAGE_W - 2 * MARGIN

    # --- Seitenvorlagen ---------------------------------------------------
    def on_cover(c, doc):
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(0, PAGE_H - 118 * mm, PAGE_W, 118 * mm, stroke=0, fill=1)
        for i, a in enumerate((0.10, 0.07, 0.05, 0.03)):  # weicher Lichtschein oben links
            c.setFillColor(colors.Color(0.35, 0.38, 0.75, alpha=a))
            c.circle(0, PAGE_H, (90 - i * 18) * mm, stroke=0, fill=1)
        draw_logo(c, MARGIN, PAGE_H - MARGIN - 11 * mm, 11 * mm)
        c.setFillColor(colors.white)
        c.setFont(head_font(False), 11.5)
        c.drawString(MARGIN + 14.5 * mm, PAGE_H - MARGIN - 6.9 * mm, " ".join(APP_NAME.upper()))
        wm = c.stringWidth(" ".join(APP_NAME.upper()), head_font(False), 11.5)
        badge = f"v{VERSION}"
        c.setFont(mono, 7.5)
        bw = c.stringWidth(badge, mono, 7.5) + 6
        bx = MARGIN + 14.5 * mm + wm + 3 * mm
        c.setFillColor(colors.HexColor("#2a2f5c"))
        c.roundRect(bx, PAGE_H - MARGIN - 7.9 * mm, bw, 4.4 * mm, 1.2 * mm, stroke=0, fill=1)
        c.setFillColor(colors.HexColor("#c9cbff"))
        c.drawString(bx + 3, PAGE_H - MARGIN - 6.8 * mm, badge)
        c.setFillColor(colors.HexColor("#aab1c8"))
        c.setFont(body, 10)
        c.drawString(MARGIN, PAGE_H - 58 * mm, t("report", lang))
        c.setFillColor(colors.white)
        c.setFont(head_font(), 34)
        c.drawString(MARGIN, PAGE_H - 74 * mm, domain)
        c.setFont(body, 12)
        c.setFillColor(colors.HexColor("#aab1c8"))
        c.drawString(MARGIN, PAGE_H - 83 * mm, t("tagline", lang))
        c.setFont(body, 10.5)
        c.drawString(MARGIN, PAGE_H - 97 * mm, f"{t('generated', lang)} {date_str}   {t('started_by', lang)}: {scan.get('started_by') or '–'}")
        c.drawString(MARGIN, PAGE_H - 103 * mm,
                     f"{ov.get('netbios') or ''}  {'Samba AD' if ov.get('domain_type') == 'samba' else 'Windows AD'}  "
                     f"{t('func_level', lang)} {ov.get('domain_level') or '–'}  {t('dc', lang)} {ov.get('dc_host') or '–'}")
        # Siegel
        draw_seal(c, PAGE_W - MARGIN - 34 * mm, PAGE_H - 70 * mm, 30 * mm, scan.get("score_global"), lang, fonts,
                  dark_bg=True)
        c.setFont(body, 9)
        c.setFillColor(colors.HexColor("#c7d1dc"))
        c.drawCentredString(PAGE_W - MARGIN - 34 * mm, PAGE_H - 108 * mm, t("risk_score", lang))
        # Bereiche
        y = PAGE_H - 140 * mm
        c.setFillColor(INK)
        c.setFont(head_font(), 13)
        c.drawString(MARGIN, y, t("summary", lang))
        y -= 12 * mm
        for cat in CATEGORIES:
            v = scan.get(f"score_{cat}") or 0
            c.setFillColor(CAT[cat])
            c.circle(MARGIN + 1.4 * mm, y + 1.2 * mm, 1.4 * mm, stroke=0, fill=1)
            c.setFillColor(INK)
            c.setFont(bold, 11)
            c.drawString(MARGIN + 5 * mm, y, t(f"cat_{cat}", lang))
            c.setFont(body, 9)
            c.setFillColor(INK3)
            c.drawString(MARGIN + 5 * mm, y - 4.6 * mm, t(f"catd_{cat}", lang))
            c.setFillColor(lv_color(v))
            c.setFont(head_font(), 17)
            c.drawRightString(PAGE_W - MARGIN, y - 2 * mm, str(v))
            bx, bw = MARGIN + 115 * mm, content_w - 115 * mm - 16 * mm
            c.setFillColor(LINE2)
            c.roundRect(bx, y - 2.2 * mm, bw, 2.4 * mm, 1.2 * mm, stroke=0, fill=1)
            c.setFillColor(lv_color(v))
            c.roundRect(bx, y - 2.2 * mm, max(1.5 * mm, bw * v / 100), 2.4 * mm, 1.2 * mm, stroke=0, fill=1)
            y -= 17 * mm
        # Schweregrade
        y -= 2 * mm
        x = MARGIN
        for sv in SEVERITIES[:4]:
            n = data["sev_counts"].get(sv, 0)
            c.setStrokeColor(LINE)
            c.setFillColor(colors.white)
            c.roundRect(x, y - 13 * mm, 40 * mm, 15 * mm, 2 * mm, stroke=1, fill=1)
            c.setFillColor(SEV[sv])
            c.rect(x + 4 * mm, y - 9.5 * mm, 2.4 * mm, 2.4 * mm, stroke=0, fill=1)
            c.setFillColor(INK)
            c.setFont(bold, 18)
            c.drawString(x + 9 * mm, y - 10 * mm, str(n))
            c.setFont(body, 9.5)
            c.setFillColor(INK2)
            c.drawString(x + 19 * mm, y - 9.4 * mm, t(f"sev_{sv}", lang))
            x += 43.5 * mm
        c.setFont(body, 8.5)
        c.setFillColor(INK3)
        c.drawString(MARGIN, MARGIN - 4 * mm, f"{t('confidential', lang)}  –  {APP_NAME} v{VERSION}  –  {t('tz', lang)} {LOCAL_TZ}")
        c.restoreState()

    def on_page(c, doc):
        c.saveState()
        c.setFont(body, 8.5)
        c.setFillColor(INK3)
        c.drawString(MARGIN, PAGE_H - 11 * mm, f"{APP_NAME} v{VERSION}  –  {t('report', lang)} {domain}")
        c.drawRightString(PAGE_W - MARGIN, PAGE_H - 11 * mm, date_str)
        c.setStrokeColor(LINE)
        c.setLineWidth(0.5)
        c.line(MARGIN, PAGE_H - 13 * mm, PAGE_W - MARGIN, PAGE_H - 13 * mm)
        c.drawString(MARGIN, 10 * mm, t("confidential", lang))
        c.restoreState()

    buf = io.BytesIO()
    doc = NumberedDoc(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN + 2 * mm,
                      bottomMargin=MARGIN, title=f"{t('report', lang)} {domain}", author=f"{APP_NAME} v{VERSION}",
                      subject=t("tagline", lang), lang=lang, body_font=body)
    frame = Frame(MARGIN, MARGIN, content_w, PAGE_H - 2 * MARGIN - 2 * mm, id="f", leftPadding=0, rightPadding=0,
                  topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate("cover", [frame], onPage=on_cover),
                          PageTemplate("body", [frame], onPage=on_page)])

    S: list = [NextPageTemplate("body"), PageBreak()]

    def tbl(rows, widths, header=True, zebra=False, mono_cols=()):
        out = []
        for ri, row in enumerate(rows):
            cells = []
            for ci, v in enumerate(row):
                if isinstance(v, Flowable):
                    cells.append(v)
                    continue
                style = st["th"] if header and ri == 0 else (st["cellmono"] if ci in mono_cols else st["cell"])
                cells.append(Paragraph(X(v), style))
            out.append(cells)
        tb = Table(out, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        ts = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5),
              ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 3.5),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE2)]
        if header:
            ts += [("LINEBELOW", (0, 0), (-1, 0), 0.8, LINE), ("BACKGROUND", (0, 0), (-1, 0), SURF2)]
        tb.setStyle(TableStyle(ts))
        return tb

    # --- 1. Zusammenfassung ----------------------------------------------
    fails = data["fails"]
    S.append(Paragraph(X(t("summary", lang)), st["h1"]))
    n_cat = sum(1 for c in CATEGORIES if data["by_cat"][c])
    S.append(Paragraph(X(t("summary_text", lang, n=len(fails), c=n_cat, crit=data["sev_counts"]["critical"],
                           high=data["sev_counts"]["high"])), st["body"]))
    S.append(Spacer(1, 4 * mm))
    S.append(Paragraph(X(t("top_findings", lang)), st["h2"]))
    rows = [["#", t("findings", lang), t("category", lang), t("severity", lang), t("points", lang)]]
    for i, f in enumerate(data["top"], 1):
        rows.append([str(i), f["rule"].title[lang], t(f"cat_{f['category']}", lang),
                     Paragraph(f'<font color="{SEV[f["severity"]].hexval()}"><b>{X(t("sev_" + f["severity"], lang))}</b></font>', st["cell"]),
                     f"+{f['points']}"])
    S.append(tbl(rows, [8 * mm, 86 * mm, 36 * mm, 26 * mm, 18 * mm]))
    S.append(Spacer(1, 6 * mm))

    S.append(Paragraph(X(t("findings", lang)) + f" ({len(fails)})", st["h2"]))
    rows = [[t("rule_id", lang), t("findings", lang), t("severity", lang), t("points", lang), "#"]]
    for f in fails:
        rows.append([f["rule_id"], f["rule"].title[lang],
                     Paragraph(f'<font color="{SEV[f["severity"]].hexval()}"><b>{X(t("sev_" + f["severity"], lang))}</b></font>', st["cell"]),
                     f"+{f['points']}", str(f["count"])])
    S.append(tbl(rows, [46 * mm, 80 * mm, 22 * mm, 14 * mm, 12 * mm], mono_cols=(0,)))

    # --- 2. Domänenüberblick -------------------------------------------
    S.append(PageBreak())
    S.append(Paragraph(X(t("overview", lang)), st["h1"]))
    u, cpt, pol = ov.get("users", {}), ov.get("computers", {}), ov.get("policy", {})
    laps = ov.get("laps", {})
    facts = [
        [t("domain", lang), domain, "NetBIOS", ov.get("netbios") or "–"],
        ["SID", ov.get("sid") or "–", t("func_level", lang), f"{ov.get('domain_level')} / {ov.get('forest_level')}"],
        [t("users", lang), f"{u.get('enabled', 0)} {t('enabled', lang)} / {u.get('total', 0)}", t("computers", lang),
         f"{cpt.get('enabled', 0)} {t('enabled', lang)} / {cpt.get('total', 0)}"],
        [t("admins", lang), str(ov.get("admins", 0)), "LAPS",
         f"{laps.get('covered', 0)} / {laps.get('total', 0)}" if laps.get("total") else "–"],
        [t("groups", lang), str(ov.get("groups", 0)), t("sysvol_status", lang),
         f"{ov.get('sysvol', {}).get('status')} ({ov.get('sysvol', {}).get('files', 0)})"],
    ]
    S.append(tbl(facts, [30 * mm, 57 * mm, 30 * mm, 57 * mm], header=False))
    S.append(Spacer(1, 5 * mm))

    S.append(Paragraph(X(t("dcs", lang)), st["h2"]))
    rows = [["Name", t("col_os", lang), t("col_last_logon", lang)]]
    rows += [[d["name"] + (" (RODC)" if d.get("rodc") else ""), d.get("os") or "–", d.get("last_logon")] for d in ov.get("dcs", [])]
    S.append(tbl(rows, [70 * mm, 74 * mm, 30 * mm]))
    S.append(Spacer(1, 4 * mm))

    S.append(KeepTogether([Paragraph(X(t("pwd_policy", lang)), st["h2"]), tbl([
        [t("min_length", lang), str(pol.get("min_length")), t("complexity", lang), t("yes" if pol.get("complexity") else "no", lang)],
        [t("history", lang), str(pol.get("history")), t("max_age", lang), str(round(pol.get("max_age_days") or 0))],
        [t("lockout", lang), str(pol.get("lockout_threshold")), t("maq", lang), "–" if ov.get("maq") is None else str(ov.get("maq"))],
    ], [42 * mm, 45 * mm, 42 * mm, 45 * mm], header=False)]))
    S.append(Spacer(1, 4 * mm))

    rows = [[t("col_group", lang), t("members", lang), ""]]
    for g in ov.get("priv_groups", []):
        mem = ", ".join(g.get("members", [])[:12]) + (", …" if len(g.get("members", [])) > 12 else "")
        rows.append([g["name"], str(g["count"]), mem])
    S.append(KeepTogether([Paragraph(X(t("priv_groups", lang)), st["h2"]), tbl(rows, [52 * mm, 18 * mm, 104 * mm])]))
    S.append(Spacer(1, 4 * mm))

    os_rows = [(("Andere" if lang == "de" else "Other") if n == "@other" else n, v) for n, v in ov.get("os_dist", [])]
    if os_rows:
        S.append(KeepTogether([Paragraph(X(t("os_dist", lang)), st["h2"]), Bars(os_rows, content_w, fonts)]))
        S.append(Spacer(1, 4 * mm))
    if ov.get("trusts"):
        rows = [[t("col_trust", lang), t("col_direction", lang), t("col_changed", lang)]]
        rows += [[tr["name"], t(f"dir_{tr['direction']}", lang), tr.get("changed")] for tr in ov["trusts"]]
        S.append(KeepTogether([Paragraph(X(t("trusts", lang)), st["h2"]), tbl(rows, [80 * mm, 50 * mm, 44 * mm])]))

    # --- 3. Befunde im Detail -----------------------------------------
    for cat in CATEGORIES:
        S.append(PageBreak())
        score = data["scores"][cat]
        head = Table([[Paragraph(f'<font name="Mono" color="{CAT[cat].hexval()}">●</font> ' + X(t(f"cat_{cat}", lang)), st["h1"]),
                       Paragraph(f'<font color="{lv_color(score).hexval()}" size="20">{score}</font>', st["right"])]],
                     colWidths=[content_w - 30 * mm, 30 * mm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                  ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        S.append(head)
        S.append(Paragraph(X(t(f"catd_{cat}", lang)), st["muted"]))
        S.append(Spacer(1, 2 * mm))
        S.append(ScoreMeter(score, content_w))
        S.append(Spacer(1, 6 * mm))
        if not data["by_cat"][cat]:
            S.append(Paragraph(X(t("no_findings", lang)), st["body"]))
        for f in data["by_cat"][cat]:
            S += finding_block(f, lang, st, content_w, tbl)

    # --- 4. Anhang ------------------------------------------------------
    S.append(PageBreak())
    S.append(Paragraph(X(t("passed", lang)) + f" ({len(data['passed'])})", st["h1"]))
    rows = [[t("rule_id", lang), t("findings", lang)]] + [[f["rule_id"], f["rule"].title[lang]] for f in data["passed"]]
    S.append(tbl(rows, [45 * mm, 129 * mm], mono_cols=(0,)))
    if data["resolved"]:
        S.append(Spacer(1, 5 * mm))
        S.append(Paragraph(X(t("resolved_since", lang)), st["h2"]))
        S.append(tbl([[t("rule_id", lang), t("findings", lang)]] + [[r.id, r.title[lang]] for r in data["resolved"]],
                     [45 * mm, 129 * mm], mono_cols=(0,)))
    if data["na"]:
        S.append(Spacer(1, 5 * mm))
        S.append(Paragraph(X(t("not_checked", lang)), st["h2"]))
        S.append(tbl([[t("rule_id", lang), t("findings", lang), t("col_detail", lang)]] +
                     [[f["rule_id"], f["rule"].title[lang], t(f["note"], lang) if f.get("note") else ""] for f in data["na"]],
                     [45 * mm, 79 * mm, 50 * mm], mono_cols=(0,)))
    S.append(Spacer(1, 6 * mm))
    S.append(Paragraph(X(t("scope_note", lang)), st["muted"]))

    doc.build(S)
    return buf.getvalue()


MAX_PDF_ROWS = 40


def finding_block(f: dict, lang: str, st: dict, content_w: float, tbl) -> list:
    r = f["rule"]
    color = SEV[f["severity"]]
    meta = (f'<font color="{color.hexval()}"><b>{X(t("sev_" + f["severity"], lang))}</b></font>'
            f'   {X(f["rule_id"])}   +{f["points"]} {X(t("points", lang))}   {f["count"]} '
            f'{"Objekt(e)" if lang == "de" else "object(s)"}')
    if f.get("note"):
        meta += f"   {X(tv(f['note'], lang))}"
    header = Table([["", [Paragraph(X(r.title[lang]), st["h3"]), Spacer(1, 1.5), Paragraph(meta, st["small"])]]],
                   colWidths=[2.2 * mm, content_w - 2.2 * mm])
    header.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), color), ("LEFTPADDING", (1, 0), (1, 0), 8),
                                ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    block = [header,
             Paragraph(X(t("what", lang)), st["label"]), Paragraph(X(r.desc[lang]), st["body"]),
             Paragraph(X(t("how_fix", lang)), st["label"]), Paragraph(X(r.fix[lang]), st["body"])]
    out: list = [CondPageBreak(60 * mm), KeepTogether(block)]
    if r.code:
        code_tbl = Table([[Preformatted(r.code, st["code"])]], colWidths=[content_w])
        code_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SURF2), ("BOX", (0, 0), (-1, -1), 0.5, LINE2),
                                      ("LEFTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 5),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        out += [Spacer(1, 2.5 * mm), code_tbl]
    cols = f.get("columns") or []
    items = f.get("items") or []
    if items and cols:
        mono_cols = tuple(i for i, c in enumerate(cols) if c in ("dn", "sid_history", "file", "spn"))
        weights = {"dn": 3, "sid_history": 2.4, "file": 3, "spn": 2.2, "account": 1.4, "group": 1.8, "os": 1.6,
                   "principal": 1.8, "template": 1.6, "value": 1.6, "detail": 1.6, "rights": 1.4}
        tw = sum(weights.get(c, 1) for c in cols)
        widths = [content_w * weights.get(c, 1) / tw for c in cols]
        rows = [[t(f"col_{c}", lang) for c in cols]]
        rows += [[tv(it.get(c, ""), lang) for c in cols] for it in items[:MAX_PDF_ROWS]]
        out += [Paragraph(X(t("affected", lang)) + f" ({f['count']})", st["label"]), tbl(rows, widths, mono_cols=mono_cols)]
        if f["count"] > MAX_PDF_ROWS:
            out.append(Paragraph(X(t("more_items", lang, n=f["count"] - MAX_PDF_ROWS)), st["muted"]))
    if r.refs:
        links = "   ".join(f'<link href="{X(u)}" color="{ACCENT.hexval()}">{X(lbl)}</link>' for lbl, u in r.refs)
        out += [Paragraph(X(t("references", lang)), st["label"]), Paragraph(links, st["small"])]
    out.append(Spacer(1, 8 * mm))
    return out


class NumberedDoc(BaseDocTemplate):
    """Zweiter Durchlauf für „Seite X von Y“."""

    def __init__(self, *a, lang="de", body_font="Helvetica", **kw):
        self._lang, self._font = lang, body_font
        super().__init__(*a, **kw)

    def build(self, flowables, **kw):
        from reportlab.pdfgen.canvas import Canvas
        lang, font = self._lang, self._font

        class _Canvas(Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved = []

            def showPage(self):
                self._saved.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                total = len(self._saved)
                for state in self._saved:
                    self.__dict__.update(state)
                    if self._pageNumber > 1:
                        self.setFont(font, 8.5)
                        self.setFillColor(INK3)
                        self.drawRightString(PAGE_W - MARGIN, 10 * mm,
                                             f"{t('page', lang)} {self._pageNumber} {t('of', lang)} {total}")
                    super().showPage()
                super().save()

        super().build(flowables, canvasmaker=_Canvas, **kw)
