# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Consolidated PDF report generator.

Single source of truth. Produces a multi-page branded PDF that matches the
Streamlit UI section-for-section. Replaces the older `generate_report_pdf`
in both `ai_access_checker.py` and `pages/7_🔒_LLM_Access_Checker.py`.

The PDF embeds the Pattern logo (PATTERN_LOGO_SVG, the same SVG the Streamlit
UI renders) via svglib, so the brand is rendered identically across surfaces.

Function signature accepts the audit dict (the value stored in
`st.session_state["_audit"]`), the domain, and the recommendations list.
Everything else — Bifrost AI analyses, Pattern Brain output, security
findings, semantic results — is read from the audit dict.

    pdf_bytes = generate_report_pdf(
        audit=st.session_state["_audit"],
        domain=parsed.netloc,
        recs=recs,
    )

Requirements:
    reportlab>=4.0.0
    svglib>=1.6.0
"""

from __future__ import annotations

import io
import time
from typing import Optional

from reportlab.lib.colors import HexColor, white, Color
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect, Circle, String
from reportlab.platypus.flowables import Flowable
from svglib.svglib import svg2rlg


# ─── PATTERN LOGO ─────────────────────────────────────────────────────────────
# Identical to PATTERN_LOGO_SVG used by the Streamlit UI. Kept inline so the
# generator has no on-disk asset dependencies.
PATTERN_LOGO_SVG = '''<svg width="180" height="36" viewBox="0 0 675 135.7" fill="none" xmlns="http://www.w3.org/2000/svg">
<path fill="#009BFF" d="M81.55,0.99L0.99,81.55c-1.32,1.32-1.32,3.47,0,4.8l19.84,19.84c1.32,1.32,3.47,1.32,4.8,0l80.56-80.56c1.32-1.32,1.32-3.47,0-4.8L86.35,0.99C85.02-0.33,82.88-0.33,81.55,0.99z"/>
<path fill="#009BFF" d="M114.73,34.17L67.37,81.54c-1.32,1.32-1.32,3.47,0,4.8l19.84,19.84c1.32,1.32,3.47,1.32,4.8,0l47.36-47.36c1.32-1.32,1.32-3.47,0-4.8l-19.84-19.84C118.2,32.85,116.05,32.85,114.73,34.17z"/>
<path fill="#F2F2F2" d="M254.36,64.21c0,24.35-18.47,42.98-40.69,42.98c-12.74,0-22.39-5.23-28.6-13.73v40.25c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2V25.35c0-1.1,0.89-2,2-2h13.65c1.1,0,2,0.89,2,2v9.77c6.21-8.66,15.85-13.89,28.6-13.89C235.9,21.23,254.36,40.02,254.36,64.21z M236.71,64.21c0-15.2-11.11-26.15-25.82-26.15c-14.71,0-25.82,10.95-25.82,26.15c0,15.2,11.11,26.15,25.82,26.15C225.6,90.35,236.71,79.4,236.71,64.21z"/>
<path fill="#F2F2F2" d="M347.84,25.35v77.71c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2v-9.77c-6.21,8.66-15.85,13.89-28.6,13.89c-22.22,0-40.69-18.79-40.69-42.98c0-24.35,18.46-42.98,40.69-42.98c12.74,0,22.39,5.23,28.6,13.73v-9.6c0-1.1,0.89-2,2-2h13.65C346.95,23.35,347.84,24.25,347.84,25.35z M330.19,64.21c0-15.2-11.11-26.15-25.82-26.15s-25.82,10.95-25.82,26.15c0,15.2,11.11,26.15,25.82,26.15S330.19,79.4,330.19,64.21z"/>
<path fill="#F2F2F2" d="M397.4,40.35c1.1,0,2-0.89,2-2v-13c0-1.1-0.89-2-2-2h-21V2c0-1.1-0.89-2-2-2h-13.65c-1.1,0-2,0.89-2,2v78.96c0,16.77,8.09,24.83,24.97,24.83l13.68-0.01c1.1,0,2-0.9,2-2V91.42c0-1.1-0.9-2-2-2c-2.84,0-8.3-0.01-10.5-0.01c-8.05,0-10.5-2.09-10.5-9.85V40.35H397.4z"/>
<path fill="#F2F2F2" d="M445.33,40.35c1.1,0,2-0.89,2-2v-13c0-1.1-0.89-2-2-2h-21V2c0-1.1-0.89-2-2-2h-13.65c-1.1,0-2,0.89-2,2v78.96c0,16.77,8.09,24.83,24.97,24.83l13.68-0.01c1.1,0,1.99-0.9,1.99-2V91.42c0-1.1-0.9-2-2-2c-2.84,0-8.3-0.01-10.5-0.01c-8.05,0-10.5-2.09-10.5-9.85V40.35H445.33z"/>
<path fill="#F2F2F2" d="M493.81,91.01c9.04,0,15.99-3.75,20.09-8.81c0.61-0.75,1.69-0.91,2.52-0.42l11.12,6.5c1.02,0.59,1.33,1.95,0.62,2.89c-7.59,10.04-19.37,16.03-34.51,16.03c-26.96,0-44.45-18.46-44.45-42.98c0-24.18,17.48-42.98,43.14-42.98c24.35,0,41.02,19.61,41.02,43.14c0,2.45-0.33,5.07-0.65,7.35h-65.04C470.44,84.47,480.74,91.01,493.81,91.01z M515.54,57.34c-2.45-14.05-12.75-20.1-23.37-20.1c-13.24,0-22.22,7.84-24.67,20.1H515.54z"/>
<path fill="#F2F2F2" d="M583.58,21.88c-10.29,0-20.26,4.09-25.16,15.2V25.35c0-1.1-0.89-2-2-2h-13.65c-1.1,0-2,0.89-2,2v77.71c0,1.1,0.89,2,2,2h13.65c1.1,0,2-0.89,2-2V63.88c0-18.3,13.28-22.88,25.16-22.88h6.15c1.1,0,2-0.89,2-2V23.88c0-1.1-0.89-2-2-2H583.58z"/>
<path fill="#F2F2F2" d="M675,54.89v48.17c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2V56.69c0-12.42-7.19-18.96-18.3-18.96c-11.6,0-20.75,6.86-20.75,23.53v41.8c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2V25.35c0-1.1,0.89-2,2-2h13.65c1.1,0,2,0.89,2,2v8.46c5.39-8.5,14.22-12.58,25.33-12.58C661.93,21.23,675,33.65,675,54.89z"/>
</svg>'''

PATTERN_WEBSITE = "https://au.pattern.com/"

# ─── BRAND ────────────────────────────────────────────────────────────────────
# Single source of truth — must match BRAND dict in ai_access_checker.py
BRAND = {
    "bg_dark":        "#090a0f",
    "bg_card":        "#12131a",
    "bg_surface":     "#1e1f2a",
    "primary":        "#009bff",
    "primary_light":  "#73cdff",
    "purple":         "#770bff",
    "teal":           "#4cc3ae",
    "warning":        "#ffb548",
    "danger":         "#e53e51",
    "white":          "#fcfcfc",
    "text_secondary": "#b3b3b3",
    "border":         "#2a2b36",
}

C_BG       = HexColor(BRAND["bg_dark"])
C_CARD     = HexColor(BRAND["bg_card"])
C_SURFACE  = HexColor(BRAND["bg_surface"])
C_BORDER   = HexColor(BRAND["border"])
C_WHITE    = HexColor(BRAND["white"])
C_MUTED    = HexColor(BRAND["text_secondary"])
C_PRIMARY  = HexColor(BRAND["primary"])
C_PURPLE   = HexColor(BRAND["purple"])
C_TEAL     = HexColor(BRAND["teal"])
C_WARN     = HexColor(BRAND["warning"])
C_DANGER   = HexColor(BRAND["danger"])

GRADE_THRESHOLDS = [(85, "A", "Excellent"), (70, "B", "Good"),
                    (50, "C", "Needs Work"), (35, "D", "Poor"), (0, "F", "Critical")]


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _score_color(score) -> HexColor:
    """Match the UI's colour bands."""
    try:
        s = int(score)
    except (TypeError, ValueError):
        return C_MUTED
    if s >= 75: return C_TEAL
    if s >= 50: return C_PRIMARY
    if s >= 35: return C_WARN
    return C_DANGER


def _grade(score: int) -> tuple[str, str]:
    """Return (letter, label)."""
    for threshold, letter, label in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter, label
    return "F", "Critical"


# ─── STYLES ───────────────────────────────────────────────────────────────────
_styles_base = getSampleStyleSheet()
_style_cache: dict[tuple, ParagraphStyle] = {}

def _style(name: str, **kw) -> ParagraphStyle:
    key = (name, tuple(sorted(kw.items())))
    if key not in _style_cache:
        _style_cache[key] = ParagraphStyle(
            f"{name}_{len(_style_cache)}", parent=_styles_base["Normal"], **kw
        )
    return _style_cache[key]


def _S_H1():    return _style("H1",    fontSize=22, textColor=C_WHITE,   fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=6)
def _S_H2():    return _style("H2",    fontSize=15, textColor=C_WHITE,   fontName="Helvetica-Bold", spaceAfter=6)
def _S_H3():    return _style("H3",    fontSize=11, textColor=C_WHITE,   fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=6)
def _S_BODY():  return _style("BODY",  fontSize=9,  textColor=C_WHITE,   fontName="Helvetica",      leading=14, spaceAfter=2)
def _S_MUTED(): return _style("MUTED", fontSize=8,  textColor=C_MUTED,   fontName="Helvetica",      leading=12, spaceAfter=2)
def _S_LABEL(): return _style("LABEL", fontSize=8,  textColor=C_MUTED,   fontName="Helvetica-Bold", spaceAfter=2)
def _S_AI():    return _style("AI",    fontSize=9,  textColor=C_WHITE,   fontName="Helvetica",      leading=14, spaceAfter=3)
def _S_KICKER():return _style("KICK",  fontSize=8,  textColor=C_MUTED,   fontName="Helvetica-Bold", spaceAfter=1)


# ─── REUSABLE FLOWABLES ───────────────────────────────────────────────────────

class ScoreBar(Flowable):
    """Horizontal score bar — track + filled portion in the score colour."""
    def __init__(self, score: int, width: float = 460, height: float = 6):
        super().__init__()
        self.score = max(0, min(100, int(score or 0)))
        self.width = width
        self.height = height

    def wrap(self, *_):
        return self.width, self.height + 2

    def draw(self):
        c = self.canv
        c.setFillColor(C_BORDER)
        c.roundRect(0, 0, self.width, self.height, self.height/2, fill=1, stroke=0)
        filled = self.width * (self.score / 100)
        if filled > 0:
            c.setFillColor(_score_color(self.score))
            c.roundRect(0, 0, filled, self.height, self.height/2, fill=1, stroke=0)


class NumberedCircle(Flowable):
    """Small filled blue circle with white bold number — for Executive Summary numbered items."""
    def __init__(self, number: int, diameter: float = 14):
        super().__init__()
        self.number = number
        self.diameter = diameter
        self.width = diameter
        self.height = diameter

    def wrap(self, *_):
        return self.width, self.height

    def draw(self):
        c = self.canv
        r = self.diameter / 2
        c.setFillColor(C_PRIMARY)
        c.circle(r, r, r, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 8)
        text = str(self.number)
        tw = c.stringWidth(text, "Helvetica-Bold", 8)
        c.drawString(r - tw / 2, r - 3, text)


class ScoreLegend(Flowable):
    """Horizontal row of grade-band pills for the cover page."""
    BANDS = [
        ("A", "85+", C_TEAL),
        ("B", "70+", C_PRIMARY),
        ("C", "50+", C_WARN),
        ("D", "35+", HexColor("#ff8c00")),
        ("F", "<35",  C_DANGER),
    ]

    def __init__(self, width: float = 460):
        super().__init__()
        self.width = width
        self.height = 24

    def wrap(self, *_):
        return self.width, self.height

    def draw(self):
        c = self.canv
        pill_w = 72
        pill_h = 18
        gap = 8
        total = len(self.BANDS) * pill_w + (len(self.BANDS) - 1) * gap
        x_start = (self.width - total) / 2
        for i, (letter, threshold, color) in enumerate(self.BANDS):
            x = x_start + i * (pill_w + gap)
            y = (self.height - pill_h) / 2
            bg = Color(color.red, color.green, color.blue, alpha=0.2)
            c.setFillColor(bg)
            c.roundRect(x, y, pill_w, pill_h, pill_h / 2, fill=1, stroke=0)
            c.setStrokeColor(color)
            c.setLineWidth(0.5)
            c.roundRect(x, y, pill_w, pill_h, pill_h / 2, fill=0, stroke=1)
            c.setFillColor(color)
            c.setFont("Helvetica-Bold", 9)
            label = f"{letter}  {threshold}"
            tw = c.stringWidth(label, "Helvetica-Bold", 9)
            c.drawString(x + (pill_w - tw) / 2, y + 5, label)


def _pill(text: str, color: HexColor, font_size: int = 7) -> Paragraph:
    """Inline rounded pill."""
    hex_color = color.hexval()[2:] if hasattr(color, "hexval") else str(color)
    return Paragraph(
        f'<font color="#{hex_color}" size="{font_size}"><b>{text}</b></font>',
        _style(f"pill_{text}", fontSize=font_size, fontName="Helvetica-Bold",
               textColor=color,
               borderPadding=(2, 6, 2, 6), borderRadius=8, leading=font_size + 4)
    )


def _status_dot(text: str, status: str = "info", muted: bool = False) -> Paragraph:
    """Coloured dot + text — analogue of the UI's brand_status helper."""
    color_map = {"success": C_TEAL, "warning": C_WARN, "danger": C_DANGER, "info": C_PRIMARY}
    c = color_map.get(status, C_PRIMARY)
    text_color = "#b3b3b3" if muted else "#fcfcfc"
    return Paragraph(
        f'<font color="#{c.hexval()[2:]}" size="11">●</font> '
        f'<font color="{text_color}" size="9">{text}</font>',
        _style("dot", fontSize=9, leading=13, fontName="Helvetica", spaceAfter=1)
    )


def _section_divider() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.6, color=C_PRIMARY,
                      spaceBefore=8, spaceAfter=8)


def _thin_divider() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.4, color=C_BORDER,
                      spaceBefore=4, spaceAfter=4)


def _sp(h: float = 4) -> Spacer:
    return Spacer(1, h)


def _table_header_style() -> TableStyle:
    """Canonical table style — tight header row, generous body rows."""
    return TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  C_PURPLE),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  white),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, 0),  8),
        ("ALIGN",          (0, 0), (-1, 0),  "LEFT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_CARD]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_BORDER),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
        # Header row — slimmer
        ("TOPPADDING",     (0, 0), (-1, 0),  6),
        ("BOTTOMPADDING",  (0, 0), (-1, 0),  6),
        # Body rows — taller
        ("TOPPADDING",     (0, 1), (-1, -1), 8),
        ("BOTTOMPADDING",  (0, 1), (-1, -1), 8),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ])


def _ai_block(text: str | None, label: str = "AI Analysis") -> list:
    """Render a Bifrost AI analysis block — left-bordered card with body text."""
    if not text:
        return []

    body_paragraphs = []
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith(("•", "-", "*")) and len(line) > 1:
            cleaned = line[1:].strip()
            body_paragraphs.append(Paragraph(
                f'<font color="#73cdff"><b>›</b></font>&nbsp;&nbsp;{cleaned}', _S_AI()
            ))
        else:
            body_paragraphs.append(Paragraph(line, _S_AI()))

    inner = [
        Paragraph(f'<b><font color="#009bff">{label.upper()}</font></b>',
                  _style("ai_label", fontSize=8, textColor=C_PRIMARY,
                         fontName="Helvetica-Bold", spaceAfter=8)),
        *body_paragraphs,
    ]

    box = Table([[inner]], colWidths=[460])
    box.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_CARD),
        ("LINEBEFORE",   (0, 0), (0, -1),  3, C_PRIMARY),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING",   (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 12),
    ]))
    return [_sp(6), box, _sp(10)]


def _callout(message: str, kind: str = "warning") -> Table:
    """Coloured callout box — used for Cloudflare warnings, no-blog notices, etc."""
    color_map = {"warning": C_WARN, "danger": C_DANGER, "info": C_PRIMARY, "success": C_TEAL}
    accent = color_map.get(kind, C_WARN)
    para = Paragraph(message, _style(f"call_{kind}", fontSize=9, textColor=C_WHITE,
                                     fontName="Helvetica", leading=14))
    box = Table([[para]], colWidths=[460])
    box.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_CARD),
        ("LINEBEFORE",   (0, 0), (0, -1),  3, accent),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
    ]))
    return box


def _pillar_header(num: int | str, title: str, score: int) -> list:
    """Pillar number kicker + title + score, wrapped in KeepTogether."""
    sc_color = _score_color(score)
    header_table = Table(
        [[
            Paragraph(f'<b>PILLAR {num}</b>', _style("pn", fontSize=8, textColor=C_MUTED,
                                                     fontName="Helvetica-Bold")),
            Paragraph(f'<font color="#{sc_color.hexval()[2:]}"><b>{score}</b></font>'
                      f'<font color="#{C_MUTED.hexval()[2:]}" size="9">/100</font>',
                      _style("ps", fontSize=18, fontName="Helvetica-Bold", alignment=2)),
        ],
        [
            Paragraph(title, _style("pt", fontSize=14, textColor=C_WHITE,
                                    fontName="Helvetica-Bold")),
            "",
        ]],
        colWidths=[380, 80],
    )
    header_table.setStyle(TableStyle([
        ("ALIGN",        (1, 0), (1, 0),  "RIGHT"),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
        ("SPAN",         (1, 0), (1, 1)),
    ]))
    # KeepTogether ensures kicker/title/score/bar never split across pages
    return [KeepTogether([
        _sp(12),
        header_table,
        _sp(2),
        ScoreBar(score, width=460, height=4),
        _thin_divider(),
    ])]


def _page_block_header(label: str, score: int | None = None) -> Paragraph:
    """Per-page sub-section header inside a pillar."""
    score_html = ""
    if score is not None:
        sc = _score_color(score)
        score_html = f' <font color="#{sc.hexval()[2:]}" size="10"><b>{score}/100</b></font>'
    return Paragraph(
        f'<font color="#{C_WHITE.hexval()[2:]}"><b>{label}</b></font>{score_html}',
        _style("pbh", fontSize=11, textColor=C_WHITE, fontName="Helvetica-Bold",
               spaceBefore=12, spaceAfter=6)
    )


def _pattern_logo(width_pt: float = 150.0) -> Drawing:
    """Render the Pattern logo SVG as a centred ReportLab Drawing."""
    drawing = svg2rlg(io.StringIO(PATTERN_LOGO_SVG))
    if drawing is None:
        empty = Drawing(width_pt, 12)
        empty.add(String(width_pt / 2, 0, "pattern",
                         fontName="Helvetica-Bold", fontSize=14,
                         fillColor=C_WHITE, textAnchor="middle"))
        return empty

    scale = width_pt / drawing.width
    drawing.scale(scale, scale)
    drawing.width *= scale
    drawing.height *= scale
    drawing.hAlign = "CENTER"
    return drawing


def _wordmark():
    """Header lockup: Pattern logo."""
    return _pattern_logo(width_pt=150.0)


def _exec_summary_flowables(pattern_brain: str) -> list:
    """Render the Pattern Brain markdown-ish output as ReportLab flowables.

    Handles `## ` and `### ` headings, `- / • / *` bullets, `1. `-style numbered
    items, and falls back to plain paragraphs. `**bold**` markers are stripped
    rather than parsed so we never produce unbalanced inline tags.

    Changes:
    - "Top 3 Quick Wins This Week" → "Top 3 Quick Wins" at render time
    - Numbered items rendered as filled blue circle + 2-column Table
    - ### headings bumped to 13pt with spaceBefore=14
    - Body paragraphs after headings get spaceBefore=4
    """
    out: list = []
    if not pattern_brain:
        return out

    # Strip "This Week" suffix wherever it appears
    pattern_brain = pattern_brain.replace("Top 3 Quick Wins This Week", "Top 3 Quick Wins")

    out.append(_sp(12))
    out.append(Paragraph("Access Checker — Executive Summary", _S_H2()))
    out.append(Paragraph(
        "AI-generated analysis powered by Pattern's Bifrost gateway",
        _S_MUTED()))
    out.append(_section_divider())
    out.append(_sp(4))

    prev_was_heading = False
    for line in pattern_brain.split("\n"):
        line = line.strip()
        if not line:
            out.append(_sp(3))
            prev_was_heading = False
            continue
        if line.startswith("### "):
            out.append(Paragraph(line[4:], _style("pb_h3", fontSize=13,
                textColor=C_PRIMARY, fontName="Helvetica-Bold",
                spaceBefore=14, spaceAfter=2)))
            prev_was_heading = True
        elif line.startswith("## "):
            out.append(Paragraph(line[3:], _style("pb_h2", fontSize=12,
                textColor=C_WHITE, fontName="Helvetica-Bold",
                spaceBefore=8, spaceAfter=4)))
            prev_was_heading = True
        elif line.startswith(("• ", "- ", "* ")):
            out.append(Paragraph(
                f'<font color="#{C_PRIMARY.hexval()[2:]}"><b>›</b></font>'
                f'&nbsp;&nbsp;{line[2:]}',
                _style("pb_bul", fontSize=9, textColor=C_WHITE, leading=14,
                       leftIndent=10, spaceAfter=2)))
            prev_was_heading = False
        elif line and line[0].isdigit() and len(line) > 2 and line[1] in ".)":
            # Numbered item — render as circle + text in a 2-column Table
            body_text = line[2:].strip().replace("**", "")
            num = int(line[0])
            circle = NumberedCircle(num, diameter=14)
            text_para = Paragraph(body_text, _style(
                f"pb_num_{num}", fontSize=9, textColor=C_WHITE, leading=14,
                spaceBefore=0, spaceAfter=0))
            num_table = Table([[circle, text_para]], colWidths=[20, 440])
            num_table.setStyle(TableStyle([
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING",   (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
            ]))
            out.append(num_table)
            out.append(_sp(2))
            prev_was_heading = False
        else:
            rendered = line.replace("**", "")
            sb = 4 if prev_was_heading else 0
            out.append(Paragraph(rendered, _style(f"pb_p_{sb}", fontSize=9,
                textColor=C_WHITE, leading=14, spaceBefore=sb, spaceAfter=2)))
            prev_was_heading = False
    return out


def _detailed_analysis_divider() -> list:
    """Full-bleed divider page — content vertically centred (~42% from top) with small logo."""
    small_logo = _pattern_logo(width_pt=80.0)
    return [
        PageBreak(),
        _sp(200),   # ~42% lead-in from content-area top
        small_logo,
        _sp(16),
        Paragraph(
            f'<font color="#{C_MUTED.hexval()[2:]}" size="9"><b>'
            f'PART TWO</b></font>',
            _style("dap_kicker", alignment=TA_CENTER, leading=12, spaceAfter=8)),
        Paragraph(
            "Detailed Analysis",
            _style("dap_h", fontSize=28, textColor=C_WHITE,
                   fontName="Helvetica-Bold", alignment=TA_CENTER, leading=32,
                   spaceAfter=6)),
        Paragraph(
            "Pillar-by-pillar breakdown of every check, every page, and every "
            "AI-bot crawl result that fed into the score above.",
            _style("dap_sub", fontSize=10, textColor=C_MUTED,
                   alignment=TA_CENTER, leading=14, spaceAfter=18)),
        _section_divider(),
    ]


def _cover_page_flowables(domain: str, overall: int, grade_letter: str,
                           grade_label: str) -> list:
    """Build the cover page (page 1) flowables."""
    grade_color = _score_color(overall)
    timestamp = time.strftime("%Y-%m-%d %H:%M UTC")
    logo = _pattern_logo(width_pt=180.0)
    return [
        _sp(120),   # ~25% from top of content area
        logo,
        _sp(16),
        Paragraph(
            f'<font color="#{C_WHITE.hexval()[2:]}"><b>{domain}</b></font>',
            _style("cov_domain", fontSize=24, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, leading=28, spaceAfter=4)),
        Paragraph(
            "LLM Access Audit",
            _style("cov_sub", fontSize=11, textColor=C_MUTED,
                   fontName="Helvetica", alignment=TA_CENTER, leading=14, spaceAfter=2)),
        Paragraph(
            f'Generated {timestamp}',
            _style("cov_ts", fontSize=8, textColor=C_MUTED,
                   fontName="Helvetica", alignment=TA_CENTER, leading=11, spaceAfter=20)),
        _sp(20),
        Paragraph(
            f'<font color="#{grade_color.hexval()[2:]}"><b>{overall}%</b></font>',
            _style("cov_score", fontSize=64, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, leading=68, spaceAfter=4)),
        Paragraph(
            "Overall LLM Readiness",
            _style("cov_rlbl", fontSize=11, textColor=C_MUTED,
                   fontName="Helvetica", alignment=TA_CENTER, leading=14, spaceAfter=6)),
        Paragraph(
            f'<font color="#{grade_color.hexval()[2:]}"><b>Grade {grade_letter}</b></font>'
            f'<font color="#{C_MUTED.hexval()[2:]}"> — {grade_label}</font>',
            _style("cov_grade", fontSize=14, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, leading=18, spaceAfter=30)),
        _sp(24),
        ScoreLegend(width=460),
        PageBreak(),
    ]


# ─── MAIN GENERATOR ───────────────────────────────────────────────────────────

def generate_report_pdf(audit: dict, domain: str, recs: list) -> bytes:
    """Generate the full branded PDF audit report.

    Args:
        audit: The session_state["_audit"] dict — contains everything the UI
               renders, including js_results, schema_results, robots_result,
               llm_result, semantic_results, security_result, bot_crawl_results,
               and the AI analysis cache (_bifrost_js, _bifrost_robots,
               _bifrost_schema, _bifrost_llm, _bifrost_sem, pattern_brain).
        domain: Domain string for the header (e.g. "okanui.com").
        recs:   List of (severity, pillar, text) tuples from the recommendations
                builder. Also accepts dicts with severity/pillar/text keys.

    Returns:
        PDF file bytes.
    """
    # ── Pull data from the audit dict ─────────────────────────────────────────
    overall          = audit.get("overall", 0)
    overall_grade    = audit.get("overall_grade", {})
    js_results       = audit.get("js_results", {})
    js_score         = audit.get("js_score", 0)
    robots_result    = audit.get("robots_result", {})
    robots_score     = audit.get("robots_score", 0)
    schema_results   = audit.get("schema_results", {})
    schema_score     = audit.get("schema_score", 0)
    llm_result       = audit.get("llm_result", {})
    llm_score        = audit.get("llm_score", 0)
    semantic_results = audit.get("semantic_results", {})
    semantic_score   = audit.get("semantic_score", 0)
    security_result  = audit.get("security_result", {})
    security_score   = audit.get("security_score", 0)
    bot_crawl        = audit.get("bot_crawl_results", {})
    url_labels       = audit.get("url_labels", {})
    no_blog          = audit.get("no_blog", False)

    bifrost_js     = audit.get("_bifrost_js", {}) or {}
    bifrost_robots = audit.get("_bifrost_robots")
    bifrost_schema = audit.get("_bifrost_schema", {}) or {}
    bifrost_llm    = audit.get("_bifrost_llm")
    bifrost_sem    = audit.get("_bifrost_sem", {}) or {}
    pattern_brain  = audit.get("pattern_brain")

    grade_letter = overall_grade.get("letter", "?") if isinstance(overall_grade, dict) else "?"
    grade_label  = overall_grade.get("label", "")  if isinstance(overall_grade, dict) else ""

    pillar_scores = {
        "JS Rendering":       js_score,
        "Robots & Crawl":     robots_score,
        "Schema & Entity":    schema_score,
        "AI Discoverability": llm_score,
        "Semantic Hierarchy": semantic_score,
        "Security":           security_score,
    }

    sorted_pillars = sorted(pillar_scores.items(), key=lambda x: x[1])
    weakest, strongest = sorted_pillars[0], sorted_pillars[-1]

    # ── Document setup ────────────────────────────────────────────────────────
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=18*mm, bottomMargin=22*mm,
        title=f"Pattern LLM Access Audit — {domain}",
    )

    story: list = []

    # ── 1. COVER PAGE ────────────────────────────────────────────────────────
    story.extend(_cover_page_flowables(domain, overall, grade_letter, grade_label))

    # ── 2. PILLAR SCORE TABLE (page 2) ───────────────────────────────────────
    story.append(_sp(12))
    story.append(Paragraph("Pillar Scores", _S_H2()))
    story.append(_sp(6))

    pillar_rows = [["Pillar", "Score Bar", "%", "Grade"]]
    for pname, psc in pillar_scores.items():
        gl, _ = _grade(psc)
        sc_color = _score_color(psc)
        pillar_rows.append([
            Paragraph(pname, _style(f"pn_{pname}", fontSize=9, textColor=C_WHITE,
                                    fontName="Helvetica-Bold")),
            ScoreBar(psc, width=160, height=5),
            Paragraph(f'<font color="#{sc_color.hexval()[2:]}"><b>{psc}%</b></font>',
                      _style(f"pp_{pname}", fontSize=9, alignment=TA_CENTER)),
            Paragraph(f'<font color="#{sc_color.hexval()[2:]}"><b>{gl}</b></font>',
                      _style(f"pg_{pname}", fontSize=10, alignment=TA_CENTER,
                             fontName="Helvetica-Bold")),
        ])
    pt = Table(pillar_rows, colWidths=[170, 180, 50, 50])
    pt.setStyle(_table_header_style())
    story.append(pt)
    story.append(_sp(12))

    # ── 3. STRONGEST / WEAKEST ───────────────────────────────────────────────
    sw_table = Table([[
        Paragraph(
            f'<font color="#{C_MUTED.hexval()[2:]}" size="7"><b>STRONGEST PILLAR</b></font><br/>'
            f'<br/>'
            f'<font color="#{_score_color(strongest[1]).hexval()[2:]}" size="11"><b>{strongest[0]}</b></font>'
            f'<font color="#{C_WHITE.hexval()[2:]}" size="11"> — {strongest[1]}%</font>',
            _style("strong", fontSize=9, leading=14)),
        Paragraph(
            f'<font color="#{C_MUTED.hexval()[2:]}" size="7"><b>PRIORITY FOCUS</b></font><br/>'
            f'<br/>'
            f'<font color="#{_score_color(weakest[1]).hexval()[2:]}" size="11"><b>{weakest[0]}</b></font>'
            f'<font color="#{C_WHITE.hexval()[2:]}" size="11"> — {weakest[1]}%</font>',
            _style("weak", fontSize=9, leading=14)),
    ]], colWidths=[225, 225])
    sw_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, 0),  C_CARD),
        ("BACKGROUND",   (1, 0), (1, 0),  C_CARD),
        ("LINEBEFORE",   (0, 0), (0, 0),  3, _score_color(strongest[1])),
        ("LINEBEFORE",   (1, 0), (1, 0),  3, _score_color(weakest[1])),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING",   (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 14),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(sw_table)
    story.append(_sp(12))

    # ── 4. ANTI-BOT / CLOUDFLARE CALLOUT ─────────────────────────────────────
    cf = robots_result.get("cloudflare", {}) if isinstance(robots_result, dict) else {}
    if cf.get("bot_fight_mode_likely"):
        blocked = ", ".join(cf.get("blocked_bots", []))
        story.append(_callout(
            f"<b>Anti-Bot Protection Active.</b> Cloudflare Bot Fight Mode is "
            f"blocking AI crawlers: {blocked}. This overrides robots.txt. "
            f"Disable it or allowlist AI user-agents in your Cloudflare dashboard.",
            kind="danger"))
        story.append(_sp(6))
    elif cf.get("cloudflare_detected") and cf.get("blocked_bots"):
        blocked = ", ".join(cf.get("blocked_bots", []))
        story.append(_callout(
            f"<b>Cloudflare Detected.</b> Some AI bots blocked: {blocked}. "
            f"Review Bot Fight Mode settings.",
            kind="warning"))
        story.append(_sp(6))

    # ── 5. NO-BLOG NOTICE ────────────────────────────────────────────────────
    if no_blog:
        story.append(_callout(
            "<b>No editorial blog audited.</b> A 10pt schema penalty has been applied. "
            "AI systems preferentially cite brands with regular editorial content — "
            "consider creating a blog or resource hub to improve citation potential.",
            kind="warning"))
        story.append(_sp(6))

    # ── 6. EXECUTIVE SUMMARY ─────────────────────────────────────────────────
    if pattern_brain:
        story.append(PageBreak())
        story.extend(_exec_summary_flowables(pattern_brain))

    # ── 7. PER-PAGE SUMMARY ──────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(_sp(12))
    story.append(Paragraph("Per-Page Results", _S_H2()))
    story.append(_sp(4))
    story.append(Paragraph(
        "Per-pillar checks run on a representative page from each template — empty "
        "cells indicate the pillar wasn't audited on that page type. See the "
        "detailed analysis below for full results.",
        _style("pp_note", fontSize=8, textColor=C_MUTED, fontName="Helvetica",
               leading=12, spaceAfter=4)))
    story.append(_sp(2))

    pp_rows = [["Page", "URL", "JS", "Schema", "Semantic"]]
    for url_key, label in url_labels.items():
        js_s  = js_results.get(url_key, {}).get("score")
        sc_s  = schema_results.get(url_key, {}).get("score")
        sem_r = semantic_results.get(url_key, {})
        if sem_r and not sem_r.get("error"):
            ps = 100
            if not sem_r.get("hierarchy_ok", True):       ps -= 30
            if not sem_r.get("semantic_elements"):        ps -= 20
            hl = sem_r.get("html_length", 0)
            tl = sem_r.get("text_length", 0)
            if hl > 0 and (tl / hl * 100) < 15:           ps -= 20
            if sem_r.get("nosnippet_elements", 0) > 5:    ps -= 10
            sem_s = max(0, ps)
        else:
            sem_s = None

        def _cell(v):
            if not isinstance(v, int):
                # Muted dot instead of dash
                return Paragraph(
                    f'<font color="#{C_MUTED.hexval()[2:]}" size="10">·</font>',
                    _style("pp_dot", fontSize=10, textColor=C_MUTED, alignment=TA_CENTER))
            c = _score_color(v)
            return Paragraph(f'<font color="#{c.hexval()[2:]}"><b>{v}</b></font>',
                             _style(f"pp_{v}", fontSize=9, alignment=TA_CENTER, fontName="Helvetica-Bold"))

        url_display = url_key if len(url_key) <= 60 else url_key[:57] + "…"
        pp_rows.append([
            Paragraph(label,        _style(f"pl_{label}", fontSize=8, textColor=C_WHITE, fontName="Helvetica-Bold")),
            Paragraph(url_display,  _style(f"pu_{url_key}", fontSize=7, textColor=C_MUTED)),
            _cell(js_s), _cell(sc_s), _cell(sem_s),
        ])

    ppt = Table(pp_rows, colWidths=[70, 250, 45, 45, 45])
    ppt.setStyle(_table_header_style())
    story.append(ppt)
    story.append(_sp(16))

    # ── 8. PRIORITY RECOMMENDATIONS ──────────────────────────────────────────
    story.append(Paragraph("Priority Recommendations", _S_H2()))
    story.append(_sp(8))
    if not recs:
        story.append(_status_dot("Excellent! Your site scores well across all pillars.", "success"))
    else:
        for i, rec in enumerate(recs, 1):
            # Support both (severity, pillar, text) tuples and dict form
            if isinstance(rec, dict):
                severity = rec.get("severity", "warning")
                pillar   = rec.get("pillar", "")
                text     = rec.get("text", str(rec))
            else:
                try:
                    severity, pillar, text = rec
                except (TypeError, ValueError):
                    severity, pillar, text = "warning", "", str(rec)

            # Map severity → colour and kicker label
            sev_lower = (severity or "warning").lower()
            if sev_lower in ("critical", "danger"):
                color     = C_DANGER
                sev_label = "CRITICAL"
            elif sev_lower == "info":
                color     = C_PRIMARY
                sev_label = "RECOMMENDATION"
            else:
                color     = C_WARN
                sev_label = "WARNING"

            rec_para = Paragraph(
                f'<font color="#{color.hexval()[2:]}" size="7"><b>{sev_label} · {pillar.upper()}</b></font><br/>'
                f'<br/>'
                f'<font color="#{C_WHITE.hexval()[2:]}" size="9">{i}. {text}</font>',
                _style(f"rec_{i}", fontSize=9, leading=14))
            box = Table([[rec_para]], colWidths=[460])
            box.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), C_CARD),
                ("LINEBEFORE",   (0, 0), (0, -1),  3, color),
                ("LEFTPADDING",  (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING",   (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
            ]))
            story.append(box)
            if i < len(recs):
                story.append(_sp(8))

    # ── DETAILED ANALYSIS DIVIDER ─────────────────────────────────────────────
    story.extend(_detailed_analysis_divider())

    # ─────────────────────────────────────────────────────────────────────────
    # PILLAR 1 — JAVASCRIPT RENDERING
    # ─────────────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(_pillar_header(1, "JavaScript Rendering", js_score))
    story.append(Paragraph(
        f"Page-level · Checked on each of your {len(js_results)} pages",
        _S_MUTED()))
    story.append(_sp(6))

    for test_url, js_r in js_results.items():
        label = url_labels.get(test_url, test_url)
        if js_r.get("error"):
            story.append(Paragraph(
                f'<font color="#{C_DANGER.hexval()[2:]}"><b>{label}: ERROR</b></font> '
                f'<font color="#{C_MUTED.hexval()[2:]}">— {js_r["error"]}</font>',
                _S_BODY()))
            story.append(_sp(4))
            continue

        story.append(_page_block_header(label, js_r.get("score", 0)))
        provider = js_r.get("js_provider")
        if provider:
            story.append(Paragraph(f"Rendered via: {provider}", _S_MUTED()))

        comp = js_r.get("comparison")
        if comp and comp.get("comparison"):
            cmp_rows = [["Content", "HTML (Crawler)", "JS (Browser)", "Status"]]
            for c in comp["comparison"]:
                if not c.get("name"):
                    continue
                if c["status"] == "missing":
                    st_label, st_color = "MISSING", C_DANGER
                elif c["status"] == "warn":
                    st_label, st_color = "MINOR GAP", C_WARN
                else:
                    st_label, st_color = "OK", C_TEAL
                cmp_rows.append([
                    Paragraph(str(c["name"]),     _style(f"c1_{c['name']}", fontSize=8, textColor=C_WHITE)),
                    Paragraph(str(c["html_val"]), _style(f"c2_{c['name']}", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)),
                    Paragraph(str(c["js_val"]),   _style(f"c3_{c['name']}", fontSize=8, textColor=C_TEAL, alignment=TA_CENTER)),
                    Paragraph(f'<font color="#{st_color.hexval()[2:]}"><b>{st_label}</b></font>',
                              _style(f"c4_{c['name']}", fontSize=8, alignment=TA_CENTER, fontName="Helvetica-Bold")),
                ])
            cmp_t = Table(cmp_rows, colWidths=[180, 100, 100, 80])
            cmp_t.setStyle(_table_header_style())
            story.append(cmp_t)
            story.append(_sp(4))

            html_t = comp.get("html_summary", {}).get("text_content_length", 0)
            js_t   = comp.get("js_summary",   {}).get("text_content_length", 0)
            if js_t > html_t:
                pct = round(html_t / max(js_t, 1) * 100)
                pct_color = _score_color(pct)
                vis_para = Paragraph(
                    f'<font color="#{C_MUTED.hexval()[2:]}" size="7"><b>CONTENT VISIBILITY</b></font><br/>'
                    f'<br/>'
                    f'<font color="#{pct_color.hexval()[2:]}" size="14"><b>{pct}%</b></font>'
                    f'<font color="#{C_WHITE.hexval()[2:]}" size="9"> visible to AI crawlers</font><br/>'
                    f'<font color="#{C_MUTED.hexval()[2:]}" size="8">'
                    f'HTML: {html_t:,} chars · JS-rendered: {js_t:,} chars · '
                    f'Hidden: {js_t - html_t:,} chars</font>',
                    _style("vis", fontSize=9, leading=16))
                box = Table([[vis_para]], colWidths=[460])
                box.setStyle(TableStyle([
                    ("BACKGROUND",   (0, 0), (-1, -1), C_CARD),
                    ("LINEBEFORE",   (0, 0), (0, -1),  3, pct_color),
                    ("LEFTPADDING",  (0, 0), (-1, -1), 14),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                    ("TOPPADDING",   (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING",(0, 0), (-1, -1), 12),
                ]))
                story.append(box)
                story.append(_sp(6))

        for fname, fsev, fnote in (js_r.get("frameworks") or []):
            sev_kind = "danger" if fsev == "high" else "warning"
            story.append(_status_dot(f"<b>{fname}</b> ({fsev}) — {fnote}", sev_kind))

        story.extend(_ai_block(bifrost_js.get(test_url)))

    # ─────────────────────────────────────────────────────────────────────────
    # PILLAR 2 — ROBOTS & CRAWLABILITY
    # ─────────────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(_pillar_header(2, "Robots & Crawlability", robots_score))
    story.append(Paragraph("Site-level · Controls all crawler access", _S_MUTED()))
    story.append(_sp(4))

    if robots_result.get("found"):
        story.append(_status_dot(
            f"robots.txt found · {len(robots_result.get('sitemaps', []))} sitemap(s) declared",
            "success"))
        blocked_res = robots_result.get("blocked_resources", [])
        if blocked_res:
            story.append(_status_dot(
                f"CSS/JS blocked: {', '.join(blocked_res[:3])}", "danger"))
        else:
            story.append(_status_dot("CSS/JS not blocked — AI agents can render pages", "success"))

        ai_results = robots_result.get("ai_agent_results", robots_result.get("ai_results", {}))
        if ai_results:
            story.append(_sp(6))
            story.append(Paragraph("AI Bot Access (per robots.txt):", _S_H3()))
            bot_rows = [["Bot", "Company", "Status"]]
            for bn, info in ai_results.items():
                allowed = info.get("robots_allowed", info.get("allowed"))
                if allowed is True:
                    st_text, st_color = "Allowed", C_TEAL
                elif allowed is False:
                    st_text, st_color = "Blocked", C_DANGER
                else:
                    st_text, st_color = "Unknown", C_MUTED
                bot_rows.append([
                    Paragraph(bn, _style(f"rb1_{bn}", fontSize=8, textColor=C_WHITE)),
                    Paragraph(info.get("company", "—"),
                              _style(f"rb2_{bn}", fontSize=8, textColor=C_MUTED)),
                    Paragraph(f'<font color="#{st_color.hexval()[2:]}"><b>{st_text}</b></font>',
                              _style(f"rb3_{bn}", fontSize=8, fontName="Helvetica-Bold")),
                ])
            bt = Table(bot_rows, colWidths=[180, 140, 140])
            bt.setStyle(_table_header_style())
            story.append(bt)

        sensitive = robots_result.get("sensitive_paths", {})
        exposed = [p for p, r in sensitive.items()
                   if not r.get("blocked", not r.get("accessible_per_robots", False))]
        if exposed:
            story.append(_sp(6))
            story.append(Paragraph(
                f'<font color="#{C_WARN.hexval()[2:]}"><b>Sensitive paths without Disallow rule ({len(exposed)}):</b></font>',
                _S_BODY()))
            for path in exposed[:10]:
                story.append(_status_dot(path, "warning"))
            if len(exposed) > 10:
                story.append(Paragraph(f"…and {len(exposed) - 10} more", _S_MUTED()))
    else:
        story.append(_status_dot("No robots.txt found — AI crawlers have no access instructions", "danger"))

    story.extend(_ai_block(bifrost_robots))

    # ─────────────────────────────────────────────────────────────────────────
    # PILLAR 3 — SCHEMA & ENTITY
    # ─────────────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(_pillar_header(3, "Schema & Entity", schema_score))
    story.append(Paragraph(f"Page-level · Checked on each of your {len(schema_results)} pages",
                           _S_MUTED()))
    story.append(_sp(4))

    for test_url, sr in schema_results.items():
        label = url_labels.get(test_url, test_url)
        if sr.get("error"):
            story.append(Paragraph(
                f'<font color="#{C_DANGER.hexval()[2:]}"><b>{label}: ERROR</b></font>',
                _S_BODY()))
            continue

        story.append(_page_block_header(label, sr.get("score", 0)))

        schema_data = sr.get("schema", {})
        types       = schema_data.get("types", [])
        validations = schema_data.get("validations", [])
        ess_found   = schema_data.get("essential_found", [])
        ess_missing = schema_data.get("essential_missing", [])
        meta_data   = sr.get("meta", {})
        entity_data = sr.get("entity", {})

        if types:
            story.append(Paragraph(
                f'<font color="#{C_MUTED.hexval()[2:]}" size="8"><b>TYPES FOUND: </b></font>'
                f'<font color="#{C_PRIMARY.hexval()[2:]}" size="9">{", ".join(types)}</font>',
                _S_BODY()))

        if ess_found:
            story.append(_status_dot(f"Essential found: {', '.join(ess_found)}", "success"))
        if ess_missing:
            story.append(_status_dot(f"Essential missing: {', '.join(ess_missing)}", "warning"))

        for v in validations:
            comp_pct = v.get("completeness", 0)
            if comp_pct >= 80:   kind = "success"
            elif comp_pct >= 50: kind = "warning"
            else:                kind = "danger"
            text = f"<b>{v.get('type', '?')}</b> — {comp_pct}% complete"
            if v.get("missing"):
                text += f" · Missing: {', '.join(v['missing'][:5])}"
                if len(v.get("missing", [])) > 5:
                    text += f" (+{len(v['missing']) - 5} more)"
            story.append(_status_dot(text, kind))

        if meta_data:
            title = meta_data.get("title", "")
            desc_len = meta_data.get("desc_len", 0)
            canon = meta_data.get("canonical", "")
            story.append(_status_dot(
                f"Title ({len(title)} chars): {title[:80] or '(missing)'}",
                "success" if title else "danger"))
            story.append(_status_dot(f"Meta description: {desc_len} chars",
                                     "success" if 100 <= desc_len <= 160 else "warning"))
            if canon and meta_data.get("canonical_matches_url"):
                story.append(_status_dot("Canonical matches URL", "success"))
            elif canon:
                story.append(_status_dot(f"Canonical mismatch — {canon[:60]}", "danger"))
            else:
                story.append(_status_dot("Canonical: missing", "warning"))

        if entity_data and entity_data.get("is_article_page"):
            story.append(_status_dot(
                f"Author: {'Found' if entity_data.get('has_author') else 'Missing'}",
                "success" if entity_data.get("has_author") else "warning"))
            story.append(_status_dot(
                f"Publication date: {'Found' if entity_data.get('has_date_published') else 'Missing'}",
                "success" if entity_data.get("has_date_published") else "warning"))

        if not schema_data.get("schemas"):
            story.append(_status_dot("No Schema.org structured data found", "warning"))

        story.extend(_ai_block(bifrost_schema.get(test_url)))

    # ─────────────────────────────────────────────────────────────────────────
    # PILLAR 4 — AI DISCOVERABILITY
    # ─────────────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(_pillar_header(4, "AI Discoverability", llm_score))
    story.append(Paragraph("Site-level · llm.txt files + AI Info Page", _S_MUTED()))
    story.append(_sp(4))

    story.append(Paragraph("llm.txt Files:", _S_H3()))
    llm_txt_data = llm_result.get("llm_txt", llm_result.get("files", {}))
    any_found = False
    for path, info in (llm_txt_data or {}).items():
        if info.get("found"):
            any_found = True
            q = info.get("quality", {})
            quality_bits = []
            if q.get("lines"):    quality_bits.append(f"{q['lines']} lines")
            if q.get("chars"):    quality_bits.append(f"{q['chars']:,} chars")
            quality_bits.append("links: yes" if q.get("has_links") else "links: no")
            quality_bits.append("sections: yes" if q.get("has_sections") else "sections: no")
            story.append(_status_dot(
                f"<b>{path}</b> — {' · '.join(quality_bits)}", "success"))
        else:
            story.append(_status_dot(path, "info", muted=True))
    if not any_found:
        story.append(_status_dot("No llm.txt files found at any standard path", "warning"))

    story.append(_sp(4))
    story.append(Paragraph("AI Info Page:", _S_H3()))
    ai_info = llm_result.get("ai_info_page", {})
    if ai_info.get("found"):
        story.append(_status_dot(f"Found at {ai_info.get('url', '')[:80]}", "success"))
        story.append(_status_dot(
            f"Linked from footer: {'Yes' if ai_info.get('linked_from_footer') else 'No'}",
            "success" if ai_info.get("linked_from_footer") else "warning"))
        if "indexable" in ai_info:
            story.append(_status_dot(
                f"Indexable: {'Yes' if ai_info['indexable'] else 'No (has noindex)'}",
                "success" if ai_info.get("indexable") else "danger"))
    else:
        story.append(_status_dot(
            "No AI Info Page found at /ai-info, /llm-info or similar paths",
            "warning"))

    wellknown = llm_result.get("wellknown", {})
    if wellknown:
        story.append(_sp(4))
        story.append(Paragraph("Well-Known AI Files:", _S_H3()))
        for path, info in wellknown.items():
            kind = "success" if info.get("found") else "info"
            story.append(_status_dot(
                f"{path}{' (found)' if info.get('found') else ' (not found)'}",
                kind, muted=not info.get("found")))

    story.extend(_ai_block(bifrost_llm))

    # ─────────────────────────────────────────────────────────────────────────
    # PILLAR 5 — SEMANTIC HIERARCHY
    # ─────────────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(_pillar_header(5, "Semantic Hierarchy & Content Structure", semantic_score))
    story.append(Paragraph("Page-level · Heading structure, semantic HTML, meta directives",
                           _S_MUTED()))
    story.append(_sp(4))

    for test_url, sem_r in semantic_results.items():
        label = url_labels.get(test_url, test_url)
        if sem_r.get("error"):
            story.append(Paragraph(
                f'<font color="#{C_DANGER.hexval()[2:]}"><b>{label}: ERROR</b></font>',
                _S_BODY()))
            continue

        story.append(_page_block_header(label))

        hier_ok = sem_r.get("hierarchy_ok", True)
        story.append(_status_dot(
            f"Heading hierarchy: {'Valid — no skipped levels' if hier_ok else 'Issues — skipped heading levels'}",
            "success" if hier_ok else "warning"))

        sem_elems = sem_r.get("semantic_elements", {}) or {}
        if sem_elems:
            elems_str = ", ".join(f"{tag}:{c}" for tag, c in sem_elems.items())
            story.append(_status_dot(f"Semantic elements: {elems_str}", "success"))
        else:
            story.append(_status_dot("No semantic HTML5 elements found", "warning"))

        for tag in (sem_r.get("meta_tags") or []):
            story.append(_status_dot(f"meta {tag['name']}: {tag['content']}", "info"))

        html_len = sem_r.get("html_length", 0)
        text_len = sem_r.get("text_length", 0)
        if html_len > 0:
            ratio = text_len / html_len * 100
            story.append(_status_dot(
                f"Text-to-HTML ratio: {ratio:.1f}%",
                "success" if ratio >= 15 else "warning"))

        story.extend(_ai_block(bifrost_sem.get(test_url)))

    # ─────────────────────────────────────────────────────────────────────────
    # PILLAR 6 — SECURITY & EXPOSURE
    # ─────────────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(_pillar_header(6, "Security & Exposure", security_score))
    story.append(Paragraph("Site-level · Sensitive path probing as AI bots", _S_MUTED()))
    story.append(_sp(4))

    sec_findings = security_result.get("findings", {}) or {}
    sec_total = security_result.get("total_exposed", 0)

    if sec_total == 0 and not sec_findings.get("html_exposure") and not sec_findings.get("robots_allowlist"):
        story.append(_status_dot(
            "No sensitive paths accessible to AI bots — all probed paths returned 403/404/401",
            "success"))
    else:
        for cat, cat_label, kind in [
            ("critical", "Critical paths (admin/env/config)", "danger"),
            ("backend",  "Backend paths (API/GraphQL)",        "warning"),
            ("customer", "Customer paths (account/checkout)",  "warning"),
        ]:
            items = sec_findings.get(cat, []) or []
            if items:
                story.append(_sp(8))
                story.append(Paragraph(
                    f'<font color="#{C_WARN.hexval()[2:] if kind == "warning" else C_DANGER.hexval()[2:]}"><b>{cat_label}:</b></font>',
                    _style(f"sec_cat_{cat}", fontSize=9, textColor=C_WHITE,
                           fontName="Helvetica", leading=14, spaceAfter=2, spaceBefore=8)))
                story.append(_sp(2))
                for f in items:
                    story.append(_status_dot(
                        f"{f['path']} — HTTP {f['status']} ({f.get('size', 0):,} bytes)", kind))

        if sec_findings.get("html_exposure"):
            story.append(_sp(8))
            story.append(Paragraph(
                f'<font color="#{C_WARN.hexval()[2:]}"><b>Sensitive content in HTML source:</b></font>',
                _style("sec_html", fontSize=9, textColor=C_WHITE,
                       fontName="Helvetica", leading=14, spaceAfter=2, spaceBefore=8)))
            story.append(_sp(2))
            for item in sec_findings["html_exposure"]:
                story.append(_status_dot(item, "warning"))

        if sec_findings.get("robots_allowlist"):
            story.append(_sp(8))
            story.append(Paragraph(
                f'<font color="#{C_WARN.hexval()[2:]}"><b>robots.txt allows sensitive paths for AI bots:</b></font>',
                _style("sec_robots", fontSize=9, textColor=C_WHITE,
                       fontName="Helvetica", leading=14, spaceAfter=2, spaceBefore=8)))
            story.append(_sp(2))
            for item in sec_findings["robots_allowlist"]:
                story.append(_status_dot(f"{item['bot']}: {item['path']}", "warning"))

    # ─────────────────────────────────────────────────────────────────────────
    # LIVE BOT CRAWL
    # ─────────────────────────────────────────────────────────────────────────
    if bot_crawl:
        story.append(PageBreak())
        story.append(_sp(12))
        story.append(Paragraph("Live Bot Crawl Results", _S_H2()))
        allowed_n = sum(1 for r in bot_crawl.values() if r.get("is_allowed"))
        total_n = len(bot_crawl)
        story.append(Paragraph(
            f'<font color="#{C_TEAL.hexval()[2:]}"><b>{allowed_n}</b></font>'
            f'<font color="#{C_MUTED.hexval()[2:]}"> allowed · </font>'
            f'<font color="#{C_DANGER.hexval()[2:]}"><b>{total_n - allowed_n}</b></font>'
            f'<font color="#{C_MUTED.hexval()[2:]}"> blocked · {total_n} total</font>',
            _S_BODY()))
        story.append(_sp(8))

        bc_rows = [["Bot", "Company", "Status", "HTTP", "Load"]]
        for bn, r in bot_crawl.items():
            if r.get("error"):
                bc_rows.append([
                    Paragraph(bn, _style(f"bce_{bn}", fontSize=8, textColor=C_WHITE)),
                    Paragraph("—", _S_MUTED()),
                    Paragraph(f'<font color="#{C_DANGER.hexval()[2:]}"><b>ERROR</b></font>',
                              _style(f"bcs_{bn}", fontSize=8)),
                    Paragraph("—", _S_MUTED()),
                    Paragraph("—", _S_MUTED()),
                ])
            else:
                allowed = r.get("is_allowed")
                st_label, st_color = ("Allowed", C_TEAL) if allowed else ("BLOCKED", C_DANGER)
                bc_rows.append([
                    Paragraph(bn, _style(f"bc1_{bn}", fontSize=8, textColor=C_WHITE)),
                    Paragraph(r.get("company", "—"),
                              _style(f"bc2_{bn}", fontSize=8, textColor=C_MUTED)),
                    Paragraph(f'<font color="#{st_color.hexval()[2:]}"><b>{st_label}</b></font>',
                              _style(f"bc3_{bn}", fontSize=8, fontName="Helvetica-Bold")),
                    Paragraph(str(r.get("status_code", "—")),
                              _style(f"bc4_{bn}", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)),
                    Paragraph(f"{r.get('load_time', '—')}s",
                              _style(f"bc5_{bn}", fontSize=8, textColor=C_MUTED, alignment=TA_CENTER)),
                ])
        bct = Table(bc_rows, colWidths=[120, 100, 100, 60, 60])
        bct.setStyle(_table_header_style())
        story.append(bct)

    # ─────────────────────────────────────────────────────────────────────────
    # FOOTER (last flowable on the document body)
    # ─────────────────────────────────────────────────────────────────────────
    story.append(_sp(20))
    story.append(_thin_divider())
    story.append(Paragraph(
        f'<font color="#{C_MUTED.hexval()[2:]}" size="8">'
        f'Want to action these findings? Pattern is an ecommerce growth agency '
        f'specialising in AI/LLM readiness audits and remediation. Get in touch at '
        f'<a href="{PATTERN_WEBSITE}"><font color="#{C_PRIMARY.hexval()[2:]}">au.pattern.com</font></a>.'
        f'</font>',
        _style("ft", fontSize=8, alignment=TA_CENTER, leading=12)))

    # ── Page background + page numbers ────────────────────────────────────────
    def _on_page(canvas, doc_):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        page_num = canvas.getPageNumber()
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(18*mm, 12*mm, f"{domain}  ·  Pattern LLM Access Audit")
        canvas.drawRightString(A4[0] - 18*mm, 12*mm, f"Page {page_num}")
        link_text = "au.pattern.com"
        canvas.setFillColor(C_PRIMARY)
        text_w = canvas.stringWidth(link_text, "Helvetica", 7)
        cx = (A4[0] - text_w) / 2
        canvas.drawString(cx, 12*mm, link_text)
        canvas.linkURL(
            PATTERN_WEBSITE,
            (cx - 2, 12*mm - 2, cx + text_w + 2, 12*mm + 8),
            relative=0, thickness=0,
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()
