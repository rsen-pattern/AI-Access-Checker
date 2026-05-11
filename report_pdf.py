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
import re
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

# ─── TOPLINE COPY ─────────────────────────────────────────────────────────────
# Static strings for the topline summary PDF — edit here, not in layout code.

TOPLINE_COVER_SUBTITLE = (
    "How discoverable is your brand to ChatGPT, Claude, and Perplexity?"
)

TOPLINE_UNLOCKS_BLOCKS = [
    {
        "heading": "Be cited when customers research your category",
        # Citation needs both a discoverable AI guidance surface AND clean
        # entity data so the AI knows what to cite about your brand.
        "powered_by_pillars": ["ai_discoverability", "schema_entity"],
        "body": (
            "Perplexity, ChatGPT, and Google AI Overviews now answer purchase-intent "
            "queries directly. Brands not indexed by AI crawlers are invisible in that "
            "answer — the gap shows up as a missed mention every time a customer searches."
        ),
    },
    {
        "heading": "Surface in AI shopping agents",
        # Shopping agents need structured product data — AND the product detail
        # has to be in the raw HTML, not loaded later via JavaScript, because
        # most AI crawlers don't execute scripts.
        "powered_by_pillars": ["schema_entity", "js_rendering"],
        "body": (
            "A new layer of AI-powered comparison tools is being built on top of structured "
            "product data. Brands with clean, machine-readable product information are "
            "included automatically; those without are skipped entirely."
        ),
    },
    {
        "heading": "Own your brand entity before competitors do",
        # Entity assembly needs structured data — AND crawlers need to reach
        # the pages that publish it.
        "powered_by_pillars": ["schema_entity", "robots_crawl"],
        "body": (
            "AI knowledge graphs are being assembled now, using publicly available "
            "structured data. Establishing your organisation's entity sets the foundation "
            "for how AI describes your brand for years."
        ),
    },
]

TOPLINE_CTA_PRIMARY = (
    "Reply to your Pattern contact",
    "Hit reply on the email this PDF came with — share two or three times that work "
    "and we'll lock in a 45-minute walkthrough.",
)

TOPLINE_CTA_FALLBACK = (
    "Didn't come via email? Visit {url} and mention your LLM Readiness audit."
)

TOPLINE_CTA_FALLBACK_URL = "https://au.pattern.com/contact"

# ─── TOPLINE PILLAR REGISTRY ──────────────────────────────────────────────────
# Topline-only pillar slugs. Maps a canonical key to (display_name, audit-dict
# score key). Single source of truth for page 2 grouping, page 3 finding labels,
# and page 4 "Powered by" lookups.
#
# Display names match the rest of the codebase ("JS Rendering", "Robots & Crawl")
# rather than the longer form in the methodology doc. Drift between the two
# would be confusing — flag in the PR if the doc changes.
TOPLINE_PILLAR_REGISTRY = {
    "js_rendering":       {"display": "JS Rendering",       "score_key": "js_score"},
    "robots_crawl":       {"display": "Robots & Crawl",     "score_key": "robots_score"},
    "schema_entity":      {"display": "Schema & Entity",    "score_key": "schema_score"},
    "ai_discoverability": {"display": "AI Discoverability", "score_key": "llm_score"},
    "semantic_hierarchy": {"display": "Semantic Hierarchy", "score_key": "semantic_score"},
    "security":           {"display": "Security",           "score_key": "security_score"},
}

# Which pillars contribute to the weighted overall vs scored separately.
# Weights (in core.llm_access_checks.compute_overall):
#   JS Rendering 25% · Robots & Crawl 25% · Schema & Entity 35% · AI Discoverability 15%
# Semantic Hierarchy and Security are tracked but not blended in.
TOPLINE_PILLAR_GROUPS = {
    "weighted":   ["js_rendering", "robots_crawl", "schema_entity", "ai_discoverability"],
    "additional": ["semantic_hierarchy", "security"],
}

# Pillar weights — used only for the footnote string under the page 2 table.
TOPLINE_PILLAR_WEIGHTS_NOTE = (
    "Overall score is a weighted average: Schema & Entity 35%, JS Rendering 25%, "
    "Robots & Crawl 25%, AI Discoverability 15%. Semantic Hierarchy and Security "
    "are scored separately."
)

# One-line plain-English description per pillar. Renders inside each page 2
# row in muted-grey small text, below the pillar name. No jargon, no fix names.
TOPLINE_PILLAR_DESCRIPTIONS = {
    "js_rendering":       "Whether AI crawlers can read your pages without running JavaScript",
    "robots_crawl":       "Whether AI bots are allowed to reach and index your content",
    "schema_entity":      "Whether your structured data tells AI what you sell and who you are",
    "ai_discoverability": "Whether AI agents can find dedicated information about how to use your site",
    "semantic_hierarchy": "Whether your page structure makes sense to AI parsers",
    "security":           "Whether your site exposes anything that AI crawlers shouldn't see",
}


def _topline_pillar_score(audit: dict, pillar_key: str) -> int:
    """Look up the integer score for a topline pillar key from the audit dict.

    Raises KeyError if the slug isn't in TOPLINE_PILLAR_REGISTRY. Fail loudly —
    drift between the registry and the audit shape should surface immediately,
    not be papered over with a silent zero.
    """
    if pillar_key not in TOPLINE_PILLAR_REGISTRY:
        raise KeyError(
            f"Unknown topline pillar key {pillar_key!r}. "
            f"Add it to TOPLINE_PILLAR_REGISTRY or fix the caller."
        )
    score_key = TOPLINE_PILLAR_REGISTRY[pillar_key]["score_key"]
    return int(audit.get(score_key, 0) or 0)


def _topline_pillar_display(pillar_key: str) -> str:
    """Look up the human-facing display name for a topline pillar key."""
    if pillar_key not in TOPLINE_PILLAR_REGISTRY:
        raise KeyError(
            f"Unknown topline pillar key {pillar_key!r}. "
            f"Add it to TOPLINE_PILLAR_REGISTRY or fix the caller."
        )
    return TOPLINE_PILLAR_REGISTRY[pillar_key]["display"]


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


_BOLD_RE      = re.compile(r'\*\*(.+?)\*\*')
_NUMBERED_RE  = re.compile(r'^(\d+)[.)]\s+(.+)$')


def _apply_bold(text: str) -> str:
    """Convert balanced **...** markers to ReportLab <b>...</b> tags."""
    return _BOLD_RE.sub(r'<b>\1</b>', text)


def _exec_summary_flowables(pattern_brain: str) -> list:
    """Render the Pattern Brain markdown output as ReportLab flowables.

    Handles ## / ### headings, - / • / * bullets, multi-digit numbered items
    (1. … 99.), and **bold** markers. Falls back to plain paragraphs.

    Changes vs original:
    - Numbered items use regex so 10+ are detected and displayed correctly.
    - **bold** converted to <b>...</b> instead of being stripped.
    - "Top 3 Quick Wins This Week" → "Top 3 Quick Wins" at render time.
    - ### headings 13pt with spaceBefore=14; body after heading gets spaceBefore=4.
    """
    out: list = []
    if not pattern_brain:
        return out

    pattern_brain = pattern_brain.replace("Top 3 Quick Wins This Week", "Top 3 Quick Wins")

    out.append(_sp(12))
    out.append(Paragraph("Access Checker — Executive Summary", _S_H2()))
    out.append(Paragraph(
        "AI-generated analysis · Pattern Brain",
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
            out.append(Paragraph(_apply_bold(line[4:]), _style("pb_h3", fontSize=13,
                textColor=C_PRIMARY, fontName="Helvetica-Bold",
                spaceBefore=14, spaceAfter=2)))
            prev_was_heading = True
        elif line.startswith("## "):
            out.append(Paragraph(_apply_bold(line[3:]), _style("pb_h2", fontSize=12,
                textColor=C_WHITE, fontName="Helvetica-Bold",
                spaceBefore=8, spaceAfter=4)))
            prev_was_heading = True
        elif line.startswith(("• ", "- ", "* ")):
            out.append(Paragraph(
                f'<font color="#{C_PRIMARY.hexval()[2:]}"><b>›</b></font>'
                f'&nbsp;&nbsp;{_apply_bold(line[2:])}',
                _style("pb_bul", fontSize=9, textColor=C_WHITE, leading=14,
                       leftIndent=10, spaceAfter=2)))
            prev_was_heading = False
        else:
            m = _NUMBERED_RE.match(line)
            if m:
                # Numbered item (supports 1–99) — circle + text in a 2-col Table
                num       = int(m.group(1))
                body_text = _apply_bold(m.group(2))
                circle    = NumberedCircle(num, diameter=14)
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
                sb = 4 if prev_was_heading else 0
                out.append(Paragraph(_apply_bold(line), _style(f"pb_p_{sb}", fontSize=9,
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


# ─── TOPLINE HELPERS ──────────────────────────────────────────────────────────

def _topline_pillar_rows(
    audit: dict,
    pillar_keys: list[str],
    header_label: str | None = "Pillar",
    subordinate: bool = False,
) -> list:
    """Build the page 2 pillar table rows.

    pillar_keys: list of TOPLINE_PILLAR_REGISTRY slugs in render order.
    header_label: column header text. If None, the table renders without a
        header row — useful for the "Additional checks" section which has its
        own kicker label above it.
    subordinate: when True, the table uses a slightly more muted treatment so
        readers eye it as secondary to the section above.

    Returns a list of flowables (the table — wrapped in a list for easy
    concatenation into the story array).
    """
    rows: list = []
    if header_label is not None:
        rows.append([header_label, "Performance", "%"])

    for key in pillar_keys:
        pname = _topline_pillar_display(key)
        psc   = _topline_pillar_score(audit, key)
        desc  = TOPLINE_PILLAR_DESCRIPTIONS.get(key, "")
        sc_color = _score_color(psc)
        # Two-line cell: pillar name (bold white) + one-line description (muted).
        name_cell = Paragraph(
            f'<font color="#{C_WHITE.hexval()[2:]}"><b>{pname}</b></font>'
            f'<br/><font color="#{C_MUTED.hexval()[2:]}" size="7">{desc}</font>',
            _style(f"tl_pn_{key}", fontSize=9, leading=12, spaceAfter=0),
        )
        rows.append([
            name_cell,
            ScoreBar(psc, width=210, height=5),
            Paragraph(f'<font color="#{sc_color.hexval()[2:]}"><b>{psc}%</b></font>',
                      _style(f"tl_pp_{key}", fontSize=9, alignment=TA_CENTER)),
        ])

    tbl = Table(rows, colWidths=[210, 195, 45])
    style_cmds = [
        ("ROWBACKGROUNDS", (0, 1 if header_label else 0), (-1, -1), [C_BG, C_CARD]),
        ("GRID",           (0, 0), (-1, -1), 0.4, C_BORDER),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
        ("TOPPADDING",     (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]
    if header_label is not None:
        style_cmds.extend([
            ("BACKGROUND",    (0, 0), (-1, 0), C_SURFACE),
            ("TEXTCOLOR",     (0, 0), (-1, 0), white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0), 8),
            ("ALIGN",         (0, 0), (-1, 0), "LEFT"),
            ("TOPPADDING",    (0, 0), (-1, 0), 6),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ])
    if subordinate:
        # Slightly slimmer rows to communicate "these are real but secondary".
        style_cmds.extend([
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])

    tbl.setStyle(TableStyle(style_cmds))
    return [tbl]


def _build_headline_findings(audit: dict) -> list[dict]:
    """Rules-based generator. Returns up to 5 finding dicts in priority order.

    Each finding has:
        headline        — bold one-line heading
        what_we_found   — symptom in plain English, ~1 sentence, no fix names
        why_it_matters  — business consequence, ~1 sentence
        severity        — 'critical' | 'warning' | 'info'

    Severity rules (per methodology):
        - 'critical': a real critical-category exposure OR a weighted pillar
          score in the F band (< 35).
        - 'warning':  the "private conversation" tease, or a weighted pillar
          score in the D band (35–49).
        - 'info':     everything else.

    The "private conversation" finding is gated on actual sensitive signals
    (critical security paths reachable, or sensitive content in raw HTML) —
    NOT just a low Security score.
    """
    robots_result   = audit.get("robots_result",   {}) or {}
    schema_results  = audit.get("schema_results",  {}) or {}
    llm_result      = audit.get("llm_result",      {}) or {}
    security_result = audit.get("security_result", {}) or {}

    js_score       = int(audit.get("js_score",       0) or 0)
    schema_score   = int(audit.get("schema_score",   0) or 0)
    security_score = int(audit.get("security_score", 0) or 0)

    # Weighted-only pillar set for "generic fallback" pillar-score finding.
    # Security must not appear here — it's not in the overall, so it can't
    # "drag your readiness score".
    weighted_pillar_scores = {
        _topline_pillar_display(k): _topline_pillar_score(audit, k)
        for k in TOPLINE_PILLAR_GROUPS["weighted"]
    }
    weakest_pillar = min(weighted_pillar_scores, key=weighted_pillar_scores.get)
    weakest_score  = weighted_pillar_scores[weakest_pillar]

    cf = robots_result.get("cloudflare", {}) or {}
    findings: list[dict] = []

    def _add(headline: str, what_we_found: str, why_it_matters: str, severity: str = "info") -> None:
        findings.append({
            "headline":       headline,
            "what_we_found":  what_we_found,
            "why_it_matters": why_it_matters,
            "severity":       severity,
        })

    # 1. Cloudflare blocking AI bots
    if cf.get("bot_fight_mode_likely"):
        _add(
            "AI crawlers are being blocked before they reach your content.",
            "Major AI bots are returning errors when they try to load your pages — and the "
            "block is happening at the edge, before your site even gets the request.",
            "Your content isn't being indexed by training datasets or real-time AI search, "
            "and the failure is invisible in your analytics — so the gap keeps compounding.",
            severity="info",
        )

    # 2. No robots.txt
    if not robots_result.get("found"):
        _add(
            "Your site has no instructions for AI crawlers.",
            "There's no published guidance file telling AI bots which pages they may index "
            "or which to skip.",
            "AI systems fall back to inconsistent default behaviour — some pages get crawled, "
            "some get missed, and the brand picture they assemble is incomplete.",
            severity="info",
        )

    # 3. Severe JS rendering gap
    if js_score < 50:
        _add(
            "AI sees a near-empty version of your site.",
            "A large portion of your page content only appears after the browser runs scripts — "
            "the version AI crawlers receive is missing product descriptions, pricing, and key copy.",
            "AI shopping agents and answer engines can't cite what they can't read, so your "
            "products and brand get skipped in favour of competitors whose content is visible.",
            severity="critical" if js_score < 35 else "info",
        )

    # 4. Zero schema
    if schema_score < 25:
        _add(
            "AI has no structured data to understand your products.",
            "Your pages don't expose the machine-readable metadata AI uses to identify what you sell.",
            "Without that signal, AI systems can't reliably surface your products, prices, or "
            "brand in shopping queries — it's the difference between being found and being invisible.",
            severity="critical",  # schema_score < 25 is always below the 35% threshold
        )

    # 5. No GTIN/MPN on product pages
    if len(findings) < 5:
        product_pages_missing = [
            url for url, res in schema_results.items()
            if isinstance(res, dict)
            and (res.get("ecommerce") or {}).get("is_product_page")
            and not (res.get("ecommerce") or {}).get("has_gtin_or_mpn")
        ]
        if product_pages_missing:
            _add(
                "AI shopping agents can't identify your products.",
                "Your product pages don't publish the universal product identifiers AI agents "
                "use to match items across catalogues.",
                "When an AI agent is asked to compare or recommend in your category, your "
                "products fall out of the candidate list — competitors with identifiers stay in.",
                severity="info",
            )

    # 6. No llm.txt and no AI Info Page
    if len(findings) < 5:
        llm_txt_data = llm_result.get("llm_txt", llm_result.get("files", {})) or {}
        ai_info      = llm_result.get("ai_info_page", {}) or {}
        has_llm_txt  = any(v.get("found") for v in llm_txt_data.values()) if llm_txt_data else False
        has_ai_info  = ai_info.get("found", False)
        if not has_llm_txt and not has_ai_info:
            _add(
                "Your brand has no official voice in AI training pipelines.",
                "There's no dedicated page on your site telling AI agents who you are, what "
                "you sell, and how to talk about you.",
                "When AI assembles its understanding of your brand, the narrative gets shaped "
                "by third parties — review sites, aggregators, competitors — instead of you.",
                severity="info",
            )

    # 7. No Organisation entity / sameAs
    if len(findings) < 5:
        has_org_sameas = any(
            res.get("has_org_sameas")
            for res in schema_results.values()
            if isinstance(res, dict)
        )
        if not has_org_sameas:
            _add(
                "AI can't verify who you are across the web.",
                "Your site doesn't publish the verified external links AI uses to confirm "
                "an organisation's identity.",
                "AI agents treat unverified brands as lower-confidence sources — your name "
                "gets cited less often, or skipped in favour of competitors AI can confirm.",
                severity="info",
            )

    # 8. Critical security exposure — gated on real signals, not just low score
    if len(findings) < 5:
        sec_findings        = (security_result.get("findings", {}) or {})
        critical_paths      = sec_findings.get("critical", []) or []
        html_exposure_hits  = sec_findings.get("html_exposure", []) or []
        if critical_paths or html_exposure_hits:
            _add(
                "A sensitive exposure was identified that warrants a private conversation.",
                "Something in your site's exposed surface is sensitive enough that we'd rather "
                "not put it in writing.",
                "We'd want to walk you through what we saw before suggesting how to handle it — "
                "both for your security and to avoid putting the detail in a document that may be forwarded.",
                severity="critical",
            )

    # 9. Security low but no critical signal — methodology-honest version.
    # Replaces the old "is dragging your overall readiness score" claim (it isn't —
    # Security is scored separately). Only emitted when Security < 50 AND no
    # critical-exposure finding above already covered it.
    already_covered_security = any(
        f["headline"].startswith("A sensitive exposure") for f in findings
    )
    if (
        len(findings) < 5
        and security_score < 50
        and not already_covered_security
    ):
        _add(
            "Your Security score signals real exposure risk.",
            "Your site is leaking signals that AI crawlers — and other automated agents — "
            "are picking up on.",
            "Exposed surfaces hurt both real-world security and AI trust signals. AI agents "
            "factor exposure into how reliably they cite a source.",
            severity="critical" if security_score < 35 else "warning",
        )

    # 10. Generic fallback — weighted weakest pillar critically low. Note: Security
    # is excluded by construction (weighted_pillar_scores is weighted-only).
    if len(findings) < 3 and weakest_score < 40:
        _add(
            f"Your {weakest_pillar} score is critically low.",
            f"At {weakest_score}%, this pillar is well below where it needs to be for "
            f"AI systems to work with your content reliably.",
            "AI relies on multiple signals working together — a gap this large in one area "
            "caps how much improvement elsewhere can deliver.",
            severity="critical" if weakest_score < 35 else "warning",
        )

    return findings[:5]


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
    story.append(PageBreak())
    if pattern_brain:
        story.extend(_exec_summary_flowables(pattern_brain))
    else:
        # Fallback: render a static placeholder so the page is never silently absent.
        story.append(_sp(12))
        story.append(Paragraph("Access Checker — Executive Summary", _S_H2()))
        story.append(Paragraph("AI-generated analysis · Pattern Brain", _S_MUTED()))
        story.append(_section_divider())
        story.append(_sp(8))
        story.append(_callout(
            "AI-generated executive summary unavailable for this audit. "
            "This can occur when the Pattern Brain service is unreachable or the audit "
            "was run without an active Bifrost API key. "
            "See the Priority Recommendations on the following page for the same insights "
            "in structured form.",
            kind="warning",
        ))
        story.append(_sp(8))

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

            # Map severity → colour and kicker label.
            # Accepts both legacy strings (critical/danger/warning/info) and
            # the canonical enum values (error/warn/ok) from core.severity.
            sev_lower = (severity or "warn").lower()
            if sev_lower in ("error", "critical", "danger"):
                color     = C_DANGER
                sev_label = "CRITICAL"
            elif sev_lower in ("ok", "info", "success"):
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

        _frameworks = [f for f in (js_r.get("frameworks") or []) if f and len(f) == 3]
        for fname, fsev, fnote in _frameworks:
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

    if sec_findings.get("uniform_response_warning"):
        story.append(_callout(
            f"<b>Untrusted security findings.</b> {sec_findings['uniform_response_warning']}",
            kind="warning"))
        story.append(_sp(8))

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


# ─── TOPLINE SUMMARY GENERATOR ────────────────────────────────────────────────

def generate_topline_pdf(audit: dict, domain: str) -> bytes:
    """Generate a 5-page sales teaser PDF. Symptom-only — never names fixes."""
    from core.ui_recommendations import build_recommendations  # local import avoids module-level cycle

    overall       = int(audit.get("overall", 0) or 0)
    overall_grade = audit.get("overall_grade", {})
    grade_letter  = overall_grade.get("letter", "?") if isinstance(overall_grade, dict) else "?"
    grade_label   = overall_grade.get("label", "")  if isinstance(overall_grade, dict) else ""
    grade_color   = _score_color(overall)

    pillar_scores = {
        _topline_pillar_display(k): _topline_pillar_score(audit, k)
        for k in TOPLINE_PILLAR_REGISTRY
    }
    # Weighted-only view drives Strongest / Priority Focus + the health summary
    # sentence. Picking "Security" as Priority Focus would be misleading because
    # Security is not in the overall — methodology honesty matters here.
    weighted_scores = {
        _topline_pillar_display(k): _topline_pillar_score(audit, k)
        for k in TOPLINE_PILLAR_GROUPS["weighted"]
    }
    sorted_weighted = sorted(weighted_scores.items(), key=lambda x: x[1])
    weakest, strongest = sorted_weighted[0], sorted_weighted[-1]

    headline_findings = _build_headline_findings(audit)
    recs = build_recommendations(audit, audit.get("no_blog", False))
    n_findings = len(recs)
    n_other    = max(0, sum(1 for s in pillar_scores.values() if s < 75) - 1)

    # ── Document ──────────────────────────────────────────────────────────────
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=18*mm, bottomMargin=22*mm,
        title=f"Pattern LLM Readiness — Topline Summary — {domain}",
    )
    story: list = []
    _t = time.localtime()
    timestamp = f"{_t.tm_mday} {time.strftime('%B %Y', _t)}"

    # ── PAGE 1: COVER ─────────────────────────────────────────────────────────
    logo = _pattern_logo(width_pt=180.0)
    story.extend([
        _sp(100),
        logo,
        _sp(16),
        Paragraph(
            f'<font color="#{C_WHITE.hexval()[2:]}"><b>{domain}</b></font>',
            _style("tl_cov_domain", fontSize=24, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, leading=28, spaceAfter=4)),
        Paragraph(
            TOPLINE_COVER_SUBTITLE,
            _style("tl_cov_sub", fontSize=10, textColor=C_MUTED,
                   fontName="Helvetica", alignment=TA_CENTER, leading=14, spaceAfter=2)),
        Paragraph(
            f'Generated {timestamp}',
            _style("tl_cov_ts", fontSize=8, textColor=C_MUTED,
                   fontName="Helvetica", alignment=TA_CENTER, leading=11, spaceAfter=20)),
        _sp(20),
        Paragraph(
            f'<font color="#{grade_color.hexval()[2:]}"><b>{overall}%</b></font>',
            _style("tl_cov_score", fontSize=64, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, leading=68, spaceAfter=4)),
        Paragraph(
            "Overall LLM Readiness",
            _style("tl_cov_rlbl", fontSize=11, textColor=C_MUTED,
                   fontName="Helvetica", alignment=TA_CENTER, leading=14, spaceAfter=6)),
        Paragraph(
            f'<font color="#{grade_color.hexval()[2:]}"><b>Grade {grade_letter}</b></font>'
            f'<font color="#{C_MUTED.hexval()[2:]}"> — {grade_label}</font>',
            _style("tl_cov_grade", fontSize=14, fontName="Helvetica-Bold",
                   alignment=TA_CENTER, leading=18, spaceAfter=30)),
        _sp(24),
        ScoreLegend(width=460),
        PageBreak(),
    ])

    # ── PAGE 2: WHERE AI VISIBILITY IS LEAKING ────────────────────────────────
    story.append(_sp(12))
    story.append(Paragraph("Where AI visibility is leaking", _S_H2()))
    story.append(_sp(6))

    # Section A — pillars that roll into the weighted overall.
    story.extend(_topline_pillar_rows(
        audit,
        pillar_keys=TOPLINE_PILLAR_GROUPS["weighted"],
        header_label="Pillar",
    ))
    story.append(_sp(14))

    # Section B — additional checks. Visually subordinated with a section label
    # and a kicker that explicitly states they don't roll into the headline.
    story.append(Paragraph(
        f'<font color="#{C_MUTED.hexval()[2:]}" size="8"><b>ADDITIONAL CHECKS</b></font>'
        f' <font color="#{C_MUTED.hexval()[2:]}" size="8">· scored separately</font>',
        _style("tl_additional_kicker", fontSize=8, leading=11, spaceAfter=4),
    ))
    story.extend(_topline_pillar_rows(
        audit,
        pillar_keys=TOPLINE_PILLAR_GROUPS["additional"],
        header_label=None,  # no header row — flows under the kicker label
        subordinate=True,
    ))
    story.append(_sp(6))

    # Methodology footnote — declares the weighting so readers can decode the table.
    story.append(Paragraph(
        TOPLINE_PILLAR_WEIGHTS_NOTE,
        _style("tl_weights_note", fontSize=7, textColor=C_MUTED,
               fontName="Helvetica-Oblique", leading=10, spaceAfter=10),
    ))
    story.append(_sp(8))

    # Strongest / Priority Focus cards — derived from weighted pillars ONLY.
    sw_table = Table([[
        Paragraph(
            f'<font color="#{C_MUTED.hexval()[2:]}" size="7"><b>STRONGEST PILLAR</b></font><br/>'
            f'<br/>'
            f'<font color="#{_score_color(strongest[1]).hexval()[2:]}" size="11"><b>{strongest[0]}</b></font>'
            f'<font color="#{C_WHITE.hexval()[2:]}" size="11"> — {strongest[1]}%</font>',
            _style("tl_strong", fontSize=9, leading=14)),
        Paragraph(
            f'<font color="#{C_MUTED.hexval()[2:]}" size="7"><b>PRIORITY FOCUS</b></font><br/>'
            f'<br/>'
            f'<font color="#{_score_color(weakest[1]).hexval()[2:]}" size="11"><b>{weakest[0]}</b></font>'
            f'<font color="#{C_WHITE.hexval()[2:]}" size="11"> — {weakest[1]}%</font>',
            _style("tl_weak", fontSize=9, leading=14)),
    ]], colWidths=[225, 225])
    sw_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), C_CARD),
        ("BACKGROUND",    (1, 0), (1, 0), C_CARD),
        ("LINEBEFORE",    (0, 0), (0, 0), 3, _score_color(strongest[1])),
        ("LINEBEFORE",    (1, 0), (1, 0), 3, _score_color(weakest[1])),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(sw_table)

    # Health summary — computed only from weighted pillars. If all 4 weighted
    # pillars are ≥ 70%, the sentence shifts to point readers at the additional
    # checks instead of inventing urgency that doesn't exist.
    _weighted_values = list(weighted_scores.values())
    _healthy_weighted = sum(1 for s in _weighted_values if s >= 70)
    _total_weighted   = len(_weighted_values)
    if _healthy_weighted == _total_weighted:
        _summary_sentence = (
            "All weighted pillars are healthy. "
            "See additional checks above for further improvements."
        )
    elif _healthy_weighted > 0:
        _health_word = "pillar is" if _healthy_weighted == 1 else "pillars are"
        _summary_sentence = (
            f"{_healthy_weighted} weighted {_health_word} healthy. "
            f"{weakest[0]} needs immediate attention."
        )
    else:
        _summary_sentence = (
            f"All weighted pillars need attention. {weakest[0]} is the priority."
        )
    story.append(_sp(8))
    story.append(Paragraph(
        _summary_sentence,
        _style("tl_health_summary", fontSize=8, textColor=C_MUTED,
               fontName="Helvetica", leading=12)))
    story.append(PageBreak())

    # ── PAGE 3: WHAT'S BEHIND THE SCORE ──────────────────────────────────────
    story.append(_sp(12))
    story.append(Paragraph("What's behind the score", _S_H2()))
    story.append(_sp(8))

    _severity_colors = {"critical": C_DANGER, "warning": C_WARN, "info": C_PRIMARY}
    # Inter-card spacing tightened to keep three restructured cards on one page.
    for i, finding in enumerate(headline_findings, start=1):
        # Defensive: accept old tuple shape from any stale caller so the page
        # still renders if something hasn't been updated.
        if isinstance(finding, tuple):
            headline, body, severity = finding
            what_we_found  = body
            why_it_matters = ""
        else:
            headline       = finding["headline"]
            what_we_found  = finding.get("what_we_found", "")
            why_it_matters = finding.get("why_it_matters", "")
            severity       = finding.get("severity", "info")
        accent = _severity_colors.get(severity, C_PRIMARY)

        card_html = (
            f'<font color="#{C_MUTED.hexval()[2:]}" size="8"><b>{i}</b></font>  '
            f'<font color="#{C_WHITE.hexval()[2:]}"><b>{headline}</b></font>'
        )
        if what_we_found:
            card_html += (
                f'<br/><br/>'
                f'<font color="#{C_WHITE.hexval()[2:]}" size="8"><b>What we found:</b></font>'
                f' <font color="#{C_MUTED.hexval()[2:]}" size="8">{what_we_found}</font>'
            )
        if why_it_matters:
            card_html += (
                f'<br/>'
                f'<font color="#{C_WHITE.hexval()[2:]}" size="8"><b>Why it matters:</b></font>'
                f' <font color="#{C_MUTED.hexval()[2:]}" size="8">{why_it_matters}</font>'
            )

        card_content = Paragraph(
            card_html,
            _style(f"tl_find_{i}", fontSize=9, leading=13, spaceAfter=2),
        )
        card = Table([[card_content]], colWidths=[450])
        card.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_CARD),
            ("LINEBEFORE",    (0, 0), (-1, -1), 3, accent),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(card)
        story.append(_sp(6))

    story.append(PageBreak())

    # ── PAGE 4: WHAT AI READINESS UNLOCKS ─────────────────────────────────────
    story.append(_sp(12))
    story.append(Paragraph("What AI readiness unlocks", _S_H2()))
    story.append(_sp(10))

    for block in TOPLINE_UNLOCKS_BLOCKS:
        block_title       = block["heading"]
        block_body        = block["body"]
        powered_by_keys   = block["powered_by_pillars"]

        # Build the coloured "Powered by" line. Each pillar's score is coloured
        # using the existing _score_color() bands so the reader can see at a
        # glance how well-positioned they are to claim this opportunity.
        # Fails loudly via _topline_pillar_* if a key drifts.
        powered_by_parts = []
        for pkey in powered_by_keys:
            display = _topline_pillar_display(pkey)
            score   = _topline_pillar_score(audit, pkey)
            color   = _score_color(score)
            powered_by_parts.append({
                "display": display,
                "score":   score,
                "color":   color,
            })

        names_str = (
            f'<font color="#{C_MUTED.hexval()[2:]}">'
            + " · ".join(p["display"] for p in powered_by_parts)
            + "</font>"
        )
        scores_str = " · ".join(
            f'<font color="#{p["color"].hexval()[2:]}"><b>{p["score"]}%</b></font>'
            for p in powered_by_parts
        )
        powered_by_line = (
            f'<font color="#{C_MUTED.hexval()[2:]}" size="7"><b>POWERED BY:</b></font>  '
            f'<font size="7">{names_str}</font>  '
            f'<font color="#{C_MUTED.hexval()[2:]}" size="7">— your current scores:</font>  '
            f'<font size="7">{scores_str}</font>'
        )

        block_content = Paragraph(
            f'<font color="#{C_WHITE.hexval()[2:]}"><b>{block_title}</b></font><br/>'
            f'<br/>'
            f'{powered_by_line}<br/>'
            f'<br/>'
            f'<font color="#{C_MUTED.hexval()[2:]}" size="8">{block_body}</font>',
            _style(f"tl_unlock_{block_title[:12]}", fontSize=9, leading=13, spaceAfter=2))
        block_card = Table([[block_content]], colWidths=[450])
        block_card.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_CARD),
            ("LINEBEFORE",    (0, 0), (-1, -1), 3, C_TEAL),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(block_card)
        story.append(_sp(10))

    story.append(PageBreak())

    # ── PAGE 5: BOOK A WALKTHROUGH ────────────────────────────────────────────
    story.append(_sp(12))
    story.append(Paragraph("Book a 45-min walkthrough", _S_H2()))
    story.append(_sp(10))

    # Lead-in paragraph — bridges into the reply CTA
    lead_in = (
        f"Your audit identified {n_findings} findings — including {n_other + 1} in "
        f"{weakest[0]} that we'd want to talk through carefully. "
        f"A 45-minute walkthrough is the fastest way to get the priorities, the fixes, "
        f"and the comparisons against others in your category."
    )
    story.append(Paragraph(lead_in, _style("tl_cta_body", fontSize=10, textColor=C_WHITE,
                                            fontName="Helvetica", leading=16, spaceAfter=8)))
    story.append(_sp(16))

    # Primary CTA panel — reply prompt
    _cta_kicker, _cta_body = TOPLINE_CTA_PRIMARY
    primary_panel_content = Paragraph(
        f'<font color="#{C_WHITE.hexval()[2:]}"><b>{_cta_kicker}</b></font><br/>'
        f'<font color="#{C_MUTED.hexval()[2:]}" size="9">{_cta_body}</font>',
        _style("tl_cta_primary", fontSize=12, leading=18))
    primary_panel = Table([[primary_panel_content]], colWidths=[450])
    primary_panel.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_SURFACE),
        ("LINEBEFORE",    (0, 0), (-1, -1), 4, C_PRIMARY),
        ("LINETOP",       (0, 0), (-1, -1), 1, C_BORDER),
        ("LINEBELOW",     (0, 0), (-1, -1), 1, C_BORDER),
        ("LINEAFTER",     (0, 0), (-1, -1), 1, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 20),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 20),
        ("TOPPADDING",    (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
    ]))
    story.append(primary_panel)
    story.append(_sp(14))

    # Secondary fallback — muted, no panel treatment
    _fallback_url = TOPLINE_CTA_FALLBACK_URL
    _fallback_link = (
        f'<a href="{_fallback_url}">'
        f'<font color="#{C_PRIMARY.hexval()[2:]}">{_fallback_url.replace("https://", "")}</font>'
        f'</a>'
    )
    _fallback_text = TOPLINE_CTA_FALLBACK.format(url=_fallback_link)
    story.append(Paragraph(
        _fallback_text,
        _style("tl_cta_fallback", fontSize=8, textColor=C_MUTED,
               fontName="Helvetica", leading=12)))

    # ── Page background + page numbers ────────────────────────────────────────
    def _on_page_topline(canvas, doc_):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        page_num = canvas.getPageNumber()
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(18*mm, 12*mm, f"{domain}  ·  Pattern LLM Readiness — Topline Summary")
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

    doc.build(story, onFirstPage=_on_page_topline, onLaterPages=_on_page_topline)
    return buf.getvalue()
