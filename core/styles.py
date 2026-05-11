# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Streamlit CSS injection.

All custom CSS lives here so both entry points (ai_access_checker.py and any
future pages/) import a single function rather than duplicating a ~70-line
st.markdown block. The BRAND dict from core/branding.py is the only dependency.
"""

import streamlit as st

from core.branding import BRAND


def inject_global_styles() -> None:
    """Inject the full Pattern design-system CSS into the current Streamlit page."""
    st.markdown(_CSS.format(**BRAND), unsafe_allow_html=True)


# ─── CSS TEMPLATE ─────────────────────────────────────────────────────────────
# Uses str.format() with BRAND keys so the palette is the single source of truth.
# Double-braces {{ }} are literal braces in the CSS output.

_CSS = """
<style>
    /* ── Base ──────────────────────────────────────────────────────────────── */
    .stApp {{ background-color: {bg_dark}; }}
    .stApp > header {{ background-color: {bg_dark}; }}
    .stApp, .stApp p, .stApp span, .stApp li, .stApp div {{ color: {white}; }}
    h1, h2, h3, h4 {{ color: {white} !important; }}
    .stCaption, .stCaption p {{ color: {text_secondary} !important; }}

    /* ── Expanders ──────────────────────────────────────────────────────────── */
    div[data-testid="stExpander"] {{
        background: {bg_card};
        border: 1px solid {border};
        border-radius: 12px;
        margin-bottom: 0.5rem;
    }}
    div[data-testid="stExpander"] details {{ border: none !important; }}
    div[data-testid="stExpander"] summary {{ color: {white}; }}
    div[data-testid="stExpander"] summary:hover {{ color: {primary}; }}

    /* ── Metric cards ────────────────────────────────────────────────────────── */
    div[data-testid="stMetric"] {{
        background: {bg_surface};
        border: 1px solid {border};
        border-radius: 10px;
        padding: 12px 16px;
    }}
    div[data-testid="stMetric"] label {{ color: {text_secondary} !important; }}
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {{
        color: {white} !important;
    }}

    /* ── Primary buttons ─────────────────────────────────────────────────────── */
    .stButton > button[kind="primary"],
    button[data-testid="stBaseButton-primary"] {{
        background: linear-gradient(135deg, {purple}, {primary}) !important;
        color: {white} !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
    }}

    /* ── Focus-visible ring (meets WCAG 2.4.7 on dark backgrounds) ──────────── */
    .stButton > button:focus-visible,
    button[data-testid]:focus-visible,
    input:focus-visible,
    textarea:focus-visible,
    select:focus-visible {{
        outline: 2px solid {primary} !important;
        outline-offset: 2px !important;
    }}

    /* ── Inputs ──────────────────────────────────────────────────────────────── */
    .stTextInput > div > div > input {{
        background: {bg_surface} !important;
        border: 1px solid {border} !important;
        color: {white} !important;
        border-radius: 8px !important;
    }}
    .stTextInput > div > div > input:focus {{
        border-color: {primary} !important;
    }}
    .stTextArea > div > div > textarea {{
        background: {bg_surface} !important;
        border: 1px solid {border} !important;
        color: {white} !important;
        border-radius: 8px !important;
    }}

    /* ── Progress bar ────────────────────────────────────────────────────────── */
    .stProgress > div > div > div {{
        background: linear-gradient(90deg, {purple}, {primary}) !important;
    }}

    /* ── Alerts ──────────────────────────────────────────────────────────────── */
    .stAlert {{
        background: {bg_surface} !important;
        border: 1px solid {border} !important;
        border-radius: 10px !important;
    }}

    /* ── Dividers ────────────────────────────────────────────────────────────── */
    hr {{ border-color: {border} !important; }}
    .section-divider {{
        border-top: 1px solid {border};
        margin: 2rem 0 1.5rem 0;
    }}

    /* ── Score cards ─────────────────────────────────────────────────────────── */
    .p-score-card {{
        background: {bg_card};
        border: 1px solid {border};
        border-radius: 14px;
        padding: 1.2rem 0.8rem;
        text-align: center;
    }}
    .p-score-num {{
        font-size: 2rem;
        font-weight: 800;
        line-height: 1.1;
        color: {white};
    }}
    .p-score-label {{
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: {text_secondary};
        margin-top: 6px;
    }}

    /* ── Score legend ────────────────────────────────────────────────────────── */
    .p-score-legend {{
        display: flex;
        gap: 8px;
        justify-content: center;
        flex-wrap: wrap;
        margin: 6px 0 14px 0;
    }}
    .p-score-legend-pill {{
        font-size: 11px;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 12px;
        letter-spacing: 0.5px;
    }}

    /* ── Nav pills ───────────────────────────────────────────────────────────── */
    .nav-pill-active {{
        background: linear-gradient(135deg, {purple}, {primary});
        color: {white} !important;
        border: none !important;
        border-radius: 20px !important;
        font-weight: 700 !important;
        padding: 6px 20px !important;
    }}
    .nav-pill {{
        background: {bg_surface};
        color: {text_secondary} !important;
        border: 1px solid {border} !important;
        border-radius: 20px !important;
        padding: 6px 20px !important;
    }}

    /* ── History row hover ───────────────────────────────────────────────────── */
    .hist-row {{ transition: background 0.15s ease; cursor: pointer; }}
    .hist-row:hover {{ background: {bg_card_hover} !important; }}

    /* ── Inline validation ───────────────────────────────────────────────────── */
    .p-field-error {{
        color: {danger};
        font-size: 12px;
        margin-top: 2px;
        margin-bottom: 4px;
    }}
    .stTextInput > div > div > input.p-input-error {{
        border-color: {danger} !important;
    }}
</style>
"""


def score_legend_html() -> str:
    """Return the score legend as an HTML snippet using BRAND colours."""
    bands = [
        ("A", "≥ 85", BRAND["teal"]),
        ("B", "≥ 70", BRAND["primary"]),
        ("C", "≥ 50", BRAND["warning"]),
        ("D", "≥ 35", "#ff8c00"),
        ("F", "< 35",  BRAND["danger"]),
    ]
    pills = "".join(
        f'<span class="p-score-legend-pill" '
        f'style="background:{c}22;color:{c};border:1px solid {c}44;">'
        f'{letter}&nbsp;&nbsp;{threshold}</span>'
        for letter, threshold, c in bands
    )
    return f'<div class="p-score-legend" role="list" aria-label="Score grade bands">{pills}</div>'
