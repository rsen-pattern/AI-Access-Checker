# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Full LLM Access Audit
Branded with Pattern design system.
4 Pillars: JavaScript Rendering · LLM.txt · Robots.txt · Schema
Plus: Live Bot Crawl, Sensitive Path Scan, Semantic Hierarchy Checks
"""

import streamlit as st
import base64
from core.branding import FAVICON_SVG

FAVICON_B64 = base64.b64encode(FAVICON_SVG.encode()).decode()

st.set_page_config(
    page_title="Pattern — LLM Access Checker",
    page_icon=f"data:image/svg+xml;base64,{FAVICON_B64}",
    layout="wide",
    initial_sidebar_state="collapsed",
)

from core.branding import (
    BRAND, PATTERN_LOGO_SVG,
)
from core.persistence import (
    get_secret,
    load_audit_by_id,
    is_history_authenticated,
)
from core.ui_audit_form import render_audit_form
from core.ui_history import render_history_tab
from core.ui_results import render_results
from core.ui_audit_pipeline import execute_audit_pipeline

# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI — PATTERN BRANDED
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown(f"""
<style>
    .stApp {{ background-color: {BRAND['bg_dark']}; }}
    .stApp > header {{ background-color: {BRAND['bg_dark']}; }}
    .stApp, .stApp p, .stApp span, .stApp li, .stApp div {{ color: {BRAND['white']}; }}
    h1, h2, h3, h4 {{ color: {BRAND['white']} !important; }}
    .stCaption, .stCaption p {{ color: {BRAND['text_secondary']} !important; }}
    div[data-testid="stExpander"] {{ background: {BRAND['bg_card']}; border: 1px solid {BRAND['border']}; border-radius: 12px; margin-bottom: 0.5rem; }}
    div[data-testid="stExpander"] details {{ border: none !important; }}
    div[data-testid="stExpander"] summary {{ color: {BRAND['white']}; }}
    div[data-testid="stExpander"] summary:hover {{ color: {BRAND['primary']}; }}
    div[data-testid="stMetric"] {{ background: {BRAND['bg_surface']}; border: 1px solid {BRAND['border']}; border-radius: 10px; padding: 12px 16px; }}
    div[data-testid="stMetric"] label {{ color: {BRAND['text_secondary']} !important; }}
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {{ color: {BRAND['white']} !important; }}
    .stButton > button[kind="primary"], button[data-testid="stBaseButton-primary"] {{ background: linear-gradient(135deg, {BRAND['purple']}, {BRAND['primary']}) !important; color: {BRAND['white']} !important; border: none !important; border-radius: 8px !important; font-weight: 600 !important; }}
    .stTextInput > div > div > input {{ background: {BRAND['bg_surface']} !important; border: 1px solid {BRAND['border']} !important; color: {BRAND['white']} !important; border-radius: 8px !important; }}
    .stTextInput > div > div > input:focus {{ border-color: {BRAND['primary']} !important; }}
    .stTextArea > div > div > textarea {{ background: {BRAND['bg_surface']} !important; border: 1px solid {BRAND['border']} !important; color: {BRAND['white']} !important; border-radius: 8px !important; }}
    .stProgress > div > div > div {{ background: linear-gradient(90deg, {BRAND['purple']}, {BRAND['primary']}) !important; }}
    .stAlert {{ background: {BRAND['bg_surface']} !important; border: 1px solid {BRAND['border']} !important; border-radius: 10px !important; }}
    hr {{ border-color: {BRAND['border']} !important; }}
    .section-divider {{ border-top: 1px solid {BRAND['border']}; margin: 2rem 0 1.5rem 0; }}
    .p-score-card {{ background: {BRAND['bg_card']}; border: 1px solid {BRAND['border']}; border-radius: 14px; padding: 1.2rem 0.8rem; text-align: center; }}
    .p-score-num {{ font-size: 2rem; font-weight: 800; line-height: 1.1; color: {BRAND['white']}; }}
    .p-score-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.5px; color: {BRAND['text_secondary']}; margin-top: 6px; }}
    .nav-pill-active {{ background: linear-gradient(135deg, {BRAND['purple']}, {BRAND['primary']}); color: {BRAND['white']} !important; border: none !important; border-radius: 20px !important; font-weight: 700 !important; padding: 6px 20px !important; }}
    .nav-pill {{ background: {BRAND['bg_surface']}; color: {BRAND['text_secondary']} !important; border: 1px solid {BRAND['border']} !important; border-radius: 20px !important; padding: 6px 20px !important; }}
</style>
""", unsafe_allow_html=True)


# ── HEADER (Pattern logo + LLM Access Checker) ───────────────────────────────
st.markdown(f'<div style="text-align:center;padding:1.5rem 0 0.3rem 0;">{PATTERN_LOGO_SVG}</div>', unsafe_allow_html=True)
st.markdown(f'<div style="text-align:center;padding:0.3rem 0;"><span style="font-size:1.4rem;font-weight:700;color:{BRAND["white"]};">LLM Access Checker</span></div>', unsafe_allow_html=True)
st.markdown(f'<div style="text-align:center;color:{BRAND["text_secondary"]};font-size:0.9rem;margin-bottom:1.5rem;">Full LLM Access Audit · JavaScript Rendering · LLM.txt · Robots.txt · Schema</div>', unsafe_allow_html=True)

# ── Router: initialise _view and _view_origin ─────────────────────────────────
if "_view" not in st.session_state:
    st.session_state["_view"] = "new"
if "_view_origin" not in st.session_state:
    st.session_state["_view_origin"] = "new"

# ── SHARED LINK: load audit from ?audit=<id> query param ─────────────────────
# Auth is intentionally NOT required here. Audit IDs are UUID v4 (122 bits of
# entropy) and shareable links are a supported workflow — anyone with the link
# can view the report without signing in. If private-by-default is ever needed,
# re-add `and is_history_authenticated()` to the condition below.
# Reload if the requested audit ID differs from the currently loaded one.
_qp_audit_id = st.query_params.get("audit")
_current_audit_id = st.session_state.get("_loaded_audit_id")
if _qp_audit_id and _qp_audit_id != _current_audit_id:
    _qp_row = load_audit_by_id(_qp_audit_id)
    if _qp_row and _qp_row.get("full_results"):
        _fr = _qp_row["full_results"]
        st.session_state["_audit"] = _fr
        st.session_state["_loaded_audit_id"] = _qp_audit_id
        _d = _qp_row.get("domain", "?")
        _dt = (_qp_row.get("audited_at") or "")[:10]
        _sc = _qp_row.get("overall_score", 0)
        st.session_state["_loaded_from_history"] = f"{_d} · {_dt} · {_sc}%"
        # Route to report view for shared links
        st.session_state["_view"] = "report"
    elif _qp_row:
        # Row found but full_results is missing (old save or failed write).
        # Clear the stale param so the user isn't stuck in a redirect loop.
        st.query_params.pop("audit", None)
        st.warning("The shared report could not be loaded (saved data is incomplete). Please run a new audit.")

# ── Bulk rerun queue processor ───────────────────────────────────────────────
# Must run BEFORE rendering so _pending_rerun is set before render_audit_form
# consumes it.
if st.session_state.get("_bulk_rerun_queue") and not st.session_state.get("_pending_rerun"):
    _bq_next_id = st.session_state["_bulk_rerun_queue"][0]
    _bq_row = load_audit_by_id(_bq_next_id)
    _bq_label_key_map = {
        "Homepage": "home", "Category 1": "cat1", "Category 2": "cat2",
        "Blog 1": "blog1", "Blog 2": "blog2", "Content 1": "blog1",
        "Content 2": "blog2", "Product 1": "prod1", "Product 2": "prod2",
    }
    if _bq_row and _bq_row.get("full_results"):
        _bfr = _bq_row["full_results"]
        _bq_inv = {v: k for k, v in (_bfr.get("url_labels") or {}).items()}
        for _lbl, _wk in _bq_label_key_map.items():
            if _lbl in _bq_inv:
                st.session_state[_wk] = _bq_inv[_lbl]
        st.session_state["no_blog"]            = bool(_bfr.get("no_blog", False))
        st.session_state["run_bot_crawl"]      = bool(_bfr.get("bot_crawl_results"))
        st.session_state.pop("_audit", None)
        st.session_state.pop("_loaded_audit_id", None)
        st.session_state.pop("_loaded_from_history", None)
        st.query_params.pop("audit", None)
        st.session_state["_bulk_rerun_current_id"] = str(_bq_next_id)
        st.session_state["_pending_rerun"] = True
        st.session_state["_view"] = "new"
    else:
        # Skip row — no usable full_results
        st.session_state["_bulk_rerun_queue"].pop(0)
        _bq_prog = st.session_state.get("_bulk_rerun_progress", {"total": 0, "done": 0})
        _bq_prog["done"] = _bq_prog.get("done", 0) + 1
        st.session_state["_bulk_rerun_progress"] = _bq_prog

# ── Bulk rerun status banner ─────────────────────────────────────────────────
if st.session_state.get("_bulk_rerun_queue") or st.session_state.get("_bulk_rerun_current_id"):
    _bq_prog = st.session_state.get("_bulk_rerun_progress", {"total": 0, "done": 0})
    _bq_done  = _bq_prog.get("done", 0)
    _bq_total = _bq_prog.get("total", 1)
    st.info(f"🔄 Bulk rerun in progress — {_bq_done}/{_bq_total} complete. Do not close this tab.")

# Apply any pending prefill values BEFORE widgets are rendered
_PREFILL_KEYS = ["home", "cat1", "cat2", "blog1", "blog2", "prod1", "prod2", "no_blog", "run_bot_crawl"]
for _pk in _PREFILL_KEYS:
    _pfk = f"_prefill_{_pk}"
    if _pfk in st.session_state:
        st.session_state[_pk] = st.session_state.pop(_pfk)

# ═══════════════════════════════════════════════════════════════════════════════
# TOP NAV — pill buttons (only in new/history views, only when authenticated)
# ═══════════════════════════════════════════════════════════════════════════════
_current_view = st.session_state["_view"]

if _current_view in ("new", "history") and is_history_authenticated():
    _nav_c1, _nav_c2, _nav_spacer = st.columns([1, 1, 6])
    with _nav_c1:
        if st.button(
            "🔍  New Audit",
            key="_nav_new",
            type="primary" if _current_view == "new" else "secondary",
            use_container_width=True,
        ):
            st.session_state["_view"] = "new"
            st.rerun()
    with _nav_c2:
        if st.button(
            "📋  Past Audits",
            key="_nav_history",
            type="primary" if _current_view == "history" else "secondary",
            use_container_width=True,
        ):
            st.session_state["_view"] = "history"
            st.rerun()
    st.markdown("<div style='margin-bottom:12px'></div>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# VIEW ROUTER
# ═══════════════════════════════════════════════════════════════════════════════

_view = st.session_state["_view"]

if _view == "history":
    render_history_tab()

elif _view == "report":
    _audit_data = st.session_state.get("_audit")
    if _audit_data:
        render_results(_audit_data, get_secret)
    else:
        st.warning("No report loaded. Please select an audit from Past Audits or run a new audit.")
        if st.button("← Back to Past Audits", key="_back_empty"):
            st.session_state["_view"] = "history"
            st.rerun()

else:
    # _view == "new"
    all_url_inputs, no_blog, run_bot_crawl, run_audit = render_audit_form()

    # ── AUDIT EXECUTION ───────────────────────────────────────────────────────
    if run_audit:
        _a = execute_audit_pipeline(
            all_url_inputs=all_url_inputs,
            no_blog=no_blog,
            run_bot_crawl=run_bot_crawl,
            get_secret_fn=get_secret,
        )
        if _a is not None:
            # New audit completed — populate header label and route to report view
            from urllib.parse import urlparse as _up
            _a_urls = _a.get("all_test_urls", [])
            _a_dom  = _up(_a_urls[0]).netloc if _a_urls else "?"
            import time as _time
            _a_date = _time.strftime("%Y-%m-%d")
            _a_sc   = _a.get("overall", 0)
            st.session_state["_loaded_from_history"] = f"{_a_dom} · {_a_date} · {_a_sc}%"
            st.session_state["_view"] = "report"
            st.session_state["_view_origin"] = "new"
            st.rerun()
