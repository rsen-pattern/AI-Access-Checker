# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Full LLM Access Audit
Branded with Pattern design system.
4 Pillars: JavaScript Rendering · LLM.txt · Robots.txt · Schema
Plus: Live Bot Crawl, Sensitive Path Scan, Semantic Hierarchy Checks
"""

import streamlit as st
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from protego import Protego
import json
import re
import time
import math
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from report_pdf import generate_report_pdf as _generate_report_pdf
from core.branding import (
    BRAND, PATTERN_LOGO_SVG, FAVICON_SVG, PILLAR_INFO,
    BROWSER_UA, SENSITIVE_PATHS, EXPECTED_SCHEMA_TYPES, SCHEMA_KEY_FIELDS,
)
from core.persistence import (
    get_secret,
    get_supabase,
    save_audit_to_db,
    update_audit_in_db,
    load_audit_history,
    load_audit_by_id,
)
from core.ui_helpers import (
    _make_json_safe,
    normalise_url,
    _page_type_from_label,
    fetch,
    generate_gauge_svg,
    brand_score_bar,
    brand_pill,
    brand_status,
    pillar_header,
    _md_to_html,
    pillar_explainer,
)
from core.ui_audit_form import render_audit_form
from core.ui_history import render_history_tab
from core.ui_recommendations import build_recommendations

FAVICON_B64 = base64.b64encode(FAVICON_SVG.encode()).decode()

# ─── CONFIG ───────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Pattern — LLM Access Checker",
    page_icon=f"data:image/svg+xml;base64,{FAVICON_B64}",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ─── AI BOT DEFINITIONS ──────────────────────────────────────────────────────
AI_BOTS = {
    "OpenAI": {
        "GPTBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
        "ChatGPT-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
        "OAI-SearchBot": "OAI-SearchBot/1.0; +https://openai.com/searchbot",
    },
    "Anthropic": {
        "ClaudeBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
        "Claude-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
    },
    "Google": {
        "Google-Extended": "Mozilla/5.0 (compatible; Google-Extended)",
        "Googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    },
    "Perplexity": {
        "PerplexityBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
        "Perplexity-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
    },
    "Other AI": {
        "CCBot": "CCBot/2.0 (https://commoncrawl.org/faq/)",
        "Bytespider": "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
        "Meta-ExternalAgent": "Mozilla/5.0 (compatible; Meta-ExternalAgent/1.0; +https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "Amazonbot": "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
        "Applebot-Extended": "Mozilla/5.0 (Applebot-Extended/0.3; +http://www.apple.com/go/applebot)",
        "Cohere-ai": "Mozilla/5.0 (compatible; cohere-ai)",
    },
}




# ═══════════════════════════════════════════════════════════════════════════════
# JS RENDERING API — CASCADING FALLBACK
# ═══════════════════════════════════════════════════════════════════════════════

# ─── AUDIT LOGIC: all imported from checks.py (single source of truth) ─────────
from core.llm_access_checks import (
    AI_BOTS, BOT_TYPES, KEY_AI_BOTS, SENSITIVE_PATHS, ALL_SENSITIVE_PATHS,
    CMS_PROFILES, SCHEMA_KEY_FIELDS, EXPECTED_SCHEMA_TYPES, AUTHORITATIVE_DOMAINS,
    GRADE_THRESHOLDS, get_grade, ScoreBuilder, compute_overall,
    fetch, normalise_url, extract_jsonld, flatten_schema_types, detect_cms,
    fetch_js_rendered, analyse_html_content, detect_js_frameworks, compare_html_vs_js,
    check_js_rendering, check_cloudflare_bot_protection, check_robots_crawlability,
    run_live_bot_crawl, validate_schema_fields, check_schema_meta,
    check_llm_discoverability, check_security_exposure,
    pattern_brain_analysis, analyse_schema_quality, analyse_content_clarity, analyse_entity_coherence,
    ai_analyse_js_gap, analyse_semantic_hierarchy, analyse_robots_access, analyse_llm_discoverability,
)

def check_semantic_hierarchy(url):
    """Check heading structure, semantic elements, meta directives per page."""
    resp, err = fetch(url)
    if err or not resp or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}
    from bs4 import BeautifulSoup
    import re as _re
    soup = BeautifulSoup(resp.text, "html.parser")
    results = {"headings": [], "hierarchy_ok": True, "semantic_elements": {},
               "meta_tags": [], "x_robots_tag": None, "nosnippet_elements": 0,
               "html_length": len(resp.text), "text_length": 0}
    headings = soup.find_all(_re.compile(r'^h[1-6]$'))
    for h in headings:
        results["headings"].append({"level": int(h.name[1]), "text": h.get_text(strip=True)[:120]})
    levels = [int(h.name[1]) for h in headings]
    for i in range(1, len(levels)):
        if levels[i] > levels[i-1] + 1:
            results["hierarchy_ok"] = False; break
    for tag in ["article", "section", "nav", "aside", "main", "header", "footer", "figure", "time"]:
        c = len(soup.find_all(tag))
        if c: results["semantic_elements"][tag] = c
    for tag in soup.find_all("meta", attrs={"name": True}):
        name = tag.get("name", "").lower()
        if name in ("robots", "googlebot", "google-extended"):
            results["meta_tags"].append({"name": name, "content": tag.get("content", "")})
    results["x_robots_tag"] = resp.headers.get("X-Robots-Tag")
    results["nosnippet_elements"] = len(soup.find_all(attrs={"data-nosnippet": True}))
    results["text_length"] = len(soup.get_text(separator=" ", strip=True))
    return results





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
</style>
""", unsafe_allow_html=True)


# ── HEADER (Pattern logo + LLM Access Checker) ───────────────────────────────
st.markdown(f'<div style="text-align:center;padding:1.5rem 0 0.3rem 0;">{PATTERN_LOGO_SVG}</div>', unsafe_allow_html=True)
st.markdown(f'<div style="text-align:center;padding:0.3rem 0;"><span style="font-size:1.4rem;font-weight:700;color:{BRAND["white"]};">LLM Access Checker</span></div>', unsafe_allow_html=True)
st.markdown(f'<div style="text-align:center;color:{BRAND["text_secondary"]};font-size:0.9rem;margin-bottom:1.5rem;">Full LLM Access Audit · JavaScript Rendering · LLM.txt · Robots.txt · Schema</div>', unsafe_allow_html=True)

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
    elif _qp_row:
        # Row found but full_results is missing (old save or failed write).
        # Clear the stale param so the user isn't stuck in a redirect loop.
        st.query_params.pop("audit", None)
        st.warning("The shared report could not be loaded (saved data is incomplete). Please run a new audit.")

# ── Bulk rerun queue processor ───────────────────────────────────────────────
# Must run BEFORE tabs so _pending_rerun is set before tab_audit renders
# and run_audit consumes it.
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

tab_audit, tab_history = st.tabs(["\U0001f50d  New Audit", "\U0001f4cb  Past Audits"])
with tab_audit:
    all_url_inputs, no_blog, run_bot_crawl, run_audit = render_audit_form()

with tab_history:
    render_history_tab()


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

if run_audit or "_audit" in st.session_state:
    if run_audit:
        st.session_state.pop("_audit", None)
        st.session_state.pop("_loaded_audit_id", None)
        st.session_state.pop("_loaded_from_history", None)
        st.query_params.pop("audit", None)
        # Validate all 7 URLs are provided
        missing = [name for name, u in all_url_inputs.items() if not u or not u.strip()]
        if missing:
            st.error(f"Please provide all required URLs. Missing: {', '.join(missing)}")
            st.stop()

        all_test_urls = [normalise_url(u.strip()) for u in all_url_inputs.values() if u and u.strip()]
        url = all_test_urls[0]  # homepage
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # URL labels and page types for display and scoring
        url_labels = {}
        url_page_types = {}
        for name, u in all_url_inputs.items():
            if u and u.strip():
                # Remap blog labels when no_blog is flagged
                display_name = name.replace("Blog", "Content") if (no_blog and "Blog" in name) else name
                norm = normalise_url(u.strip())
                url_labels[norm] = display_name
                url_page_types[norm] = _page_type_from_label(display_name)

        # ── ESTIMATED TIME BREAKDOWN ──────────────────────────────────────────
        n_pages = len(all_test_urls)
        has_js_api = any(get_secret(k, "") for k in ["SCRAPINGBEE_API_KEY", "SCRAPFLY_API_KEY", "BROWSERLESS_API_KEY"])
        has_bifrost = bool(get_secret("BIFROST_API_KEY", ""))

        # Per-step timing estimates (seconds)
        t_js        = n_pages * (18 if has_js_api else 5)   # JS render is slow if API key present
        t_robots    = 35   # robots + Cloudflare live bot tests (16 bots × ~2s)
        t_schema    = n_pages * 4
        t_llm       = 15   # llm.txt paths + AI info page checks
        t_security  = 25   # sensitive path crawls (4 categories × ~3-4 paths each)
        t_botcrawl  = 30 if run_bot_crawl else 0
        t_brain     = 20 if has_bifrost else 0
        total_est   = t_js + t_robots + t_schema + t_llm + t_security + t_botcrawl + t_brain
        total_min   = total_est // 60
        total_sec   = total_est % 60
        time_label  = f"{total_min}m {total_sec}s" if total_min > 0 else f"~{total_sec}s"

        # Show the timing breakdown card
        js_label       = f"~{t_js}s {'(JS render API active)' if has_js_api else '(HTML-only, add render API key for full comparison)'}"
        robots_label   = f"~{t_robots}s (robots.txt + 16 live bot crawl tests + Cloudflare check)"
        schema_label   = f"~{t_schema}s ({n_pages} pages × schema + entity)"
        llm_label      = f"~{t_llm}s (llm.txt variants + AI info page detection + well-known files)"
        security_label = f"~{t_security}s (critical / backend / customer / HTML exposure checks)"
        botcrawl_label = f"~{t_botcrawl}s (sending requests as 16 AI bots)" if run_bot_crawl else "Skipped"
        brain_label    = f"~{t_brain}s (4 AI analysis calls via Bifrost)" if has_bifrost else "Skipped (add BIFROST_API_KEY to enable)"

        st.markdown(f"""
    <div style="background:{BRAND['bg_card']};border:1px solid {BRAND['border']};border-radius:12px;padding:16px 20px;margin-bottom:16px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <span style="font-weight:700;color:{BRAND['white']};font-size:15px;">⏱ Estimated Audit Time: {time_label}</span>
        <span style="color:{BRAND['text_secondary']};font-size:12px;">{n_pages} pages · {'JS render API active' if has_js_api else 'HTML-only mode'}</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px 20px;">
        <div style="color:{BRAND['text_secondary']};font-size:12px;"><span style="color:{BRAND['primary']};font-weight:600;">P1 JS Rendering</span> &nbsp;{js_label}</div>
        <div style="color:{BRAND['text_secondary']};font-size:12px;"><span style="color:{BRAND['primary']};font-weight:600;">P2 Robots & Crawl</span> &nbsp;{robots_label}</div>
        <div style="color:{BRAND['text_secondary']};font-size:12px;"><span style="color:{BRAND['primary']};font-weight:600;">P3 Schema & Entity</span> &nbsp;{schema_label}</div>
        <div style="color:{BRAND['text_secondary']};font-size:12px;"><span style="color:{BRAND['primary']};font-weight:600;">P4 AI Discoverability</span> &nbsp;{llm_label}</div>
        <div style="color:{BRAND['text_secondary']};font-size:12px;"><span style="color:{BRAND['warning']};font-weight:600;">Security Check</span> &nbsp;{security_label}</div>
        <div style="color:{BRAND['text_secondary']};font-size:12px;"><span style="color:{BRAND['teal']};font-weight:600;">Live Bot Crawl</span> &nbsp;{botcrawl_label}</div>
        <div style="color:{BRAND['text_secondary']};font-size:12px;"><span style="color:{BRAND['purple']};font-weight:600;">Pattern Brain</span> &nbsp;{brain_label}</div>
      </div>
      <div style="margin-top:10px;padding-top:10px;border-top:1px solid {BRAND['border']};color:{BRAND['text_secondary']};font-size:11px;">
        ℹ️ The audit makes live HTTP requests to your site as each AI bot. Do not close this tab.
        {'Longer because JS rendering API is active — each page is loaded twice for full comparison.' if has_js_api else ''}
      </div>
    </div>
    """, unsafe_allow_html=True)

        audit_start = time.time()
        progress = st.progress(0, text=f"Starting audit — estimated {time_label}…")

        # ── PILLAR 1: JS RENDERING (all pages — parallelized) ────────────────
        progress.progress(3, text=f"[1/6] JS Rendering — checking {n_pages} pages… (est. {js_label.split('(')[0].strip()})")
        js_results = {}
        with ThreadPoolExecutor(max_workers=3) as _pool:
            _futs = {_pool.submit(check_js_rendering, u, get_secret, url_page_types.get(u, "general")): u for u in all_test_urls}
            for _done_count, _f in enumerate(as_completed(_futs), 1):
                _u = _futs[_f]
                try:
                    js_results[_u] = _f.result(timeout=60)
                except Exception:
                    js_results[_u] = {"score": 0, "error": "timeout/crash"}
                elapsed = round(time.time() - audit_start)
                progress.progress(3 + round(14 * (_done_count / n_pages)),
                    text=f"[1/6] JS Rendering — {_done_count}/{n_pages} done · {elapsed}s elapsed")
        js_score = round(sum(r.get("score", 0) for r in js_results.values()) / len(js_results))

        # ── PILLAR 2: ROBOTS & CRAWLABILITY (site-level) ──────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(18, text=f"[2/6] Robots & Crawlability — fetching robots.txt + Cloudflare check… · {elapsed}s elapsed")
        homepage_resp, _ = fetch(url)
        homepage_html = homepage_resp.text if homepage_resp else ""
        progress.progress(20, text=f"[2/6] Robots & Crawlability — running 16 live bot crawl tests… · {elapsed}s elapsed")
        robots_result = check_robots_crawlability(base_url, homepage_html)
        robots_score = robots_result.get("score", 0)

        # ── PILLAR 3: SCHEMA & ENTITY (all pages — parallelized) ─────────────
        schema_results = {}
        with ThreadPoolExecutor(max_workers=3) as _pool:
            _futs = {_pool.submit(check_schema_meta, u, url_page_types.get(u, "general")): u for u in all_test_urls}
            for _done_count, _f in enumerate(as_completed(_futs), 1):
                _u = _futs[_f]
                try:
                    schema_results[_u] = _f.result(timeout=60)
                except Exception:
                    schema_results[_u] = {"score": 0, "error": "timeout/crash"}
                elapsed = round(time.time() - audit_start)
                progress.progress(38 + round(14 * (_done_count / n_pages)),
                    text=f"[3/6] Schema & Entity — {_done_count}/{n_pages} done · {elapsed}s elapsed")
        schema_score = round(sum(r.get("score", 0) for r in schema_results.values()) / len(schema_results))

        # ── PILLAR 4: AI DISCOVERABILITY (site-level) ──────────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(55, text=f"[4/7] AI Discoverability — llm.txt, AI info page, well-known files… · {elapsed}s elapsed")
        llm_result = check_llm_discoverability(base_url, homepage_html)
        llm_score = llm_result.get("score", 0)
        # No-blog penalty: AI cannot learn about the brand without editorial content
        if no_blog:
            llm_score = max(0, llm_score - 10)

        # ── SEMANTIC HIERARCHY (all pages) ────────────────────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(62, text=f"[5/7] Semantic Hierarchy — checking heading structure… · {elapsed}s elapsed")
        semantic_results = {}
        with ThreadPoolExecutor(max_workers=3) as _pool:
            _futs = {_pool.submit(check_semantic_hierarchy, u): u for u in all_test_urls}
            for _f in as_completed(_futs):
                _u = _futs[_f]
                try:
                    semantic_results[_u] = _f.result(timeout=60)
                except Exception:
                    semantic_results[_u] = {"score": 0, "error": "timeout/crash"}

        # ── SECURITY CHECK (separate score) ───────────────────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(67, text=f"[6/7] Security Check — probing sensitive paths as AI bots… · {elapsed}s elapsed (this step takes ~{t_security}s)")
        security_result = check_security_exposure(
            base_url,
            robots_raw=robots_result.get("raw", ""),
            homepage_html=homepage_html,
            sensitive_paths=robots_result.get("sensitive_paths", {}),
        )
        # Apply robots.txt Disallow coverage deduction inline (ai_access_checker.py
        # is re-executed on every Streamlit rerun; checks.py is only loaded once).
        _sensitive = robots_result.get("sensitive_paths", {})
        _no_disallow = [p for p, r in _sensitive.items()
                        if not r.get("blocked", not r.get("accessible_per_robots", False))]
        if _no_disallow:
            _deduction = min(len(_no_disallow) * 5, 25)
            _base_score = security_result.get("score", 100)
            _new_score = max(0, _base_score - _deduction)
            security_result["score"] = _new_score
            security_result.setdefault("findings", {})["no_disallow"] = _no_disallow
            security_result.setdefault("items", []).append({
                "label": f"{len(_no_disallow)} sensitive path(s) have no Disallow rule in robots.txt (−5 each, max −25)",
                "points": -_deduction,
                "status": "fail",
                "category": "no_disallow",
            })
        security_score = security_result.get("score", 100)

        # ── LIVE BOT CRAWL (homepage) ─────────────────────────────────────────
        bot_crawl_results = {}
        if run_bot_crawl:
            elapsed = round(time.time() - audit_start)
            progress.progress(80, text=f"[7/7] Live Bot Crawl — sending requests as 16 AI bots… · {elapsed}s elapsed (~{t_botcrawl}s remaining)")
            bot_crawl_results = run_live_bot_crawl(url, robots_result.get("parser"))

        # ── FINAL SCORING ─────────────────────────────────────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(93, text=f"Calculating scores and grades… · {elapsed}s elapsed")
        overall_result = compute_overall(
            {"js": js_score, "robots": robots_score, "schema": schema_score, "llm": llm_score},
            robots_missing=not robots_result.get("found", False),
        )
        overall = overall_result["score"]
        overall_grade = overall_result["grade"]

        total_elapsed = round(time.time() - audit_start)
        time.sleep(0.3)
        progress.progress(100, text=f"Audit complete in {total_elapsed}s!")
        time.sleep(0.5)
        progress.empty()
        # ── Save results to session state so they survive reruns ──────────
        st.session_state["_audit"] = {
            "all_test_urls": all_test_urls,
            "url_labels":    url_labels,
            "js_results":    js_results,
            "js_score":      js_score,
            "robots_result": robots_result,
            "robots_score":  robots_score,
            "schema_results": schema_results,
            "schema_score":  schema_score,
            "llm_result":    llm_result,
            "llm_score":     llm_score,
            "semantic_results": semantic_results,
            "security_result": security_result,
            "security_score": security_score,
            "bot_crawl_results": bot_crawl_results,
            "overall":       overall,
            "overall_grade": overall_grade,
            "overall_result": overall_result,
            "no_blog":       no_blog,
        }

    # ── Unpack results (fresh audit or cached) ────────────────────────────
    _a              = st.session_state["_audit"]
    all_test_urls   = _a.get("all_test_urls", [])
    url_labels      = _a.get("url_labels", {})
    js_results      = _a.get("js_results", {})
    js_score        = _a.get("js_score", 0)
    robots_result   = _a.get("robots_result", {"found": False, "score": 0})
    robots_score    = _a.get("robots_score", 0)
    schema_results  = _a.get("schema_results", {})
    schema_score    = _a.get("schema_score", 0)
    llm_result      = _a.get("llm_result", {})
    llm_score       = _a.get("llm_score", 0)
    semantic_results = _a.get("semantic_results", {})
    security_result = _a.get("security_result", {"found": False, "score": 0})
    security_score  = _a.get("security_score", 0)
    bot_crawl_results = _a.get("bot_crawl_results", {})
    overall         = _a.get("overall", 0)
    overall_grade   = _a.get("overall_grade", "?")
    overall_result  = _a.get("overall_result", {"score": overall, "grade": overall_grade})
    no_blog         = _a.get("no_blog", False)
    url             = all_test_urls[0]
    parsed          = urlparse(url)
    base_url        = f"{parsed.scheme}://{parsed.netloc}"

    # Compute semantic hierarchy score from per-page results (no pre-computed score)
    _sem_scores = []
    for _sr in semantic_results.values():
        if not _sr.get("error"):
            _ps = 100
            if not _sr.get("hierarchy_ok", True):              _ps -= 30
            if not _sr.get("semantic_elements"):               _ps -= 20
            _hl = _sr.get("html_length", 0)
            _tl = _sr.get("text_length", 0)
            if _hl > 0 and (_tl / _hl * 100) < 15:            _ps -= 20
            if _sr.get("nosnippet_elements", 0) > 5:           _ps -= 10
            _sem_scores.append(max(0, _ps))
    semantic_score = round(sum(_sem_scores) / len(_sem_scores)) if _sem_scores else 0
    # Keep _audit in sync so every path (fresh run, history load, shared link)
    # has the same key set.
    st.session_state["_audit"]["semantic_score"] = semantic_score

    # ── Save / update audit to Supabase (fresh runs only) ────────────────
    if run_audit:
        _full_results_payload = {
            "all_test_urls":     all_test_urls,
            "url_labels":        url_labels,
            "js_results":        js_results,
            "js_score":          js_score,
            "robots_result":     robots_result,
            "robots_score":      robots_score,
            "schema_results":    schema_results,
            "schema_score":      schema_score,
            "llm_result":        llm_result,
            "llm_score":         llm_score,
            "semantic_results":  semantic_results,
            "semantic_score":    semantic_score,
            "security_result":   security_result,
            "security_score":    security_score,
            "bot_crawl_results": bot_crawl_results,
            "overall":           overall,
            "overall_grade":     overall_grade,
            "overall_result":    overall_result,
            "no_blog":           no_blog,
            "pattern_brain":     None,  # populated after Pattern Brain renders below
        }
        _pillar_scores_payload = {
            "JS Rendering":       js_score,
            "Robots & Crawl":     robots_score,
            "Schema & Entity":    schema_score,
            "AI Discoverability": llm_score,
            "Semantic Hierarchy": semantic_score,
            "Security":           security_score,
        }
        _bulk_id = st.session_state.pop("_bulk_rerun_current_id", None)
        if _bulk_id:
            # Bulk rerun — UPDATE existing row in place
            _saved_id, _save_err = update_audit_in_db(
                audit_id=_bulk_id,
                overall=overall,
                pillar_scores_dict=_pillar_scores_payload,
                audited_urls=all_test_urls,
                full_results=_full_results_payload,
            )
            if _save_err:
                st.warning(f"Bulk rerun: could not update row {_bulk_id} — {_save_err}")
            # Advance queue and update progress
            if st.session_state.get("_bulk_rerun_queue"):
                st.session_state["_bulk_rerun_queue"].pop(0)
            _bq_prog = st.session_state.get("_bulk_rerun_progress", {"total": 0, "done": 0})
            _bq_prog["done"] = _bq_prog.get("done", 0) + 1
            st.session_state["_bulk_rerun_progress"] = _bq_prog
            if not st.session_state.get("_bulk_rerun_queue"):
                # All done — clean up and notify
                st.success(f"Bulk rerun complete — all {_bq_prog['total']} audits updated with fresh scores.")
                st.session_state.pop("_bulk_rerun_progress", None)
            else:
                # More items left — continue immediately
                st.rerun()
        else:
            # Normal single audit — check for existing record and ask user what to do
            _existing = load_audit_history(domain=parsed.netloc, limit=1)
            if _existing and get_supabase() is not None:
                # Store pending data; confirmation prompt rendered in tab_audit below
                st.session_state["_pending_overwrite"] = {
                    "existing_id":   _existing[0]["id"],
                    "existing_date": _existing[0].get("audited_at", "")[:10],
                    "domain":        parsed.netloc,
                    "overall":       overall,
                    "pillar_scores": _pillar_scores_payload,
                    "urls":          all_test_urls,
                    "full_results":  _full_results_payload,
                }
            else:
                _saved_id, _save_err = save_audit_to_db(
                    domain=parsed.netloc,
                    overall=overall,
                    pillar_scores_dict=_pillar_scores_payload,
                    audited_urls=all_test_urls,
                    full_results=_full_results_payload,
                )
                if _saved_id:
                    st.query_params["audit"] = str(_saved_id)
                    st.session_state["_loaded_audit_id"] = str(_saved_id)
                elif get_supabase() is None:
                    st.info("Add SUPABASE_URL and SUPABASE_KEY to Streamlit secrets to save audits and generate shareable links.")
                elif _save_err:
                    st.warning(f"Audit completed but could not be saved to history — DB error: {_save_err}")

    with tab_audit:
        # ══════════════════════════════════════════════════════════════════════
        # RESULTS
        # ══════════════════════════════════════════════════════════════════════

        # ── Overwrite confirmation prompt ─────────────────────────────────────
        if "_pending_overwrite" in st.session_state:
            _pov = st.session_state["_pending_overwrite"]
            st.warning(
                f"A previous audit for **{_pov['domain']}** already exists "
                f"(from {_pov['existing_date']}). How would you like to save this run?"
            )
            _ov_col1, _ov_col2 = st.columns(2)
            with _ov_col1:
                if st.button("Overwrite existing", type="primary", key="_btn_overwrite"):
                    _ov_id, _ov_err = update_audit_in_db(
                        audit_id=_pov["existing_id"],
                        overall=_pov["overall"],
                        pillar_scores_dict=_pov["pillar_scores"],
                        audited_urls=_pov["urls"],
                        full_results=_pov["full_results"],
                    )
                    st.session_state.pop("_pending_overwrite", None)
                    if _ov_id:
                        st.query_params["audit"] = str(_ov_id)
                        st.session_state["_loaded_audit_id"] = str(_ov_id)
                    elif _ov_err:
                        st.warning(f"Could not save — DB error: {_ov_err}")
                    st.rerun()
            with _ov_col2:
                if st.button("Save as new entry", key="_btn_save_new"):
                    _ov_id, _ov_err = save_audit_to_db(
                        domain=_pov["domain"],
                        overall=_pov["overall"],
                        pillar_scores_dict=_pov["pillar_scores"],
                        audited_urls=_pov["urls"],
                        full_results=_pov["full_results"],
                    )
                    st.session_state.pop("_pending_overwrite", None)
                    if _ov_id:
                        st.query_params["audit"] = str(_ov_id)
                        st.session_state["_loaded_audit_id"] = str(_ov_id)
                    elif _ov_err:
                        st.warning(f"Could not save — DB error: {_ov_err}")
                    st.rerun()

        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)

        # ── ANTI-BOT PROTECTION CALLOUT ───────────────────────────────────────
        _antibot_urls = [
            u for u in all_test_urls
            if js_results.get(u, {}).get("error") and any(
                x in str(js_results[u].get("error", "")).lower()
                for x in ("403", "blocked", "cloudflare", "challenge", "forbidden")
            )
        ]
        _antibot_schema = [
            u for u in all_test_urls
            if schema_results.get(u, {}).get("error") and any(
                x in str(schema_results[u].get("error", "")).lower()
                for x in ("403", "blocked", "cloudflare", "challenge", "forbidden")
            )
        ]
        _cf_detected = robots_result.get("cloudflare", {}).get("cloudflare_detected", False)
        _cf_blocking = robots_result.get("cloudflare", {}).get("bot_fight_mode_likely", False)
        _bots_blocked = robots_result.get("cloudflare", {}).get("blocked_bots", [])
        _all_bots_blocked = bot_crawl_results and all(not r.get("is_allowed") for r in bot_crawl_results.values())

        if _cf_blocking or _antibot_urls or _antibot_schema or _all_bots_blocked:
            _blocked_pages = list(dict.fromkeys([url_labels.get(u, u) for u in _antibot_urls + _antibot_schema]))
            _bot_list = ", ".join(_bots_blocked) if _bots_blocked else ("All tested bots" if _all_bots_blocked else "")
            _detail_parts = []
            if _cf_blocking:
                _detail_parts.append(f"Cloudflare Bot Fight Mode is actively blocking AI crawlers ({_bot_list})")
            if _blocked_pages:
                _detail_parts.append(f"Crawl failed on: {', '.join(_blocked_pages)}")
            if _all_bots_blocked and not _cf_blocking:
                _detail_parts.append("All AI bots were blocked in the live crawl test")
            _detail_html = " · ".join(_detail_parts)
            st.markdown(
                f'<div style="background:#ff4b4b18;border:1px solid #ff4b4b55;border-left:4px solid #ff4b4b;border-radius:0 10px 10px 0;padding:16px 20px;margin:12px 0;">'
                f'<div style="font-size:14px;font-weight:700;color:#ff4b4b;margin-bottom:6px;">🛡️ Anti-Bot Protection Detected — Results May Be Incomplete</div>'
                f'<div style="font-size:13px;color:{BRAND["white"]};line-height:1.6;">{_detail_html}</div>'
                f'<div style="font-size:12px;color:{BRAND["text_secondary"]};margin-top:8px;">Scores for affected pages are based on what our crawlers could access. Manual verification is recommended. Security section will still show exposure data collected before the block.</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        elif _cf_detected:
            st.markdown(
                f'<div style="background:{BRAND["warning"]}18;border:1px solid {BRAND["warning"]}55;border-left:4px solid {BRAND["warning"]};border-radius:0 10px 10px 0;padding:12px 18px;margin:12px 0;">'
                f'<div style="font-size:13px;font-weight:600;color:{BRAND["warning"]};">⚠️ Cloudflare detected on this site — monitor bot access settings to ensure AI crawlers are not blocked</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

        # ── NO-BLOG NOTICE ─────────────────────────────────────────────────────
        if no_blog:
            st.markdown(
                f'<div style="background:{BRAND["warning"]}15;border:1px solid {BRAND["warning"]}44;border-left:4px solid {BRAND["warning"]};border-radius:0 10px 10px 0;padding:12px 18px;margin:12px 0;">'
                f'<div style="font-size:13px;font-weight:600;color:{BRAND["warning"]};">📝 No editorial blog — 10pt schema penalty applied</div>'
                f'<div style="font-size:12px;color:{BRAND["text_secondary"]};margin-top:4px;">Content pages (About/Contact/Story) evaluated against appropriate schema expectations. Editorial content significantly improves AI discoverability and citation potential.</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

        # ── GAUGE + SCORE CARDS ───────────────────────────────────────────────
        col_gauge, col_pillars = st.columns([1, 2])

        with col_gauge:
            gauge_svg = generate_gauge_svg(overall, label="LLM Readiness Score", size=220)
            st.markdown(f'<div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:{BRAND["text_secondary"]};text-align:center;margin-bottom:8px;">LLM Access Audit</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="text-align:center;">{gauge_svg}</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};text-align:center;margin-top:4px;">{parsed.netloc}</div>', unsafe_allow_html=True)

        with col_pillars:
            overall_grade = overall_result.get("grade", {})
            grade_letter = overall_grade.get("letter", "?") if isinstance(overall_grade, dict) else "?"
            grade_label = overall_grade.get("label", "") if isinstance(overall_grade, dict) else ""

            pillar_items = [
                ("JS Rendering", js_score),
                ("Robots & Crawl", robots_score),
                ("Schema & Entity", schema_score),
                ("AI Discovery", llm_score),
            ]
            p_cols = st.columns(5)
            for i, (label, sc) in enumerate(pillar_items):
                color = BRAND["teal"] if sc >= 75 else BRAND["primary"] if sc >= 50 else BRAND["warning"] if sc >= 35 else BRAND["danger"]
                p_cols[i].markdown(f'<div class="p-score-card"><div class="p-score-num" style="color:{color};font-size:1.6rem;">{sc}<span style="font-size:12px;opacity:0.4;">%</span></div><div class="p-score-label" style="font-size:0.6rem;">{label}</div></div>', unsafe_allow_html=True)
            # Security as separate card
            sec_color = BRAND["teal"] if security_score >= 80 else BRAND["warning"] if security_score >= 50 else BRAND["danger"]
            p_cols[4].markdown(f'<div class="p-score-card" style="border-color:{sec_color}40;"><div class="p-score-num" style="color:{sec_color};font-size:1.6rem;">{security_score}<span style="font-size:12px;opacity:0.4;">%</span></div><div class="p-score-label" style="font-size:0.6rem;">Security</div></div>', unsafe_allow_html=True)

            # Summary row
            st.markdown("")
            sub_cols = st.columns(4)
            with sub_cols[0]:
                st.metric("Pages Tested", len(all_test_urls))
            with sub_cols[1]:
                allowed_bots = sum(1 for r in bot_crawl_results.values() if r.get("is_allowed")) if bot_crawl_results else "—"
                total_bots = len(bot_crawl_results) if bot_crawl_results else "—"
                st.metric("Bot Access", f"{allowed_bots}/{total_bots}")
            with sub_cols[2]:
                exposed_count = sum(1 for p, r in robots_result.get("sensitive_paths", {}).items() if not r.get("blocked", not r.get("accessible_per_robots", False)))
                st.metric("Paths No Disallow", exposed_count)
            with sub_cols[3]:
                st.metric("Overall Grade", f"{grade_letter} ({grade_label})")

        # ── STRONGEST / WEAKEST PILLAR ────────────────────────────────────────
        pillar_scores = {
            "JS Rendering":       js_score,
            "Robots & Crawl":     robots_score,
            "Schema & Entity":    schema_score,
            "AI Discoverability": llm_score,
            "Semantic Hierarchy": semantic_score,
            "Security":           security_score,
        }
        sorted_pillars = sorted(pillar_scores.items(), key=lambda x: x[1])
        weakest_name, weakest_sc = sorted_pillars[0]
        strongest_name, strongest_sc = sorted_pillars[-1]
        weak_color = BRAND["danger"] if weakest_sc < 40 else BRAND["warning"]
        strong_color = BRAND["teal"] if strongest_sc >= 70 else BRAND["primary"]

        st.markdown("")
        sw_cols = st.columns(2)
        with sw_cols[0]:
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:14px 18px;border-left:3px solid {strong_color};"><div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;">Strongest Pillar</div><div style="font-size:18px;font-weight:700;color:{strong_color};">{strongest_name} — {strongest_sc}%</div></div>', unsafe_allow_html=True)
        with sw_cols[1]:
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:14px 18px;border-left:3px solid {weak_color};"><div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;">Weakest Pillar — Priority Focus</div><div style="font-size:18px;font-weight:700;color:{weak_color};">{weakest_name} — {weakest_sc}%</div></div>', unsafe_allow_html=True)

        # ── PER-PAGE SUMMARY TABLE ────────────────────────────────────────────
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Per-Page Results")

        for test_url in all_test_urls:
            label = url_labels.get(test_url, test_url)
            js_s = js_results.get(test_url, {}).get("score", "—")
            sc_s = schema_results.get(test_url, {}).get("score", "—")
            js_color = BRAND["teal"] if isinstance(js_s, int) and js_s >= 70 else BRAND["warning"] if isinstance(js_s, int) and js_s >= 40 else BRAND["danger"]
            sc_color = BRAND["teal"] if isinstance(sc_s, int) and sc_s >= 70 else BRAND["warning"] if isinstance(sc_s, int) and sc_s >= 40 else BRAND["danger"]
            st.markdown(f'<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:1px solid {BRAND["border"]};"><div style="color:{BRAND["white"]};font-size:13px;"><strong>{label}</strong> — <span style="color:{BRAND["text_secondary"]};font-size:12px;">{test_url}</span></div><div style="display:flex;gap:16px;"><span style="color:{js_color};font-weight:700;">JS: {js_s}</span><span style="color:{sc_color};font-weight:700;">Schema: {sc_s}</span></div></div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 1: JS RENDERING
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(1, "JavaScript Rendering", js_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("PAGE-LEVEL", BRAND["primary"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked on each of your {len(all_test_urls)} pages</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(js_score), unsafe_allow_html=True)
        pillar_explainer("js_rendering")

        for test_url, js_r in js_results.items():
            label = url_labels.get(test_url, test_url)
            if js_r.get("error"):
                st.error(f"Could not fetch {label}: {js_r['error']}")
                continue

            comp = js_r.get("comparison")
            provider = js_r.get("js_provider")
            js_err = js_r.get("js_error")

            with st.expander(f"{label} — Score: {js_r['score']}/100" + (f" (via {provider})" if provider else "")):

                # Frameworks detected
                frameworks = js_r.get("frameworks") or []
                if frameworks:
                    st.markdown("**JS Frameworks Detected:**")
                    for name, severity, note in frameworks:
                        st.markdown(brand_status(f"**{name}** ({severity}) — {note}", "danger" if severity == "high" else "warning"), unsafe_allow_html=True)

                # === COMPARISON TABLE (if JS rendering API was available) ===
                if comp:
                    st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:12px 0 8px 0;">HTML vs JavaScript — What AI Crawlers Miss:</div>', unsafe_allow_html=True)

                    # Table header
                    st.markdown(f'<div style="display:flex;padding:8px 12px;background:{BRAND["bg_surface"]};border-radius:8px 8px 0 0;font-weight:600;font-size:12px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;"><div style="flex:2;">Content</div><div style="flex:1;text-align:center;">HTML (Crawler)</div><div style="flex:1;text-align:center;">JS (Browser)</div><div style="flex:2;">Impact</div></div>', unsafe_allow_html=True)

                    for c in comp["comparison"]:
                        # Guard against pre-fix rows where strings were stored as null
                        if not c.get("name"):
                            continue
                        html_v = str(c["html_val"])
                        js_v = str(c["js_val"])
                        if c["status"] == "missing":
                            row_bg = f"{BRAND['danger']}15"
                            impact_html = f'<span style="color:{BRAND["danger"]};font-size:12px;">{c["impact"]}</span>'
                            html_color = BRAND["danger"]
                            js_color = BRAND["teal"]
                        elif c["status"] == "warn":
                            row_bg = f"{BRAND['warning']}10"
                            impact_html = f'<span style="color:{BRAND["warning"]};font-size:12px;">Minor JS dependency (&lt;10% gap)</span>'
                            html_color = BRAND["warning"]
                            js_color = BRAND["teal"]
                        else:
                            row_bg = "transparent"
                            impact_html = f'<span style="color:{BRAND["teal"]};font-size:12px;">OK</span>'
                            html_color = BRAND["teal"]
                            js_color = BRAND["teal"]

                        st.markdown(f'<div style="display:flex;padding:6px 12px;border-bottom:1px solid {BRAND["border"]};background:{row_bg};align-items:center;"><div style="flex:2;color:{BRAND["white"]};font-size:13px;">{c["name"]}</div><div style="flex:1;text-align:center;color:{html_color};font-weight:700;font-size:13px;">{html_v}</div><div style="flex:1;text-align:center;color:{js_color};font-size:13px;">{js_v}</div><div style="flex:2;">{impact_html}</div></div>', unsafe_allow_html=True)

                    # Text content gap highlight
                    html_text = comp.get("html_summary", {}).get("text_content_length", 0)
                    js_text = comp.get("js_summary", {}).get("text_content_length", 0)
                    if js_text > html_text:
                        pct = round(html_text / max(js_text, 1) * 100)
                        gap_color = BRAND["danger"] if pct < 30 else BRAND["warning"] if pct < 70 else BRAND["teal"]
                        st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:14px 18px;margin:12px 0;"><div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;">Content Visibility</div><div style="font-size:20px;font-weight:700;color:{gap_color};">{pct}% <span style="font-size:14px;opacity:0.5;">of content visible to AI</span></div><div style="font-size:12px;color:{BRAND["text_secondary"]};">HTML: {html_text:,} chars · JS-rendered: {js_text:,} chars · Hidden: {js_text - html_text:,} chars</div></div>', unsafe_allow_html=True)

                    # AI Analysis
                    try:
                        ai_analysis = ai_analyse_js_gap(test_url, comp, label, get_secret)
                    except Exception:
                        ai_analysis = None
                    st.session_state["_audit"].setdefault("_bifrost_js", {})[test_url] = ai_analysis
                    if ai_analysis:
                        st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
                        st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{ai_analysis}</div>', unsafe_allow_html=True)

                else:
                    # Fallback display when no JS rendering API available
                    if js_err:
                        st.markdown(brand_status(f"JS rendering not available: {js_err}", "info"), unsafe_allow_html=True)
                        st.caption("Configure API keys in Streamlit Secrets for full HTML vs JS comparison.")

                    if js_r["risk_factors"]:
                        st.markdown("**Risk Factors (estimated from HTML analysis):**")
                        for rf in js_r["risk_factors"]:
                            st.markdown(brand_status(rf, "warning"), unsafe_allow_html=True)

                    c = js_r.get("content") or {}
                    if c:
                        st.markdown("**Content Visible in Raw HTML:**")
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.markdown(brand_status(f"Title: {c.get('title') or 'Missing'}", "success" if c.get("title") else "danger"), unsafe_allow_html=True)
                            st.markdown(brand_status(f"Meta Desc: {'Present' if c.get('meta_description') else 'Missing'}", "success" if c.get("meta_description") else "danger"), unsafe_allow_html=True)
                            st.markdown(brand_status(f"H1 Tags: {len(c.get('h1_tags') or [])}", "success" if c.get("h1_tags") else "warning"), unsafe_allow_html=True)
                            st.markdown(brand_status(f"Prices: {len(c.get('prices') or [])} found", "success" if c.get("prices") else "info"), unsafe_allow_html=True)
                        with col_b:
                            st.markdown(brand_status(f"Nav Links: {c.get('nav_links', 0)}", "success" if c.get("nav_links") else "warning"), unsafe_allow_html=True)
                            st.markdown(brand_status(f"Total Links: {c.get('total_links', 0)}", "success" if c.get("total_links") else "warning"), unsafe_allow_html=True)
                            st.markdown(brand_status(f"Images (alt): {c.get('images_with_alt', 0)} / (no alt): {c.get('images_without_alt', 0)}", "success" if not c.get("images_without_alt") else "warning"), unsafe_allow_html=True)
                            st.markdown(brand_status(f"Text: {c.get('text_content_length', 0):,} chars", "success" if c.get("text_content_length", 0) > 500 else "warning"), unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 2: ROBOTS & CRAWLABILITY
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(2, "Robots.txt & Crawler Access", robots_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked once — controls all crawler access</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(robots_score), unsafe_allow_html=True)
        pillar_explainer("robots_txt")

        if robots_result.get("found"):
            robots_url = robots_result.get("robots", {}).get("url", robots_result.get("url", ""))
            st.markdown(brand_status(f"robots.txt found at {robots_url}", "success"), unsafe_allow_html=True)
            st.markdown(f"**AI Agent Access:**")
            for company in AI_BOTS:
                company_bots = {k: v for k, v in robots_result.get("ai_agent_results", robots_result.get("ai_results", {})).items() if v["company"] == company}
                if company_bots:
                    with st.expander(f"{company} ({len(company_bots)} agents)"):
                        for bot_name, info in company_bots.items():
                            allowed_val = info.get("robots_allowed", info.get("allowed"))
                            if allowed_val is True:
                                st.markdown(brand_status(f"**{bot_name}**: Allowed", "success"), unsafe_allow_html=True)
                            elif allowed_val is False:
                                st.markdown(brand_status(f"**{bot_name}**: Blocked", "danger"), unsafe_allow_html=True)
                            else:
                                st.markdown(brand_status(f"**{bot_name}**: Unknown", "warning"), unsafe_allow_html=True)
            _sitemaps = robots_result.get("sitemaps") or []
            if _sitemaps:
                with st.expander(f"Sitemaps ({len(_sitemaps)} found)"):
                    for sm in _sitemaps:
                        st.markdown(brand_status(sm, "success"), unsafe_allow_html=True)
            else:
                st.markdown(brand_status("No sitemaps in robots.txt", "warning"), unsafe_allow_html=True)
            _blocked_res = robots_result.get("blocked_resources") or []
            if _blocked_res:
                st.markdown(brand_status(f"Blocked resources: {', '.join(_blocked_res)}", "danger"), unsafe_allow_html=True)
            else:
                st.markdown(brand_status("CSS/JS not blocked — AI agents can render pages", "success"), unsafe_allow_html=True)
            exposed = [(p, r) for p, r in robots_result.get("sensitive_paths", {}).items() if not r.get("blocked", not r.get("accessible_per_robots", False))]
            blocked = [(p, r) for p, r in robots_result.get("sensitive_paths", {}).items() if r.get("blocked", not r.get("accessible_per_robots", True))]
            with st.expander(f"Sensitive Path Scan — {len(exposed)} exposed, {len(blocked)} blocked"):
                if exposed:
                    for path, r in exposed:
                        st.markdown(brand_status(f"`{path}`", "warning"), unsafe_allow_html=True)
                if blocked:
                    for path, r in blocked[:10]:
                        st.markdown(brand_status(f"`{path}`", "success"), unsafe_allow_html=True)
                    if len(blocked) > 10:
                        st.caption(f"…and {len(blocked) - 10} more")
            with st.expander("Raw robots.txt"):
                st.code((robots_result.get("raw") or "")[:8000], language="text")
        else:
            robots_url = robots_result.get("robots", {}).get("url", robots_result.get("url", ""))
            st.markdown(brand_status(f"No robots.txt found at {robots_url}", "danger"), unsafe_allow_html=True)

        # AI Analysis — What This Means
        try:
            robots_ai = analyse_robots_access(parsed.netloc, robots_result, get_secret)
        except Exception:
            robots_ai = None
        st.session_state["_audit"]["_bifrost_robots"] = robots_ai
        if robots_ai:
            st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{robots_ai}</div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 3: SCHEMA & ENTITY (page-level)
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(3, "Schema & Entity", schema_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("PAGE-LEVEL", BRAND["primary"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked on each of your {len(all_test_urls)} pages</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(schema_score), unsafe_allow_html=True)
        pillar_explainer("schema")

        for test_url, sr in schema_results.items():
            label = url_labels.get(test_url, test_url)
            if sr.get("error"):
                st.error(f"Could not check {label}: {sr['error']}")
                continue

            schema_data = sr.get("schema", {})
            meta_data = sr.get("meta", {})
            entity_data = sr.get("entity", {})
            schemas = schema_data.get("schemas", [])
            types_found = schema_data.get("types", [])
            validations = schema_data.get("validations", [])
            grade = sr.get("grade", {})
            grade_letter = grade.get("letter", "?") if isinstance(grade, dict) else "?"

            with st.expander(f"{label} — {len(schemas)} schema item(s), Score: {sr.get('score', 0)}/100 ({grade_letter})"):
                # Schema types as pills
                if types_found:
                    pills = " ".join(brand_pill(t, BRAND["chart"][i % len(BRAND["chart"])]) for i, t in enumerate(types_found))
                    st.markdown(f'<div style="margin:8px 0;">{pills}</div>', unsafe_allow_html=True)

                # Essential types
                ess_found = schema_data.get("essential_found", [])
                ess_missing = schema_data.get("essential_missing", [])
                if ess_found or ess_missing:
                    found_str = ", ".join(ess_found) if ess_found else "None"
                    missing_str = ", ".join(ess_missing) if ess_missing else "None"
                    st.markdown(brand_status(f"Essential types — Found: {found_str} | Missing: {missing_str}", "success" if len(ess_missing) <= 1 else "warning"), unsafe_allow_html=True)

                # Speakable & sameAs
                if schema_data.get("has_speakable"):
                    st.markdown(brand_status("Speakable markup found", "success"), unsafe_allow_html=True)
                if schema_data.get("has_sameas"):
                    st.markdown(brand_status("sameAs references found", "success"), unsafe_allow_html=True)

                # Field validations
                if validations:
                    st.markdown("**Field Completeness:**")
                    for v in validations:
                        comp = v.get("completeness", 0)
                        s = "success" if comp >= 80 else "warning" if comp >= 50 else "danger"
                        st.markdown(brand_status(f"**{v.get('type', '?')}** — {comp}% complete", s), unsafe_allow_html=True)
                        if v.get("missing"):
                            st.caption(f"Missing: {', '.join(v['missing'])}")

                # Meta info
                if meta_data:
                    st.markdown("**Meta:**")
                    title = meta_data.get("title", "")
                    st.markdown(brand_status(f"Title ({len(title)} chars): {title[:70]}", "success" if title else "danger"), unsafe_allow_html=True)
                    desc = meta_data.get("desc", "")
                    desc_len = meta_data.get("desc_len", len(desc))
                    st.markdown(brand_status(f"Description ({desc_len} chars)", "success" if 100 <= desc_len <= 160 else "warning" if desc else "danger"), unsafe_allow_html=True)
                    canon = meta_data.get("canonical", "")
                    if not canon:
                        st.markdown(brand_status("Canonical: Missing", "warning"), unsafe_allow_html=True)
                    elif meta_data.get("canonical_matches_url"):
                        st.markdown(brand_status(f"Canonical: Matching — {canon[:80]}", "success"), unsafe_allow_html=True)
                    else:
                        st.markdown(brand_status(f"Canonical: Not matching — {canon[:80]}", "danger"), unsafe_allow_html=True)
                    if meta_data.get("was_redirected"):
                        st.markdown(brand_status(f"Redirect detected — fetched URL: {meta_data.get('final_url', '')[:80]}", "warning"), unsafe_allow_html=True)
                    og = meta_data.get("og_tags", {})
                    st.markdown(brand_status(f"OG tags: {len(og)}", "success" if len(og) >= 3 else "warning"), unsafe_allow_html=True)

                # Entity — author/date only meaningful on editorial/article pages
                if entity_data and entity_data.get("is_article_page"):
                    st.markdown(brand_status(f"Author: {'Found' if entity_data.get('has_author') else 'Missing'}", "success" if entity_data.get("has_author") else "warning"), unsafe_allow_html=True)
                    st.markdown(brand_status(f"Publication date: {'Found' if entity_data.get('has_date_published') else 'Missing'}", "success" if entity_data.get("has_date_published") else "warning"), unsafe_allow_html=True)

                # ScoreBuilder rubric items
                items = sr.get("items", [])
                if items:
                    with st.expander("View scoring rubric"):
                        for item in items:
                            pts = item.get("points", 0)
                            lbl = item.get("label", "")
                            s = "success" if pts > 0 else "warning" if "missing" in lbl.lower() or "no " in lbl.lower() else "info"
                            st.markdown(brand_status(f"+{pts} pts — {lbl}", s), unsafe_allow_html=True)

                # Raw schema data
                for s_item in schemas:
                    if s_item.get("data"):
                        with st.expander(f"View `{s_item.get('type', '?')}` data"):
                            st.json(_make_json_safe(s_item["data"]))

                if not schemas:
                    st.markdown(brand_status("No Schema.org structured data found on this page", "warning"), unsafe_allow_html=True)

                # AI Analysis — What This Means
                try:
                    schema_ai = analyse_schema_quality(test_url, schemas, get_secret)
                except Exception:
                    schema_ai = None
                st.session_state["_audit"].setdefault("_bifrost_schema", {})[test_url] = schema_ai
                if schema_ai:
                    st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
                    st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{schema_ai}</div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 4: AI DISCOVERABILITY
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(4, "AI Discoverability", llm_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">llm.txt files + AI Info Page</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(llm_score), unsafe_allow_html=True)
        pillar_explainer("llm_txt")

        # llm.txt files
        st.markdown(f'<div style="font-weight:600;color:{BRAND["white"]};margin:12px 0 8px;">llm.txt Files:</div>', unsafe_allow_html=True)
        llm_txt_data = llm_result.get("llm_txt", llm_result.get("files", {}))
        any_llm = any(v.get("found") for v in llm_txt_data.values()) if llm_txt_data else False
        if any_llm:
            for path, info in llm_txt_data.items():
                if info.get("found"):
                    st.markdown(brand_status(f"Found: {path}", "success"), unsafe_allow_html=True)
                    q = info.get("quality", {})
                    if q:
                        q_cols = st.columns(4)
                        q_cols[0].metric("Lines", q.get("line_count", q.get("lines", "—")))
                        q_cols[1].metric("Chars", q.get("char_count", q.get("chars", "—")))
                        q_cols[2].metric("Links", "Yes" if q.get("has_links") else "No")
                        q_cols[3].metric("Sections", "Yes" if q.get("has_sections") else "No")
                    with st.expander(f"View contents of {path}"):
                        st.code(info.get("content", ""), language="markdown")
                else:
                    st.caption(f"— {path} not found")
        else:
            st.markdown(brand_status("No llm.txt files found", "warning"), unsafe_allow_html=True)
            st.info("💡 **llm.txt** provides direct guidance to AI bots on what to prioritise. [Learn more →](https://llmstxt.org)")

        # AI Info Page
        ai_info = llm_result.get("ai_info_page", {})
        st.markdown(f'<div style="font-weight:600;color:{BRAND["white"]};margin:16px 0 8px;">AI Info Page:</div>', unsafe_allow_html=True)
        if ai_info.get("found"):
            st.markdown(brand_status(f"AI Info Page found: {ai_info.get('url', '')}", "success"), unsafe_allow_html=True)
            st.markdown(brand_status(f"Linked from footer: {'Yes' if ai_info.get('linked_from_footer') else 'No — critical for discoverability'}", "success" if ai_info.get("linked_from_footer") else "danger"), unsafe_allow_html=True)
            if "indexable" in ai_info:
                st.markdown(brand_status(f"Indexable: {'Yes' if ai_info['indexable'] else 'No — has noindex'}", "success" if ai_info.get("indexable") else "danger"), unsafe_allow_html=True)
            if "has_updated_date" in ai_info:
                st.markdown(brand_status(f"'Last Updated' date: {'Found' if ai_info['has_updated_date'] else 'Missing — add for freshness'}", "success" if ai_info.get("has_updated_date") else "warning"), unsafe_allow_html=True)
            if "is_simple_html" in ai_info:
                st.markdown(brand_status(f"Simple HTML: {'Yes' if ai_info['is_simple_html'] else 'Heavy JS — should be simple for AI'}", "success" if ai_info.get("is_simple_html") else "warning"), unsafe_allow_html=True)
        else:
            if ai_info.get("redirects"):
                st.markdown(brand_status("AI Info Page URL redirects elsewhere — page does not exist", "danger"), unsafe_allow_html=True)
            else:
                st.markdown(brand_status("No AI Info Page found at /ai-info, /llm-info, or similar", "warning"), unsafe_allow_html=True)
            st.info("💡 Create an **AI Info Page** at `/ai-info` — your brand's official fact sheet for AI. Include brand basics, key products, FAQs, and a 'Last Updated' date. Link it from your footer. Keep it simple HTML.")

        # ScoreBuilder rubric
        llm_items = llm_result.get("items", [])
        if llm_items:
            with st.expander("View AI Discoverability scoring rubric"):
                for item in llm_items:
                    pts = item.get("points", 0)
                    lbl = item.get("label", "")
                    s = "success" if pts > 0 else "info"
                    st.markdown(brand_status(f"+{pts} pts — {lbl}", s), unsafe_allow_html=True)

        # AI Analysis — What This Means
        try:
            llm_ai = analyse_llm_discoverability(parsed.netloc, llm_result, get_secret)
        except Exception:
            llm_ai = None
        st.session_state["_audit"]["_bifrost_llm"] = llm_ai
        if llm_ai:
            st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{llm_ai}</div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # LIVE BOT CRAWL
        # ══════════════════════════════════════════════════════════════════════
        if bot_crawl_results:
            allowed_count = sum(1 for r in bot_crawl_results.values() if r["is_allowed"])
            total_bots = len(bot_crawl_results)
            st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
            st.markdown(f'<div style="font-size:20px;font-weight:700;color:{BRAND["white"]};margin-bottom:4px;">Live Bot Crawl Results</div>', unsafe_allow_html=True)
            st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Tested against homepage</span>', unsafe_allow_html=True)
            pillar_explainer("bot_crawl")
            st.markdown(f'<div style="font-size:14px;color:{BRAND["text_secondary"]};margin-bottom:12px;"><span style="color:{BRAND["teal"]};font-weight:700;">{allowed_count}</span> allowed · <span style="color:{BRAND["danger"]};font-weight:700;">{total_bots - allowed_count}</span> blocked · {total_bots} total</div>', unsafe_allow_html=True)
            for company in list(dict.fromkeys(r["company"] for r in bot_crawl_results.values())):
                cr = {k: v for k, v in bot_crawl_results.items() if v["company"] == company}
                ca = sum(1 for r in cr.values() if r["is_allowed"])
                with st.expander(f"{company} — {ca}/{len(cr)} allowed"):
                    for bn, r in cr.items():
                        if r["error"]:
                            st.markdown(brand_status(f"**{bn}**: Error — {r['error']}", "danger"), unsafe_allow_html=True)
                        else:
                            st.markdown(brand_status(f"**{bn}**: {'Allowed' if r['is_allowed'] else 'BLOCKED'}", "success" if r["is_allowed"] else "danger"), unsafe_allow_html=True)
                            st.caption(f"HTTP {r['status_code']} · Robots: {'✓' if r['robots_allowed'] else '✗'} · Meta: {r['robots_meta']} · {r['content_length']:,} chars · {r['load_time']}s")

        # ══════════════════════════════════════════════════════════════════════
        # SEMANTIC HIERARCHY & OTHER CHECKS (replaces Supplementary)
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(5, "Semantic Hierarchy & Content Structure", semantic_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("PAGE-LEVEL", BRAND["primary"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Heading structure, semantic HTML, meta directives — checked per page</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(semantic_score), unsafe_allow_html=True)
        pillar_explainer("semantic_content")

        for test_url, sem_r in semantic_results.items():
            label = url_labels.get(test_url, test_url)
            if sem_r.get("error"):
                st.error(f"Could not check {label}: {sem_r['error']}")
                continue

            with st.expander(f"{label}"):
                col_left, col_right = st.columns(2)

                with col_left:
                    st.markdown("**Heading Hierarchy:**")
                    if sem_r["headings"]:
                        hierarchy_status = "success" if sem_r["hierarchy_ok"] else "warning"
                        st.markdown(brand_status(f"Hierarchy: {'Valid — no skipped levels' if sem_r['hierarchy_ok'] else 'Issues — skipped heading levels detected'}", hierarchy_status), unsafe_allow_html=True)
                        for h in sem_r["headings"][:20]:
                            indent = "&nbsp;" * (h["level"] - 1) * 4
                            st.markdown(f'<div style="color:{BRAND["text_secondary"]};font-size:12px;">{indent}H{h["level"]}: {h["text"][:80]}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(brand_status("No headings found", "danger"), unsafe_allow_html=True)

                    st.markdown("**Semantic Elements:**")
                    if sem_r["semantic_elements"]:
                        for tag, count in sem_r["semantic_elements"].items():
                            st.markdown(brand_status(f"<{tag}>: {count}", "success"), unsafe_allow_html=True)
                    else:
                        st.markdown(brand_status("No semantic HTML5 elements found", "warning"), unsafe_allow_html=True)

                with col_right:
                    st.markdown("**Meta Directives:**")
                    if sem_r["meta_tags"]:
                        for tag in sem_r["meta_tags"]:
                            st.markdown(brand_status(f'{tag["name"]}: {tag["content"]}', "info"), unsafe_allow_html=True)
                    else:
                        st.caption("No robots meta tags")
                    if sem_r.get("x_robots_tag"):
                        st.markdown(brand_status(f"X-Robots-Tag: {sem_r['x_robots_tag']}", "info"), unsafe_allow_html=True)
                    st.markdown(brand_status(f"data-nosnippet: {sem_r.get('nosnippet_elements', 0)} element(s)", "info"), unsafe_allow_html=True)
                    html_len = sem_r.get("html_length", 0)
                    text_len = sem_r.get("text_length", 0)
                    if html_len > 0:
                        ratio = text_len / html_len * 100
                        st.markdown(brand_status(f"Text-to-HTML ratio: {ratio:.1f}%", "success" if ratio >= 15 else "warning"), unsafe_allow_html=True)

                # AI Analysis — What This Means
                try:
                    sem_ai = analyse_semantic_hierarchy(test_url, sem_r, label, get_secret)
                except Exception:
                    sem_ai = None
                st.session_state["_audit"].setdefault("_bifrost_sem", {})[test_url] = sem_ai
                if sem_ai:
                    st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
                    st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{sem_ai}</div>', unsafe_allow_html=True)

        # Well-known AI files (site-level)
        st.markdown(f'<div style="margin:16px 0 8px 0;">{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="font-weight:600;color:{BRAND["white"]};">AI Policy Files:</span></div>', unsafe_allow_html=True)
        wellknown_result = llm_result.get("wellknown", {})
        for path, info in wellknown_result.items():
            if info.get("found"):
                st.markdown(brand_status(f"Found: {path}", "success"), unsafe_allow_html=True)
            else:
                st.caption(f"— {path} not found")

        # ══════════════════════════════════════════════════════════════════════
        # SECURITY DRILLDOWN
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(6, "Security & Exposure", security_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Sensitive path probing — checked once against your live site</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(security_score), unsafe_allow_html=True)
        sec_findings = security_result.get("findings", {})
        sec_total_exposed = security_result.get("total_exposed", 0)

        if sec_total_exposed == 0 and not sec_findings.get("html_exposure") and not sec_findings.get("robots_allowlist"):
            st.markdown(brand_status("No sensitive paths accessible to AI bots — all probed paths returned 403/404/401", "success"), unsafe_allow_html=True)
        else:
            for cat, label_str, color_key in [
                ("critical", "Critical paths (admin/env/config)", "danger"),
                ("backend", "Backend paths (API/GraphQL)", "warning"),
                ("customer", "Customer paths (account/checkout)", "warning"),
            ]:
                items = sec_findings.get(cat, [])
                if items:
                    st.markdown(f'<div style="font-weight:600;color:{BRAND[color_key]};margin:10px 0 4px 0;">{label_str} — accessible to AI bots:</div>', unsafe_allow_html=True)
                    for f in items:
                        st.markdown(brand_status(f'{f["path"]} — HTTP {f["status"]} ({f["size"]:,} bytes)', color_key), unsafe_allow_html=True)
            if sec_findings.get("html_exposure"):
                st.markdown(f'<div style="font-weight:600;color:{BRAND["warning"]};margin:10px 0 4px 0;">Sensitive content in HTML source:</div>', unsafe_allow_html=True)
                for item in sec_findings["html_exposure"]:
                    st.markdown(brand_status(item, "warning"), unsafe_allow_html=True)
            if sec_findings.get("robots_allowlist"):
                st.markdown(f'<div style="font-weight:600;color:{BRAND["warning"]};margin:10px 0 4px 0;">robots.txt explicitly allows sensitive paths for AI bots:</div>', unsafe_allow_html=True)
                for item in sec_findings["robots_allowlist"]:
                    st.markdown(brand_status(f'{item["bot"]}: {item["path"]}', "warning"), unsafe_allow_html=True)

        # Robots.txt coverage note (separate from HTTP accessibility)
        sensitive = robots_result.get("sensitive_paths", {}) if isinstance(robots_result, dict) else {}
        no_disallow = [p for p, r in sensitive.items() if not r.get("blocked", not r.get("accessible_per_robots", False))]
        if no_disallow:
            with st.expander(f"Robots.txt coverage — {len(no_disallow)} paths have no Disallow rule"):
                st.caption("These paths are not necessarily accessible — this is about robots.txt hygiene, not HTTP exposure.")
                for p in no_disallow:
                    st.markdown(brand_status(f"No Disallow rule: {p}", "danger"), unsafe_allow_html=True)

        # Score breakdown
        sec_items = security_result.get("items", [])
        if sec_items:
            with st.expander("Score breakdown"):
                for item in sec_items:
                    pts = item.get("points", 0)
                    lbl = item.get("label", "")
                    s = "success" if pts >= 0 else "danger"
                    prefix = f"+{pts}" if pts >= 0 else str(pts)
                    st.markdown(brand_status(f"{prefix} pts — {lbl}", s), unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # RECOMMENDATIONS
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Priority Recommendations")

        recs = build_recommendations(_a, no_blog)

        if not recs:
            st.markdown(brand_status("Excellent! Your site scores well across all pillars.", "success"), unsafe_allow_html=True)
        else:
            _severity_order = {"critical": 0, "danger": 0, "warning": 1, "info": 2}
            recs_sorted = sorted(recs, key=lambda r: _severity_order.get(r[0], 1))
            seen = set()
            for status, pillar, text in recs_sorted:
                key = f"{pillar}:{text[:60]}"
                if key in seen: continue
                seen.add(key)
                color = BRAND["danger"] if status in ("danger", "critical") else \
                        BRAND["primary"] if status == "info" else BRAND["warning"]
                st.markdown(f'<div style="background:{BRAND["bg_card"]};border-left:3px solid {color};border-radius:0 10px 10px 0;padding:14px 18px;margin:6px 0;"><div style="margin-bottom:6px;">{brand_pill(pillar, color)}</div><div style="color:{BRAND["white"]};font-size:14px;">{text}</div></div>', unsafe_allow_html=True)

        # ── PATTERN BRAIN AI ANALYSIS ─────────────────────────────────────────────
        bifrost_key = get_secret("BIFROST_API_KEY", "")
        if bifrost_key:
            st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
            st.markdown(f'### {brand_pill("PATTERN BRAIN", BRAND["purple"])} AI Analysis', unsafe_allow_html=True)
            st.caption("Powered by Pattern's AI via Bifrost · openai/gpt-4o-mini")

            with st.spinner("Generating Pattern Brain analysis..."):
                # Build compact results dict for the brain
                all_results_for_brain = {
                    "robots": robots_result if isinstance(robots_result, dict) else {},
                    "cloudflare": (robots_result.get("cloudflare", {}) if isinstance(robots_result, dict) else {}),
                    "schema_summary": {
                        "types_found": [t for sr in schema_results.values() for t in sr.get("schema", {}).get("types", [])],
                        "has_org_sameas": any(sr.get("entity", {}).get("has_org_sameas") for sr in schema_results.values()),
                        "has_author": any(sr.get("entity", {}).get("has_author") for sr in schema_results.values()),
                        "has_date_published": any(sr.get("entity", {}).get("has_date_published") for sr in schema_results.values()),
                    },
                    "ecommerce_summary": {
                        "has_gtin": any(sr.get("ecommerce", {}).get("has_gtin_or_mpn") for sr in schema_results.values()),
                        "has_return_policy": any(sr.get("ecommerce", {}).get("has_return_policy_schema") for sr in schema_results.values()),
                    },
                    "llm_discoverability": {
                        "has_llm_txt": llm_result.get("score", 0) > 25,
                        "ai_info_found": bool(llm_result.get("ai_info_page", {}).get("found")),
                        "has_ucp": bool(llm_result.get("wellknown", {}).get("has_ucp")),
                        "has_mcp": bool(llm_result.get("wellknown", {}).get("has_mcp")),
                    },
                    "semantic_summary": {
                        "has_lead_paragraph": False,
                        "cluster_count": 0,
                        "auth_citations": 0,
                        "vague_phrases": 0,
                    },
                    "pillar_scores": {
                        "overall": overall,
                        "js": js_score,
                        "robots": robots_score,
                        "schema": schema_score,
                        "llm": llm_score,
                    },
                }

                try:
                    brain_analysis = pattern_brain_analysis(parsed.netloc, all_results_for_brain, get_secret)
                except Exception:
                    brain_analysis = None
                st.session_state["_audit"]["pattern_brain"] = brain_analysis

            if brain_analysis:
                st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:12px;padding:20px 24px;margin:8px 0;"><div style="color:{BRAND["white"]};font-size:14px;line-height:1.7;">{_md_to_html(brain_analysis)}</div></div>', unsafe_allow_html=True)
            else:
                st.caption("Pattern Brain analysis unavailable — check BIFROST_API_KEY in Streamlit secrets.")

        # ── DOWNLOAD REPORT ──────────────────────────────────────────────────
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Download Report")

        pillar_scores_dict = {
            "JS Rendering":       js_score,
            "Robots & Crawl":     robots_score,
            "Schema & Entity":    schema_score,
            "AI Discoverability": llm_score,
            "Semantic Hierarchy": semantic_score,
            "Security":           security_score,
        }
        domain_slug = parsed.netloc.replace(".", "_")
        date_slug   = time.strftime("%Y%m%d")

        _audit_dict = {
            "overall":           overall,
            "overall_grade":     overall_grade,
            "url_labels":        url_labels,
            "js_results":        js_results,
            "js_score":          js_score,
            "robots_result":     robots_result,
            "robots_score":      robots_score,
            "schema_results":    schema_results,
            "schema_score":      schema_score,
            "llm_result":        llm_result,
            "llm_score":         llm_score,
            "semantic_results":  semantic_results,
            "semantic_score":    semantic_score,
            "security_result":   security_result,
            "security_score":    security_score,
            "bot_crawl_results": bot_crawl_results,
            "no_blog":           no_blog,
            "_bifrost_js":       st.session_state.get("_audit", {}).get("_bifrost_js", {}),
            "_bifrost_robots":   st.session_state.get("_audit", {}).get("_bifrost_robots"),
            "_bifrost_schema":   st.session_state.get("_audit", {}).get("_bifrost_schema", {}),
            "_bifrost_llm":      st.session_state.get("_audit", {}).get("_bifrost_llm"),
            "_bifrost_sem":      st.session_state.get("_audit", {}).get("_bifrost_sem", {}),
            "pattern_brain":     st.session_state.get("_audit", {}).get("pattern_brain"),
        }
        _recs_dicts = [{"severity": s, "pillar": p, "text": t} for s, p, t in recs]
        report_pdf = _generate_report_pdf(
            audit=_audit_dict,
            domain=parsed.netloc,
            recs=_recs_dicts,
        )
        report_json = json.dumps(_make_json_safe({
            "domain":        parsed.netloc,
            "overall_score": overall,
            "overall_grade": overall_grade,
            "generated_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pillar_scores": pillar_scores_dict,
            "urls":          url_labels,
            "recommendations": [{"severity": s, "pillar": p, "text": t} for s, p, t in recs],
            "js_results":        js_results,
            "robots_result":     robots_result,
            "schema_results":    schema_results,
            "llm_result":        llm_result,
            "semantic_results":  semantic_results,
            "security_result":   security_result,
            "bot_crawl_results": bot_crawl_results,
        }), indent=2)

        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button(
                label="⬇ PDF Report",
                data=report_pdf,
                file_name=f"llm_access_audit_{domain_slug}_{date_slug}.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary",
                key="dl_pdf",
            )
            st.caption("Formatted PDF — scores, tables, recommendations.")
        with dl_col2:
            st.download_button(
                label="⬇ JSON Data",
                data=report_json,
                file_name=f"llm_access_audit_{domain_slug}_{date_slug}.json",
                mime="application/json",
                use_container_width=True,
                key="dl_json",
            )
            st.caption("Raw scores + full results for integrations.")

        # ── FOOTER ────────────────────────────────────────────────────────────
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(f'<div style="text-align:center;padding:1rem 0;">{PATTERN_LOGO_SVG}<div style="color:{BRAND["text_secondary"]};font-size:12px;margin-top:8px;">Pattern LLM Access Checker — Full LLM Access Audit</div></div>', unsafe_allow_html=True)
