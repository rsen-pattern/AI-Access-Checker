# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — audit results rendering.

Renders the entire results pane: overwrite-confirmation prompt, gauge,
pillar score cards, strongest/weakest cards, per-page summary table,
all six pillar sections with their per-page AI Analysis cards, live bot
crawl results, security drilldown, recommendations, Pattern Brain
analysis, download buttons, and footer.

Persists per-pillar Bifrost AI analyses to st.session_state["_audit"] as
side effects (preserves PR #26 fix). Specifically writes:
- _audit["_bifrost_js"][test_url]      (per-page)
- _audit["_bifrost_robots"]            (site-level)
- _audit["_bifrost_schema"][test_url]  (per-page)
- _audit["_bifrost_llm"]               (site-level)
- _audit["_bifrost_sem"][test_url]     (per-page)
- _audit["pattern_brain"]              (site-level)

These are read by report_pdf.py at PDF generation time. Do not change
the keys or structure.
"""

import json
import time
from urllib.parse import urlparse

import streamlit as st

from core.branding import BRAND, PATTERN_LOGO_SVG
from core.persistence import is_history_authenticated
from core.llm_access_checks import (
    AI_BOTS,
    pattern_brain_analysis,
    analyse_schema_quality,
    ai_analyse_js_gap,
    analyse_semantic_hierarchy,
    analyse_robots_access,
    analyse_llm_discoverability,
)
from core.persistence import (
    get_supabase,
    load_audit_history,
    save_audit_to_db,
    update_audit_in_db,
)
from core.ui_helpers import (
    _make_json_safe,
    brand_pill,
    brand_score_bar,
    brand_status,
    generate_gauge_svg,
    pillar_explainer,
    pillar_header,
    _md_to_html,
)
from core.ui_recommendations import build_recommendations
from report_pdf import generate_report_pdf as _generate_report_pdf


def render_results(audit: dict, get_secret_fn) -> None:
    """Render the full audit results pane.

    Args:
        audit: The audit dict from st.session_state["_audit"]. Read-write —
            the function persists per-pillar Bifrost AI analyses back into
            this dict via st.session_state["_audit"] mutations.
        get_secret_fn: A callable matching the signature of
            core.persistence.get_secret. Passed through to all Bifrost
            analyser calls so the function works in any session context.

    Must be called inside `with tab_audit:`. Returns nothing — all output
    is rendered via st.markdown / st.download_button / etc.
    """
    with st.spinner("Loading report…"):
        all_test_urls     = audit.get("all_test_urls", [])
        url_labels        = audit.get("url_labels", {})
        js_results        = audit.get("js_results", {})
        js_score          = audit.get("js_score", 0)
        robots_result     = audit.get("robots_result", {"found": False, "score": 0})
        robots_score      = audit.get("robots_score", 0)
        schema_results    = audit.get("schema_results", {})
        schema_score      = audit.get("schema_score", 0)
        llm_result        = audit.get("llm_result", {})
        llm_score         = audit.get("llm_score", 0)
        semantic_results  = audit.get("semantic_results", {})
        semantic_score    = audit.get("semantic_score", 0)
        security_result   = audit.get("security_result", {"found": False, "score": 0})
        security_score    = audit.get("security_score", 0)
        bot_crawl_results = audit.get("bot_crawl_results", {})
        overall           = audit.get("overall", 0)
        overall_grade     = audit.get("overall_grade", "?")
        overall_result    = audit.get("overall_result", {"score": overall, "grade": overall_grade})
        no_blog           = audit.get("no_blog", False)
        url               = all_test_urls[0] if all_test_urls else "https://example.com"
        parsed            = urlparse(url)

    # ── AUDIT RELIABILITY FLAG ────────────────────────────────────────────
    # Computed once; used by Pattern Brain, per-pillar AI calls, and banners.
    _block_decision = audit.get("_block_decision", {})
    _n_blocked_bots = (
        sum(1 for r in bot_crawl_results.values() if r.get("status_code") in (403, 503, 429))
        if bot_crawl_results else 0
    )
    _bot_block_rate = _n_blocked_bots / max(len(bot_crawl_results), 1) if bot_crawl_results else 0
    _total_page_checks = len(js_results) + len(schema_results) + len(semantic_results)
    _failed_page_checks = (
        sum(1 for r in js_results.values()       if r.get("error"))
      + sum(1 for r in schema_results.values()   if r.get("error"))
      + sum(1 for r in semantic_results.values() if r.get("error"))
    )
    _pillar_failure_rate = _failed_page_checks / max(_total_page_checks, 1)
    # Master flag — suppresses all Bifrost calls when the crawl was blocked
    _audit_unreliable = (
        _block_decision.get("warning", False)
        or _bot_block_rate >= 0.5
        or _pillar_failure_rate >= 0.5
    )

    # ── Report view header strip ──────────────────────────────────────────
    # Shown when _view == "report". Provides back navigation, domain summary,
    # and action buttons (Rerun, PDF, Share).
    if st.session_state.get("_view") == "report":
        _rh_domain    = parsed.netloc or "—"
        _rh_label     = st.session_state.get("_loaded_from_history", "")
        _rh_date      = _rh_label.split("·")[1].strip() if "·" in _rh_label else ""
        _rh_score_str = _rh_label.split("·")[2].strip() if _rh_label.count("·") >= 2 else f"{overall}%"
        _rh_audit_id  = st.session_state.get("_loaded_audit_id")

        # Build share URL from current query params
        _rh_host = st.context.headers.get("host", "") if hasattr(st, "context") else ""
        _rh_share_url = f"https://{_rh_host}/?audit={_rh_audit_id}" if _rh_audit_id and _rh_host else ""

        _rh_back_col, _rh_title_col, _rh_btn_col = st.columns([1, 5, 3])
        with _rh_back_col:
            if st.button("← Back", key="_rh_back", use_container_width=True):
                _origin = st.session_state.get("_view_origin", "history")
                st.session_state["_view"] = _origin
                st.session_state.pop("_view_origin", None)
                st.session_state.pop("_audit", None)
                st.session_state.pop("_loaded_audit_id", None)
                st.session_state.pop("_loaded_from_history", None)
                st.query_params.pop("audit", None)
                st.rerun()
        with _rh_title_col:
            _sc_color = (
                BRAND["teal"] if overall >= 75
                else BRAND["primary"] if overall >= 50
                else BRAND["warning"] if overall >= 35
                else BRAND["danger"]
            )
            _rh_grade = next(v for k, v in sorted({90:"A",75:"B",60:"C",40:"D",0:"F"}.items(), reverse=True) if overall >= k)
            _rh_badge = (
                f'<span style="background:{_sc_color}22;color:{_sc_color};'
                f'padding:4px 10px;border-radius:6px;font-size:13px;font-weight:700;">'
                f'{overall}% {_rh_grade}</span>'
            )
            _rh_subtitle = f"audited {_rh_date} · " if _rh_date else ""
            st.markdown(
                f'<div style="padding:6px 0;">'
                f'<span style="font-size:1.1rem;font-weight:700;color:{BRAND["white"]};">{_rh_domain}</span>'
                f'<span style="color:{BRAND["text_secondary"]};font-size:0.85rem;margin-left:10px;">{_rh_subtitle}</span>'
                f'{_rh_badge}'
                f'</div>',
                unsafe_allow_html=True,
            )
        with _rh_btn_col:
            _rh_b1, _rh_b2, _rh_b3 = st.columns(3)
            with _rh_b1:
                if is_history_authenticated():
                    _LABEL_TO_KEY = {
                        "Homepage": "home", "Category 1": "cat1", "Category 2": "cat2",
                        "Blog 1": "blog1", "Blog 2": "blog2",
                        "Content 1": "blog1", "Content 2": "blog2",
                        "Product 1": "prod1", "Product 2": "prod2",
                    }
                    if st.button("🔄 Rerun", key="_rh_rerun", use_container_width=True):
                        _inv = {v: k for k, v in (audit.get("url_labels") or {}).items()}
                        for _lbl, _wk in _LABEL_TO_KEY.items():
                            if _lbl in _inv:
                                st.session_state[f"_prefill_{_wk}"] = _inv[_lbl]
                        st.session_state["_prefill_no_blog"]       = bool(audit.get("no_blog", False))
                        st.session_state["_prefill_run_bot_crawl"] = bool(audit.get("bot_crawl_results"))
                        st.session_state.pop("_audit", None)
                        st.session_state.pop("_loaded_audit_id", None)
                        st.session_state.pop("_loaded_from_history", None)
                        st.query_params.pop("audit", None)
                        st.session_state["_pending_rerun"] = True
                        st.session_state["_view"] = "new"
                        st.rerun()
                else:
                    st.markdown(
                        f'<div style="font-size:11px;color:{BRAND["text_secondary"]};padding:8px 0;">Sign in to rerun or save audits.</div>',
                        unsafe_allow_html=True,
                    )
            with _rh_b2:
                # Two-step PDF download
                _rh_pdf_ready = st.session_state.get("_rh_pdf_ready")
                if _rh_pdf_ready:
                    from core.ui_recommendations import build_recommendations as _build_recs
                    _rh_recs = _build_recs(audit, no_blog)
                    _rh_pdf_bytes = _generate_report_pdf(
                        audit=audit, domain=parsed.netloc, recs=_rh_recs
                    )
                    st.download_button(
                        "📥 PDF",
                        data=_rh_pdf_bytes,
                        file_name=f"llm_audit_{parsed.netloc}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                        key="_rh_pdf_dl",
                    )
                    st.session_state.pop("_rh_pdf_ready", None)
                else:
                    if st.button("📥 PDF", key="_rh_pdf_btn", use_container_width=True):
                        st.session_state["_rh_pdf_ready"] = True
                        st.rerun()
            with _rh_b3:
                if _rh_audit_id:
                    _rh_share_open = st.session_state.get("_rh_share_open")
                    if st.button("🔗 Share", key="_rh_share_btn", use_container_width=True):
                        st.session_state["_rh_share_open"] = not _rh_share_open
                        st.rerun()
                    if _rh_share_open and _rh_share_url:
                        st.markdown(
                            f'<div style="font-size:11px;color:{BRAND["teal"]};margin-top:4px;">✓ Shareable links — copy and send</div>',
                            unsafe_allow_html=True,
                        )
                        _rh_pdf_share = f"{_rh_share_url}&format=pdf"
                        _rs_c1, _rs_c2 = st.columns(2)
                        with _rs_c1:
                            st.caption("View report")
                            st.code(_rh_share_url, language=None)
                        with _rs_c2:
                            st.caption("Direct PDF")
                            st.code(_rh_pdf_share, language=None)

        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)

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

    # Detect retroactive soft-block: pages with known challenge-page titles
    _softblock_urls = []
    _SOFT_TITLE_SIGS = (
        "pardon our interruption", "access denied", "checking your browser",
        "just a moment", "perimeterx", "datadome", "verify you are human",
    )
    for _u, _jr in js_results.items():
        _title = (_jr.get("content", {}).get("title") or "").lower()
        if any(sig in _title for sig in _SOFT_TITLE_SIGS):
            _softblock_urls.append(_u)
    # Uniform text length across all pages also indicates a block page
    _page_lengths = [
        _jr.get("content", {}).get("text_content_length", 0)
        for _jr in js_results.values() if not _jr.get("error")
    ]
    _page_lengths_nz = [L for L in _page_lengths if L > 0]
    if len(_page_lengths_nz) >= 3 and (max(_page_lengths_nz) - min(_page_lengths_nz)) < 50 and max(_page_lengths_nz) < 2000:
        _softblock_urls = list(js_results.keys())

    _cf_detected = robots_result.get("cloudflare", {}).get("cloudflare_detected", False)
    _cf_blocking = robots_result.get("cloudflare", {}).get("bot_fight_mode_likely", False)
    _bots_blocked = robots_result.get("cloudflare", {}).get("blocked_bots", [])
    _all_bots_blocked = bot_crawl_results and all(not r.get("is_allowed") for r in bot_crawl_results.values())

    if _cf_blocking or _antibot_urls or _antibot_schema or _all_bots_blocked or _softblock_urls:
        _blocked_pages = list(dict.fromkeys([url_labels.get(u, u) for u in _antibot_urls + _antibot_schema]))
        _bot_list = ", ".join(_bots_blocked) if _bots_blocked else ("All tested bots" if _all_bots_blocked else "")
        _detail_parts = []
        if _cf_blocking:
            _detail_parts.append(f"Cloudflare Bot Fight Mode is actively blocking AI crawlers ({_bot_list})")
        if _blocked_pages:
            _detail_parts.append(f"Crawl failed on: {', '.join(_blocked_pages)}")
        if _all_bots_blocked and not _cf_blocking:
            _detail_parts.append("All AI bots were blocked in the live crawl test")
        if _softblock_urls and not _antibot_urls:
            _detail_parts.append(
                f"All audited pages returned identical/near-identical content "
                f"({len(_softblock_urls)} pages) — strong indicator of an anti-bot "
                f"soft-block (Imperva, Akamai, PerimeterX, DataDome, or similar)"
            )
        _detail_html = " · ".join(_detail_parts)
        st.markdown(
            f'<div style="background:#ff4b4b18;border:1px solid #ff4b4b55;border-left:4px solid #ff4b4b;border-radius:0 10px 10px 0;padding:16px 20px;margin:12px 0;">'
            f'<div style="font-size:14px;font-weight:700;color:#ff4b4b;margin-bottom:6px;">🛡️ Anti-Bot Protection Detected — Results May Be Incomplete</div>'
            f'<div style="font-size:13px;color:{BRAND["white"]};line-height:1.6;">{_detail_html}</div>'
            f'<div style="font-size:12px;color:{BRAND["text_secondary"]};margin-top:8px;">Scores for affected pages are based on what our crawlers could access. Manual verification is recommended. Security section will still show exposure data collected before the block.</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Hard-block banner: fires for 403-based blocks that don't match soft-block signatures
    if _audit_unreliable and not _cf_blocking and not _antibot_urls and not _softblock_urls:
        _hr_reasons = []
        if _bot_block_rate >= 0.5:
            _hr_reasons.append(
                f"<strong>{_n_blocked_bots} of {len(bot_crawl_results)} AI bots returned 403/503/429</strong> "
                f"— the site is hard-blocking AI crawlers at the WAF/CDN level"
            )
        if _pillar_failure_rate >= 0.5:
            _hr_reasons.append(
                f"<strong>{_failed_page_checks} of {_total_page_checks} per-page checks failed</strong> "
                f"— most page audits could not fetch real content"
            )
        if _hr_reasons:
            st.markdown(
                f'<div style="background:#ff4b4b18;border:1px solid #ff4b4b55;'
                f'border-left:4px solid #ff4b4b;border-radius:0 10px 10px 0;'
                f'padding:16px 20px;margin:12px 0;">'
                f'<div style="font-size:14px;font-weight:700;color:#ff4b4b;margin-bottom:6px;">'
                f'🛡️ Audit Unreliable — Crawl Blocked at WAF Level</div>'
                f'<div style="font-size:13px;color:{BRAND["white"]};line-height:1.6;">'
                f'{"<br>".join(_hr_reasons)}</div>'
                f'<div style="font-size:12px;color:{BRAND["text_secondary"]};margin-top:10px;">'
                f'Scores below are based on incomplete data and should NOT be presented as a '
                f'real assessment. Pattern Brain analysis has been suppressed. To get an '
                f'accurate audit, the site owner must allowlist Pattern\'s infrastructure.'
                f'</div></div>',
                unsafe_allow_html=True,
            )
    elif _audit_unreliable:
        # 1-signal warning path (block_decision.warning) without a harder-coded banner above
        _bw_signals = ", ".join(k for k, v in _block_decision.get("signals", {}).items() if v)
        if _bw_signals:
            st.markdown(
                f'<div style="background:{BRAND["warning"]}18;border:1px solid {BRAND["warning"]}55;'
                f'border-left:4px solid {BRAND["warning"]};border-radius:0 10px 10px 0;'
                f'padding:12px 18px;margin:12px 0;">'
                f'<div style="font-size:13px;font-weight:600;color:{BRAND["warning"]};">'
                f'⚠️ Possible anti-bot interference — review results carefully ({_bw_signals})</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    if _cf_detected and not _cf_blocking:
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
            frameworks = [f for f in (js_r.get("frameworks") or []) if f and len(f) == 3]
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

                # AI Analysis (suppressed when crawl is unreliable)
                if _audit_unreliable:
                    ai_analysis = None
                else:
                    try:
                        ai_analysis = ai_analyse_js_gap(test_url, comp, label, get_secret_fn)
                    except Exception:
                        ai_analysis = None
                if "_audit" in st.session_state:
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

    # AI Analysis — What This Means (suppressed when crawl is unreliable)
    if _audit_unreliable:
        robots_ai = None
    else:
        try:
            robots_ai = analyse_robots_access(parsed.netloc, robots_result, get_secret_fn)
        except Exception:
            robots_ai = None
    if "_audit" in st.session_state:
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

            # AI Analysis — What This Means (suppressed when crawl is unreliable)
            if _audit_unreliable:
                schema_ai = None
            else:
                try:
                    schema_ai = analyse_schema_quality(test_url, schemas, get_secret_fn)
                except Exception:
                    schema_ai = None
            if "_audit" in st.session_state:
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

    # AI Analysis — What This Means (suppressed when crawl is unreliable)
    if _audit_unreliable:
        llm_ai = None
    else:
        try:
            llm_ai = analyse_llm_discoverability(parsed.netloc, llm_result, get_secret_fn)
        except Exception:
            llm_ai = None
    if "_audit" in st.session_state:
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

            # AI Analysis — What This Means (suppressed when crawl is unreliable)
            if _audit_unreliable:
                sem_ai = None
            else:
                try:
                    sem_ai = analyse_semantic_hierarchy(test_url, sem_r, label, get_secret_fn)
                except Exception:
                    sem_ai = None
            if "_audit" in st.session_state:
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

    if sec_findings.get("uniform_response_warning"):
        st.warning(f"🛡️ {sec_findings['uniform_response_warning']}")

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

    recs = build_recommendations(audit, no_blog)

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
    bifrost_key = get_secret_fn("BIFROST_API_KEY", "")
    if bifrost_key:
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(f'### {brand_pill("PATTERN BRAIN", BRAND["purple"])} AI Analysis', unsafe_allow_html=True)
        st.caption("Powered by Pattern's AI via Bifrost · openai/gpt-4o-mini")

        if _audit_unreliable:
            # Don't spend a Bifrost call on garbage data
            _ur_reasons = []
            if _bot_block_rate >= 0.5:
                _ur_reasons.append(f"{_n_blocked_bots}/{len(bot_crawl_results)} AI bots blocked at the WAF level")
            if _pillar_failure_rate >= 0.5:
                _ur_reasons.append(f"{_failed_page_checks}/{_total_page_checks} per-page checks failed")
            if not _ur_reasons and _block_decision.get("warning"):
                _ur_reasons.append("anti-bot interference signal detected")
            st.markdown(
                f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["warning"]}55;'
                f'border-left:3px solid {BRAND["warning"]};border-radius:0 10px 10px 0;'
                f'padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;">'
                f'<strong style="color:{BRAND["warning"]};">⚠️ Pattern Brain analysis suppressed.</strong><br/>'
                f'The crawl appears to have been blocked: '
                f'{"; ".join(_ur_reasons)}. '
                f'Generating an executive summary from this data would produce '
                f'misleading recommendations based on phantom findings.<br/><br/>'
                f'<strong>What to do:</strong> Resolve the block (contact the site owner '
                f'to allowlist Pattern\'s audit infrastructure), then rerun this audit.'
                f'</div>',
                unsafe_allow_html=True,
            )
            if "_audit" in st.session_state:
                st.session_state["_audit"]["pattern_brain"] = None
        else:
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
                    brain_analysis = pattern_brain_analysis(parsed.netloc, all_results_for_brain, get_secret_fn)
                except Exception:
                    brain_analysis = None
                if "_audit" in st.session_state:
                    st.session_state["_audit"]["pattern_brain"] = brain_analysis

                # Persist Pattern Brain back to Supabase so PDF downloads from history include it
                _loaded_id = st.session_state.get("_loaded_audit_id")
                if brain_analysis and _loaded_id:
                    try:
                        from core.persistence import get_supabase
                        _sb = get_supabase()
                        if _sb:
                            _existing = _sb.table("audits").select("full_results").eq("id", str(_loaded_id)).limit(1).execute().data
                            if _existing and _existing[0].get("full_results"):
                                _fr = _existing[0]["full_results"]
                                if not _fr.get("pattern_brain"):
                                    _fr["pattern_brain"] = brain_analysis
                                    for _key in ("_bifrost_js", "_bifrost_robots", "_bifrost_schema", "_bifrost_llm", "_bifrost_sem"):
                                        if _key in st.session_state.get("_audit", {}):
                                            _fr[_key] = st.session_state["_audit"][_key]
                                    _sb.table("audits").update({"full_results": _fr}).eq("id", str(_loaded_id)).execute()
                    except Exception:
                        pass  # Non-fatal — PDF will still generate from session state

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
    report_pdf = _generate_report_pdf(
        audit=_audit_dict,
        domain=parsed.netloc,
        recs=recs,
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
