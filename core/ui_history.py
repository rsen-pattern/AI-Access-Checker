# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Past Audits view.

Renders the history view: auth gate, search/filter/sort bar, unified row
layout (checkbox | domain+date | score | pillar bars | Open | PDF | Share | Delete),
Before/After comparison expander, and Bulk Rerun expander.

Side effects on session state:
- Sets st.session_state["_history_user"] on successful sign-in.
- Sets st.session_state["_audit"] when the user clicks Open on a past audit.
- Sets st.session_state["_loaded_audit_id"] and st.session_state["_loaded_from_history"] alongside.
- Queues bulk reruns by setting st.session_state["_bulk_rerun_queue"] and
  st.session_state["_bulk_rerun_progress"].
- Sets st.session_state["_prefill_*"] for individual rerun buttons.
- Sets st.session_state["_pending_rerun"] to trigger an audit run on next rerender.
- Mutates st.query_params["audit"] when sharing or loading.
- Tracks _bulk_delete_selected (set[str]) for multi-row delete.

These side effects are consumed by the audit form and the top-of-script
bulk-rerun queue processor and prefill handlers. Do not change the keys or
semantics. _bulk_rerun_current_id is set by the top-of-script queue processor
(not here) and consumed by the audit pipeline to overwrite the existing DB row.
"""

import csv
import io
import json
import re

import streamlit as st

from core.branding import BRAND
from core.persistence import (
    auth_sign_in,
    delete_audit_by_id,
    get_supabase,
    is_history_authenticated,
    load_audit_history,
)

_PILLARS   = ["JS Rendering", "Robots & Crawl", "Schema & Entity", "AI Discoverability", "Semantic Hierarchy", "Security"]
_P_SHORT   = ["JS", "Robots", "Schema", "AI", "Sem", "Sec"]
_GRADE_MAP = {90: "A", 75: "B", 60: "C", 40: "D", 0: "F"}

_LABEL_TO_KEY = {
    "Homepage":   "home",
    "Category 1": "cat1", "Category 2": "cat2",
    "Blog 1":     "blog1", "Blog 2":     "blog2",
    "Content 1":  "blog1", "Content 2":  "blog2",
    "Product 1":  "prod1", "Product 2":  "prod2",
}


def _score_color(s: int) -> str:
    return (
        BRAND["teal"]    if s >= 75 else
        BRAND["primary"] if s >= 50 else
        BRAND["warning"] if s >= 35 else
        BRAND["danger"]
    )


def _grade(s: int) -> str:
    return next(v for k, v in sorted(_GRADE_MAP.items(), reverse=True) if s >= k)


def _score_badge(score: int) -> str:
    color = _score_color(score)
    grade = _grade(score)
    return (
        f'<span style="background:{color}22;color:{color};'
        f'padding:4px 10px;border-radius:6px;font-size:13px;'
        f'font-weight:700;">{score}% {grade}</span>'
    )


def _highlight(text: str, query: str) -> str:
    """Highlight query matches inside text with a subtle primary-colour mark."""
    if not query or len(query) < 2:
        return text
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    return pattern.sub(
        lambda m: (
            f'<mark style="background:{BRAND["primary"]}33;color:{BRAND["white"]};'
            f'padding:0 2px;border-radius:2px;">{m.group(0)}</mark>'
        ),
        text,
    )


def _render_auth_gate(message: str) -> None:
    """Render the login form with a context-specific message.

    Halts the calling view by returning early — caller checks
    is_history_authenticated() before proceeding past this call.
    """
    st.markdown(
        f'<div style="color:{BRAND["text_secondary"]};font-size:14px;margin-bottom:16px;">{message}</div>',
        unsafe_allow_html=True,
    )
    _login_col, _ = st.columns([1, 1])
    with _login_col:
        _email    = st.text_input("Email", key="hist_email")
        _password = st.text_input("Password", type="password", key="hist_password")
        if st.button("Sign in", type="primary", use_container_width=True, key="hist_login"):
            if _email and _password:
                _user, _err = auth_sign_in(_email, _password)
                if _user:
                    st.session_state["_history_user"] = _user
                    st.session_state["_view"] = "new"
                    st.rerun()
                else:
                    st.error("Login failed — check your email and password.")
            else:
                st.warning("Enter your email and password.")


def _pillar_bars_html(ps: dict) -> str:
    """Return HTML for a 3×2 grid of mini pillar score bars."""
    bars = ""
    for short, full in zip(_P_SHORT, _PILLARS):
        score = ps.get(full, 0)
        color = _score_color(score)
        pct   = min(score, 100)
        bars += (
            f'<div style="display:inline-block;width:62px;margin:1px 2px;vertical-align:top;">'
            f'<div style="background:{BRAND["border"]};border-radius:2px;height:4px;width:100%;">'
            f'<div style="background:{color};width:{pct}%;height:4px;border-radius:2px;"></div></div>'
            f'<div style="font-size:9px;color:{BRAND["text_secondary"]};margin-top:2px;text-align:center;">{short}</div>'
            f'</div>'
        )
    return (
        f'<div style="display:flex;flex-wrap:wrap;width:220px;gap:0;">'
        + bars
        + '</div>'
    )


def _render_audit_row(
    row: dict,
    row_index: int,
    host: str,
    row_key_prefix: str = "",
) -> None:
    """Render a single unified audit row (checkbox | info | score | bars | actions).

    row_key_prefix allows disambiguation when rows appear inside group expanders.
    """
    _dom      = row.get("domain", "—")
    _date     = (row.get("audited_at") or "")[:10]
    _sc       = row.get("overall_score", 0)
    _audit_id = str(row.get("id") or "")
    _fr       = row.get("full_results")
    _has_full = isinstance(_fr, dict) and "js_results" in _fr

    try:
        _ps = json.loads(row.get("pillar_scores") or "{}")
    except Exception:
        _ps = {}

    _row_bg  = BRAND["bg_card"] if row_index % 2 == 0 else BRAND["bg_surface"]
    _pfx     = f"{row_key_prefix}{_audit_id}"

    # Shared state keys (single-item, so no prefix needed — only one can be active at a time)
    _share_key = "_share_open_id"
    _pdf_key   = "_pdf_ready_id"
    _del_key   = "_delete_pending_id"

    _share_open  = st.session_state.get(_share_key) == _audit_id
    _pdf_ready   = st.session_state.get(_pdf_key) == _audit_id
    _del_pending = st.session_state.get(_del_key) == _audit_id

    # Bulk-delete selection state
    _bulk_sel: set = st.session_state.get("_bulk_delete_selected") or set()
    _is_selected   = _audit_id in _bulk_sel
    _bulk_confirm  = st.session_state.get("_bulk_delete_confirm", False)

    with st.container():
        st.markdown(
            f'<div class="hist-row" style="background:{_row_bg};border-bottom:1px solid {BRAND["border"]};'
            f'padding:10px 4px;min-height:64px;">',
            unsafe_allow_html=True,
        )

        if _del_pending:
            # In-place single-row delete confirmation — full width
            _dc1, _dc2, _dc3 = st.columns([4, 1, 1])
            with _dc1:
                st.markdown(
                    f'<div style="padding:8px 0;color:{BRAND["danger"]};font-size:13px;font-weight:600;">'
                    f'Delete <strong>{_dom}</strong> from {_date}?</div>',
                    unsafe_allow_html=True,
                )
            with _dc2:
                if st.button("Confirm delete", key=f"del_yes_{_pfx}", type="primary", use_container_width=True):
                    delete_audit_by_id(_audit_id)
                    st.session_state.pop(_del_key, None)
                    st.rerun()
            with _dc3:
                if st.button("Cancel", key=f"del_cancel_{_pfx}", use_container_width=True):
                    st.session_state.pop(_del_key, None)
                    st.rerun()
        else:
            # Normal row — [0.4, 3, 1, 3, 1, 0.7, 0.7, 0.7, 0.5]
            _c_chk, _c_info, _c_score, _c_bars, _c_open, _c_rerun, _c_pdf, _c_share, _c_del = st.columns(
                [0.4, 3, 1, 3, 1, 0.7, 0.7, 0.7, 0.5]
            )

            with _c_chk:
                if _audit_id and _has_full and not _bulk_confirm:
                    _checked = st.checkbox(
                        "",
                        value=_is_selected,
                        key=f"chk_{_pfx}",
                        label_visibility="collapsed",
                    )
                    if _checked != _is_selected:
                        _new_sel = set(_bulk_sel)
                        if _checked:
                            _new_sel.add(_audit_id)
                        else:
                            _new_sel.discard(_audit_id)
                        st.session_state["_bulk_delete_selected"] = _new_sel
                        st.rerun()

            with _c_info:
                _dom_html = _highlight(_dom, st.session_state.get("hist_search", ""))
                st.markdown(
                    f'<div style="padding:6px 0;">'
                    f'<div style="font-size:14px;font-weight:700;color:{BRAND["white"]};">{_dom_html}</div>'
                    f'<div style="font-size:12px;color:{BRAND["text_secondary"]};margin-top:2px;">{_date}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            with _c_score:
                st.markdown(
                    f'<div style="padding:6px 0;">{_score_badge(_sc)}</div>',
                    unsafe_allow_html=True,
                )

            with _c_bars:
                st.markdown(_pillar_bars_html(_ps), unsafe_allow_html=True)

            with _c_open:
                if st.button(
                    "Open",
                    key=f"open_{_pfx}",
                    type="primary",
                    disabled=not _has_full,
                    use_container_width=True,
                ):
                    st.session_state["_audit"]               = _fr
                    st.session_state["_loaded_from_history"]  = f"{_dom} · {_date} · {_sc}%"
                    st.session_state["_loaded_audit_id"]     = _audit_id
                    st.session_state["_view"]                = "report"
                    st.session_state["_view_origin"]         = "history"
                    st.query_params["audit"]                 = _audit_id
                    st.rerun()

            with _c_rerun:
                _bulk_active = bool(st.session_state.get("_bulk_rerun_queue"))
                if _audit_id and _has_full and is_history_authenticated() and not _bulk_active:
                    if st.button(
                        "🔄",
                        key=f"rerun_{_pfx}",
                        use_container_width=True,
                        help="Rerun this audit (overwrites existing row)",
                    ):
                        _label_to_key = {
                            "Homepage": "home", "Category 1": "cat1", "Category 2": "cat2",
                            "Blog 1": "blog1", "Blog 2": "blog2",
                            "Content 1": "blog1", "Content 2": "blog2",
                            "Product 1": "prod1", "Product 2": "prod2",
                        }
                        _inv = {v: k for k, v in (_fr.get("url_labels") or {}).items()}
                        for _lbl, _wk in _label_to_key.items():
                            if _lbl in _inv:
                                st.session_state[f"_prefill_{_wk}"] = _inv[_lbl]
                        st.session_state["_prefill_no_blog"]       = bool(_fr.get("no_blog", False))
                        st.session_state["_prefill_run_bot_crawl"] = bool(_fr.get("bot_crawl_results"))
                        # Mark as in-place rerun — pipeline will UPDATE not INSERT
                        st.session_state["_bulk_rerun_current_id"] = str(_audit_id)
                        st.session_state.pop("_audit", None)
                        st.session_state.pop("_loaded_audit_id", None)
                        st.session_state.pop("_loaded_from_history", None)
                        st.query_params.pop("audit", None)
                        st.session_state["_pending_rerun"] = True
                        st.session_state["_view"] = "new"
                        st.rerun()
                elif _audit_id and _has_full:
                    _help = (
                        "Sign in to rerun audits" if not is_history_authenticated()
                        else "Bulk rerun in progress — wait until it completes"
                    )
                    st.button(
                        "🔄",
                        key=f"rerun_{_pfx}",
                        use_container_width=True,
                        disabled=True,
                        help=_help,
                    )

            with _c_pdf:
                if _has_full:
                    if _pdf_ready:
                        from core.ui_recommendations import build_recommendations as _br
                        from report_pdf import generate_report_pdf as _grpdf
                        from urllib.parse import urlparse as _urlparse
                        _pdf_urls  = _fr.get("all_test_urls", [])
                        _pdf_url   = _pdf_urls[0] if _pdf_urls else "https://example.com"
                        _pdf_dom   = _urlparse(_pdf_url).netloc or _dom
                        _pdf_recs  = _br(_fr, bool(_fr.get("no_blog", False)))
                        _pdf_bytes = _grpdf(audit=_fr, domain=_pdf_dom, recs=_pdf_recs)
                        st.download_button(
                            "📥",
                            data=_pdf_bytes,
                            file_name=f"llm_audit_{_dom}.pdf",
                            mime="application/pdf",
                            use_container_width=True,
                            key=f"pdf_dl_{_pfx}",
                        )
                        st.session_state.pop(_pdf_key, None)
                    else:
                        if st.button("📥", key=f"pdf_btn_{_pfx}", use_container_width=True, help="Download PDF report"):
                            st.session_state[_pdf_key] = _audit_id
                            st.rerun()

            with _c_share:
                if _audit_id and _has_full:
                    if st.button("🔗", key=f"share_{_pfx}", use_container_width=True, help="Copy shareable link"):
                        if _share_open:
                            st.session_state.pop(_share_key, None)
                        else:
                            st.session_state[_share_key] = _audit_id
                        st.rerun()

            with _c_del:
                # Hide single-row delete when bulk-confirm is active
                if _audit_id and not _bulk_confirm:
                    if st.button("⋮", key=f"del_{_pfx}", use_container_width=True, help="Delete audit"):
                        st.session_state[_del_key] = _audit_id
                        st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

    # Share block — rendered full-width immediately below the row
    if _share_open and _audit_id:
        _share_url = f"https://{host}/?audit={_audit_id}" if host else f"/?audit={_audit_id}"
        _pdf_url_s = f"https://{host}/?audit={_audit_id}&format=pdf" if host else f"/?audit={_audit_id}&format=pdf"
        st.markdown(
            f'<div style="color:{BRAND["teal"]};font-size:12px;margin:4px 0 2px 0;">'
            f'✓ Shareable links — copy and send</div>',
            unsafe_allow_html=True,
        )
        _sl_c1, _sl_c2 = st.columns(2)
        with _sl_c1:
            st.caption("View report")
            st.code(_share_url, language=None)
        with _sl_c2:
            st.caption("Direct PDF")
            st.code(_pdf_url_s, language=None)


def render_history_tab() -> None:
    """Render the Past Audits view."""
    st.markdown(
        f'<div style="font-size:22px;font-weight:800;color:{BRAND["white"]};margin-bottom:4px;">Past Audits</div>'
        f'<div style="height:2px;background:linear-gradient(90deg,{BRAND["purple"]},{BRAND["primary"]},transparent);margin-bottom:20px;"></div>',
        unsafe_allow_html=True,
    )

    # ── Auth gate ─────────────────────────────────────────────────────────────
    if not is_history_authenticated():
        _render_auth_gate(
            "Authentication is required to browse past audits. "
            "Shared report links work without signing in."
        )
        return

    # ── Signed-in header ──────────────────────────────────────────────────────
    _auth_col, _logout_col = st.columns([5, 1])
    with _auth_col:
        st.markdown(
            f'<div style="color:{BRAND["text_secondary"]};font-size:12px;margin-bottom:12px;">'
            f'Signed in as <strong style="color:{BRAND["teal"]};">{st.session_state["_history_user"]}</strong></div>',
            unsafe_allow_html=True,
        )
    with _logout_col:
        if st.button("Sign out", key="hist_logout"):
            st.session_state.pop("_history_user", None)
            st.rerun()

    if get_supabase() is None:
        st.info("Add SUPABASE_URL and SUPABASE_KEY to Streamlit secrets to enable audit history.")
        return

    _hist_all = load_audit_history(limit=50)

    # ── Empty state (no audits at all) ────────────────────────────────────────
    if not _hist_all:
        st.markdown(
            f'''<div style="background:{BRAND['bg_card']};border:1px solid {BRAND['border']};
                border-radius:12px;padding:32px 24px;text-align:center;margin-top:24px;">
              <div style="font-size:32px;margin-bottom:8px;">📋</div>
              <div style="font-size:16px;font-weight:600;color:{BRAND['white']};
                          margin-bottom:6px;">No audits yet</div>
              <div style="color:{BRAND['text_secondary']};font-size:13px;
                          margin-bottom:16px;">Run your first audit to see results here.</div>
            </div>''',
            unsafe_allow_html=True,
        )
        if st.button("Run your first audit", type="primary", key="empty_state_cta"):
            st.session_state["_view"] = "new"
            st.rerun()
        return

    # ── Bulk-delete selection action bar ─────────────────────────────────────
    _bulk_sel: set = st.session_state.get("_bulk_delete_selected") or set()
    _bulk_confirm  = st.session_state.get("_bulk_delete_confirm", False)
    _del_pending_single = st.session_state.get("_delete_pending_id")

    if _bulk_sel and not _del_pending_single:
        _n_sel = len(_bulk_sel)
        if _bulk_confirm:
            _bc1, _bc2, _bc3, _bc4 = st.columns([3, 1, 1, 1])
            with _bc1:
                st.markdown(
                    f'<div style="padding:8px 0;color:{BRAND["danger"]};font-size:13px;font-weight:600;">'
                    f'Delete {_n_sel} audit{"s" if _n_sel != 1 else ""}? This cannot be undone.</div>',
                    unsafe_allow_html=True,
                )
            with _bc2:
                if st.button("Confirm", key="bulk_del_confirm_yes", type="primary", use_container_width=True):
                    for _bid in list(_bulk_sel):
                        delete_audit_by_id(_bid)
                    st.session_state.pop("_bulk_delete_selected", None)
                    st.session_state.pop("_bulk_delete_confirm", None)
                    st.rerun()
            with _bc3:
                if st.button("Cancel", key="bulk_del_confirm_no", use_container_width=True):
                    st.session_state.pop("_bulk_delete_confirm", None)
                    st.rerun()
        else:
            _ba1, _ba2, _ba3, _ba4 = st.columns([2, 1.5, 1, 2])
            with _ba1:
                st.markdown(
                    f'<div style="padding:8px 0;color:{BRAND["white"]};font-size:13px;font-weight:600;">'
                    f'{_n_sel} selected</div>',
                    unsafe_allow_html=True,
                )
            with _ba2:
                if st.button("🗑 Delete selected", key="bulk_del_btn", type="primary", use_container_width=True):
                    st.session_state["_bulk_delete_confirm"] = True
                    st.rerun()
            with _ba3:
                if st.button("Clear selection", key="bulk_del_clear", use_container_width=True):
                    st.session_state.pop("_bulk_delete_selected", None)
                    st.rerun()

    # ── Search / Filter / Sort bar ────────────────────────────────────────────
    _SCORE_BANDS = ["Any", "<35 (F)", "35–49 (D)", "50–69 (C)", "70–84 (B)", "85+ (A)"]
    _SORT_OPTS   = ["Newest", "Oldest", "Highest score", "Lowest score"]

    _sb_c1, _sb_c2, _sb_c3, _sb_c4, _sb_c5 = st.columns([3, 2, 1.5, 1, 1])
    with _sb_c1:
        _search = st.text_input(
            "search",
            placeholder="Search by domain…",
            label_visibility="collapsed",
            key="hist_search",
        )
    with _sb_c2:
        _band = st.select_slider(
            "score_band",
            options=_SCORE_BANDS,
            value=st.session_state.get("hist_band_val", "Any"),
            label_visibility="collapsed",
            key="hist_band",
        )
    with _sb_c3:
        _sort = st.selectbox(
            "sort",
            _SORT_OPTS,
            index=_SORT_OPTS.index(st.session_state.get("hist_sort_val", "Newest")),
            label_visibility="collapsed",
            key="hist_sort",
        )
    with _sb_c4:
        _group_by = st.toggle(
            "Group",
            value=st.session_state.get("hist_group_by_domain", False),
            key="hist_group_by_domain",
            help="Group by domain",
        )
    with _sb_c5:
        # CSV export — built from the full unfiltered list
        _csv_buf = io.StringIO()
        _csv_w   = csv.writer(_csv_buf)
        _csv_w.writerow(["Domain", "Date", "Overall Score", "Grade"] + _PILLARS)
        for _r in _hist_all:
            _d  = _r.get("domain", "")
            _dt = (_r.get("audited_at") or "")[:10]
            _sc = _r.get("overall_score", 0)
            try:
                _ps = json.loads(_r.get("pillar_scores") or "{}")
            except Exception:
                _ps = {}
            _csv_w.writerow([_d, _dt, _sc, _grade(_sc)] + [_ps.get(p, 0) for p in _PILLARS])
        st.download_button(
            "⬇ CSV",
            _csv_buf.getvalue(),
            "audit_history.csv",
            "text/csv",
            use_container_width=True,
            key="csv_export",
        )

    # Apply filters
    def _in_band(s: int) -> bool:
        if _band == "Any":        return True
        if _band == "<35 (F)":    return s < 35
        if _band == "35–49 (D)":  return 35 <= s <= 49
        if _band == "50–69 (C)":  return 50 <= s <= 69
        if _band == "70–84 (B)":  return 70 <= s <= 84
        if _band == "85+ (A)":    return s >= 85
        return True

    _rows = [
        r for r in _hist_all
        if (_search.lower() in (r.get("domain") or "").lower())
        and _in_band(r.get("overall_score", 0))
    ]

    # Sort
    if _sort == "Newest":
        _rows.sort(key=lambda r: r.get("audited_at") or "", reverse=True)
    elif _sort == "Oldest":
        _rows.sort(key=lambda r: r.get("audited_at") or "")
    elif _sort == "Highest score":
        _rows.sort(key=lambda r: r.get("overall_score", 0), reverse=True)
    elif _sort == "Lowest score":
        _rows.sort(key=lambda r: r.get("overall_score", 0))

    _total = len(_hist_all)
    _shown = len(_rows)

    if _shown == 0:
        st.markdown(
            f'<div style="color:{BRAND["text_secondary"]};font-size:13px;margin:4px 0 16px 0;">'
            f'Showing 0 of {_total} audits</div>',
            unsafe_allow_html=True,
        )
        with st.container():
            st.markdown(
                f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};'
                f'border-radius:12px;padding:24px;text-align:center;margin-bottom:16px;">'
                f'<div style="color:{BRAND["text_secondary"]};font-size:15px;margin-bottom:12px;">'
                f'No audits match the current filters.</div></div>',
                unsafe_allow_html=True,
            )
            if st.button("Clear filters", key="hist_clear_filters"):
                st.session_state["hist_search"] = ""
                st.session_state["hist_band"]   = "Any"
                st.session_state["hist_sort"]   = "Newest"
                st.rerun()
        return
    else:
        st.markdown(
            f'<div style="color:{BRAND["text_secondary"]};font-size:13px;margin:4px 0 12px 0;">'
            f'Showing {_shown} of {_total} audit{"s" if _total != 1 else ""}</div>',
            unsafe_allow_html=True,
        )

    # Get host for share URLs
    _host = ""
    try:
        if hasattr(st, "context"):
            _host = st.context.headers.get("host", "")
    except Exception:
        pass

    # ── Row list — flat or grouped ────────────────────────────────────────────
    st.markdown('<div class="hist-list">', unsafe_allow_html=True)

    if _group_by:
        # Group rows by domain, keep domain order by latest audit date (or score sort)
        _domain_order: list[str] = []
        _domain_rows: dict[str, list] = {}
        for _r in _rows:
            _d = _r.get("domain") or "—"
            if _d not in _domain_rows:
                _domain_rows[_d] = []
                _domain_order.append(_d)
            _domain_rows[_d].append(_r)

        for _gi, _gdom in enumerate(_domain_order):
            _grow = _domain_rows[_gdom]
            # Sort within group by newest first for delta computation
            _grow_sorted = sorted(_grow, key=lambda r: r.get("audited_at") or "", reverse=True)
            _latest  = _grow_sorted[0]
            _lat_sc  = _latest.get("overall_score", 0)
            _lat_dt  = (_latest.get("audited_at") or "")[:10]

            # Delta vs previous audit in same domain
            if len(_grow_sorted) >= 2:
                _prev_sc  = _grow_sorted[1].get("overall_score", 0)
                _prev_dt  = (_grow_sorted[1].get("audited_at") or "")[:10]
                _delta    = _lat_sc - _prev_sc
                _delta_c  = BRAND["teal"] if _delta > 0 else BRAND["danger"] if _delta < 0 else BRAND["text_secondary"]
                _delta_s  = f'+{_delta}' if _delta > 0 else str(_delta)
                _delta_html = (
                    f'<span style="color:{_delta_c};font-size:12px;margin-left:8px;">'
                    f'{_delta_s}pts vs {_prev_dt}</span>'
                )
            else:
                _delta_html = (
                    f'<span style="color:{BRAND["text_secondary"]};font-size:12px;margin-left:8px;">'
                    f'First audit</span>'
                )

            _exp_title = (
                f'{_gdom} — {_score_badge(_lat_sc)} {_delta_html}'
            )
            with st.expander(_exp_title, expanded=False):
                for _ri, _gr in enumerate(_grow_sorted):
                    _render_audit_row(_gr, _ri, _host, row_key_prefix=f"g{_gi}_")
    else:
        for _i, _row in enumerate(_rows):
            _render_audit_row(_row, _i, _host)

    st.markdown('</div>', unsafe_allow_html=True)

    # ── Expanders ─────────────────────────────────────────────────────────────
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)

    with st.expander("📊 Before / After Comparison", expanded=False):
        _domains_list    = sorted(set(r.get("domain", "") for r in _hist_all if r.get("domain")))
        _comp_domains    = [d for d in _domains_list if sum(1 for r in _hist_all if r.get("domain") == d) >= 2]
        if not _comp_domains:
            st.markdown(
                f'<div style="color:{BRAND["text_secondary"]};font-size:13px;">Need at least 2 audits for the same domain to compare.</div>',
                unsafe_allow_html=True,
            )
        else:
            _comp_dom  = st.selectbox("Domain", _comp_domains, key="comp_domain")
            _dom_rows  = sorted(
                [r for r in _hist_all if r.get("domain") == _comp_dom],
                key=lambda r: r.get("audited_at") or "", reverse=True,
            )
            _comp_opts = [f"{(r.get('audited_at') or '')[:10]}  —  {r.get('overall_score', 0)}%" for r in _dom_rows]
            _c1, _c2   = st.columns(2)
            with _c1:
                _bi = st.selectbox("Before (older)", range(len(_comp_opts)),
                    format_func=lambda i: _comp_opts[i], index=min(1, len(_dom_rows)-1), key="comp_before")
            with _c2:
                _ai = st.selectbox("After (newer)", range(len(_comp_opts)),
                    format_func=lambda i: _comp_opts[i], index=0, key="comp_after")
            _brow = _dom_rows[_bi]; _arow = _dom_rows[_ai]
            try:
                _ps_b = json.loads(_brow.get("pillar_scores") or "{}")
            except Exception:
                _ps_b = {}
            try:
                _ps_a = json.loads(_arow.get("pillar_scores") or "{}")
            except Exception:
                _ps_a = {}
            _sc_b  = _brow.get("overall_score", 0)
            _sc_a  = _arow.get("overall_score", 0)
            _diff  = _sc_a - _sc_b
            _dc    = BRAND["teal"] if _diff > 0 else BRAND["danger"] if _diff < 0 else BRAND["text_secondary"]
            _ds    = "+" if _diff > 0 else ""
            st.markdown(
                f'<div style="display:flex;gap:16px;margin:12px 0;">'
                f'<div style="flex:1;background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:16px;text-align:center;">'
                f'<div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;">Before</div>'
                f'<div style="font-size:28px;font-weight:800;color:{BRAND["white"]};">{_sc_b}%</div>'
                f'<div style="font-size:11px;color:{BRAND["text_secondary"]};">{(_brow.get("audited_at") or "")[:10]}</div></div>'
                f'<div style="flex:0.5;display:flex;align-items:center;justify-content:center;">'
                f'<div style="font-size:24px;font-weight:800;color:{_dc};">{_ds}{_diff}pts</div></div>'
                f'<div style="flex:1;background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:16px;text-align:center;">'
                f'<div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;">After</div>'
                f'<div style="font-size:28px;font-weight:800;color:{BRAND["white"]};">{_sc_a}%</div>'
                f'<div style="font-size:11px;color:{BRAND["text_secondary"]};">{(_arow.get("audited_at") or "")[:10]}</div></div></div>',
                unsafe_allow_html=True,
            )
            _ph = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0;">'
            for p in _PILLARS:
                _pb = _ps_b.get(p, 0); _pa = _ps_a.get(p, 0); _pd = _pa - _pb
                _pc = BRAND["teal"] if _pd > 0 else BRAND["danger"] if _pd < 0 else BRAND["text_secondary"]
                _psgn = "+" if _pd > 0 else ""
                _ph += (
                    f'<div style="flex:1;min-width:120px;background:{BRAND["bg_surface"]};border-radius:8px;padding:10px;text-align:center;">'
                    f'<div style="font-size:10px;color:{BRAND["text_secondary"]};text-transform:uppercase;">{p}</div>'
                    f'<div style="font-size:14px;font-weight:700;color:{BRAND["white"]};">{_pb} → {_pa}</div>'
                    f'<div style="font-size:12px;font-weight:700;color:{_pc};">{_psgn}{_pd}</div></div>'
                )
            _ph += '</div>'
            st.markdown(_ph, unsafe_allow_html=True)

    with st.expander("🔄 Bulk Rerun (re-audit multiple sites at once)", expanded=False):
        _bulk_eligible_ids = [
            r.get("id") for r in _rows
            if r.get("id") and isinstance(r.get("full_results"), dict) and "js_results" in (r.get("full_results") or {})
        ]
        _active_bulk_q = st.session_state.get("_bulk_rerun_queue")
        _bulk_prog     = st.session_state.get("_bulk_rerun_progress", {"total": 0, "done": 0})
        if _active_bulk_q is not None:
            _bq_done  = _bulk_prog.get("done", 0)
            _bq_total = _bulk_prog.get("total", 1)
            st.progress(
                _bq_done / max(_bq_total, 1),
                text=f"Rerunning audits: {_bq_done}/{_bq_total} complete — {len(_active_bulk_q)} remaining",
            )
            if st.button("Cancel", key="bulk_cancel", type="secondary"):
                for _k in ("_bulk_rerun_queue", "_bulk_rerun_progress", "_bulk_rerun_current_id", "_pending_rerun"):
                    st.session_state.pop(_k, None)
                st.rerun()
        else:
            if _bulk_eligible_ids:
                st.markdown(
                    f'<div style="color:{BRAND["text_secondary"]};font-size:13px;margin-bottom:10px;">'
                    f'Reruns all <strong>{len(_bulk_eligible_ids)}</strong> audits in the current view sequentially, '
                    f'overwriting each row with fresh scores. Do not close this tab while running.</div>',
                    unsafe_allow_html=True,
                )
                if st.button(f"🔄 Rerun All ({len(_bulk_eligible_ids)} audits)", key="bulk_rerun_all", type="primary"):
                    st.session_state["_bulk_rerun_queue"]    = list(_bulk_eligible_ids)
                    st.session_state["_bulk_rerun_progress"] = {"total": len(_bulk_eligible_ids), "done": 0}
                    st.rerun()
            else:
                st.markdown(
                    f'<div style="color:{BRAND["text_secondary"]};font-size:13px;">No audits with full data available to rerun.</div>',
                    unsafe_allow_html=True,
                )
