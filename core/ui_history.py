# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Past Audits tab.

Renders the entire history tab: auth gate, history table, CSV export,
load/rerun/share/delete buttons, before/after comparison, and bulk rerun.

Side effects on session state:
- Sets st.session_state["_history_user"] on successful sign-in.
- Sets st.session_state["_audit"] when the user clicks Load on a past audit.
- Sets st.session_state["_loaded_audit_id"] and st.session_state["_loaded_from_history"] alongside.
- Queues bulk reruns by setting st.session_state["_bulk_rerun_queue"] and
  st.session_state["_bulk_rerun_progress"].
- Sets st.session_state["_prefill_*"] for individual rerun buttons.
- Sets st.session_state["_pending_rerun"] to trigger an audit run on next rerender.
- Mutates st.query_params["audit"] when sharing or loading.

These side effects are consumed by the audit tab and the top-of-script
bulk-rerun queue processor and prefill handlers. Do not change the keys or
semantics. _bulk_rerun_current_id is set by the top-of-script queue processor
(not here) and consumed by the audit pipeline to overwrite the existing DB row.
"""

import csv
import io
import json

import streamlit as st

from core.branding import BRAND
from core.persistence import (
    auth_sign_in,
    delete_audit_by_id,
    get_supabase,
    is_history_authenticated,
    load_audit_history,
)


def render_history_tab() -> None:
    """Render the Past Audits tab.

    Must be called inside a `with tab_history:` context. Returns nothing —
    all interactions persist via session state and query params, which the
    rest of the app reads on subsequent rerenders.
    """
    st.markdown(f'<div style="font-size:22px;font-weight:800;color:{BRAND["white"]};margin-bottom:4px;">Past Audits</div><div style="height:2px;background:linear-gradient(90deg,{BRAND["purple"]},{BRAND["primary"]},transparent);margin-bottom:20px;"></div>', unsafe_allow_html=True)

    # ── Auth gate ────────────────────────────────────────────────────────────
    if not is_history_authenticated():
        st.markdown(f'<div style="color:{BRAND["text_secondary"]};font-size:14px;margin-bottom:16px;">Sign in to view and manage past audits.</div>', unsafe_allow_html=True)
        _login_col, _ = st.columns([1, 1])
        with _login_col:
            _email = st.text_input("Email", key="hist_email")
            _password = st.text_input("Password", type="password", key="hist_password")
            if st.button("Sign in", type="primary", use_container_width=True, key="hist_login"):
                if _email and _password:
                    _user, _err = auth_sign_in(_email, _password)
                    if _user:
                        st.session_state["_history_user"] = _user
                        st.rerun()
                    else:
                        st.error("Login failed — check your email and password.")
                else:
                    st.warning("Enter your email and password.")
    else:
        # Logged-in header
        _auth_col, _logout_col = st.columns([5, 1])
        with _auth_col:
            st.markdown(f'<div style="color:{BRAND["text_secondary"]};font-size:12px;margin-bottom:12px;">Signed in as <strong style="color:{BRAND["teal"]};">{st.session_state["_history_user"]}</strong></div>', unsafe_allow_html=True)
        with _logout_col:
            if st.button("Sign out", key="hist_logout"):
                st.session_state.pop("_history_user", None)
                st.rerun()

        _hist_all = load_audit_history(limit=50)

        if get_supabase() is None:
            st.info("Add SUPABASE_URL and SUPABASE_KEY to Streamlit secrets to enable audit history.")
        elif not _hist_all:
            st.info("No audits saved yet — run your first audit from the New Audit tab.")
        else:
            _domains_list = sorted(set(r.get("domain", "") for r in _hist_all if r.get("domain")))
            _filter_col, _count_col = st.columns([2, 4])
            with _filter_col:
                _filter_dom = st.selectbox("Filter by domain", ["All domains"] + _domains_list, key="hist_filter", label_visibility="collapsed")
            _rows = _hist_all if _filter_dom == "All domains" else [r for r in _hist_all if r.get("domain") == _filter_dom]
            with _count_col:
                st.markdown(f'<div style="padding:8px 0;color:{BRAND["text_secondary"]};font-size:13px;">{len(_rows)} audit{"s" if len(_rows) != 1 else ""} · sorted newest first</div>', unsafe_allow_html=True)

            _PILLARS = ["JS Rendering", "Robots & Crawl", "Schema & Entity", "AI Discoverability", "Semantic Hierarchy", "Security"]
            _P_SHORT  = ["JS", "Robots", "Schema", "AI", "Semantic", "Security"]

            def _hsc(s):
                return BRAND["teal"] if s >= 75 else BRAND["warning"] if s >= 50 else BRAND["danger"]

            def _badge(s):
                c = _hsc(s)
                return f'<span style="background:{c}22;color:{c};padding:2px 9px;border-radius:6px;font-size:12px;font-weight:700;">{s}</span>'

            _TH = f'padding:10px 16px;text-align:left;color:{BRAND["text_secondary"]};font-size:11px;text-transform:uppercase;letter-spacing:1px;white-space:nowrap;border-bottom:1px solid {BRAND["border"]};'
            _TD = f'padding:10px 16px;color:{BRAND["white"]};font-size:13px;vertical-align:middle;'

            _pillar_headers = ''.join(f'<th style="{_TH}">{s}</th>' for s in _P_SHORT)
            _thead = f'<tr style="background:{BRAND["bg_surface"]};">' \
                     f'<th style="{_TH}">Domain</th><th style="{_TH}">Date</th>' \
                     f'<th style="{_TH}">Score</th>{_pillar_headers}</tr>'

            _tbody = ""
            _grade_map = {90: "A", 75: "B", 60: "C", 40: "D", 0: "F"}
            for i, _row in enumerate(_rows):
                _dom   = _row.get("domain", "—")
                _date  = (_row.get("audited_at") or "")[:10]
                _sc    = _row.get("overall_score", 0)
                _bg    = BRAND["bg_card"] if i % 2 == 0 else BRAND["bg_surface"]
                _g     = next(v for k, v in sorted(_grade_map.items(), reverse=True) if _sc >= k)
                try:
                    _ps = json.loads(_row.get("pillar_scores") or "{}")
                except Exception:
                    _ps = {}
                _pillar_cells = ''.join(f'<td style="{_TD}">{_badge(_ps.get(p, 0))}</td>' for p in _PILLARS)
                _tbody += (
                    f'<tr style="background:{_bg};border-bottom:1px solid {BRAND["border"]};">'
                    f'<td style="{_TD}font-weight:600;">{_dom}</td>'
                    f'<td style="{_TD}color:{BRAND["text_secondary"]};">{_date}</td>'
                    f'<td style="{_TD}"><span style="color:{_hsc(_sc)};font-size:20px;font-weight:800;">{_sc}%</span>'
                    f'<span style="color:{BRAND["text_secondary"]};font-size:12px;margin-left:5px;">{_g}</span></td>'
                    f'{_pillar_cells}</tr>'
                )

            st.markdown(
                f'<div style="border:1px solid {BRAND["border"]};border-radius:12px;overflow:auto;">'
                f'<table style="width:100%;border-collapse:collapse;min-width:900px;">'
                f'<thead>{_thead}</thead><tbody>{_tbody}</tbody></table></div>',
                unsafe_allow_html=True
            )

            # ── CSV Export ─────────────────────────────────────────────────────────
            _csv_buf = io.StringIO()
            _csv_w = csv.writer(_csv_buf)
            _csv_w.writerow(["Domain", "Date", "Overall Score", "Grade"] + _PILLARS)
            for _row in _rows:
                _dom = _row.get("domain", "")
                _date = (_row.get("audited_at") or "")[:10]
                _sc = _row.get("overall_score", 0)
                _g = next((v for k, v in sorted(_grade_map.items(), reverse=True) if _sc >= k), "F")
                try:
                    _ps = json.loads(_row.get("pillar_scores") or "{}")
                except Exception:
                    _ps = {}
                _csv_w.writerow([_dom, _date, _sc, _g] + [_ps.get(p, 0) for p in _PILLARS])
            st.download_button("Download CSV", _csv_buf.getvalue(), "audit_history.csv", "text/csv",
                               use_container_width=False, key="csv_export")

            # ── Load / Rerun Report buttons ──────────────────────────────────────
            # Maps stored url_labels keys → text_input widget session-state keys
            _LABEL_TO_KEY = {
                "Homepage":   "home",
                "Category 1": "cat1", "Category 2": "cat2",
                "Blog 1":     "blog1", "Blog 2":     "blog2",
                "Content 1":  "blog1", "Content 2":  "blog2",  # no_blog aliases
                "Product 1":  "prod1", "Product 2":  "prod2",
            }
            st.markdown(f'<div style="margin-top:16px;color:{BRAND["text_secondary"]};font-size:12px;margin-bottom:6px;">Load, rerun, or share a full report:</div>', unsafe_allow_html=True)
            for _row in _rows:
                _fr = _row.get("full_results")
                _dom  = _row.get("domain", "—")
                _date = (_row.get("audited_at") or "")[:10]
                _sc   = _row.get("overall_score", 0)
                _label = f"{_dom} · {_date} · {_sc}%"
                _has_full = _fr is not None and isinstance(_fr, dict) and "js_results" in _fr
                _audit_id = _row.get("id")
                _btn_col, _rerun_col, _share_col, _del_col, _info_col = st.columns([3, 1, 1, 1, 3])
                with _btn_col:
                    if st.button(f"📋 {_label}", key=f"load_{_audit_id or _label}", disabled=not _has_full, use_container_width=True):
                        st.session_state["_audit"] = _fr
                        st.session_state["_loaded_from_history"] = _label
                        if _audit_id:
                            st.query_params["audit"] = str(_audit_id)
                            st.session_state["_loaded_audit_id"] = str(_audit_id)
                        st.rerun()
                with _rerun_col:
                    if _has_full and st.button("🔄", key=f"rerun_{_audit_id}", help="Rerun this audit with fresh checks", use_container_width=True):
                        # Pre-populate form inputs via prefill keys (applied before widgets render)
                        _inv = {v: k for k, v in (_fr.get("url_labels") or {}).items()}
                        for _lbl, _widget_key in _LABEL_TO_KEY.items():
                            if _lbl in _inv:
                                st.session_state[f"_prefill_{_widget_key}"] = _inv[_lbl]
                        # Restore Advanced Options flags
                        st.session_state["_prefill_no_blog"]       = bool(_fr.get("no_blog", False))
                        st.session_state["_prefill_run_bot_crawl"] = bool(_fr.get("bot_crawl_results"))
                        # Clear any previously cached result so a fresh audit runs
                        st.session_state.pop("_audit", None)
                        st.session_state.pop("_loaded_audit_id", None)
                        st.session_state.pop("_loaded_from_history", None)
                        st.query_params.pop("audit", None)
                        st.session_state["_pending_rerun"] = True
                        st.rerun()
                with _share_col:
                    if _audit_id and _has_full:
                        if st.button("🔗", key=f"share_{_audit_id}", help="Set shareable link in address bar"):
                            st.query_params["audit"] = str(_audit_id)
                            # Keep _loaded_audit_id in sync so the top-of-script
                            # ?audit= reload guard doesn't swap the displayed results.
                            st.session_state["_loaded_audit_id"] = str(_audit_id)
                            st.session_state[f"_shared_{_audit_id}"] = True
                        if st.session_state.get(f"_shared_{_audit_id}"):
                            st.markdown(f'<div style="font-size:10px;color:{BRAND["teal"]};">URL updated ✓</div>', unsafe_allow_html=True)
                with _del_col:
                    if _audit_id:
                        _confirm_key = f"_del_confirm_{_audit_id}"
                        if st.session_state.get(_confirm_key):
                            if st.button("✓ Yes", key=f"del_yes_{_audit_id}", help="Confirm delete"):
                                if delete_audit_by_id(_audit_id):
                                    st.session_state.pop(_confirm_key, None)
                                    st.rerun()
                        else:
                            if st.button("🗑", key=f"del_{_audit_id}", help="Delete this audit"):
                                st.session_state[_confirm_key] = True
                                st.rerun()
                with _info_col:
                    if st.session_state.get(f"_del_confirm_{_audit_id}"):
                        st.markdown(f'<div style="padding:6px 0;color:{BRAND["danger"]};font-size:11px;">Delete {_dom} ({_date})? Click ✓ Yes to confirm.</div>', unsafe_allow_html=True)
                    elif not _has_full:
                        st.markdown(f'<div style="padding:6px 0;color:{BRAND["text_secondary"]};font-size:11px;">⚠ Saved before full-result storage was enabled</div>', unsafe_allow_html=True)
                    else:
                        _url_count = len(_fr.get("all_test_urls") or [])
                        st.markdown(f'<div style="padding:6px 0;color:{BRAND["text_secondary"]};font-size:11px;">{_url_count} URLs · all pillar data available</div>', unsafe_allow_html=True)

            if st.session_state.get("_loaded_from_history"):
                st.success(f"Report loaded: **{st.session_state['_loaded_from_history']}** — switch to the **New Audit** tab to view it. You can also share the current URL.")

            # ── Before / After Comparison ─────────────────────────────────────────
            _comp_domains = [d for d in _domains_list if sum(1 for r in _rows if r.get("domain") == d) >= 2]
            if _comp_domains:
                st.markdown(f'<div style="font-size:18px;font-weight:700;color:{BRAND["white"]};margin:24px 0 8px 0;">Before / After Comparison</div>', unsafe_allow_html=True)
                _comp_dom = st.selectbox("Domain", _comp_domains, key="comp_domain")
                _dom_rows = sorted(
                    [r for r in _rows if r.get("domain") == _comp_dom],
                    key=lambda r: r.get("audited_at") or "", reverse=True
                )
                _comp_options = [f"{(_r.get('audited_at') or '')[:10]}  —  {_r.get('overall_score', 0)}%" for _r in _dom_rows]
                _c1, _c2 = st.columns(2)
                with _c1:
                    _before_idx = st.selectbox("Before (older)", range(len(_comp_options)),
                        format_func=lambda i: _comp_options[i], index=min(1, len(_dom_rows)-1), key="comp_before")
                with _c2:
                    _after_idx = st.selectbox("After (newer)", range(len(_comp_options)),
                        format_func=lambda i: _comp_options[i], index=0, key="comp_after")
                _before = _dom_rows[_before_idx]
                _after = _dom_rows[_after_idx]
                try:
                    _ps_b = json.loads(_before.get("pillar_scores") or "{}")
                except Exception:
                    _ps_b = {}
                try:
                    _ps_a = json.loads(_after.get("pillar_scores") or "{}")
                except Exception:
                    _ps_a = {}
                _sc_b = _before.get("overall_score", 0)
                _sc_a = _after.get("overall_score", 0)
                _diff = _sc_a - _sc_b
                _diff_color = BRAND["teal"] if _diff > 0 else BRAND["danger"] if _diff < 0 else BRAND["text_secondary"]
                _diff_sign = "+" if _diff > 0 else ""
                st.markdown(
                    f'<div style="display:flex;gap:16px;margin:12px 0;">'
                    f'<div style="flex:1;background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:16px;text-align:center;">'
                    f'<div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;">Before</div>'
                    f'<div style="font-size:28px;font-weight:800;color:{BRAND["white"]};">{_sc_b}%</div>'
                    f'<div style="font-size:11px;color:{BRAND["text_secondary"]};">{(_before.get("audited_at") or "")[:10]}</div></div>'
                    f'<div style="flex:0.5;display:flex;align-items:center;justify-content:center;">'
                    f'<div style="font-size:24px;font-weight:800;color:{_diff_color};">{_diff_sign}{_diff}pts</div></div>'
                    f'<div style="flex:1;background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:16px;text-align:center;">'
                    f'<div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;">After</div>'
                    f'<div style="font-size:28px;font-weight:800;color:{BRAND["white"]};">{_sc_a}%</div>'
                    f'<div style="font-size:11px;color:{BRAND["text_secondary"]};">{(_after.get("audited_at") or "")[:10]}</div></div></div>',
                    unsafe_allow_html=True
                )
                # Per-pillar diff
                _pdiff_html = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0;">'
                for p in _PILLARS:
                    _pb = _ps_b.get(p, 0); _pa = _ps_a.get(p, 0); _pd = _pa - _pb
                    _pc = BRAND["teal"] if _pd > 0 else BRAND["danger"] if _pd < 0 else BRAND["text_secondary"]
                    _ps_sign = "+" if _pd > 0 else ""
                    _pdiff_html += (
                        f'<div style="flex:1;min-width:120px;background:{BRAND["bg_surface"]};border-radius:8px;padding:10px;text-align:center;">'
                        f'<div style="font-size:10px;color:{BRAND["text_secondary"]};text-transform:uppercase;">{p}</div>'
                        f'<div style="font-size:14px;font-weight:700;color:{BRAND["white"]};">{_pb} → {_pa}</div>'
                        f'<div style="font-size:12px;font-weight:700;color:{_pc};">{_ps_sign}{_pd}</div></div>'
                    )
                _pdiff_html += '</div>'
                st.markdown(_pdiff_html, unsafe_allow_html=True)

            # ── Bulk Rerun ─────────────────────────────────────────────────────────
            st.markdown(
                f'<div style="height:2px;background:linear-gradient(90deg,{BRAND["purple"]},{BRAND["primary"]},transparent);margin:28px 0 16px 0;"></div>'
                f'<div style="font-size:18px;font-weight:700;color:{BRAND["white"]};margin-bottom:6px;">Bulk Rerun</div>',
                unsafe_allow_html=True,
            )
            _bulk_eligible_ids = [
                r.get("id") for r in _rows
                if r.get("id") and isinstance(r.get("full_results"), dict) and "js_results" in (r.get("full_results") or {})
            ]
            _active_bulk_q = st.session_state.get("_bulk_rerun_queue")
            _bulk_prog     = st.session_state.get("_bulk_rerun_progress", {"total": 0, "done": 0})
            if _active_bulk_q is not None:
                _bq_done  = _bulk_prog.get("done", 0)
                _bq_total = _bulk_prog.get("total", 1)
                st.progress(_bq_done / max(_bq_total, 1),
                    text=f"Rerunning audits: {_bq_done}/{_bq_total} complete — {len(_active_bulk_q)} remaining")
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
