# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — audit execution pipeline.

Runs all six pillar checks (JS rendering, robots, schema, LLM
discoverability, semantic hierarchy, security), the live bot crawl, and
final scoring. Persists results to Supabase and to st.session_state["_audit"].

Renders inline progress feedback (time estimate card + progress bar) but
no actual results — that's render_results in core.ui_results.

Bulk rerun: when called with a _bulk_rerun_current_id set in session state,
updates the existing DB row instead of inserting a new one. Otherwise asks
the user via a confirmation prompt (rendered later by render_results).
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import streamlit as st

from core.branding import BRAND
from core.llm_access_checks import (
    check_js_rendering,
    check_robots_crawlability,
    check_schema_meta,
    check_llm_discoverability,
    check_security_exposure,
    compute_overall,
    fetch,
    run_live_bot_crawl,
)
from core.persistence import (
    get_supabase,
    load_audit_history,
    save_audit_to_db,
    update_audit_in_db,
)
from core.ui_helpers import normalise_url, _page_type_from_label

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



def execute_audit_pipeline(
    all_url_inputs: dict,
    no_blog: bool,
    run_bot_crawl: bool,
    get_secret_fn,
) -> dict | None:
    """Run the full audit pipeline.

    Args:
        all_url_inputs: dict with 7 keys (Homepage / Category 1 / etc.)
            mapping to user-entered URL strings.
        no_blog: User's "no editorial blog" flag.
        run_bot_crawl: User's "run live bot crawl" flag.
        get_secret_fn: Callable for fetching secrets (matches
            core.persistence.get_secret signature).

    Returns:
        The populated `_audit` dict (already written to st.session_state).
        Returns None if URL validation failed (st.error + st.stop already
        called).

    Side effects:
        - Pops st.session_state["_audit"], "_loaded_audit_id", "_loaded_from_history"
        - Pops st.query_params["audit"]
        - Sets st.session_state["_audit"] with the full results
        - Sets st.query_params["audit"] and st.session_state["_loaded_audit_id"]
          on successful save (single audits only)
        - Sets st.session_state["_pending_overwrite"] when a previous audit
          for the same domain exists (consumed later by render_results)
        - Pops st.session_state["_bulk_rerun_current_id"] if set, advances
          st.session_state["_bulk_rerun_queue"] and "_bulk_rerun_progress"
        - Renders st.progress() bar and the time-estimate card
    """
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
    has_js_api = any(get_secret_fn(k, "") for k in ["SCRAPINGBEE_API_KEY", "SCRAPFLY_API_KEY", "BROWSERLESS_API_KEY"])
    has_bifrost = bool(get_secret_fn("BIFROST_API_KEY", ""))

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
        _futs = {_pool.submit(check_js_rendering, u, get_secret_fn, url_page_types.get(u, "general")): u for u in all_test_urls}
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
    _a = st.session_state["_audit"]
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
    _save_audit_to_supabase(_a, parsed, all_test_urls, no_blog)

    return _a

def _save_audit_to_supabase(audit: dict, parsed, all_test_urls: list, no_blog: bool) -> None:
    """Persist audit results to Supabase. Handles bulk rerun (UPDATE) and
    normal (check-for-existing / save) branches."""
    url_labels        = audit.get("url_labels", {})
    js_results        = audit.get("js_results", {})
    js_score          = audit.get("js_score", 0)
    robots_result     = audit.get("robots_result", {})
    robots_score      = audit.get("robots_score", 0)
    schema_results    = audit.get("schema_results", {})
    schema_score      = audit.get("schema_score", 0)
    llm_result        = audit.get("llm_result", {})
    llm_score         = audit.get("llm_score", 0)
    semantic_results  = audit.get("semantic_results", {})
    semantic_score    = audit.get("semantic_score", 0)
    security_result   = audit.get("security_result", {})
    security_score    = audit.get("security_score", 0)
    bot_crawl_results = audit.get("bot_crawl_results", {})
    overall           = audit.get("overall", 0)
    overall_grade     = audit.get("overall_grade", "?")
    overall_result    = audit.get("overall_result", {})
    no_blog           = audit.get("no_blog", no_blog)
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
