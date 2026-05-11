# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — user-facing copy strings.

All strings that appear in the UI are defined here so that tone audits,
Australian English reviews, and future localisation only need to touch
one file.  Import with:

    from core.copy import COPY
    st.error(COPY["form_url_required"])
"""

COPY: dict[str, str] = {
    # ── New Audit form ──────────────────────────────────────────────────────
    "form_header":
        "Enter the URLs to audit",
    "form_subheader":
        "A representative set of 7 pages — one per template type.",

    "form_url_required":
        "All URL fields are required. Please fill in every field before running the audit.",
    "form_url_invalid":
        "One or more URLs look invalid (check for typos like 'htttps://'). Please fix them before continuing.",
    "form_url_domain_mismatch":
        "All URLs should belong to the same domain. Mixed domains detected: {domains}.",

    "form_homepage_label":      "Homepage",
    "form_cat1_label":          "Category Page 1",
    "form_cat2_label":          "Category Page 2",
    "form_blog1_label":         "Blog / Content Page 1",
    "form_blog2_label":         "Blog / Content Page 2",
    "form_prod1_label":         "Product Page 1",
    "form_prod2_label":         "Product Page 2",

    "form_no_blog_label":
        "This site has no blog — using About / Contact / Story pages instead",
    "form_no_blog_warning":
        "⚠️ A penalty will be applied to the Schema & Entity score for missing editorial blog content. "
        "These pages will be evaluated against About / Contact schema expectations instead.",
    "form_run_bot_crawl_label":
        "Run live bot crawl test (sends requests as each AI bot)",

    "form_run_button":          "Run Audit",
    "form_sample_button":       "Try a sample site",
    "form_sample_tooltip":
        "Pre-fills the form with a real DTC brand so you can explore a sample report.",

    "form_estimate_prefix":
        "This audit will take approximately",

    # ── Past Audits / history ───────────────────────────────────────────────
    "history_sign_in_prompt":   "Sign in to view and run audits.",
    "history_rerun_tooltip":    "Rerun this audit",
    "history_pdf_tooltip":      "Download PDF report",
    "history_share_tooltip":    "Copy share link",
    "history_delete_tooltip":   "Delete this audit",
    "history_open_tooltip":     "Open this report",
    "history_bulk_rerun_warn":
        "Bulk rerun in progress — do not close this tab. "
        "If you close it the queue will be lost.",

    # ── Report view ─────────────────────────────────────────────────────────
    "report_back":              "← Back",
    "report_rerun":             "Rerun",
    "report_download_pdf":      "Download PDF",
    "report_share":             "Share",

    "report_antibot_title":     "🛡️ Anti-Bot Protection Detected",
    "report_no_blog_notice":
        "📝 No editorial blog — 10pt schema penalty applied",

    "report_pattern_brain_caption":
        "AI-generated analysis · Pattern Brain",

    # ── Bulk rerun ──────────────────────────────────────────────────────────
    "bulk_rerun_complete":
        "Bulk rerun complete — all {n} audits updated.",

    # ── Bot crawl section ───────────────────────────────────────────────────
    "bot_crawl_progress":
        "Crawling your site as {n} AI bots — this is the slowest step (about 30 seconds).",

    # ── Score legend ────────────────────────────────────────────────────────
    "score_legend":
        "A ≥ 85 · B ≥ 70 · C ≥ 50 · D ≥ 35 · F < 35",
}
