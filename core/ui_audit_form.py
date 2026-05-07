# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — New Audit form rendering.

Renders the 7-URL form, advanced options, and Run Audit button. Returns
the inputs as a tuple so the caller can run validation and execute the
audit pipeline. No audit logic lives here.
"""

import streamlit as st

from core.branding import BRAND
from core.persistence import is_history_authenticated
from core.ui_history import _render_auth_gate


def render_audit_form() -> tuple:
    """Render the New Audit tab form.

    Returns:
        (all_url_inputs, no_blog, run_bot_crawl, run_audit)

        all_url_inputs: dict with keys Homepage / Category 1 / Category 2 /
            Blog 1 / Blog 2 / Product 1 / Product 2 mapping to the user's
            input strings (may be empty/whitespace — caller validates).
        no_blog: bool — whether the user ticked "no editorial blog".
        run_bot_crawl: bool — whether to run the live bot crawl test.
        run_audit: bool — True if Run Audit was clicked OR a pending rerun
            from history is being consumed.

    Must be called inside a `with tab_audit:` or view context.
    """
    # ── Auth gate for new audit view ──────────────────────────────────────────
    if not is_history_authenticated():
        _render_auth_gate("Sign in to run a new audit.")
        return {}, False, False, False

    # ── INPUT: Mandatory URL structure ────────────────────────────────────────
    st.markdown(f'<div style="font-weight:600;color:{BRAND["white"]};margin-bottom:8px;">Enter the URLs to audit (minimum 7 pages required)</div>', unsafe_allow_html=True)

    col_home, _ = st.columns([3, 1])
    with col_home:
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:4px;">Homepage URL <span style="color:{BRAND["danger"]};">*</span></div>', unsafe_allow_html=True)
        home_url = st.text_input("Homepage URL", placeholder="https://example.com", key="home", label_visibility="collapsed")

    col_cat, col_blog, col_prod = st.columns(3)
    with col_cat:
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:4px;">Category / Collection Pages (2 required) <span style="color:{BRAND["danger"]};">*</span></div>', unsafe_allow_html=True)
        cat_url_1 = st.text_input("Category Page 1", placeholder="https://example.com/collections/all", key="cat1", label_visibility="collapsed")
        cat_url_2 = st.text_input("Category Page 2", placeholder="https://example.com/collections/shoes", key="cat2", label_visibility="collapsed")

    with col_blog:
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:4px;">Blog / Content Pages (2 required) <span style="color:{BRAND["danger"]};">*</span></div>', unsafe_allow_html=True)
        blog_url_1 = st.text_input("Blog Page 1", placeholder="https://example.com/blog/post-1", key="blog1", label_visibility="collapsed")
        blog_url_2 = st.text_input("Blog Page 2", placeholder="https://example.com/blog/post-2", key="blog2", label_visibility="collapsed")

    with col_prod:
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:4px;">Product Pages (2 required) <span style="color:{BRAND["danger"]};">*</span></div>', unsafe_allow_html=True)
        prod_url_1 = st.text_input("Product Page 1", placeholder="https://example.com/products/item-1", key="prod1", label_visibility="collapsed")
        prod_url_2 = st.text_input("Product Page 2", placeholder="https://example.com/products/item-2", key="prod2", label_visibility="collapsed")

    with st.expander("⚙️  Advanced Options"):
        run_bot_crawl = st.checkbox("Run live bot crawl test (sends requests as each AI bot)", value=True, key="run_bot_crawl")
        st.markdown("---")
        st.markdown(f'<div style="font-size:13px;font-weight:600;color:{BRAND["white"]};margin-bottom:4px;">Content / Blog Pages</div>', unsafe_allow_html=True)
        no_blog = st.checkbox(
            "This site has no blog — using About / Contact / Story pages instead",
            value=False,
            key="no_blog",
            help="When checked, blog field URLs are treated as general content pages. A scoring penalty applies for the absence of editorial content.",
        )
        if no_blog:
            st.markdown(f'<div style="font-size:12px;color:{BRAND["warning"]};margin-top:4px;">⚠️ A penalty will be applied to the Schema & Entity score for missing editorial blog content. These pages will be evaluated against About/Contact schema expectations instead.</div>', unsafe_allow_html=True)

    run_audit = (
        st.button("Run Audit", type="primary", use_container_width=True)
        or st.session_state.pop("_pending_rerun", False)
    )

    all_url_inputs = {
        "Homepage": home_url,
        "Category 1": cat_url_1, "Category 2": cat_url_2,
        "Blog 1": blog_url_1, "Blog 2": blog_url_2,
        "Product 1": prod_url_1, "Product 2": prod_url_2,
    }

    return all_url_inputs, no_blog, run_bot_crawl, run_audit
