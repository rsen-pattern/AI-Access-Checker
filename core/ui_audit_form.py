# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — New Audit form rendering.

Renders the 7-URL form, no-blog toggle (at form level), advanced options,
and Run Audit button. Returns the inputs as a tuple so the caller can
execute the audit pipeline. No audit logic lives here.

Form improvements over the original:
- Required asterisk on every individual field, not just the group header.
- Per-field inline URL validation on submit (format check + non-empty).
- "No blog" toggle moved from Advanced Options to form body, adjacent to
  the Blog 1 / Blog 2 inputs.
- "Try a sample site" button pre-fills the form with a real DTC brand.
"""

import re
import streamlit as st

from core.branding import BRAND
from core.copy import COPY
from core.persistence import is_history_authenticated
from core.ui_history import _render_auth_gate


# Sample DTC brand used by the "Try a sample site" affordance.
_SAMPLE_URLS = {
    "home":  "https://okanui.com",
    "cat1":  "https://okanui.com/collections/mens-wetsuits",
    "cat2":  "https://okanui.com/collections/womens-wetsuits",
    "blog1": "https://okanui.com/blogs/surf/how-to-choose-a-wetsuit",
    "blog2": "https://okanui.com/blogs/surf/wetsuit-thickness-guide",
    "prod1": "https://okanui.com/products/mens-4-3-wetsuit",
    "prod2": "https://okanui.com/products/womens-3-2-wetsuit",
}

# Basic URL validity pattern — must start with http:// or https:// after
# normalisation, no spaces, no obvious typos like htttps://.
_URL_RE = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)


def _url_is_valid(raw: str) -> bool:
    """Return True if raw (stripped, scheme-normalised) looks like a valid URL."""
    url = raw.strip()
    if not url:
        return False
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return bool(_URL_RE.match(url))


def _field_label(text: str, required: bool = True) -> str:
    """Styled field label with optional required asterisk."""
    asterisk = f' <span style="color:{BRAND["danger"]};" aria-hidden="true">*</span>' if required else ""
    return (
        f'<div style="font-size:13px;color:{BRAND["text_secondary"]};'
        f'margin-bottom:4px;">{text}{asterisk}</div>'
    )


def render_audit_form() -> tuple:
    """Render the New Audit form tab.

    Returns:
        (all_url_inputs, no_blog, run_bot_crawl, run_audit)

        all_url_inputs: dict mapping label → input string (may be empty —
            caller validates for the pipeline, but this function validates
            format and surfaces inline errors before returning run_audit=True).
        no_blog: bool — whether the user ticked the no-blog checkbox.
        run_bot_crawl: bool — whether to run the live bot crawl test.
        run_audit: bool — True if Run Audit was clicked (and validated) or a
            pending rerun from history is being consumed.
    """
    if not is_history_authenticated():
        _render_auth_gate("Sign in to run a new audit.")
        return {}, False, False, False

    # ── Sample site affordance ────────────────────────────────────────────────
    _col_hdr, _col_sample = st.columns([4, 1])
    with _col_hdr:
        st.markdown(
            f'<div style="font-weight:600;color:{BRAND["white"]};margin-bottom:4px;">'
            f'{COPY["form_header"]}</div>'
            f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:12px;">'
            f'{COPY["form_subheader"]}</div>',
            unsafe_allow_html=True,
        )
    with _col_sample:
        if st.button(
            COPY["form_sample_button"],
            key="_form_sample",
            help=COPY["form_sample_tooltip"],
            use_container_width=True,
        ):
            for k, v in _SAMPLE_URLS.items():
                st.session_state[k] = v
            st.rerun()

    # ── Homepage ──────────────────────────────────────────────────────────────
    col_home, _ = st.columns([3, 1])
    with col_home:
        st.markdown(_field_label(COPY["form_homepage_label"]), unsafe_allow_html=True)
        home_url = st.text_input(
            COPY["form_homepage_label"],
            placeholder="https://example.com",
            key="home",
            label_visibility="collapsed",
        )

    # ── Three-column section: Category | Blog | Product ───────────────────────
    col_cat, col_blog, col_prod = st.columns(3)

    with col_cat:
        st.markdown(
            _field_label("Category / Collection Pages"),
            unsafe_allow_html=True,
        )
        cat_url_1 = st.text_input(
            COPY["form_cat1_label"],
            placeholder="https://example.com/collections/all",
            key="cat1",
            label_visibility="collapsed",
        )
        cat_url_2 = st.text_input(
            COPY["form_cat2_label"],
            placeholder="https://example.com/collections/shoes",
            key="cat2",
            label_visibility="collapsed",
        )

    with col_blog:
        st.markdown(
            _field_label("Blog / Content Pages"),
            unsafe_allow_html=True,
        )
        blog_url_1 = st.text_input(
            COPY["form_blog1_label"],
            placeholder="https://example.com/blog/post-1",
            key="blog1",
            label_visibility="collapsed",
        )
        blog_url_2 = st.text_input(
            COPY["form_blog2_label"],
            placeholder="https://example.com/blog/post-2",
            key="blog2",
            label_visibility="collapsed",
        )
        # ── No-blog toggle — lives next to the Blog fields, not hidden in Advanced Options ──
        no_blog = st.checkbox(
            COPY["form_no_blog_label"],
            value=False,
            key="no_blog",
            help="When ticked, blog fields are treated as general content pages and a schema penalty applies.",
        )
        if no_blog:
            st.markdown(
                f'<div class="p-field-error" style="color:{BRAND["warning"]};">'
                f'{COPY["form_no_blog_warning"]}</div>',
                unsafe_allow_html=True,
            )

    with col_prod:
        st.markdown(
            _field_label("Product Pages"),
            unsafe_allow_html=True,
        )
        prod_url_1 = st.text_input(
            COPY["form_prod1_label"],
            placeholder="https://example.com/products/item-1",
            key="prod1",
            label_visibility="collapsed",
        )
        prod_url_2 = st.text_input(
            COPY["form_prod2_label"],
            placeholder="https://example.com/products/item-2",
            key="prod2",
            label_visibility="collapsed",
        )

    all_url_inputs = {
        "Homepage":   home_url,
        "Category 1": cat_url_1, "Category 2": cat_url_2,
        "Blog 1":     blog_url_1, "Blog 2":     blog_url_2,
        "Product 1":  prod_url_1, "Product 2":  prod_url_2,
    }

    # ── Advanced Options ──────────────────────────────────────────────────────
    with st.expander("⚙️  Advanced Options"):
        run_bot_crawl = st.checkbox(
            COPY["form_run_bot_crawl_label"],
            value=True,
            key="run_bot_crawl",
        )

    # ── Submit ────────────────────────────────────────────────────────────────
    st.markdown(
        f'<div style="font-size:12px;color:{BRAND["text_secondary"]};'
        f'margin-bottom:6px;text-align:center;">'
        f'Typically takes 2–3 minutes · all 7 URLs required</div>',
        unsafe_allow_html=True,
    )
    clicked = st.button(COPY["form_run_button"], type="primary", use_container_width=True)
    pending_rerun = st.session_state.pop("_pending_rerun", False)
    run_audit = clicked or pending_rerun

    # ── Per-field validation (runs on submit only, not on pending rerun) ──────
    if clicked and not pending_rerun:
        errors = _validate_urls(all_url_inputs)
        if errors:
            for msg in errors:
                st.error(msg)
            run_audit = False

    return all_url_inputs, no_blog, run_bot_crawl, run_audit


def _validate_urls(inputs: dict) -> list[str]:
    """Validate all URL inputs and return a list of error messages (empty = valid)."""
    errors: list[str] = []

    empty_fields = [label for label, url in inputs.items() if not url.strip()]
    if empty_fields:
        errors.append(
            f"The following fields are required: {', '.join(empty_fields)}. "
            f"Please fill in every field before running the audit."
        )
        return errors  # no point checking format if fields are empty

    invalid_fields = [
        label for label, url in inputs.items()
        if not _url_is_valid(url)
    ]
    if invalid_fields:
        errors.append(
            f"These URLs look invalid (check for typos like 'htttps://'): "
            f"{', '.join(invalid_fields)}."
        )

    # Warn if URLs belong to clearly different domains
    from urllib.parse import urlparse as _up
    domains = set()
    for url in inputs.values():
        u = url.strip()
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        try:
            d = _up(u).netloc.lstrip("www.")
            if d:
                domains.add(d)
        except Exception:
            pass
    if len(domains) > 2:
        errors.append(
            COPY["form_url_domain_mismatch"].format(domains=", ".join(sorted(domains)))
        )

    return errors
