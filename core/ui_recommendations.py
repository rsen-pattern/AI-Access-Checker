# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — recommendations builder.

Pure function that takes the audit dict and returns a list of
(severity, pillar, text) tuples. The caller is responsible for sorting,
deduplicating, and rendering. This separation lets the recommendations
logic evolve independently of UI rendering and is the natural place to
add tests later.

Severity tiers (PR #27):
- "critical" — site-down or data-leaking issues that must be fixed
  immediately. Renders red, label "CRITICAL".
- "danger" — kept as alias for "critical" in the legacy callsites that
  haven't been migrated. Same rendering as "critical".
- "warning" — standard advisory. Renders amber, label "WARNING".
- "info" — informational, nice-to-have. Renders blue, label
  "RECOMMENDATION". Reserved for future use; currently nothing emits it.
"""


def build_recommendations(audit: dict, no_blog: bool) -> list:
    """Build the priority recommendations list for an audit.

    Args:
        audit: The full audit dict from session state. Reads:
            - js_score (int)
            - robots_result (dict — uses .cloudflare, .found, .sitemaps,
              .blocked_resources, .ai_agent_results, .sensitive_paths)
            - schema_score (int)
            - schema_results (dict — per-URL schema results, used for
              missing-field aggregation and ecommerce checks)
            - llm_score (int)
            - security_result (dict — uses .findings.critical for the
              top-priority security exposure rec)
        no_blog: Whether the user flagged "no editorial blog" in the form.

    Returns:
        List of (severity, pillar, text) tuples. Order matters for ties
        within the same severity tier — the caller sorts by severity but
        preserves insertion order within each tier.
    """
    js_score        = audit.get("js_score", 0)
    robots_result   = audit.get("robots_result", {})
    schema_score    = audit.get("schema_score", 0)
    schema_results  = audit.get("schema_results", {})
    llm_score       = audit.get("llm_score", 0)
    security_result = audit.get("security_result", {})

    recs = []

    # ── Critical security exposures (top priority) ────────────────────────────
    sec_findings = security_result.get("findings", {}) if isinstance(security_result, dict) else {}
    critical_paths = sec_findings.get("critical", []) or []
    if critical_paths:
        paths_str = ", ".join(f["path"] for f in critical_paths[:5])
        recs.append((
            "critical",
            "Security Exposure",
            f"Critical paths returning HTTP 200 to AI bots: {paths_str}. "
            f"This may expose admin interfaces, environment files, or configuration data. "
            f"Verify these paths are intentionally public; if not, return 403/404 immediately. "
            f"AI bots will index any 200 response — this is the highest-priority fix in this audit.",
        ))

    # ── BAISOM L1: Cloudflare (CRITICAL — silent AI blocker) ──────────────────
    cf_result = robots_result.get("cloudflare", {}) if isinstance(robots_result, dict) else {}
    if cf_result.get("bot_fight_mode_likely"):
        blocked = cf_result.get("blocked_bots", [])
        recs.append(("critical", "Cloudflare", f"Bot Fight Mode is blocking key AI crawlers: {', '.join(blocked)}. Disable it or allowlist AI user-agents in Cloudflare dashboard. This overrides your robots.txt."))
    elif cf_result.get("cloudflare_detected") and cf_result.get("blocked_bots"):
        recs.append(("warning", "Cloudflare", f"Cloudflare is blocking some AI bots ({', '.join(cf_result['blocked_bots'])}). Review Bot Fight Mode settings."))

    # ── JS Rendering ──────────────────────────────────────────────────────────
    if js_score < 60:
        recs.append(("danger", "JS Rendering", "Critical content is invisible to AI crawlers. Implement server-side rendering (SSR) for product pages, prices, and navigation — especially for Shopify/Next.js sites."))
    elif js_score < 80:
        recs.append(("warning", "JS Rendering", "Some content requires JavaScript. Ensure prices, specs, and pagination are in raw HTML. Check for lazy-loaded images lacking width/height attributes (causes agent screenshot instability)."))

    # ── AI Discoverability ────────────────────────────────────────────────────
    if llm_score == 0:
        recs.append(("warning", "AI Discoverability", "No AI guidance files found. Quick win: create an /ai-info page describing your brand and key products for AI agents. Also create a basic llm.txt pointing to your key pages."))
    elif llm_score < 40:
        recs.append(("warning", "AI Discoverability", "llm.txt or AI Info Page found but incomplete. Add a title, description, and links to key product/category pages to maximise AI agent guidance."))

    # ── Robots & Crawlability ─────────────────────────────────────────────────
    if isinstance(robots_result, dict):
        if not robots_result.get("found"):
            recs.append(("critical", "Robots.txt", "No robots.txt found — the foundational control for all crawler access. Create one immediately that explicitly allows GPTBot, ClaudeBot, and PerplexityBot."))
        else:
            if not robots_result.get("sitemaps"):
                recs.append(("warning", "Robots.txt", "No sitemap referenced in robots.txt. Add 'Sitemap: https://yourdomain.com/sitemap.xml' so AI crawlers can discover all pages."))
            if robots_result.get("blocked_resources"):
                recs.append(("critical", "Robots.txt", f"CSS/JS blocked in robots.txt: {', '.join(robots_result['blocked_resources'][:3])}. This prevents AI from understanding page structure — remove these Disallow rules."))
            ai_r = robots_result.get("ai_agent_results", robots_result.get("ai_results", {}))
            explicitly_blocked = [n for n, r in ai_r.items()
                                  if r.get("allowed") is False and n in ["GPTBot", "ClaudeBot", "PerplexityBot", "ChatGPT-User"]]
            if explicitly_blocked:
                recs.append(("critical", "Robots.txt", f"AI crawlers explicitly blocked: {', '.join(explicitly_blocked)}. Add Allow rules for these bots to restore AI visibility."))
            sensitive = robots_result.get("sensitive_paths", robots_result.get("sensitive", {}))
            critical_exposed = [p for p, r in sensitive.items()
                                if not r.get("blocked", not r.get("accessible_per_robots", r.get("exposed", False)))
                                and any(x in p for x in ["/admin", "/api", "/.env", "/config", "/database"])]
            if critical_exposed:
                recs.append(("warning", "Robots.txt", f"Sensitive paths have no Disallow rule in robots.txt: {', '.join(critical_exposed[:4])}. These paths aren't necessarily accessible — but adding explicit Disallow rules is best practice to prevent accidental AI bot indexing."))

    # ── No editorial blog ─────────────────────────────────────────────────────
    if no_blog:
        recs.append(("warning", "Editorial Content", "No blog or editorial content pages were audited. AI systems like Perplexity, ChatGPT, and Claude preferentially cite and surface brands with regular editorial content. Consider creating a blog, resource hub, or thought-leadership section — even 4–6 quality posts significantly improves AI citation potential."))

    # ── Schema ────────────────────────────────────────────────────────────────
    if schema_score < 30:
        recs.append(("danger", "Schema", "Add JSON-LD schema: Organisation + WebSite + BreadcrumbList site-wide. Product + Offer + AggregateRating on product pages. This is your highest-leverage AI visibility action."))
    elif schema_score < 60:
        all_missing = []
        for sr in schema_results.values():
            for v in sr.get("schema", {}).get("validations", []):
                all_missing.extend(v.get("missing", []))
        missing_set = list(set(all_missing))
        if missing_set:
            recs.append(("warning", "Schema", f"Incomplete schema fields: {', '.join(missing_set[:8])}. Priority: add GTIN/MPN to products, sameAs to Organisation, and hasMerchantReturnPolicy to Offers."))

    # ── Ecommerce-specific schema gaps ────────────────────────────────────────
    for sr in schema_results.values():
        ecomm = sr.get("ecommerce", {})
        if ecomm.get("is_product_page") and not ecomm.get("has_gtin_or_mpn"):
            recs.append(("warning", "Product Schema", "Product pages lack GTIN/MPN identifiers. Research shows 60% of catalogues missing GTINs are downgraded or excluded by AI shopping agents. Add gtin13 or mpn to all Product schema."))
            break
    for sr in schema_results.values():
        ecomm = sr.get("ecommerce", {})
        if ecomm.get("is_product_page") and not ecomm.get("has_return_policy_schema"):
            recs.append(("warning", "Product Schema", "No MerchantReturnPolicy schema on product pages. AI agents actively parse return policies when building shopping recommendations — this is a trust signal."))
            break

    # ── Organisation sameAs ───────────────────────────────────────────────────
    no_sameas = all(not sr.get("entity", {}).get("has_org_sameas") for sr in schema_results.values() if sr.get("entity"))
    if schema_results and no_sameas:
        recs.append(("warning", "Brand Entity", "Organisation schema lacks sameAs links. Add LinkedIn, Wikipedia, and social profile URLs to your Organisation schema to establish consistent brand entity across AI knowledge graphs."))

    # ── Content Architecture ──────────────────────────────────────────────────
    if not recs or len(recs) < 5:
        # Only add content rec if not already overloaded
        no_lead_para = all(not sr.get("content_architecture", {}).get("has_lead_paragraph")
                           for sr in schema_results.values() if sr.get("content_architecture"))
        if no_lead_para and schema_results:
            recs.append(("warning", "Content Architecture", "No answer-first summary paragraph detected. Per BAISOM Layer 4: add a concise 40–60 word summary at the top of key pages. AI reads top-down and decides in milliseconds."))

    return recs
