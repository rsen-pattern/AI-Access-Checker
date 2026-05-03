"""
Minimal visual test harness for report_pdf.generate_report_pdf.
Writes a sample PDF to tests/sample_report.pdf for manual/rasterised inspection.

Run:  python tests/test_pdf_visual.py
Then: pdftoppm -r 140 tests/sample_report.pdf tests/page && ls tests/page-*.ppm
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report_pdf import generate_report_pdf

DOMAIN = "example.com"

AUDIT = {
    "overall": 62,
    "overall_grade": {"letter": "C", "label": "Needs Work"},
    "js_score": 75,
    "robots_score": 88,
    "schema_score": 55,
    "llm_score": 40,
    "semantic_score": 70,
    "security_score": 90,
    "no_blog": False,
    "url_labels": {
        "https://example.com/": "Homepage",
        "https://example.com/products/widget": "Product",
        "https://example.com/blog/post-1": "Blog",
    },
    "js_results": {
        "https://example.com/": {
            "score": 78,
            "js_provider": "Next.js",
            "comparison": {
                "comparison": [
                    {"name": "H1 tag",        "html_val": "1", "js_val": "1", "status": "ok"},
                    {"name": "Product images","html_val": "0", "js_val": "12","status": "missing"},
                    {"name": "Nav links",     "html_val": "3", "js_val": "8", "status": "warn"},
                ],
                "html_summary": {"text_content_length": 4200},
                "js_summary":   {"text_content_length": 9800},
            },
            "frameworks": [("Next.js", "low", "SSR detected — most content server-rendered")],
        },
        "https://example.com/products/widget": {
            "score": 72,
            "js_provider": "React",
            "comparison": None,
            "frameworks": [],
        },
        "https://example.com/blog/post-1": {
            "score": 85,
            "js_provider": None,
            "comparison": None,
            "frameworks": [],
        },
    },
    "robots_result": {
        "found": True,
        "sitemaps": ["https://example.com/sitemap.xml"],
        "blocked_resources": [],
        "cloudflare": {"cloudflare_detected": False, "bot_fight_mode_likely": False, "blocked_bots": []},
        "ai_agent_results": {
            "GPTBot":        {"company": "OpenAI",    "robots_allowed": True},
            "ClaudeBot":     {"company": "Anthropic", "robots_allowed": True},
            "PerplexityBot": {"company": "Perplexity","robots_allowed": False},
            "Googlebot":     {"company": "Google",    "robots_allowed": True},
        },
        "sensitive_paths": {},
    },
    "schema_results": {
        "https://example.com/": {
            "score": 60,
            "schema": {
                "types": ["Organization", "WebSite"],
                "validations": [
                    {"type": "Organization", "completeness": 85, "missing": []},
                    {"type": "WebSite",      "completeness": 60, "missing": ["potentialAction"]},
                ],
                "essential_found":   ["Organization"],
                "essential_missing": ["Product"],
                "schemas": [{}],
            },
            "meta": {
                "title": "Example — Great Widgets",
                "desc_len": 145,
                "canonical": "https://example.com/",
                "canonical_matches_url": True,
            },
            "entity": {"is_article_page": False},
        },
        "https://example.com/products/widget": {
            "score": 50,
            "schema": {
                "types": ["Product"],
                "validations": [
                    {"type": "Product", "completeness": 50,
                     "missing": ["aggregateRating", "review", "offers.availability"]},
                ],
                "essential_found":   ["Product"],
                "essential_missing": [],
                "schemas": [{}],
            },
            "meta": {
                "title": "Widget Pro — Example",
                "desc_len": 80,
                "canonical": "https://example.com/products/widget",
                "canonical_matches_url": True,
            },
            "entity": {"is_article_page": False},
        },
        "https://example.com/blog/post-1": {
            "score": 70,
            "schema": {
                "types": ["Article", "BreadcrumbList"],
                "validations": [
                    {"type": "Article", "completeness": 75, "missing": ["publisher"]},
                ],
                "essential_found":   ["Article"],
                "essential_missing": [],
                "schemas": [{}],
            },
            "meta": {
                "title": "10 Ways to Use Widgets — Example Blog",
                "desc_len": 155,
                "canonical": "https://example.com/blog/post-1",
                "canonical_matches_url": True,
            },
            "entity": {
                "is_article_page": True,
                "has_author": True,
                "has_date_published": True,
            },
        },
    },
    "llm_result": {
        "llm_txt": {
            "/llm.txt":         {"found": False},
            "/llms.txt":        {"found": False},
            "/llm-info.txt":    {"found": False},
        },
        "ai_info_page": {"found": False},
        "wellknown": {
            "/.well-known/ai-plugin.json": {"found": False},
        },
    },
    "semantic_results": {
        "https://example.com/": {
            "hierarchy_ok": True,
            "semantic_elements": {"main": 1, "nav": 2, "footer": 1, "article": 0},
            "meta_tags": [{"name": "robots", "content": "index, follow"}],
            "html_length": 28000,
            "text_length": 5200,
        },
        "https://example.com/products/widget": {
            "hierarchy_ok": False,
            "semantic_elements": {"main": 1, "nav": 1},
            "meta_tags": [],
            "html_length": 42000,
            "text_length": 3100,
        },
        "https://example.com/blog/post-1": {
            "hierarchy_ok": True,
            "semantic_elements": {"main": 1, "article": 1, "nav": 1, "aside": 1},
            "meta_tags": [{"name": "robots", "content": "index, follow"}],
            "html_length": 18000,
            "text_length": 6800,
        },
    },
    "security_result": {
        "total_exposed": 1,
        "findings": {
            "critical": [{"path": "/admin", "status": 200, "size": 4200}],
            "backend":  [],
            "customer": [],
            "html_exposure": [],
            "robots_allowlist": [],
        },
    },
    "bot_crawl_results": {
        "GPTBot":    {"company": "OpenAI",    "is_allowed": True,  "status_code": 200, "load_time": 1.2},
        "ClaudeBot": {"company": "Anthropic", "is_allowed": True,  "status_code": 200, "load_time": 0.9},
        "Bingbot":   {"company": "Microsoft", "is_allowed": False, "status_code": 403, "load_time": 0.3},
    },
    "_bifrost_js": {
        "https://example.com/": (
            "The homepage loads ~57% of its content via JavaScript. "
            "AI crawlers fetching raw HTML will miss product carousels, dynamic navigation "
            "and pricing data.\n"
            "• Enable SSR or pre-rendering for key content blocks.\n"
            "• Ensure H1 and meta description are server-rendered.\n"
            "• Use Next.js getServerSideProps to surface product data."
        ),
    },
    "_bifrost_robots": (
        "robots.txt is well-configured for most AI agents.\n"
        "• PerplexityBot is currently blocked — consider allowlisting.\n"
        "• No CSS/JS blocking detected — good for rendering.\n"
        "• Sitemaps are declared and should accelerate indexation."
    ),
    "_bifrost_schema": {},
    "_bifrost_llm": (
        "No llm.txt or AI Info Page found. This is a significant gap.\n"
        "• Create /llm.txt with a structured description of your product catalogue.\n"
        "• Add an /ai-info page and link it from the footer.\n"
        "• Register with OpenAI's plugin directory if applicable."
    ),
    "_bifrost_sem": {},
    "pattern_brain": """## Executive Summary

Your site scores 62% overall — a **C grade**. Core crawlability is strong but AI discoverability is holding you back.

### Top 3 Quick Wins This Week

1. Add an llm.txt file at the root of your domain. This is a 30-minute task that immediately signals AI readiness to crawlers like GPTBot and ClaudeBot.

2. Fix the /admin path exposure. HTTP 200 on an admin path is a critical security issue that needs to be resolved before any AI audit sharing.

3. Enable server-side rendering for product carousels. Your Next.js setup supports this natively — flip getStaticProps to getServerSideProps on the product listing template.

### Schema Opportunities

Product schema completeness sits at 50%. Adding aggregateRating and offers.availability will unlock rich results in AI-powered search surfaces.

### Content Structure

Blog content is well-structured with proper article schema and authorship signals. Replicate this pattern on product pages.
""",
}

RECS = [
    {"severity": "critical", "pillar": "Security",           "text": "Admin path /admin is returning HTTP 200 to AI crawlers. Restrict access immediately."},
    {"severity": "warning",  "pillar": "AI Discoverability", "text": "No llm.txt file found. Add one to signal AI readiness and describe your content to LLM crawlers."},
    {"severity": "warning",  "pillar": "JS Rendering",       "text": "57% of homepage content is hidden from crawlers. Enable SSR for product carousels."},
    {"severity": "info",     "pillar": "Schema",             "text": "Product schema completeness is 50%. Add aggregateRating and offers.availability fields."},
]

if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "sample_report.pdf")
    pdf_bytes = generate_report_pdf(audit=AUDIT, domain=DOMAIN, recs=RECS)
    with open(out_path, "wb") as f:
        f.write(pdf_bytes)
    size_kb = len(pdf_bytes) // 1024
    print(f"PDF written to {out_path} ({size_kb} KB, {len(pdf_bytes):,} bytes)")
