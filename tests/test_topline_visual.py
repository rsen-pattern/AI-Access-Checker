"""
Minimal visual harness for report_pdf.generate_topline_pdf.

Writes three sample topline PDFs to tests/sample_topline_*.pdf for manual
inspection. Run:

    python tests/test_topline_visual.py
    pdftoppm -r 140 tests/sample_topline_default.pdf tests/topline_default

Scenarios:
- default:   moderate scores, no critical exposure, no Cloudflare block
- critical:  schema/js critically low + a real /admin exposure
- healthy:   all 4 weighted pillars >= 75, semantic + security mixed

These are used to verify the methodology-honesty changes in this PR:
- Page 2 splits weighted vs additional checks
- Strongest/Priority computed from weighted only
- Page 3 findings restructured into What/Why beats
- Page 4 "Powered by" lines anchored to reader scores
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report_pdf import generate_topline_pdf


def _audit(
    overall: int = 62,
    js: int = 75, robots: int = 88, schema: int = 55, llm: int = 40,
    semantic: int = 70, security: int = 90,
    critical_exposure: bool = False,
    cloudflare_blocking: bool = False,
    found_robots_txt: bool = True,
) -> dict:
    """Build a minimal audit dict for topline rendering."""
    return {
        "overall": overall,
        "overall_grade": {
            "letter": ("A" if overall >= 85 else "B" if overall >= 70
                       else "C" if overall >= 50 else "D" if overall >= 35 else "F"),
            "label":  ("Excellent" if overall >= 85 else "Good" if overall >= 70
                       else "Needs Work" if overall >= 50 else "Poor" if overall >= 35
                       else "Critical"),
        },
        "js_score":       js,
        "robots_score":   robots,
        "schema_score":   schema,
        "llm_score":      llm,
        "semantic_score": semantic,
        "security_score": security,
        "no_blog":        False,
        "url_labels":     {"https://example.com/": "Homepage"},
        "js_results":     {},
        "robots_result": {
            "found":  found_robots_txt,
            "sitemaps": ["https://example.com/sitemap.xml"] if found_robots_txt else [],
            "blocked_resources": [],
            "cloudflare": {
                "cloudflare_detected": cloudflare_blocking,
                "bot_fight_mode_likely": cloudflare_blocking,
                "blocked_bots": (["GPTBot", "ClaudeBot"] if cloudflare_blocking else []),
            },
            "ai_agent_results": {},
            "sensitive_paths":  {},
        },
        "schema_results": {
            "https://example.com/": {
                "score": schema,
                "schema": {"types": ["Organization"], "validations": [], "essential_found": [], "essential_missing": [], "schemas": []},
                "entity": {"has_org_sameas": False},
                "ecommerce": {},
                "content_architecture": {"has_lead_paragraph": True},
            },
        },
        "llm_result":      {"llm_txt": {}, "ai_info_page": {"found": False}, "wellknown": {}},
        "semantic_results": {},
        "security_result": {
            "total_exposed": 1 if critical_exposure else 0,
            "findings": {
                "critical": [{"path": "/admin", "status": 200, "size": 4200}] if critical_exposure else [],
                "backend":  [],
                "customer": [],
                "html_exposure": [],
                "robots_allowlist": [],
            },
        },
        "bot_crawl_results": {},
    }


SCENARIOS = {
    "default":  _audit(),
    "critical": _audit(overall=38, js=30, schema=22, security=15, critical_exposure=True),
    "healthy":  _audit(overall=82, js=85, robots=90, schema=80, llm=78, semantic=60, security=72),
}


if __name__ == "__main__":
    out_dir = os.path.dirname(__file__)
    for name, audit_data in SCENARIOS.items():
        pdf_bytes = generate_topline_pdf(audit=audit_data, domain="example.com")
        out_path = os.path.join(out_dir, f"sample_topline_{name}.pdf")
        with open(out_path, "wb") as f:
            f.write(pdf_bytes)
        print(f"{name:>9}: wrote {out_path} ({len(pdf_bytes):,} bytes)")
