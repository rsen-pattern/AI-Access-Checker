# -*- coding: utf-8 -*-
"""
Pattern AI Accessibility Checker — Full LLM Access Audit
Branded with Pattern design system, inspired by GEO Scorecard UI.
4 Pillars: JavaScript Rendering · LLM.txt · Robots.txt · Schema
Plus: Live Bot Crawl Test, Sensitive Path Scan, Meta Tags, Well-Known Files
"""

import streamlit as st
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from protego import Protego
import json
import re
import time
import math
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── CONFIG ───────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Pattern — AI Accessibility Checker",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── BRAND COLORS ─────────────────────────────────────────────────────────────
BRAND = {
    "bg_dark": "#090a0f",
    "bg_card": "#12131a",
    "bg_card_hover": "#1a1b24",
    "bg_surface": "#1e1f2a",
    "primary": "#009bff",
    "primary_light": "#73cdff",
    "white": "#fcfcfc",
    "text_secondary": "#b3b3b3",
    "purple": "#770bff",
    "teal": "#4cc3ae",
    "navy": "#00084d",
    "border": "#2a2b36",
    "border_light": "#3a3b46",
    # Status
    "success": "#4cc3ae",
    "warning": "#ffb548",
    "danger": "#e53e51",
    # Chart colors
    "chart": ["#73cdff", "#076ae2", "#004589", "#e53e51", "#f56969", "#ffb548", "#c2e76b"],
}

# ─── PATTERN LOGO SVG ────────────────────────────────────────────────────────
PATTERN_LOGO_SVG = '''<svg width="28" height="22" viewBox="0 0 28 22" fill="none" xmlns="http://www.w3.org/2000/svg">
<path fill-rule="evenodd" clip-rule="evenodd" d="M0.197401 16.3997L16.2682 0.835708C16.5314 0.580806 16.9649 0.580806 17.2281 0.835708L21.1839 4.66673C21.4471 4.92913 21.4471 5.34148 21.1839 5.59638L5.11308 21.1604C4.84214 21.4153 4.41637 21.4153 4.15317 21.1604L0.197401 17.3294C-0.0658005 17.0745 -0.0658005 16.6546 0.197401 16.3997ZM13.4348 16.3997L22.8869 7.24577C23.1501 6.99086 23.5836 6.99086 23.8468 7.24577L27.8026 11.0768C28.0658 11.3392 28.0658 11.7515 27.8026 12.0064L18.3505 21.1604C18.0796 21.4153 17.6538 21.4153 17.3906 21.1604L13.4348 17.3294C13.1716 17.0745 13.1716 16.6546 13.4348 16.3997Z" fill="#fcfcfc"/>
</svg>'''


# ─── AI BOT DEFINITIONS ──────────────────────────────────────────────────────
AI_BOTS = {
    "OpenAI": {
        "GPTBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
        "ChatGPT-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
        "OAI-SearchBot": "OAI-SearchBot/1.0; +https://openai.com/searchbot",
    },
    "Anthropic": {
        "ClaudeBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
        "Claude-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
    },
    "Google": {
        "Google-Extended": "Mozilla/5.0 (compatible; Google-Extended)",
        "Googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    },
    "Perplexity": {
        "PerplexityBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
        "Perplexity-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
    },
    "Other AI": {
        "CCBot": "CCBot/2.0 (https://commoncrawl.org/faq/)",
        "Bytespider": "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
        "Meta-ExternalAgent": "Mozilla/5.0 (compatible; Meta-ExternalAgent/1.0; +https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "Amazonbot": "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
        "Applebot-Extended": "Mozilla/5.0 (Applebot-Extended/0.3; +http://www.apple.com/go/applebot)",
        "Cohere-ai": "Mozilla/5.0 (compatible; cohere-ai)",
    },
}

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

SENSITIVE_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/account", "/my-account", "/user", "/profile",
    "/checkout", "/cart", "/payment",
    "/api", "/api/v1", "/graphql",
    "/staging", "/preview", "/dev", "/test",
    "/cms", "/backend", "/dashboard", "/panel",
    "/config", "/env", "/.env", "/debug",
    "/phpmyadmin", "/adminer", "/database",
]

EXPECTED_SCHEMA_TYPES = {
    "site_wide": ["Organization", "WebSite", "WebPage", "BreadcrumbList"],
    "product": ["Product", "Offer", "Brand", "AggregateRating", "Review"],
    "article": ["Article", "NewsArticle", "BlogPosting"],
    "faq": ["FAQPage", "Question", "Answer"],
    "local": ["LocalBusiness", "Store", "Place"],
    "collection": ["ItemList", "CollectionPage", "ProductCollection"],
}

SCHEMA_KEY_FIELDS = {
    "Product": ["name", "description", "image", "sku", "brand", "offers"],
    "Offer": ["price", "priceCurrency", "availability", "url"],
    "Organization": ["name", "url", "logo", "contactPoint"],
    "WebSite": ["name", "url", "potentialAction"],
    "BreadcrumbList": ["itemListElement"],
    "FAQPage": ["mainEntity"],
    "Article": ["headline", "author", "datePublished", "image"],
    "BlogPosting": ["headline", "author", "datePublished", "image"],
    "AggregateRating": ["ratingValue", "reviewCount"],
    "Review": ["author", "reviewRating", "reviewBody"],
    "LocalBusiness": ["name", "address", "telephone", "openingHours"],
    "ItemList": ["itemListElement", "numberOfItems"],
}

BENCHMARKS = {
    "js_rendering": 60,
    "llm_txt": 0,
    "robots_txt": 80,
    "schema": 50,
}


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch(url: str, timeout: int = 15, user_agent: str = None):
    headers = {"User-Agent": user_agent or BROWSER_UA}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r, None
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            return r, "SSL warning"
        except Exception as e:
            return None, str(e)
    except Exception as e:
        return None, str(e)


# ─── GAUGE SVG GENERATOR (matches GEO Scorecard style) ───────────────────────

def generate_gauge_svg(score: int, label: str = "", size: int = 200):
    """Generate an SVG donut gauge matching the GEO Scorecard style."""
    cx, cy = size // 2, size // 2
    radius = size // 2 - 20
    stroke_width = 14
    circumference = 2 * math.pi * radius

    # Arc: 270 degrees total (from 135° to 405°)
    arc_total = 270
    arc_length = circumference * (arc_total / 360)
    filled = arc_length * (score / 100)
    gap = arc_length - filled

    # Color based on score
    if score >= 75:
        stroke_color = BRAND["teal"]
        glow_color = BRAND["teal"]
    elif score >= 50:
        stroke_color = BRAND["primary"]
        glow_color = BRAND["primary"]
    elif score >= 35:
        stroke_color = BRAND["warning"]
        glow_color = BRAND["warning"]
    else:
        stroke_color = BRAND["danger"]
        glow_color = BRAND["danger"]

    # Score text label
    if score >= 75:
        status_text = "Strong"
        status_color = BRAND["teal"]
    elif score >= 50:
        status_text = "Moderate"
        status_color = BRAND["primary"]
    elif score >= 35:
        status_text = "Needs Work"
        status_color = BRAND["warning"]
    else:
        status_text = "Critical"
        status_color = BRAND["danger"]

    svg = f'''
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" style="stop-color:{BRAND['purple']};stop-opacity:1" />
          <stop offset="100%" style="stop-color:{stroke_color};stop-opacity:1" />
        </linearGradient>
      </defs>
      <!-- Background track -->
      <circle cx="{cx}" cy="{cy}" r="{radius}" fill="none"
              stroke="{BRAND['border']}" stroke-width="{stroke_width}"
              stroke-dasharray="{arc_length} {circumference - arc_length}"
              stroke-dashoffset="{-(circumference - arc_length) / 2 - (circumference * (45/360))}"
              stroke-linecap="round"
              transform="rotate(0 {cx} {cy})" />
      <!-- Filled arc -->
      <circle cx="{cx}" cy="{cy}" r="{radius}" fill="none"
              stroke="url(#gaugeGrad)" stroke-width="{stroke_width}"
              stroke-dasharray="{filled} {circumference - filled}"
              stroke-dashoffset="{-(circumference - arc_length) / 2 - (circumference * (45/360))}"
              stroke-linecap="round"
              filter="url(#glow)"
              transform="rotate(0 {cx} {cy})" />
      <!-- Score number -->
      <text x="{cx}" y="{cy - 8}" text-anchor="middle" dominant-baseline="central"
            font-family="-apple-system, BlinkMacSystemFont, sans-serif"
            font-size="{size // 4}" font-weight="800" fill="{BRAND['white']}">{score}%</text>
      <!-- Status text -->
      <text x="{cx}" y="{cy + 22}" text-anchor="middle" dominant-baseline="central"
            font-family="-apple-system, BlinkMacSystemFont, sans-serif"
            font-size="{size // 14}" fill="{status_color}">{status_text}</text>
      <!-- Label -->
      <text x="{cx}" y="{cy + 42}" text-anchor="middle" dominant-baseline="central"
            font-family="-apple-system, BlinkMacSystemFont, sans-serif"
            font-size="{size // 18}" fill="{BRAND['text_secondary']}">{label}</text>
    </svg>
    '''
    return svg


# ─── UI COMPONENT HELPERS ────────────────────────────────────────────────────

def brand_score_bar(score, benchmark=None, height=8):
    """Progress bar with Pattern brand gradient and benchmark marker."""
    if score >= 75:
        bar_color = BRAND["teal"]
    elif score >= 50:
        bar_color = BRAND["primary"]
    elif score >= 35:
        bar_color = BRAND["warning"]
    else:
        bar_color = BRAND["danger"]

    benchmark_html = ""
    if benchmark is not None:
        benchmark_html = f'''
        <div style="position:absolute;left:{benchmark}%;top:-4px;bottom:-4px;width:2px;
                     background:{BRAND['white']};border-radius:1px;opacity:0.7;"
             title="Benchmark: {benchmark}%">
        </div>
        <div style="position:absolute;left:{benchmark}%;top:-18px;transform:translateX(-50%);
                     font-size:9px;color:{BRAND['text_secondary']};white-space:nowrap;">
            Avg: {benchmark}%
        </div>
        '''

    return f'''
    <div style="position:relative;background:{BRAND['border']};border-radius:{height}px;
                height:{height}px;margin:20px 0 8px 0;overflow:visible;">
        <div style="width:{score}%;background:linear-gradient(90deg, {BRAND['purple']}, {bar_color});
                     height:100%;border-radius:{height}px;transition:width 0.6s ease;"></div>
        {benchmark_html}
    </div>
    '''


def brand_card(content, padding="1.2rem"):
    """Wrap content in a Pattern-styled card."""
    return f'''
    <div style="background:{BRAND['bg_card']};border:1px solid {BRAND['border']};
                border-radius:12px;padding:{padding};margin-bottom:0.8rem;">
        {content}
    </div>
    '''


def brand_pill(text, color=None):
    """Small colored pill/tag."""
    c = color or BRAND["primary"]
    return f'<span style="display:inline-block;background:{c}20;color:{c};padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;margin:2px 3px;">{text}</span>'


def brand_status(text, status="success"):
    """Status indicator with dot."""
    colors = {"success": BRAND["teal"], "warning": BRAND["warning"], "danger": BRAND["danger"], "info": BRAND["primary"]}
    c = colors.get(status, BRAND["primary"])
    return f'''<div style="display:flex;align-items:center;gap:8px;margin:4px 0;">
        <div style="width:8px;height:8px;border-radius:50%;background:{c};flex-shrink:0;"></div>
        <span style="color:{BRAND['white']};font-size:14px;">{text}</span>
    </div>'''


def pillar_header(number, icon, title, score, benchmark=None):
    """Pillar section header with score and benchmark bar."""
    bench_text = f"&nbsp;&nbsp;·&nbsp;&nbsp;Industry Avg: {benchmark}%" if benchmark is not None else ""
    html = f'''
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px;">
        <div style="background:linear-gradient(135deg, {BRAND['purple']}, {BRAND['primary']});
                     width:36px;height:36px;border-radius:10px;display:flex;align-items:center;
                     justify-content:center;font-size:18px;flex-shrink:0;">{icon}</div>
        <div>
            <div style="font-size:11px;color:{BRAND['text_secondary']};text-transform:uppercase;letter-spacing:1.5px;">
                Pillar {number}
            </div>
            <div style="font-size:20px;font-weight:700;color:{BRAND['white']};">{title}</div>
        </div>
        <div style="margin-left:auto;text-align:right;">
            <div style="font-size:28px;font-weight:800;color:{BRAND['white']};">{score}<span style="font-size:16px;opacity:0.5;">/100</span></div>
            <div style="font-size:11px;color:{BRAND['text_secondary']};">{bench_text}</div>
        </div>
    </div>
    '''
    return html


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 1: JAVASCRIPT RENDERING
# ═══════════════════════════════════════════════════════════════════════════════

def detect_js_frameworks(html: str):
    soup = BeautifulSoup(html, "html.parser")
    frameworks = []

    if soup.find(id="root") or soup.find(id="__next") or soup.find(id="app"):
        root_el = soup.find(id="root") or soup.find(id="__next") or soup.find(id="app")
        if root_el and len(root_el.get_text(strip=True)) < 50:
            frameworks.append(("React / Next.js", "high", "Empty root container — content likely client-side"))

    if soup.find(id="__nuxt") or soup.find(attrs={"data-v-app": True}):
        frameworks.append(("Vue.js / Nuxt", "high", "Vue app container detected"))

    if soup.find(attrs={"ng-app": True}) or soup.find("app-root"):
        frameworks.append(("Angular", "high", "Angular app root detected"))

    noscript_tags = soup.find_all("noscript")
    noscript_warnings = [ns for ns in noscript_tags if "enable javascript" in ns.get_text().lower() or "requires javascript" in ns.get_text().lower()]
    if noscript_warnings:
        frameworks.append(("JavaScript Required", "high", f"{len(noscript_warnings)} &lt;noscript&gt; warning(s)"))

    scripts = soup.find_all("script", src=True)
    bundled = [s for s in scripts if any(x in (s.get("src", "") or "") for x in ["chunk", "bundle", "webpack", "main.", "app."])]
    if len(bundled) > 3:
        frameworks.append(("Bundled JS (Webpack/Vite)", "medium", f"{len(bundled)} bundled script(s)"))

    return frameworks


def analyse_html_content(html: str):
    soup = BeautifulSoup(html, "html.parser")
    results = {
        "title": "", "meta_description": "", "h1_tags": [], "h2_tags": [],
        "prices": [], "images_with_alt": 0, "images_without_alt": 0,
        "nav_links": 0, "product_elements": 0, "text_content_length": 0,
        "total_links": 0, "pagination": False,
    }

    title = soup.find("title")
    results["title"] = title.get_text(strip=True) if title else ""

    meta_desc = soup.find("meta", attrs={"name": "description"})
    results["meta_description"] = meta_desc.get("content", "") if meta_desc else ""

    results["h1_tags"] = [h.get_text(strip=True) for h in soup.find_all("h1")][:10]
    results["h2_tags"] = [h.get_text(strip=True) for h in soup.find_all("h2")][:20]

    text = soup.get_text()
    price_patterns = re.findall(r'[\$£€]\s?\d+[\.,]?\d*', text)
    results["prices"] = list(set(price_patterns))[:20]

    price_elements = soup.find_all(class_=re.compile(r'price|cost|amount', re.I))
    price_elements += soup.find_all(attrs={"itemprop": "price"})
    if price_elements and not results["prices"]:
        for el in price_elements[:10]:
            txt = el.get_text(strip=True)
            if txt:
                results["prices"].append(txt)

    images = soup.find_all("img")
    results["images_with_alt"] = sum(1 for img in images if img.get("alt", "").strip())
    results["images_without_alt"] = sum(1 for img in images if not img.get("alt", "").strip())

    nav = soup.find_all("nav")
    results["nav_links"] = sum(len(n.find_all("a")) for n in nav)
    results["total_links"] = len(soup.find_all("a", href=True))

    product_indicators = soup.find_all(class_=re.compile(r'product|item|card', re.I))
    results["product_elements"] = len(product_indicators)

    pagination = soup.find_all(class_=re.compile(r'pagination|pager|page-nav', re.I))
    results["pagination"] = len(pagination) > 0 or bool(soup.find("a", string=re.compile(r'^(next|›|»|→)', re.I)))

    results["text_content_length"] = len(soup.get_text(separator=" ", strip=True))
    return results


def check_js_rendering(url: str):
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}

    html = resp.text
    frameworks = detect_js_frameworks(html)
    content = analyse_html_content(html)

    risk_factors = []
    score = 100

    high_risk = [f for f in frameworks if f[1] == "high"]
    if high_risk:
        score -= 30
        risk_factors.append(f"JS framework detected: {', '.join(f[0] for f in high_risk)}")

    if not content["title"]:
        score -= 10
        risk_factors.append("No <title> tag in raw HTML")

    if not content["h1_tags"]:
        score -= 10
        risk_factors.append("No <h1> tags found in raw HTML")

    if content["product_elements"] > 0 and not content["prices"]:
        score -= 15
        risk_factors.append("Product elements detected but no prices in HTML")

    if content["text_content_length"] < 200:
        score -= 20
        risk_factors.append(f"Very little text content ({content['text_content_length']} chars)")
    elif content["text_content_length"] < 500:
        score -= 10
        risk_factors.append(f"Low text content ({content['text_content_length']} chars)")

    if content["nav_links"] == 0:
        score -= 10
        risk_factors.append("No navigation links in raw HTML")

    if not content["pagination"] and content["product_elements"] > 5:
        score -= 5
        risk_factors.append("Product listing but no pagination in HTML")

    noscript_fw = [f for f in frameworks if f[0] == "JavaScript Required"]
    if noscript_fw:
        score -= 15

    return {
        "score": max(0, min(100, score)),
        "frameworks": frameworks,
        "content": content,
        "risk_factors": risk_factors,
        "html_length": len(html),
        "error": None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 2: LLM.TXT
# ═══════════════════════════════════════════════════════════════════════════════

def check_llm_txt(base_url: str):
    results = {}
    for path in ["/llm.txt", "/llms.txt", "/llms-full.txt", "/.well-known/llm.txt"]:
        url = urljoin(base_url, path)
        resp, err = fetch(url, timeout=10)
        found = False
        content = ""
        quality = {}

        if resp and resp.status_code == 200:
            text = resp.text.strip()
            if len(text) > 10 and not text.startswith("<!DOCTYPE") and not text.startswith("<html"):
                found = True
                content = text[:5000]
                quality = {
                    "has_title": bool(re.search(r'^#\s+', text, re.M)),
                    "has_description": len(text) > 100,
                    "has_links": bool(re.search(r'https?://', text)),
                    "has_sections": text.count("\n\n") > 2,
                    "char_count": len(text),
                    "line_count": len(text.splitlines()),
                }

        results[path] = {"found": found, "url": url, "content": content, "quality": quality}

    any_found = any(v["found"] for v in results.values())
    if not any_found:
        score = 0
    else:
        score = 50
        found_items = [v for v in results.values() if v["found"]]
        q = found_items[0].get("quality", {})
        if q.get("has_title"): score += 10
        if q.get("has_description"): score += 10
        if q.get("has_links"): score += 15
        if q.get("has_sections"): score += 10
        if q.get("char_count", 0) > 500: score += 5

    return {"files": results, "score": min(score, 100)}


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 3: ROBOTS.TXT & CRAWLER ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

def check_robots(base_url: str):
    robots_url = urljoin(base_url, "/robots.txt")
    resp, err = fetch(robots_url)
    if err or resp is None or resp.status_code != 200:
        return {
            "found": False, "url": robots_url, "error": err,
            "raw": "", "parser": None, "sitemaps": [],
            "ai_agent_results": {}, "sensitive_paths": {},
            "blocked_resources": [], "score": 0,
        }

    raw = resp.text
    try:
        parser = Protego.parse(raw)
    except Exception:
        parser = None

    sitemaps = []
    for line in raw.splitlines():
        stripped = line.split("#")[0].strip()
        if stripped.lower().startswith("sitemap:"):
            sitemap_url = stripped.split(":", 1)[1].strip()
            sitemaps.append(sitemap_url)

    ai_agent_results = {}
    test_url = base_url + "/"
    for company, bots in AI_BOTS.items():
        for bot_name, ua_string in bots.items():
            if parser:
                try:
                    allowed = parser.can_fetch(ua_string, test_url)
                except Exception:
                    allowed = None
            else:
                allowed = None
            ai_agent_results[bot_name] = {
                "company": company, "ua_string": ua_string, "robots_allowed": allowed,
            }

    sensitive_results = {}
    for path in SENSITIVE_PATHS:
        full_path = base_url + path
        if parser:
            try:
                exposed = parser.can_fetch(BROWSER_UA, full_path)
            except Exception:
                exposed = True
        else:
            exposed = True
        mentioned = path.lower() in raw.lower()
        sensitive_results[path] = {"accessible_per_robots": exposed, "mentioned_in_robots": mentioned}

    blocked_resources = []
    for ext_pattern in [".css", ".js", "/css/", "/js/", "/static/", "/assets/"]:
        test_path = base_url + ext_pattern
        if parser:
            try:
                if not parser.can_fetch(BROWSER_UA, test_path):
                    blocked_resources.append(ext_pattern)
            except Exception:
                pass

    score = 50
    ai_specific = sum(1 for name, r in ai_agent_results.items() if r["robots_allowed"] is not None and name != "*")
    if ai_specific > 3: score += 15
    elif ai_specific > 0: score += 10
    if sitemaps: score += 10

    properly_blocked = sum(1 for p, r in sensitive_results.items() if not r["accessible_per_robots"])
    if properly_blocked > len(SENSITIVE_PATHS) * 0.5: score += 10
    elif properly_blocked > 0: score += 5

    if not blocked_resources: score += 10
    else: score -= 10

    exposed_sensitive = sum(1 for p, r in sensitive_results.items() if r["accessible_per_robots"] and r["mentioned_in_robots"])
    if exposed_sensitive > 3: score -= 10

    return {
        "found": True, "url": robots_url, "raw": raw,
        "parser": parser, "sitemaps": sitemaps,
        "ai_agent_results": ai_agent_results,
        "sensitive_paths": sensitive_results,
        "blocked_resources": blocked_resources,
        "score": max(0, min(100, score)),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 4: SCHEMA (STRUCTURED DATA)
# ═══════════════════════════════════════════════════════════════════════════════

def flatten_schema_types(data, types_found=None):
    if types_found is None: types_found = []
    if isinstance(data, dict):
        t = data.get("@type")
        if t:
            if isinstance(t, list): types_found.extend(t)
            else: types_found.append(t)
        for v in data.values():
            flatten_schema_types(v, types_found)
    elif isinstance(data, list):
        for item in data:
            flatten_schema_types(item, types_found)
    return types_found


def validate_schema_fields(schema_type: str, data: dict):
    expected = SCHEMA_KEY_FIELDS.get(schema_type, [])
    if not expected: return {"expected": [], "present": [], "missing": [], "completeness": 100}
    present = [f for f in expected if f in data and data[f]]
    missing = [f for f in expected if f not in data or not data[f]]
    completeness = round(len(present) / len(expected) * 100) if expected else 100
    return {"expected": expected, "present": present, "missing": missing, "completeness": completeness}


def check_schema(url: str):
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"found": False, "error": err, "schemas": [], "types_found": [], "score": 0, "validations": [], "coverage": {}}

    soup = BeautifulSoup(resp.text, "html.parser")
    schemas = []
    all_types = []

    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            items = data if isinstance(data, list) else [data]
            for item in items:
                if "@graph" in item:
                    for graph_item in item["@graph"]:
                        schema_type = graph_item.get("@type", "Unknown")
                        if isinstance(schema_type, list): schema_type = ", ".join(schema_type)
                        schemas.append({"format": "JSON-LD", "type": schema_type, "data": graph_item})
                else:
                    schema_type = item.get("@type", "Unknown")
                    if isinstance(schema_type, list): schema_type = ", ".join(schema_type)
                    schemas.append({"format": "JSON-LD", "type": schema_type, "data": item})
            all_types.extend(flatten_schema_types(data))
        except (json.JSONDecodeError, TypeError):
            schemas.append({"format": "JSON-LD", "type": "Parse Error", "data": {}})

    microdata_items = soup.find_all(attrs={"itemscope": True})
    for item in microdata_items[:10]:
        item_type = item.get("itemtype", "Unknown")
        type_name = item_type.split("/")[-1] if "/" in item_type else item_type
        schemas.append({"format": "Microdata", "type": type_name, "data": {}})
        all_types.append(type_name)

    validations = []
    for s in schemas:
        if s["data"] and s["type"] != "Parse Error":
            primary_type = s["type"].split(",")[0].strip()
            v = validate_schema_fields(primary_type, s["data"])
            v["type"] = s["type"]
            validations.append(v)

    type_set = set(all_types)
    coverage = {}
    for category, expected_types in EXPECTED_SCHEMA_TYPES.items():
        found_in_category = [t for t in expected_types if t in type_set]
        coverage[category] = {
            "expected": expected_types,
            "found": found_in_category,
            "missing": [t for t in expected_types if t not in type_set],
            "coverage_pct": round(len(found_in_category) / len(expected_types) * 100) if expected_types else 0,
        }

    score = 0
    if schemas:
        score = 30
        avg_completeness = sum(v["completeness"] for v in validations) / len(validations) if validations else 50
        score += round(avg_completeness * 0.3)
        site_wide_coverage = coverage.get("site_wide", {}).get("coverage_pct", 0)
        score += round(site_wide_coverage * 0.2)
        if len(schemas) >= 3: score += 10
        if any(s["type"] in ("Product", "Offer") for s in schemas): score += 10

    return {
        "found": len(schemas) > 0, "schemas": schemas, "types_found": list(set(all_types)),
        "validations": validations, "coverage": coverage, "score": min(score, 100), "error": None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# LIVE BOT CRAWL TEST
# ═══════════════════════════════════════════════════════════════════════════════

def crawl_as_bot(url, bot_name, ua_string, robots_parser):
    try:
        robots_allowed = True
        if robots_parser:
            try: robots_allowed = robots_parser.can_fetch(ua_string, url)
            except Exception: robots_allowed = None

        start = time.time()
        resp = requests.get(url, headers={"User-Agent": ua_string}, timeout=20, allow_redirects=True)
        load_time = time.time() - start

        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.find("title")
        title_text = title.get_text(strip=True) if title else ""

        robots_meta = ""
        has_noindex = False
        robots_tag = soup.find("meta", attrs={"name": "robots"})
        if robots_tag:
            robots_meta = robots_tag.get("content", "")
            has_noindex = "noindex" in robots_meta.lower()

        is_allowed = resp.status_code == 200 and robots_allowed and not has_noindex

        return {
            "bot_name": bot_name, "status_code": resp.status_code,
            "robots_allowed": robots_allowed, "robots_meta": robots_meta or "None",
            "has_noindex": has_noindex, "is_allowed": is_allowed,
            "title": title_text, "load_time": round(load_time, 2),
            "content_length": len(soup.get_text(separator=" ", strip=True)),
            "error": None,
        }
    except Exception as e:
        return {
            "bot_name": bot_name, "status_code": None, "robots_allowed": None,
            "robots_meta": "N/A", "has_noindex": False, "is_allowed": False,
            "title": "", "load_time": 0, "content_length": 0, "error": str(e),
        }


def run_live_bot_crawl(url, robots_parser):
    results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for company, bots in AI_BOTS.items():
            for bot_name, ua_string in bots.items():
                f = executor.submit(crawl_as_bot, url, bot_name, ua_string, robots_parser)
                futures[f] = (company, bot_name)
        for future in as_completed(futures):
            company, bot_name = futures[future]
            result = future.result()
            result["company"] = company
            results[bot_name] = result
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# SUPPLEMENTARY CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def check_page_meta(url):
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}
    soup = BeautifulSoup(resp.text, "html.parser")
    meta_tags = []
    for tag in soup.find_all("meta", attrs={"name": True}):
        name = tag.get("name", "").lower()
        content = tag.get("content", "")
        if name in ("robots", "googlebot", "google-extended", "googlebot-news", "bingbot"):
            meta_tags.append({"name": name, "content": content})
    return {
        "meta_tags": meta_tags,
        "x_robots_tag": resp.headers.get("X-Robots-Tag", None),
        "nosnippet_elements": len(soup.find_all(attrs={"data-nosnippet": True})),
        "html_length": len(resp.text),
        "text_length": len(soup.get_text(separator=" ", strip=True)),
        "error": None,
    }


def check_wellknown(base_url):
    results = {}
    for path in ["/.well-known/ai-plugin.json", "/.well-known/aip.json", "/.well-known/tdmrep.json"]:
        url = urljoin(base_url, path)
        resp, err = fetch(url, timeout=8)
        if resp and resp.status_code == 200:
            text = resp.text.strip()
            if text and not text.startswith("<!DOCTYPE") and not text.startswith("<html"):
                results[path] = {"found": True, "url": url, "content": text[:2000]}
            else:
                results[path] = {"found": False, "url": url}
        else:
            results[path] = {"found": False, "url": url}
    return results


def compute_overall(js_score, llm_score, robots_score, schema_score):
    return round(js_score * 0.25 + llm_score * 0.15 + robots_score * 0.30 + schema_score * 0.30)


# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI — PATTERN BRANDED
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown(f"""
<style>
    /* ── Global dark theme ─────────────────────────────── */
    .stApp {{
        background-color: {BRAND['bg_dark']};
    }}
    .stApp > header {{
        background-color: {BRAND['bg_dark']};
    }}
    section[data-testid="stSidebar"] {{
        background-color: {BRAND['bg_card']};
    }}

    /* ── Typography ────────────────────────────────────── */
    .stApp, .stApp p, .stApp span, .stApp li, .stApp div {{
        color: {BRAND['white']};
    }}
    h1, h2, h3, h4 {{
        color: {BRAND['white']} !important;
    }}
    .stCaption, .stCaption p {{
        color: {BRAND['text_secondary']} !important;
    }}

    /* ── Cards / Expanders ─────────────────────────────── */
    div[data-testid="stExpander"] {{
        background: {BRAND['bg_card']};
        border: 1px solid {BRAND['border']};
        border-radius: 12px;
        margin-bottom: 0.5rem;
    }}
    div[data-testid="stExpander"] details {{
        border: none !important;
    }}
    div[data-testid="stExpander"] summary {{
        color: {BRAND['white']};
    }}
    div[data-testid="stExpander"] summary:hover {{
        color: {BRAND['primary']};
    }}

    /* ── Metrics ───────────────────────────────────────── */
    div[data-testid="stMetric"] {{
        background: {BRAND['bg_surface']};
        border: 1px solid {BRAND['border']};
        border-radius: 10px;
        padding: 12px 16px;
    }}
    div[data-testid="stMetric"] label {{
        color: {BRAND['text_secondary']} !important;
    }}
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {{
        color: {BRAND['white']} !important;
    }}

    /* ── Buttons ───────────────────────────────────────── */
    .stButton > button[kind="primary"], button[data-testid="stBaseButton-primary"] {{
        background: linear-gradient(135deg, {BRAND['purple']}, {BRAND['primary']}) !important;
        color: {BRAND['white']} !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 0.5rem 1.5rem !important;
    }}
    .stButton > button[kind="primary"]:hover, button[data-testid="stBaseButton-primary"]:hover {{
        opacity: 0.9 !important;
        border: none !important;
    }}

    /* ── Inputs ────────────────────────────────────────── */
    .stTextInput > div > div > input {{
        background: {BRAND['bg_surface']} !important;
        border: 1px solid {BRAND['border']} !important;
        color: {BRAND['white']} !important;
        border-radius: 8px !important;
    }}
    .stTextInput > div > div > input:focus {{
        border-color: {BRAND['primary']} !important;
        box-shadow: 0 0 0 2px {BRAND['primary']}33 !important;
    }}
    .stTextArea > div > div > textarea {{
        background: {BRAND['bg_surface']} !important;
        border: 1px solid {BRAND['border']} !important;
        color: {BRAND['white']} !important;
        border-radius: 8px !important;
    }}
    .stCheckbox label span {{
        color: {BRAND['white']} !important;
    }}

    /* ── Progress bar ──────────────────────────────────── */
    .stProgress > div > div > div {{
        background: linear-gradient(90deg, {BRAND['purple']}, {BRAND['primary']}) !important;
    }}

    /* ── Alerts ────────────────────────────────────────── */
    .stAlert {{
        background: {BRAND['bg_surface']} !important;
        border: 1px solid {BRAND['border']} !important;
        border-radius: 10px !important;
    }}
    div[data-testid="stAlert"] p {{
        color: {BRAND['white']} !important;
    }}

    /* ── Code blocks ───────────────────────────────────── */
    .stCodeBlock {{
        background: {BRAND['bg_surface']} !important;
        border: 1px solid {BRAND['border']} !important;
    }}
    code {{
        color: {BRAND['primary_light']} !important;
    }}

    /* ── Dividers ──────────────────────────────────────── */
    hr {{
        border-color: {BRAND['border']} !important;
    }}
    .section-divider {{
        border-top: 1px solid {BRAND['border']};
        margin: 2rem 0 1.5rem 0;
    }}

    /* ── Score card ────────────────────────────────────── */
    .p-score-card {{
        background: {BRAND['bg_card']};
        border: 1px solid {BRAND['border']};
        border-radius: 14px;
        padding: 1.2rem 0.8rem;
        text-align: center;
    }}
    .p-score-card:hover {{
        border-color: {BRAND['border_light']};
    }}
    .p-score-num {{
        font-size: 2rem;
        font-weight: 800;
        line-height: 1.1;
        color: {BRAND['white']};
    }}
    .p-score-label {{
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: {BRAND['text_secondary']};
        margin-top: 6px;
    }}
    .p-bench {{
        font-size: 0.65rem;
        color: {BRAND['text_secondary']};
        opacity: 0.6;
        margin-top: 4px;
    }}

    /* ── Header ────────────────────────────────────────── */
    .pattern-header {{
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 14px;
        padding: 1rem 0 0.3rem 0;
    }}
    .pattern-header h1 {{
        font-size: 1.6rem;
        font-weight: 700;
        margin: 0;
    }}
    .pattern-subtitle {{
        text-align: center;
        color: {BRAND['text_secondary']};
        font-size: 0.95rem;
        margin-bottom: 1.5rem;
    }}

    /* ── Bot result row ────────────────────────────────── */
    .bot-row {{
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 8px 12px;
        border-radius: 8px;
        margin: 3px 0;
    }}
    .bot-row:hover {{
        background: {BRAND['bg_surface']};
    }}
    .bot-name {{
        font-weight: 600;
        color: {BRAND['white']};
        min-width: 140px;
    }}
    .bot-status-allowed {{
        color: {BRAND['teal']};
        font-weight: 600;
    }}
    .bot-status-blocked {{
        color: {BRAND['danger']};
        font-weight: 600;
    }}
    .bot-detail {{
        color: {BRAND['text_secondary']};
        font-size: 0.8rem;
    }}
</style>
""", unsafe_allow_html=True)


# ── HEADER ────────────────────────────────────────────────────────────────────
st.markdown(f'''
<div class="pattern-header">
    {PATTERN_LOGO_SVG}
    <h1>AI Accessibility Checker</h1>
</div>
<div class="pattern-subtitle">
    Full LLM Access Audit &nbsp;·&nbsp; JavaScript Rendering &nbsp;·&nbsp; LLM.txt &nbsp;·&nbsp; Robots.txt &nbsp;·&nbsp; Schema &nbsp;·&nbsp; Live Bot Crawl
</div>
''', unsafe_allow_html=True)


# ── INPUT ─────────────────────────────────────────────────────────────────────
col_input, col_btn = st.columns([4, 1])
with col_input:
    url_input = st.text_input("URL", placeholder="example.com", label_visibility="collapsed")
with col_btn:
    run_audit = st.button("Run Audit", type="primary", use_container_width=True)

with st.expander("⚙️  Advanced Options"):
    extra_urls_raw = st.text_area(
        "Additional page URLs to test (one per line)",
        placeholder="https://example.com/product/example\nhttps://example.com/blog/example",
        height=80,
    )
    run_bot_crawl = st.checkbox("Run live bot crawl test (sends requests as each AI bot)", value=True)
    extra_urls = [u.strip() for u in extra_urls_raw.strip().splitlines() if u.strip()] if extra_urls_raw else []


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

if run_audit and url_input:
    url = normalise_url(url_input)
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    all_test_urls = [url] + [normalise_url(u) for u in extra_urls]

    progress = st.progress(0, text="Starting audit…")

    progress.progress(5, text="Pillar 1/4 — JavaScript Rendering Assessment…")
    js_results = {}
    for test_url in all_test_urls:
        js_results[test_url] = check_js_rendering(test_url)
    js_score = round(sum(r.get("score", 0) for r in js_results.values()) / len(js_results))

    progress.progress(20, text="Pillar 2/4 — LLM.txt Discovery…")
    llm_result = check_llm_txt(base_url)
    llm_score = llm_result["score"]

    progress.progress(35, text="Pillar 3/4 — Robots.txt & Crawler Access…")
    robots_result = check_robots(base_url)
    robots_score = robots_result["score"]

    progress.progress(50, text="Pillar 4/4 — Schema Structured Data…")
    schema_results = {}
    for test_url in all_test_urls:
        schema_results[test_url] = check_schema(test_url)
    schema_score = round(sum(r.get("score", 0) for r in schema_results.values()) / len(schema_results))

    progress.progress(65, text="Supplementary — Meta Tags & Well-Known Files…")
    meta_result = check_page_meta(url)
    wellknown_result = check_wellknown(base_url)

    bot_crawl_results = {}
    if run_bot_crawl:
        progress.progress(75, text="Live Bot Crawl — Testing as each AI agent…")
        bot_crawl_results = run_live_bot_crawl(url, robots_result.get("parser"))

    progress.progress(95, text="Generating report…")
    overall = compute_overall(js_score, llm_score, robots_score, schema_score)
    time.sleep(0.3)
    progress.progress(100, text="Audit complete!")
    time.sleep(0.4)
    progress.empty()

    # ══════════════════════════════════════════════════════════════════════
    # RESULTS
    # ══════════════════════════════════════════════════════════════════════

    st.markdown(f"<div class='section-divider'></div>", unsafe_allow_html=True)

    # ── OVERALL GAUGE + PILLAR SCORES ─────────────────────────────────────
    col_gauge, col_pillars = st.columns([1, 2])

    with col_gauge:
        gauge_svg = generate_gauge_svg(overall, label="AI Readiness Score", size=220)
        st.markdown(f'''
        <div style="display:flex;flex-direction:column;align-items:center;padding:1rem 0;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:{BRAND['text_secondary']};margin-bottom:8px;">
                LLM Access Audit
            </div>
            {gauge_svg}
            <div style="font-size:13px;color:{BRAND['text_secondary']};margin-top:8px;">
                {parsed.netloc}
            </div>
        </div>
        ''', unsafe_allow_html=True)

    with col_pillars:
        st.markdown(f'''
        <div style="display:flex;gap:10px;flex-wrap:wrap;padding-top:1.5rem;">
        ''', unsafe_allow_html=True)

        pillar_items = [
            ("⚡", "JS Rendering", js_score, BENCHMARKS["js_rendering"]),
            ("📖", "LLM.txt", llm_score, BENCHMARKS["llm_txt"]),
            ("📋", "Robots.txt", robots_score, BENCHMARKS["robots_txt"]),
            ("🧩", "Schema", schema_score, BENCHMARKS["schema"]),
        ]

        p_cols = st.columns(4)
        for i, (icon, label, sc, bench) in enumerate(pillar_items):
            color = BRAND["teal"] if sc >= 75 else BRAND["primary"] if sc >= 50 else BRAND["warning"] if sc >= 35 else BRAND["danger"]
            p_cols[i].markdown(f'''
            <div class="p-score-card">
                <div style="font-size:14px;margin-bottom:6px;">{icon}</div>
                <div class="p-score-num" style="color:{color};">{sc}<span style="font-size:14px;opacity:0.4;">%</span></div>
                <div class="p-score-label">{label}</div>
                <div class="p-bench">Avg: {bench}%</div>
            </div>
            ''', unsafe_allow_html=True)

        # Sub-scores row
        st.markdown("")
        sub_cols = st.columns(2)
        with sub_cols[0]:
            allowed_bots = sum(1 for r in bot_crawl_results.values() if r.get("is_allowed")) if bot_crawl_results else "—"
            total_bots = len(bot_crawl_results) if bot_crawl_results else "—"
            st.markdown(f'''
            <div style="background:{BRAND['bg_card']};border:1px solid {BRAND['border']};border-radius:10px;padding:14px 18px;">
                <div style="font-size:11px;color:{BRAND['text_secondary']};text-transform:uppercase;letter-spacing:1px;">Bot Access</div>
                <div style="font-size:22px;font-weight:700;color:{BRAND['white']};">{allowed_bots}<span style="font-size:14px;opacity:0.4;">/{total_bots}</span></div>
                <div style="font-size:11px;color:{BRAND['text_secondary']};">Bots allowed</div>
            </div>
            ''', unsafe_allow_html=True)
        with sub_cols[1]:
            exposed_count = sum(1 for p, r in robots_result.get("sensitive_paths", {}).items() if r["accessible_per_robots"])
            total_sensitive = len(robots_result.get("sensitive_paths", {}))
            sec_color = BRAND["teal"] if exposed_count < 5 else BRAND["warning"] if exposed_count < 15 else BRAND["danger"]
            st.markdown(f'''
            <div style="background:{BRAND['bg_card']};border:1px solid {BRAND['border']};border-radius:10px;padding:14px 18px;">
                <div style="font-size:11px;color:{BRAND['text_secondary']};text-transform:uppercase;letter-spacing:1px;">Security Scan</div>
                <div style="font-size:22px;font-weight:700;color:{sec_color};">{exposed_count}<span style="font-size:14px;opacity:0.4;">/{total_sensitive}</span></div>
                <div style="font-size:11px;color:{BRAND['text_secondary']};">Paths exposed</div>
            </div>
            ''', unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 1: JS RENDERING
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(pillar_header(1, "⚡", "JavaScript Rendering", js_score, BENCHMARKS["js_rendering"]), unsafe_allow_html=True)
    st.markdown(brand_score_bar(js_score, BENCHMARKS["js_rendering"]), unsafe_allow_html=True)

    for test_url, js_r in js_results.items():
        if js_r.get("error"):
            st.error(f"Could not fetch `{test_url}`: {js_r['error']}")
            continue

        with st.expander(f"📄  {test_url} — Score: {js_r['score']}/100"):
            if js_r["frameworks"]:
                st.markdown("**JS Frameworks / Indicators:**")
                for name, severity, note in js_r["frameworks"]:
                    sev_color = BRAND["danger"] if severity == "high" else BRAND["warning"]
                    st.markdown(brand_status(f"**{name}** ({severity}) — {note}", "danger" if severity == "high" else "warning"), unsafe_allow_html=True)
            else:
                st.markdown(brand_status("No JS-heavy framework indicators — content likely accessible to simple crawlers", "success"), unsafe_allow_html=True)

            if js_r["risk_factors"]:
                st.markdown("**Risk Factors:**")
                for rf in js_r["risk_factors"]:
                    st.markdown(brand_status(rf, "warning"), unsafe_allow_html=True)

            c = js_r["content"]
            st.markdown("**Content Visible in Raw HTML:**")
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(brand_status(f"Title: {c['title'] or 'Missing'}", "success" if c["title"] else "danger"), unsafe_allow_html=True)
                st.markdown(brand_status(f"Meta Description: {'Present' if c['meta_description'] else 'Missing'}", "success" if c["meta_description"] else "danger"), unsafe_allow_html=True)
                st.markdown(brand_status(f"H1 Tags: {len(c['h1_tags'])} found", "success" if c["h1_tags"] else "warning"), unsafe_allow_html=True)
                st.markdown(brand_status(f"H2 Tags: {len(c['h2_tags'])} found", "success" if c["h2_tags"] else "info"), unsafe_allow_html=True)
                st.markdown(brand_status(f"Prices in HTML: {len(c['prices'])} found", "success" if c["prices"] else "info"), unsafe_allow_html=True)
            with col_b:
                st.markdown(brand_status(f"Nav Links: {c['nav_links']}", "success" if c["nav_links"] else "warning"), unsafe_allow_html=True)
                st.markdown(brand_status(f"Total Links: {c['total_links']}", "success" if c["total_links"] else "warning"), unsafe_allow_html=True)
                st.markdown(brand_status(f"Images (with alt): {c['images_with_alt']}", "success"), unsafe_allow_html=True)
                st.markdown(brand_status(f"Images (no alt): {c['images_without_alt']}", "warning" if c["images_without_alt"] else "success"), unsafe_allow_html=True)
                st.markdown(brand_status(f"Pagination: {'Found' if c['pagination'] else 'Not found'}", "success" if c["pagination"] else "info"), unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 2: LLM.TXT
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(pillar_header(2, "📖", "LLM.txt Discovery", llm_score, BENCHMARKS["llm_txt"]), unsafe_allow_html=True)
    st.markdown(brand_score_bar(llm_score, BENCHMARKS["llm_txt"]), unsafe_allow_html=True)

    any_llm = any(v["found"] for v in llm_result["files"].values())
    if any_llm:
        for path, info in llm_result["files"].items():
            if info["found"]:
                st.markdown(brand_status(f"Found: {path}", "success"), unsafe_allow_html=True)
                q = info.get("quality", {})
                if q:
                    cols = st.columns(4)
                    cols[0].metric("Lines", q.get("line_count", "—"))
                    cols[1].metric("Chars", q.get("char_count", "—"))
                    cols[2].metric("Links", "Yes" if q.get("has_links") else "No")
                    cols[3].metric("Sections", "Yes" if q.get("has_sections") else "No")
                with st.expander(f"View contents of {path}"):
                    st.code(info["content"], language="markdown")
            else:
                st.caption(f"— {path} not found")
    else:
        st.markdown(brand_status("No llm.txt files found. Adoption is still extremely rare (industry avg: 0%)", "warning"), unsafe_allow_html=True)
        st.info("💡 **llm.txt** is an emerging standard providing direct guidance to AI bots on what to prioritise. [Learn more →](https://llmstxt.org)")

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 3: ROBOTS.TXT
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(pillar_header(3, "📋", "Robots.txt & Crawler Access", robots_score, BENCHMARKS["robots_txt"]), unsafe_allow_html=True)
    st.markdown(brand_score_bar(robots_score, BENCHMARKS["robots_txt"]), unsafe_allow_html=True)

    if robots_result["found"]:
        st.markdown(brand_status(f"robots.txt found at {robots_result['url']}", "success"), unsafe_allow_html=True)

        # AI Bot access grouped by company
        st.markdown(f"<div style='margin-top:16px;font-weight:600;font-size:15px;color:{BRAND['white']};'>AI Agent Access</div>", unsafe_allow_html=True)

        for company in AI_BOTS:
            company_bots = {k: v for k, v in robots_result["ai_agent_results"].items() if v["company"] == company}
            if company_bots:
                with st.expander(f"🏢  {company} ({len(company_bots)} agents)"):
                    for bot_name, info in company_bots.items():
                        if info["robots_allowed"] is True:
                            st.markdown(f'''<div class="bot-row">
                                <span class="bot-name">{bot_name}</span>
                                <span class="bot-status-allowed">✓ Allowed</span>
                            </div>''', unsafe_allow_html=True)
                        elif info["robots_allowed"] is False:
                            st.markdown(f'''<div class="bot-row">
                                <span class="bot-name">{bot_name}</span>
                                <span class="bot-status-blocked">✗ Blocked</span>
                            </div>''', unsafe_allow_html=True)
                        else:
                            st.markdown(f'''<div class="bot-row">
                                <span class="bot-name">{bot_name}</span>
                                <span style="color:{BRAND['warning']};font-weight:600;">? Unknown</span>
                            </div>''', unsafe_allow_html=True)

        # Sitemaps
        if robots_result["sitemaps"]:
            with st.expander(f"🗺️  Sitemaps ({len(robots_result['sitemaps'])} found)"):
                for sm in robots_result["sitemaps"]:
                    st.markdown(brand_status(sm, "success"), unsafe_allow_html=True)
        else:
            st.markdown(brand_status("No sitemaps referenced in robots.txt", "warning"), unsafe_allow_html=True)

        # Blocked resources
        if robots_result["blocked_resources"]:
            st.markdown(brand_status(f"Blocked resources: {', '.join(robots_result['blocked_resources'])} — prevents proper rendering", "danger"), unsafe_allow_html=True)
        else:
            st.markdown(brand_status("CSS/JS resources not blocked — AI agents can render pages", "success"), unsafe_allow_html=True)

        # Sensitive paths
        exposed = [(p, r) for p, r in robots_result["sensitive_paths"].items() if r["accessible_per_robots"]]
        blocked = [(p, r) for p, r in robots_result["sensitive_paths"].items() if not r["accessible_per_robots"]]

        with st.expander(f"🔐  Sensitive Path Scan — {len(exposed)} exposed, {len(blocked)} blocked"):
            if exposed:
                st.markdown(f"<div style='font-weight:600;color:{BRAND['warning']};margin-bottom:8px;'>Paths accessible to crawlers:</div>", unsafe_allow_html=True)
                for path, r in exposed:
                    mention = brand_pill("in robots.txt", BRAND["warning"]) if r["mentioned_in_robots"] else ""
                    st.markdown(brand_status(f"`{path}` {mention}", "warning"), unsafe_allow_html=True)
            if blocked:
                st.markdown(f"<div style='font-weight:600;color:{BRAND['teal']};margin:12px 0 8px 0;'>Paths blocked:</div>", unsafe_allow_html=True)
                for path, r in blocked[:10]:
                    st.markdown(brand_status(f"`{path}`", "success"), unsafe_allow_html=True)
                if len(blocked) > 10:
                    st.caption(f"…and {len(blocked) - 10} more")

        with st.expander("📄  Raw robots.txt"):
            st.code(robots_result["raw"][:8000], language="text")
    else:
        st.markdown(brand_status(f"No robots.txt found at {robots_result['url']}", "danger"), unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 4: SCHEMA
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(pillar_header(4, "🧩", "Schema (Structured Data)", schema_score, BENCHMARKS["schema"]), unsafe_allow_html=True)
    st.markdown(brand_score_bar(schema_score, BENCHMARKS["schema"]), unsafe_allow_html=True)

    for test_url, sr in schema_results.items():
        if sr.get("error"):
            st.error(f"Could not check `{test_url}`: {sr['error']}")
            continue

        with st.expander(f"📄  {test_url} — {len(sr['schemas'])} schema item(s)"):
            if sr["found"]:
                # Types pills
                pills = " ".join(brand_pill(t, BRAND["chart"][i % len(BRAND["chart"])]) for i, t in enumerate(sr["types_found"]))
                st.markdown(f"<div style='margin:8px 0;'>{pills}</div>", unsafe_allow_html=True)

                # Coverage
                st.markdown(f"<div style='font-weight:600;margin:12px 0 6px 0;color:{BRAND['white']};'>Coverage by Category:</div>", unsafe_allow_html=True)
                for cat, cov in sr["coverage"].items():
                    if cov["found"]:
                        found_str = ", ".join(cov["found"])
                        missing_str = ", ".join(cov["missing"]) if cov["missing"] else "None"
                        st.markdown(brand_status(f"**{cat.replace('_', ' ').title()}** — Found: {found_str} | Missing: {missing_str}", "success"), unsafe_allow_html=True)
                    else:
                        st.markdown(brand_status(f"**{cat.replace('_', ' ').title()}** — None found", "warning"), unsafe_allow_html=True)

                # Field completeness
                if sr["validations"]:
                    st.markdown(f"<div style='font-weight:600;margin:12px 0 6px 0;color:{BRAND['white']};'>Field Completeness:</div>", unsafe_allow_html=True)
                    for v in sr["validations"]:
                        status = "success" if v["completeness"] >= 80 else "warning" if v["completeness"] >= 50 else "danger"
                        st.markdown(brand_status(f"**{v['type']}** — {v['completeness']}% complete", status), unsafe_allow_html=True)
                        if v["missing"]:
                            st.caption(f"Missing: {', '.join(v['missing'])}")

                for i, s in enumerate(sr["schemas"]):
                    if s["data"]:
                        with st.expander(f"View `{s['type']}` data"):
                            st.json(s["data"])
            else:
                st.markdown(brand_status("No Schema.org structured data found", "warning"), unsafe_allow_html=True)
                st.info("💡 Add JSON-LD for: Organisation, WebSite, WebPage, BreadcrumbList, Product, Offer, FAQPage")

    # ══════════════════════════════════════════════════════════════════════
    # LIVE BOT CRAWL
    # ══════════════════════════════════════════════════════════════════════
    if bot_crawl_results:
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(f'''
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
            <div style="background:linear-gradient(135deg, {BRAND['purple']}, {BRAND['primary']});
                         width:36px;height:36px;border-radius:10px;display:flex;align-items:center;
                         justify-content:center;font-size:18px;">🕷️</div>
            <div>
                <div style="font-size:11px;color:{BRAND['text_secondary']};text-transform:uppercase;letter-spacing:1.5px;">Live Test</div>
                <div style="font-size:20px;font-weight:700;color:{BRAND['white']};">Bot Crawl Results</div>
            </div>
        </div>
        ''', unsafe_allow_html=True)

        allowed_count = sum(1 for r in bot_crawl_results.values() if r["is_allowed"])
        total_bots = len(bot_crawl_results)
        st.markdown(f'''<div style="font-size:14px;color:{BRAND['text_secondary']};margin-bottom:12px;">
            <span style="color:{BRAND['teal']};font-weight:700;">{allowed_count}</span> allowed &nbsp;·&nbsp;
            <span style="color:{BRAND['danger']};font-weight:700;">{total_bots - allowed_count}</span> blocked &nbsp;·&nbsp;
            {total_bots} total agents tested
        </div>''', unsafe_allow_html=True)

        companies_seen = list(dict.fromkeys(r["company"] for r in bot_crawl_results.values()))
        for company in companies_seen:
            company_results = {k: v for k, v in bot_crawl_results.items() if v["company"] == company}
            company_allowed = sum(1 for r in company_results.values() if r["is_allowed"])
            with st.expander(f"🏢  {company} — {company_allowed}/{len(company_results)} allowed"):
                for bot_name, r in company_results.items():
                    if r["error"]:
                        st.markdown(brand_status(f"**{bot_name}**: Error — {r['error']}", "danger"), unsafe_allow_html=True)
                    else:
                        status = "success" if r["is_allowed"] else "danger"
                        status_text = "Allowed" if r["is_allowed"] else "BLOCKED"
                        st.markdown(f'''<div class="bot-row">
                            <span class="bot-name">{bot_name}</span>
                            <span class="bot-status-{'allowed' if r['is_allowed'] else 'blocked'}">{status_text}</span>
                            <span class="bot-detail">HTTP {r['status_code']} · Robots: {'✓' if r['robots_allowed'] else '✗'} · Meta: {r['robots_meta']} · {r['content_length']:,} chars · {r['load_time']}s</span>
                        </div>''', unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════
    # SUPPLEMENTARY
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(f'''
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <div style="background:{BRAND['bg_surface']};border:1px solid {BRAND['border']};
                     width:36px;height:36px;border-radius:10px;display:flex;align-items:center;
                     justify-content:center;font-size:18px;">🏷️</div>
        <div style="font-size:18px;font-weight:600;color:{BRAND['white']};">Supplementary — Meta Tags, Headers & AI Policy Files</div>
    </div>
    ''', unsafe_allow_html=True)

    col_left, col_right = st.columns(2)
    with col_left:
        st.markdown(f"<div style='font-weight:600;color:{BRAND['white']};margin-bottom:8px;'>Page-Level Meta Tags</div>", unsafe_allow_html=True)
        if meta_result.get("error"):
            st.error(f"Could not fetch: {meta_result['error']}")
        else:
            if meta_result["meta_tags"]:
                for tag in meta_result["meta_tags"]:
                    st.markdown(brand_status(f'`<meta name="{tag["name"]}" content="{tag["content"]}">`', "info"), unsafe_allow_html=True)
            else:
                st.caption("No robots meta tags found")
            if meta_result.get("x_robots_tag"):
                st.markdown(brand_status(f"X-Robots-Tag: `{meta_result['x_robots_tag']}`", "info"), unsafe_allow_html=True)
            st.markdown(brand_status(f"data-nosnippet elements: {meta_result.get('nosnippet_elements', 0)}", "info"), unsafe_allow_html=True)
            html_len = meta_result.get("html_length", 0)
            text_len = meta_result.get("text_length", 0)
            if html_len > 0:
                ratio = text_len / html_len * 100
                st.markdown(brand_status(f"Text-to-HTML ratio: {ratio:.1f}%", "success" if ratio >= 15 else "warning"), unsafe_allow_html=True)

    with col_right:
        st.markdown(f"<div style='font-weight:600;color:{BRAND['white']};margin-bottom:8px;'>Well-Known AI Policy Files</div>", unsafe_allow_html=True)
        for path, info in wellknown_result.items():
            if info["found"]:
                st.markdown(brand_status(f"Found: {path}", "success"), unsafe_allow_html=True)
            else:
                st.caption(f"— {path} not found")

    # ══════════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(f'''
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
        <div style="background:linear-gradient(135deg, {BRAND['warning']}, {BRAND['danger']});
                     width:36px;height:36px;border-radius:10px;display:flex;align-items:center;
                     justify-content:center;font-size:18px;">💡</div>
        <div style="font-size:20px;font-weight:700;color:{BRAND['white']};">Priority Recommendations</div>
    </div>
    ''', unsafe_allow_html=True)

    recs = []

    if js_score < 60:
        recs.append(("danger", "JS Rendering", "Critical content may be invisible to AI crawlers. Implement server-side rendering (SSR) for key product and marketing pages."))
    elif js_score < 80:
        recs.append(("warning", "JS Rendering", "Some content may require JavaScript. Review product pages to ensure prices, specs, and pagination are in raw HTML."))

    if llm_score == 0:
        recs.append(("warning", "LLM.txt", "Create an llm.txt file to give AI agents a curated summary of your site, key pages, and content priorities."))
    elif llm_score < 70:
        recs.append(("warning", "LLM.txt", "Improve your llm.txt — add clear sections, links to key pages, and brand/product descriptions."))

    if not robots_result["found"]:
        recs.append(("danger", "Robots.txt", "Create a robots.txt file — the foundational control for managing all crawler access."))
    else:
        if not robots_result["sitemaps"]:
            recs.append(("warning", "Robots.txt", "Add sitemap references so AI crawlers can discover important pages efficiently."))
        if robots_result["blocked_resources"]:
            recs.append(("danger", "Robots.txt", f"CSS/JS blocked ({', '.join(robots_result['blocked_resources'])}). This prevents AI agents from rendering pages."))
        exposed = [(p, r) for p, r in robots_result["sensitive_paths"].items() if r["accessible_per_robots"]]
        critical = [p for p, r in exposed if any(x in p for x in ["/admin", "/api", "/.env", "/config", "/database"])]
        if critical:
            recs.append(("danger", "Security", f"Sensitive paths exposed: {', '.join(critical[:5])}. Add Disallow rules or gate these paths."))

    if schema_score < 30:
        recs.append(("danger", "Schema", "Add JSON-LD schema for Organisation, WebSite, BreadcrumbList. For product pages: Product, Offer, Brand with complete fields."))
    elif schema_score < 60:
        all_missing = []
        for sr in schema_results.values():
            for v in sr.get("validations", []):
                all_missing.extend(v.get("missing", []))
        if all_missing:
            recs.append(("warning", "Schema", f"Incomplete fields: {', '.join(set(all_missing)[:8])}. Complete these for accurate AI extraction."))
        else:
            recs.append(("warning", "Schema", "Expand schema: consider FAQPage, Review, AggregateRating types."))

    if not recs:
        st.markdown(brand_status("Excellent! Your site scores well across all four pillars.", "success"), unsafe_allow_html=True)
    else:
        for status, pillar, text in recs:
            color = BRAND["danger"] if status == "danger" else BRAND["warning"]
            st.markdown(f'''
            <div style="background:{BRAND['bg_card']};border-left:3px solid {color};
                        border-radius:0 10px 10px 0;padding:14px 18px;margin:6px 0;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                    {brand_pill(pillar, color)}
                </div>
                <div style="color:{BRAND['white']};font-size:14px;">{text}</div>
            </div>
            ''', unsafe_allow_html=True)

    # ── FOOTER ────────────────────────────────────────────────────────────
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(f'''
    <div style="display:flex;align-items:center;justify-content:center;gap:10px;padding:1rem 0;">
        {PATTERN_LOGO_SVG}
        <span style="color:{BRAND['text_secondary']};font-size:12px;">
            Pattern AI Accessibility Checker — LLM Access Audit · Benchmarks: Pattern Q1 2025 AU DTC Audit
        </span>
    </div>
    ''', unsafe_allow_html=True)

elif run_audit and not url_input:
    st.warning("Please enter a URL to audit.")
