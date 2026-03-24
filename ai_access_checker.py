# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Full LLM Access Audit
Branded with Pattern design system.
4 Pillars: JavaScript Rendering · LLM.txt · Robots.txt · Schema
Plus: Live Bot Crawl, Sensitive Path Scan, Semantic Hierarchy Checks
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
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── FAVICON: Pattern logo as base64 PNG-via-SVG ─────────────────────────────
FAVICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 28 22"><path fill-rule="evenodd" clip-rule="evenodd" d="M0.197401 16.3997L16.2682 0.835708C16.5314 0.580806 16.9649 0.580806 17.2281 0.835708L21.1839 4.66673C21.4471 4.92913 21.4471 5.34148 21.1839 5.59638L5.11308 21.1604C4.84214 21.4153 4.41637 21.4153 4.15317 21.1604L0.197401 17.3294C-0.0658005 17.0745 -0.0658005 16.6546 0.197401 16.3997ZM13.4348 16.3997L22.8869 7.24577C23.1501 6.99086 23.5836 6.99086 23.8468 7.24577L27.8026 11.0768C28.0658 11.3392 28.0658 11.7515 27.8026 12.0064L18.3505 21.1604C18.0796 21.4153 17.6538 21.4153 17.3906 21.1604L13.4348 17.3294C13.1716 17.0745 13.1716 16.6546 13.4348 16.3997Z" fill="%23009bff"/></svg>'
FAVICON_B64 = base64.b64encode(FAVICON_SVG.encode()).decode()

# ─── CONFIG ───────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Pattern — LLM Access Checker",
    page_icon=f"data:image/svg+xml;base64,{FAVICON_B64}",
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
    "success": "#4cc3ae",
    "warning": "#ffb548",
    "danger": "#e53e51",
    "chart": ["#73cdff", "#076ae2", "#004589", "#e53e51", "#f56969", "#ffb548", "#c2e76b"],
}

PATTERN_LOGO_SVG = '''<svg width="180" height="36" viewBox="0 0 675 135.7" fill="none" xmlns="http://www.w3.org/2000/svg">
<path fill="#009BFF" d="M81.55,0.99L0.99,81.55c-1.32,1.32-1.32,3.47,0,4.8l19.84,19.84c1.32,1.32,3.47,1.32,4.8,0l80.56-80.56c1.32-1.32,1.32-3.47,0-4.8L86.35,0.99C85.02-0.33,82.88-0.33,81.55,0.99z"/>
<path fill="#009BFF" d="M114.73,34.17L67.37,81.54c-1.32,1.32-1.32,3.47,0,4.8l19.84,19.84c1.32,1.32,3.47,1.32,4.8,0l47.36-47.36c1.32-1.32,1.32-3.47,0-4.8l-19.84-19.84C118.2,32.85,116.05,32.85,114.73,34.17z"/>
<path fill="#F2F2F2" d="M254.36,64.21c0,24.35-18.47,42.98-40.69,42.98c-12.74,0-22.39-5.23-28.6-13.73v40.25c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2V25.35c0-1.1,0.89-2,2-2h13.65c1.1,0,2,0.89,2,2v9.77c6.21-8.66,15.85-13.89,28.6-13.89C235.9,21.23,254.36,40.02,254.36,64.21z M236.71,64.21c0-15.2-11.11-26.15-25.82-26.15c-14.71,0-25.82,10.95-25.82,26.15c0,15.2,11.11,26.15,25.82,26.15C225.6,90.35,236.71,79.4,236.71,64.21z"/>
<path fill="#F2F2F2" d="M347.84,25.35v77.71c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2v-9.77c-6.21,8.66-15.85,13.89-28.6,13.89c-22.22,0-40.69-18.79-40.69-42.98c0-24.35,18.46-42.98,40.69-42.98c12.74,0,22.39,5.23,28.6,13.73v-9.6c0-1.1,0.89-2,2-2h13.65C346.95,23.35,347.84,24.25,347.84,25.35z M330.19,64.21c0-15.2-11.11-26.15-25.82-26.15s-25.82,10.95-25.82,26.15c0,15.2,11.11,26.15,25.82,26.15S330.19,79.4,330.19,64.21z"/>
<path fill="#F2F2F2" d="M397.4,40.35c1.1,0,2-0.89,2-2v-13c0-1.1-0.89-2-2-2h-21V2c0-1.1-0.89-2-2-2h-13.65c-1.1,0-2,0.89-2,2v78.96c0,16.77,8.09,24.83,24.97,24.83l13.68-0.01c1.1,0,2-0.9,2-2V91.42c0-1.1-0.9-2-2-2c-2.84,0-8.3-0.01-10.5-0.01c-8.05,0-10.5-2.09-10.5-9.85V40.35H397.4z"/>
<path fill="#F2F2F2" d="M445.33,40.35c1.1,0,2-0.89,2-2v-13c0-1.1-0.89-2-2-2h-21V2c0-1.1-0.89-2-2-2h-13.65c-1.1,0-2,0.89-2,2v78.96c0,16.77,8.09,24.83,24.97,24.83l13.68-0.01c1.1,0,1.99-0.9,1.99-2V91.42c0-1.1-0.9-2-2-2c-2.84,0-8.3-0.01-10.5-0.01c-8.05,0-10.5-2.09-10.5-9.85V40.35H445.33z"/>
<path fill="#F2F2F2" d="M493.81,91.01c9.04,0,15.99-3.75,20.09-8.81c0.61-0.75,1.69-0.91,2.52-0.42l11.12,6.5c1.02,0.59,1.33,1.95,0.62,2.89c-7.59,10.04-19.37,16.03-34.51,16.03c-26.96,0-44.45-18.46-44.45-42.98c0-24.18,17.48-42.98,43.14-42.98c24.35,0,41.02,19.61,41.02,43.14c0,2.45-0.33,5.07-0.65,7.35h-65.04C470.44,84.47,480.74,91.01,493.81,91.01z M515.54,57.34c-2.45-14.05-12.75-20.1-23.37-20.1c-13.24,0-22.22,7.84-24.67,20.1H515.54z"/>
<path fill="#F2F2F2" d="M583.58,21.88c-10.29,0-20.26,4.09-25.16,15.2V25.35c0-1.1-0.89-2-2-2h-13.65c-1.1,0-2,0.89-2,2v77.71c0,1.1,0.89,2,2,2h13.65c1.1,0,2-0.89,2-2V63.88c0-18.3,13.28-22.88,25.16-22.88h6.15c1.1,0,2-0.89,2-2V23.88c0-1.1-0.89-2-2-2H583.58z"/>
<path fill="#F2F2F2" d="M675,54.89v48.17c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2V56.69c0-12.42-7.19-18.96-18.3-18.96c-11.6,0-20.75,6.86-20.75,23.53v41.8c0,1.1-0.89,2-2,2h-13.65c-1.1,0-2-0.89-2-2V25.35c0-1.1,0.89-2,2-2h13.65c1.1,0,2,0.89,2,2v8.46c5.39-8.5,14.22-12.58,25.33-12.58C661.93,21.23,675,33.65,675,54.89z"/>
</svg>'''

# ─── PILLAR EXPLANATIONS ─────────────────────────────────────────────────────
PILLAR_INFO = {
    "js_rendering": {
        "what": "We load each page twice — once as raw HTML (what AI crawlers see) and once with JavaScript fully executed. We compare side-by-side to show exactly what content AI agents miss: prices, product images, navigation, reviews, text, and links. We also check for render-blocking scripts, lazy-loaded images without dimensions, and JS framework detection. An AI agent then analyses the gaps.",
        "why": "Most AI crawlers (GPTBot, ClaudeBot, PerplexityBot) do not execute JavaScript. Per BAISOM Layer 2: 'If your content needs JavaScript to appear, it doesn't exist for most AI.' This means products, prices, and descriptions that load via JS are invisible to AI shopping agents — which will then fall back to third-party data, potentially surfacing incorrect pricing or negative sentiment about your brand.",
    },
    "llm_discoverability": {
        "what": "We check for llm.txt files (4 path variants), an AI Info Page (/ai-info, /for-ai etc.), and all /.well-known/ AI guidance files: ai-plugin.json (OpenAI), ucp (Universal Commerce Protocol, Jan 2026), mcp.json (WebMCP by Microsoft/Google), and tdmrep.json. JSON files are validated — a malformed file is flagged, not just 'found'.",
        "why": "These files tell AI agents what your site does, what to prioritise, and how to interact with it. The Universal Commerce Protocol lets AI shopping agents discover your checkout capabilities. WebMCP lets agents interact with your site's tools. The AI Info Page is something you can build today — unlike llm.txt which has near 0% industry adoption — and it positions your brand to control its own AI narrative.",
    },
    "robots_txt": {
        "what": "We parse your robots.txt against 16 AI bot user agents, check for sitemaps, blocked CSS/JS, and 25+ sensitive path exposures. We run live crawl tests as each AI bot. We also detect Cloudflare Bot Fight Mode — per BAISOM: 'Check if Cloudflare is not already blocking AI bots for you' — which silently blocks legitimate AI crawlers even when robots.txt allows them.",
        "why": "robots.txt now controls AI access, not just search access. Blocking AI crawlers = choosing invisibility in AI answers. Cloudflare's Bot Fight Mode blocks ChatGPT-User (which surged 2,825% YoY) and PerplexityBot without any robots.txt instruction. A misconfigured Cloudflare setup can make your site invisible to AI agents regardless of all other optimisations.",
    },
    "schema": {
        "what": "We parse all JSON-LD and Microdata per page. We validate field completeness including ecommerce-critical fields: GTIN/MPN (product identifiers required by AI shopping agents), MerchantReturnPolicy, shippingDetails, AggregateRating depth, and Organization sameAs. We also check for price/schema consistency and outbound citations to authoritative domains.",
        "why": "Schema is the machine-readable 'entity card' that feeds both Google's Knowledge Graph and LLM entity understanding. Products without GTINs are excluded or deprioritised by AI shopping agents — research shows 60% of ecommerce catalogs have missing GTINs. Organization sameAs connects your site to your LinkedIn, Wikipedia, and social profiles, creating the consistent entity presence AI systems use to verify and trust your brand.",
    },
    "semantic_content": {
        "what": "We check BAISOM Layers 3–6: accessibility (alt text, ARIA landmarks, form labels, lang attribute), content architecture (answer-first summary paragraphs, heading hierarchy, descriptive vs vague headings), internal linking depth and topic clustering, and content clarity (specific facts vs vague marketing language).",
        "why": "BAISOM Layer 4: 'AI doesn't scroll. It reads top-down and decides in milliseconds.' A summary paragraph in the first 60 words dramatically increases AI citation probability. Topic clustering — multiple pages linked around one subject — causes AI to treat your brand as THE authoritative source on that topic. Princeton KDD research found adding statistics to content increases AI visibility by up to 41%.",
    },
    "bot_crawl": {
        "what": "We simulate live HTTP requests to your homepage impersonating each major AI crawler user-agent — GPTBot, ClaudeBot, PerplexityBot, Google-Extended, and 11 others. We record the HTTP response code, content length, load time, robots.txt compliance, and any meta robots directives returned.",
        "why": "A site can look open in robots.txt but still block AI bots via Cloudflare, WAF rules, or server-level rate limiting. The only way to know if AI crawlers can actually reach your content is to send a request as them. A 403 or empty response here means AI systems are silently unable to index your site — regardless of your SEO setup.",
    },
}

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

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

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


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def get_secret(key, default=""):
    """Safely get a secret — returns default if secrets not configured."""
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default


@st.cache_resource
def get_supabase():
    """Return a Supabase client, or None if SUPABASE_URL/KEY not configured."""
    try:
        from supabase import create_client
        url = get_secret("SUPABASE_URL", "")
        key = get_secret("SUPABASE_KEY", "")
        if url and key:
            return create_client(url, key)
    except Exception:
        pass
    return None


def _sanitise_for_db(obj, _depth=0):
    """Recursively sanitise audit data for DB storage.
    Truncates long strings to prevent Supabase row-size issues.
    Stops recursing beyond depth 8 to guard against weird structures."""
    if _depth > 8:
        return None
    if isinstance(obj, dict):
        return {k: _sanitise_for_db(v, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitise_for_db(i, _depth + 1) for i in obj]
    if isinstance(obj, str):
        return obj[:8000] + "…[truncated]" if len(obj) > 8000 else obj
    if isinstance(obj, (bool, int, float)) or obj is None:
        return obj
    # Non-serializable type (e.g. Protego parser object) — drop it
    return None


def save_audit_to_db(domain, overall, pillar_scores_dict, audited_urls, full_results=None):
    """Persist full audit results to Supabase. Silently no-ops if DB not configured."""
    sb = get_supabase()
    if not sb:
        return
    try:
        row = {
            "domain":        domain,
            "overall_score": overall,
            "pillar_scores": json.dumps(pillar_scores_dict),
            "urls":          audited_urls,
        }
        if full_results is not None:
            row["full_results"] = _sanitise_for_db(full_results)
        sb.table("audits").insert(row).execute()
    except Exception:
        pass  # Never crash the app due to a DB write failure


def load_audit_history(domain=None, limit=10):
    """Load past audits from Supabase. Returns a list of row dicts or []."""
    sb = get_supabase()
    if not sb:
        return []
    for cols in ("id,domain,audited_at,overall_score,pillar_scores,urls,full_results",
                 "id,domain,audited_at,overall_score,pillar_scores,urls"):
        try:
            q = (sb.table("audits")
                   .select(cols)
                   .order("audited_at", desc=True)
                   .limit(limit))
            if domain:
                q = q.eq("domain", domain)
            return q.execute().data or []
        except Exception:
            continue
    return []


def load_audit_by_id(audit_id):
    """Fetch a single audit row by primary key. Returns dict or None."""
    sb = get_supabase()
    if not sb:
        return None
    for cols in ("id,domain,audited_at,overall_score,pillar_scores,urls,full_results",
                 "id,domain,audited_at,overall_score,pillar_scores,urls"):
        try:
            data = (sb.table("audits")
                      .select(cols)
                      .eq("id", str(audit_id))
                      .limit(1)
                      .execute().data)
            return data[0] if data else None
        except Exception:
            continue
    return None


def delete_audit_by_id(audit_id):
    """Delete a single audit row by primary key. Returns True on success."""
    sb = get_supabase()
    if not sb or not audit_id:
        return False
    try:
        sb.table("audits").delete().eq("id", str(audit_id)).execute()
        return True
    except Exception:
        return False


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


# ─── GAUGE SVG GENERATOR ─────────────────────────────────────────────────────

def generate_gauge_svg(score: int, label: str = "", size: int = 200):
    cx, cy = size // 2, size // 2
    radius = size // 2 - 20
    stroke_width = 14
    circumference = 2 * math.pi * radius
    arc_total = 270
    arc_length = circumference * (arc_total / 360)
    filled = arc_length * (score / 100)

    if score >= 75:
        stroke_color, status_text, status_color = BRAND["teal"], "Strong", BRAND["teal"]
    elif score >= 50:
        stroke_color, status_text, status_color = BRAND["primary"], "Moderate", BRAND["primary"]
    elif score >= 35:
        stroke_color, status_text, status_color = BRAND["warning"], "Needs Work", BRAND["warning"]
    else:
        stroke_color, status_text, status_color = BRAND["danger"], "Critical", BRAND["danger"]

    offset = -(circumference - arc_length) / 2 - (circumference * (45/360))
    svg = f'''<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
      <defs><filter id="glow"><feGaussianBlur stdDeviation="3" result="coloredBlur"/><feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" style="stop-color:{BRAND['purple']};stop-opacity:1" /><stop offset="100%" style="stop-color:{stroke_color};stop-opacity:1" /></linearGradient></defs>
      <circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{BRAND['border']}" stroke-width="{stroke_width}" stroke-dasharray="{arc_length} {circumference - arc_length}" stroke-dashoffset="{offset}" stroke-linecap="round"/>
      <circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="url(#gaugeGrad)" stroke-width="{stroke_width}" stroke-dasharray="{filled} {circumference - filled}" stroke-dashoffset="{offset}" stroke-linecap="round" filter="url(#glow)"/>
      <text x="{cx}" y="{cy - 8}" text-anchor="middle" dominant-baseline="central" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="{size // 4}" font-weight="800" fill="{BRAND['white']}">{score}%</text>
      <text x="{cx}" y="{cy + 22}" text-anchor="middle" dominant-baseline="central" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="{size // 14}" fill="{status_color}">{status_text}</text>
      <text x="{cx}" y="{cy + 42}" text-anchor="middle" dominant-baseline="central" font-family="-apple-system, BlinkMacSystemFont, sans-serif" font-size="{size // 18}" fill="{BRAND['text_secondary']}">{label}</text></svg>'''
    return svg


# ─── UI COMPONENT HELPERS ────────────────────────────────────────────────────

def brand_score_bar(score, height=8):
    bar_color = BRAND["teal"] if score >= 75 else BRAND["primary"] if score >= 50 else BRAND["warning"] if score >= 35 else BRAND["danger"]
    return f'<div style="background:{BRAND["border"]};border-radius:{height}px;height:{height}px;margin:8px 0 4px 0;"><div style="width:{score}%;background:linear-gradient(90deg, {BRAND["purple"]}, {bar_color});height:100%;border-radius:{height}px;"></div></div>'


def brand_pill(text, color=None):
    c = color or BRAND["primary"]
    return f'<span style="display:inline-block;background:{c}20;color:{c};padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;margin:2px 3px;">{text}</span>'


def brand_status(text, status="success"):
    colors = {"success": BRAND["teal"], "warning": BRAND["warning"], "danger": BRAND["danger"], "info": BRAND["primary"]}
    c = colors.get(status, BRAND["primary"])
    return f'<div style="display:flex;align-items:center;gap:8px;margin:4px 0;"><div style="width:8px;height:8px;border-radius:50%;background:{c};flex-shrink:0;"></div><span style="color:{BRAND["white"]};font-size:14px;">{text}</span></div>'


def pillar_header(number, title, score):
    return f'<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;"><div><div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1.5px;">Pillar {number}</div><div style="font-size:20px;font-weight:700;color:{BRAND["white"]};">{title}</div></div><div style="text-align:right;"><div style="font-size:28px;font-weight:800;color:{BRAND["white"]};">{score}<span style="font-size:16px;opacity:0.5;">/100</span></div></div></div>'


def _md_to_html(text):
    """Convert basic LLM markdown (###, **, numbered lists) to HTML for styled div injection."""
    import re
    text = re.sub(r'^### (.+)$', r'<h3 style="color:#fff;font-size:15px;font-weight:700;margin:14px 0 6px 0;letter-spacing:0.3px;text-transform:uppercase;">\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^## (.+)$',  r'<h2 style="color:#fff;font-size:17px;font-weight:700;margin:16px 0 8px 0;">\1</h2>', text, flags=re.MULTILINE)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'^\d+\.\s+(.+)$', r'<div style="padding:3px 0 3px 12px;color:#e0e0e0;">\1</div>', text, flags=re.MULTILINE)
    text = text.replace('\n\n', '<br>').replace('\n', '')
    return text


def pillar_explainer(pillar_key):
    """Render the 'What we check & Why it matters' expandable section."""
    info = PILLAR_INFO.get(pillar_key, {})
    if not info:
        return
    with st.expander("ℹ️  What we check & Why it matters for your brand"):
        col_w, col_y = st.columns(2)
        with col_w:
            st.markdown(f"**What we check:**")
            st.markdown(f"<div style='color:{BRAND['text_secondary']};font-size:13px;line-height:1.6;'>{info['what']}</div>", unsafe_allow_html=True)
        with col_y:
            st.markdown(f"**Why it matters:**")
            st.markdown(f"<div style='color:{BRAND['text_secondary']};font-size:13px;line-height:1.6;'>{info['why']}</div>", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# JS RENDERING API — CASCADING FALLBACK
# ═══════════════════════════════════════════════════════════════════════════════

# ─── AUDIT LOGIC: all imported from checks.py (single source of truth) ─────────
from checks import (
    AI_BOTS, BOT_TYPES, KEY_AI_BOTS, SENSITIVE_PATHS, ALL_SENSITIVE_PATHS,
    CMS_PROFILES, SCHEMA_KEY_FIELDS, EXPECTED_SCHEMA_TYPES, AUTHORITATIVE_DOMAINS,
    GRADE_THRESHOLDS, get_grade, ScoreBuilder, compute_overall,
    fetch, normalise_url, extract_jsonld, flatten_schema_types, detect_cms,
    fetch_js_rendered, analyse_html_content, detect_js_frameworks, compare_html_vs_js,
    check_js_rendering, check_cloudflare_bot_protection, check_robots_crawlability,
    run_live_bot_crawl, validate_schema_fields, check_schema_meta,
    check_llm_discoverability, check_security_exposure,
    pattern_brain_analysis, analyse_schema_quality, analyse_content_clarity, analyse_entity_coherence,
    ai_analyse_js_gap, analyse_semantic_hierarchy, analyse_robots_access, analyse_llm_discoverability,
)

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

def generate_report_html(domain, overall, pillar_scores, url_labels, js_results, llm_result, robots_result, schema_results, semantic_results, bot_crawl_results, recs):
    """Generate a self-contained branded HTML report matching the live app design."""
    B = BRAND  # shorthand

    def _score_color(s):
        return B["teal"] if s >= 75 else B["primary"] if s >= 50 else B["warning"] if s >= 35 else B["danger"]

    def _grade(s):
        for t, (l, lb) in sorted({90:("A","Excellent"),75:("B","Good"),60:("C","Fair"),40:("D","Needs Work"),0:("F","Critical")}.items(), reverse=True):
            if s >= t: return l, lb
        return "F", "Critical"

    def _score_bar(score):
        c = _score_color(score)
        return f'<div style="background:{B["border"]};border-radius:8px;height:8px;margin:8px 0 4px 0;"><div style="width:{score}%;background:linear-gradient(90deg,{B["purple"]},{c});height:8px;border-radius:8px;"></div></div>'

    def _pill(text, color):
        return f'<span style="display:inline-block;background:{color}20;color:{color};padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;letter-spacing:0.5px;margin-right:6px;">{text}</span>'

    def _status(text, status):
        c = {"success":B["teal"],"warning":B["warning"],"danger":B["danger"],"info":B["primary"]}.get(status, B["primary"])
        return f'<div style="display:flex;align-items:center;gap:8px;margin:4px 0;"><div style="width:8px;height:8px;border-radius:50%;background:{c};flex-shrink:0;"></div><span style="color:{B["white"]};font-size:13px;">{text}</span></div>'

    def _card(content, accent=None):
        border = f"border-left:3px solid {accent};" if accent else ""
        return f'<div style="background:{B["bg_card"]};border:1px solid {B["border"]};{border}border-radius:{"0 10px 10px 0" if accent else "10px"};padding:14px 18px;margin:8px 0;">{content}</div>'

    def _pillar_header(num, title, score):
        sc = _score_color(score)
        return f'''<div style="margin-top:36px;">
  <div style="font-size:10px;color:{B["text_secondary"]};text-transform:uppercase;letter-spacing:2px;margin-bottom:2px;">Pillar {num}</div>
  <div style="display:flex;align-items:center;justify-content:space-between;">
    <div style="font-size:22px;font-weight:800;color:{B["white"]};">{title}</div>
    <div style="font-size:28px;font-weight:800;color:{B["white"]};">{score}<span style="font-size:14px;opacity:0.4;">/100</span></div>
  </div>
  {_score_bar(score)}
  <div style="height:1px;background:linear-gradient(90deg,{B["purple"]},{B["primary"]},transparent);margin-bottom:16px;"></div>
</div>'''

    def _section_header(title, level="SITE-LEVEL"):
        color = B["purple"] if level == "SITE-LEVEL" else B["primary"]
        return f'<div style="margin-top:36px;"><div style="font-size:22px;font-weight:800;color:{B["white"]};margin-bottom:4px;">{title}</div>{_pill(level, color)}<div style="height:1px;background:linear-gradient(90deg,{B["purple"]},{B["primary"]},transparent);margin:10px 0 16px 0;"></div></div>'

    def _page_block(label, score=None):
        sc_html = ""
        if score is not None:
            sc = _score_color(score)
            sc_html = f' <span style="color:{sc};font-size:14px;">{score}/100</span>'
        return f'<div style="font-size:16px;font-weight:700;color:{B["white"]};margin:20px 0 6px 0;">{label}{sc_html}</div>'

    sorted_pillars = sorted(pillar_scores.items(), key=lambda x: x[1])
    weakest, strongest = sorted_pillars[0], sorted_pillars[-1]
    grade_letter, grade_label = _grade(overall)
    grade_color = _score_color(overall)

    # ── Pillar score rows ────────────────────────────────────────────────
    pillar_rows = ""
    for i, (name, score) in enumerate(pillar_scores.items()):
        g, _ = _grade(score)
        c = _score_color(score)
        bg = B["bg_surface"] if i % 2 == 0 else B["bg_card"]
        bar = f'<div style="background:{B["border"]};border-radius:4px;height:6px;width:100%;"><div style="width:{score}%;background:linear-gradient(90deg,{B["purple"]},{c});height:6px;border-radius:4px;"></div></div>'
        pillar_rows += f'<tr style="background:{bg};"><td style="padding:10px 16px;color:{B["white"]};font-weight:600;">{name}</td><td style="padding:10px 16px;width:200px;">{bar}</td><td style="padding:10px 16px;text-align:center;font-weight:700;color:{c};">{score}%</td><td style="padding:10px 16px;text-align:center;color:{c};font-weight:700;">{g}</td></tr>'

    # ── Pillar 1: JS Rendering ───────────────────────────────────────────
    js_sec = _pillar_header(1, "JavaScript Rendering", pillar_scores.get("JS Rendering", 0))
    js_sec += _pill("PAGE-LEVEL", B["primary"])
    js_sec += f'<span style="color:{B["text_secondary"]};font-size:12px;"> Checked on each of your {len(js_results)} pages</span>'
    for test_url, js_r in js_results.items():
        lbl = url_labels.get(test_url, test_url)
        if js_r.get("error"):
            js_sec += _card(f'<span style="color:{B["danger"]};">{lbl}: ERROR — {js_r["error"]}</span>'); continue
        score = js_r.get("score", 0)
        js_sec += _page_block(lbl, score)
        comp = js_r.get("comparison")
        if comp:
            js_sec += f'<div style="font-weight:700;color:{B["white"]};font-size:14px;margin:12px 0 6px 0;">HTML vs JavaScript — What AI Crawlers Miss:</div>'
            js_sec += f'<table style="width:100%;border-collapse:collapse;font-size:13px;"><tr style="background:{B["bg_surface"]};"><th style="padding:7px 10px;text-align:left;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;letter-spacing:1px;">Content</th><th style="padding:7px 10px;text-align:center;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;">HTML (Crawler)</th><th style="padding:7px 10px;text-align:center;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;">JS (Browser)</th><th style="padding:7px 10px;text-align:left;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;">Impact</th></tr>'
            for c in comp["comparison"]:
                if not c.get("name"):
                    continue
                if c["status"] == "missing":
                    bg = f"{B['danger']}15"; sc = B["danger"]; label = "MISSING"
                elif c["status"] == "warn":
                    bg = f"{B['warning']}10"; sc = B["warning"]; label = "MINOR GAP"
                else:
                    bg = "transparent"; sc = B["teal"]; label = "OK"
                impact = f'<span style="color:{sc};font-weight:600;">{label}</span>'
                js_sec += f'<tr style="background:{bg};border-bottom:1px solid {B["border"]};"><td style="padding:5px 10px;color:{B["white"]};">{c["name"]}</td><td style="padding:5px 10px;text-align:center;color:{sc};">{c["html_val"]}</td><td style="padding:5px 10px;text-align:center;color:{B["teal"]};">{c["js_val"]}</td><td style="padding:5px 10px;">{impact}</td></tr>'
            js_sec += '</table>'
            html_t = comp["html_summary"]["text_content_length"]
            js_t   = comp["js_summary"]["text_content_length"]
            if js_t > html_t:
                pct = round(html_t / max(js_t, 1) * 100)
                pct_c = B["danger"] if pct < 30 else B["warning"] if pct < 70 else B["teal"]
                js_sec += _card(f'<div style="font-size:10px;color:{B["text_secondary"]};text-transform:uppercase;letter-spacing:1px;">Content Visibility</div><div style="font-size:22px;font-weight:800;color:{pct_c};">{pct}% <span style="font-size:13px;opacity:0.5;">of content visible to AI</span></div><div style="font-size:12px;color:{B["text_secondary"]};">HTML: {html_t:,} chars · JS-rendered: {js_t:,} chars · Hidden: {js_t-html_t:,} chars</div>')
        if js_r.get("frameworks"):
            for name2, sev, note in js_r["frameworks"]:
                js_sec += _status(f"<strong>{name2}</strong> ({sev}) — {note}", "danger" if sev == "high" else "warning")
        if not comp and js_r.get("risk_factors"):
            for rf in js_r["risk_factors"]:
                js_sec += _status(rf, "warning")

    # ── Pillar 2: Robots & Crawlability ─────────────────────────────────
    rob_sec = _pillar_header(2, "Robots.txt &amp; Crawler Access", pillar_scores.get("Robots & Crawl", 0))
    rob_sec += _pill("SITE-LEVEL", B["purple"])
    rob_sec += f'<span style="color:{B["text_secondary"]};font-size:12px;"> Checked once — controls all crawler access</span><br><br>'
    if robots_result.get("found"):
        rob_sec += _status("robots.txt found", "success")
        ai_res = robots_result.get("ai_agent_results", robots_result.get("ai_results", {}))
        rob_sec += f'<div style="font-weight:600;color:{B["white"]};margin:12px 0 6px 0;">AI Agent Access:</div>'
        for bn, info in ai_res.items():
            av = info.get("robots_allowed", info.get("allowed"))
            rob_sec += _status(f"<strong>{bn}</strong>: {'Allowed' if av is True else 'BLOCKED' if av is False else 'Unknown'}", "success" if av is True else "danger" if av is False else "warning")
        if robots_result.get("sitemaps"):
            rob_sec += f'<div style="font-weight:600;color:{B["white"]};margin:12px 0 6px 0;">Sitemaps ({len(robots_result["sitemaps"])}):</div>'
            for sm in robots_result["sitemaps"]:
                rob_sec += _status(sm, "success")
        if robots_result.get("blocked_resources"):
            rob_sec += _status(f"CSS/JS blocked: {', '.join(robots_result['blocked_resources'])}", "danger")
        else:
            rob_sec += _status("CSS/JS not blocked — AI agents can render pages", "success")
        exposed = [(p, r) for p, r in robots_result.get("sensitive_paths", {}).items() if not r.get("blocked", not r.get("accessible_per_robots", False))]
        if exposed:
            rob_sec += f'<div style="font-weight:600;color:{B["danger"]};margin:12px 0 6px 0;">Sensitive Paths Exposed ({len(exposed)}):</div>'
            for path, _ in exposed:
                rob_sec += _status(path, "warning")
    else:
        rob_sec += _status("No robots.txt found", "danger")

    # ── Pillar 3: Schema & Entity ────────────────────────────────────────
    schema_sec = _pillar_header(3, "Schema &amp; Entity", pillar_scores.get("Schema & Entity", 0))
    schema_sec += _pill("PAGE-LEVEL", B["primary"])
    schema_sec += f'<span style="color:{B["text_secondary"]};font-size:12px;"> Checked on each of your {len(schema_results)} pages</span>'
    for test_url, sr in schema_results.items():
        lbl = url_labels.get(test_url, test_url)
        if sr.get("error"):
            schema_sec += _card(f'<span style="color:{B["danger"]};">{lbl}: ERROR</span>'); continue
        schema_data = sr.get("schema", {})
        schemas = schema_data.get("schemas", [])
        types = schema_data.get("types", [])
        validations = schema_data.get("validations", [])
        grade2 = sr.get("grade", {})
        gl = grade2.get("letter", "?") if isinstance(grade2, dict) else "?"
        sc = sr.get("score", 0)
        schema_sec += _page_block(lbl, sc)
        if types:
            schema_sec += '<div style="margin:6px 0;">' + "".join(_pill(t, B["chart"][i % len(B["chart"])]) for i, t in enumerate(types)) + '</div>'
        ess_found   = schema_data.get("essential_found", [])
        ess_missing = schema_data.get("essential_missing", [])
        if ess_found:
            schema_sec += _status(f"Essential found: {', '.join(ess_found)}", "success")
        if ess_missing:
            schema_sec += _status(f"Essential missing: {', '.join(ess_missing)}", "warning")
        for v in validations:
            comp2 = v.get("completeness", 0)
            st3 = "success" if comp2 >= 80 else "warning" if comp2 >= 50 else "danger"
            schema_sec += _status(f"<strong>{v.get('type','?')}</strong>: {comp2}% complete" + (f" — Missing: {', '.join(v['missing'])}" if v.get('missing') else ""), st3)
        meta_data = sr.get("meta", {})
        if meta_data:
            title = meta_data.get("title", "")
            desc_len = meta_data.get("desc_len", 0)
            schema_sec += _status(f"Title ({len(title)} chars): {title[:80]}", "success" if title else "danger")
            schema_sec += _status(f"Meta description: {desc_len} chars", "success" if 100 <= desc_len <= 160 else "warning")
            canon = meta_data.get("canonical", "")
            schema_sec += _status(f"Canonical: {canon[:80] or 'Missing'}", "success" if canon else "warning")
        if not schemas:
            schema_sec += _status("No Schema.org structured data found", "warning")

    # ── Pillar 4: AI Discoverability ─────────────────────────────────────
    llm_sec = _pillar_header(4, "AI Discoverability", pillar_scores.get("AI Discoverability", 0))
    llm_sec += _pill("SITE-LEVEL", B["purple"])
    llm_sec += f'<span style="color:{B["text_secondary"]};font-size:12px;"> llm.txt files + AI Info Page</span><br><br>'
    llm_txt_data = llm_result.get("llm_txt", llm_result.get("files", {}))
    llm_sec += f'<div style="font-weight:600;color:{B["white"]};margin:8px 0 6px 0;">llm.txt Files:</div>'
    for path, info in llm_txt_data.items():
        llm_sec += _status(f"{path}: {'Found' if info.get('found') else 'Not found'}", "success" if info.get("found") else "warning")
    ai_info = llm_result.get("ai_info_page", {})
    llm_sec += f'<div style="font-weight:600;color:{B["white"]};margin:12px 0 6px 0;">AI Info Page:</div>'
    if ai_info.get("found"):
        llm_sec += _status(f"Found: {ai_info.get('url','')}", "success")
        llm_sec += _status(f"Linked from footer: {'Yes' if ai_info.get('linked_from_footer') else 'No'}", "success" if ai_info.get("linked_from_footer") else "danger")
        if "indexable" in ai_info:
            llm_sec += _status(f"Indexable: {'Yes' if ai_info['indexable'] else 'No — has noindex'}", "success" if ai_info.get("indexable") else "danger")
    else:
        llm_sec += _status("No AI Info Page found at /ai-info or similar", "warning")
    wellknown = llm_result.get("wellknown", {})
    if wellknown:
        llm_sec += f'<div style="font-weight:600;color:{B["white"]};margin:12px 0 6px 0;">AI Policy Files (/.well-known/):</div>'
        for path, info in wellknown.items():
            llm_sec += _status(path, "success" if info.get("found") else "info")

    # ── Semantic Hierarchy ───────────────────────────────────────────────
    sem_sec = _section_header("Semantic Hierarchy &amp; Content Structure", "PAGE-LEVEL")
    for test_url, sem_r in semantic_results.items():
        lbl = url_labels.get(test_url, test_url)
        if sem_r.get("error"):
            sem_sec += _card(f'<span style="color:{B["danger"]};">{lbl}: ERROR</span>'); continue
        sem_sec += _page_block(lbl)
        hier_ok = sem_r.get("hierarchy_ok", True)
        sem_sec += _status(f"Heading hierarchy: {'Valid — no skipped levels' if hier_ok else 'Issues — skipped levels detected'}", "success" if hier_ok else "warning")
        sem_elems = sem_r.get("semantic_elements", {})
        if sem_elems:
            for tag, count in sem_elems.items():
                sem_sec += _status(f"&lt;{tag}&gt;: {count}", "success")
        else:
            sem_sec += _status("No semantic HTML5 elements found", "warning")
        meta_tags = sem_r.get("meta_tags", [])
        for tag in meta_tags:
            sem_sec += _status(f'{tag["name"]}: {tag["content"]}', "info")
        nosnip = sem_r.get("nosnippet_elements", 0)
        sem_sec += _status(f"data-nosnippet: {nosnip} element(s)", "info")
        html_len = sem_r.get("html_length", 0)
        text_len = sem_r.get("text_length", 0)
        if html_len > 0:
            ratio = text_len / html_len * 100
            sem_sec += _status(f"Text-to-HTML ratio: {ratio:.1f}%", "success" if ratio >= 15 else "warning")

    # ── Live Bot Crawl ───────────────────────────────────────────────────
    bot_sec = ""
    if bot_crawl_results:
        bot_sec = _section_header("Live Bot Crawl Results", "SITE-LEVEL")
        allowed_n = sum(1 for r in bot_crawl_results.values() if r.get("is_allowed"))
        total_n = len(bot_crawl_results)
        bot_sec += f'<div style="font-size:14px;color:{B["text_secondary"]};margin-bottom:12px;"><span style="color:{B["teal"]};font-weight:700;">{allowed_n}</span> allowed · <span style="color:{B["danger"]};font-weight:700;">{total_n - allowed_n}</span> blocked · {total_n} total</div>'
        for company in list(dict.fromkeys(r["company"] for r in bot_crawl_results.values())):
            cr = {k: v for k, v in bot_crawl_results.items() if v["company"] == company}
            ca = sum(1 for r in cr.values() if r.get("is_allowed"))
            bot_sec += f'<div style="font-weight:600;color:{B["white"]};margin:12px 0 4px 0;">{company} — {ca}/{len(cr)} allowed</div>'
            for bn, r in cr.items():
                if r.get("error"):
                    bot_sec += _status(f"<strong>{bn}</strong>: Error — {r['error']}", "danger")
                else:
                    bot_sec += _status(f"<strong>{bn}</strong>: {'Allowed' if r['is_allowed'] else 'BLOCKED'} — HTTP {r['status_code']} · {r['content_length']:,} chars · {r['load_time']}s", "success" if r["is_allowed"] else "danger")

    # ── Recommendations ──────────────────────────────────────────────────
    rec_sec = f'<div style="margin-top:36px;font-size:22px;font-weight:800;color:{B["white"]};margin-bottom:4px;">Priority Recommendations</div><div style="height:1px;background:linear-gradient(90deg,{B["purple"]},{B["primary"]},transparent);margin-bottom:16px;"></div>'
    for i, (status, pillar, text) in enumerate(recs, 1):
        c = B["danger"] if status == "danger" else B["warning"]
        pill = _pill(pillar, c)
        rec_sec += f'<div style="background:{B["bg_card"]};border:1px solid {B["border"]};border-left:3px solid {c};border-radius:0 10px 10px 0;padding:14px 18px;margin:8px 0;">{pill}<div style="color:{B["white"]};font-size:14px;margin-top:6px;">{text}</div></div>'

    # ── Logo SVG (inline for offline use) ────────────────────────────────
    logo_svg = PATTERN_LOGO_SVG.replace("width=\"180\"", "width=\"140\"").replace("height=\"36\"", "height=\"28\"")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Pattern LLM Access Audit — {domain}</title>
<style>
  @media print {{ body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} .no-print {{ display:none; }} }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:{B["bg_dark"]}; color:{B["white"]}; margin:0; padding:32px 40px; line-height:1.6; font-size:14px; }}
  h1, h2, h3 {{ margin-top:0; color:{B["white"]}; }}
  table {{ border-collapse:collapse; width:100%; }}
  a {{ color:{B["primary"]}; }}
  @page {{ margin:15mm; size:A4; }}
</style>
</head>
<body>

<!-- ── HEADER ── -->
<div style="text-align:center;padding:24px 0 20px;border-bottom:3px solid transparent;border-image:linear-gradient(90deg,{B["purple"]},{B["primary"]}) 1;margin-bottom:28px;">
  <div style="margin-bottom:10px;">{logo_svg}</div>
  <div style="font-size:11px;text-transform:uppercase;letter-spacing:3px;color:{B["text_secondary"]};margin-bottom:4px;">Full LLM Access Audit</div>
  <div style="color:{B["text_secondary"]};font-size:13px;margin-top:4px;">{domain} &nbsp;·&nbsp; Generated {time.strftime("%Y-%m-%d %H:%M UTC")}</div>
</div>

<!-- ── OVERALL SCORE ── -->
<div style="display:flex;gap:20px;margin-bottom:28px;align-items:flex-start;flex-wrap:wrap;">
  <div style="background:{B["bg_card"]};border:1px solid {B["border"]};border-radius:14px;padding:24px 32px;text-align:center;min-width:160px;">
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{B["text_secondary"]};margin-bottom:6px;">LLM Access Audit</div>
    <div style="font-size:52px;font-weight:800;color:{grade_color};line-height:1;">{overall}%</div>
    <div style="font-size:13px;color:{B["text_secondary"]};margin:4px 0;">Overall AI Readiness</div>
    <div style="font-size:16px;font-weight:700;color:{grade_color};">{grade_letter} — {grade_label}</div>
  </div>
  <div style="flex:1;min-width:280px;">
    <table style="width:100%;border-radius:10px;overflow:hidden;">
      <tr style="background:{B["bg_surface"]};">
        <th style="padding:8px 14px;text-align:left;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;letter-spacing:1px;">Pillar</th>
        <th style="padding:8px 14px;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;letter-spacing:1px;width:160px;">Score Bar</th>
        <th style="padding:8px 14px;text-align:center;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;letter-spacing:1px;width:60px;">%</th>
        <th style="padding:8px 14px;text-align:center;color:{B["text_secondary"]};font-size:11px;text-transform:uppercase;letter-spacing:1px;width:50px;">Grade</th>
      </tr>
      {pillar_rows}
    </table>
    <div style="margin-top:10px;font-size:13px;">
      <span style="color:{B["teal"]};font-weight:600;">▲ Strongest: {strongest[0]} ({strongest[1]}%)</span>
      &nbsp;·&nbsp;
      <span style="color:{B["danger"]};font-weight:600;">▼ Priority Focus: {weakest[0]} ({weakest[1]}%)</span>
    </div>
  </div>
</div>

{js_sec}
{rob_sec}
{schema_sec}
{llm_sec}
{sem_sec}
{bot_sec}
{rec_sec}

<!-- ── FOOTER ── -->
<div style="text-align:center;margin-top:48px;padding-top:16px;border-top:1px solid {B["border"]};color:{B["text_secondary"]};font-size:12px;">
  {logo_svg}
  <div style="margin-top:8px;">Pattern LLM Access Checker &nbsp;·&nbsp; Full LLM Access Audit &nbsp;·&nbsp; pattern.com</div>
</div>

</body>
</html>"""
    return html

def generate_report_text(domain, overall, pillar_scores, url_labels, js_results, llm_result, robots_result, schema_results, bot_crawl_results, recs):
    """Generate a plain-text audit report for PDF/download."""
    lines = []
    lines.append("=" * 70)
    lines.append("PATTERN — LLM ACCESS CHECKER")
    lines.append(f"Full LLM Access Audit Report for {domain}")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("=" * 70)
    lines.append("")

    # Overall score
    lines.append(f"OVERALL LLM READINESS SCORE: {overall}%")
    lines.append("-" * 40)
    for name, sc in pillar_scores.items():
        bar = "█" * (sc // 5) + "░" * (20 - sc // 5)
        lines.append(f"  {name:<25} {bar} {sc}%")
    lines.append("")

    # Strongest / Weakest
    sorted_pillars = sorted(pillar_scores.items(), key=lambda x: x[1])
    lines.append(f"STRONGEST PILLAR: {sorted_pillars[-1][0]} ({sorted_pillars[-1][1]}%)")
    lines.append(f"WEAKEST PILLAR:   {sorted_pillars[0][0]} ({sorted_pillars[0][1]}%)")
    lines.append("")

    # Per-page scores
    lines.append("PER-PAGE RESULTS")
    lines.append("-" * 70)
    for test_url, label in url_labels.items():
        js_s = js_results.get(test_url, {}).get("score", "—")
        sc_s = schema_results.get(test_url, {}).get("score", "—")
        lines.append(f"  {label:<20} JS: {js_s:<5} Schema: {sc_s:<5} {test_url}")
    lines.append("")

    # Pillar 1: JS Rendering
    lines.append("PILLAR 1 — JAVASCRIPT RENDERING [PAGE-LEVEL]")
    lines.append("-" * 40)
    for test_url, js_r in js_results.items():
        label = url_labels.get(test_url, test_url)
        if js_r.get("error"):
            lines.append(f"  {label}: ERROR — {js_r['error']}")
            continue
        lines.append(f"  {label}: {js_r['score']}/100")
        comp = js_r.get("comparison")
        if comp:
            lines.append(f"    Rendered via: {js_r.get('js_provider', 'N/A')}")
            lines.append(f"    {'Content':<25} {'HTML':>8} {'JS':>8} {'Status':>10}")
            lines.append(f"    {'-'*55}")
            for c in comp["comparison"]:
                st_text = "MISSING" if c["status"] == "missing" else "MINOR GAP" if c["status"] == "warn" else "OK"
                lines.append(f"    {c['name']:<25} {str(c['html_val']):>8} {str(c['js_val']):>8} {st_text:>10}")
            html_text = comp["html_summary"]["text_content_length"]
            js_text = comp["js_summary"]["text_content_length"]
            if js_text > html_text:
                pct = round(html_text / max(js_text, 1) * 100)
                lines.append(f"    Content visibility: {pct}% ({html_text:,} / {js_text:,} chars)")
        elif js_r["risk_factors"]:
            for rf in js_r["risk_factors"]:
                lines.append(f"    ⚠ {rf}")
    lines.append("")

    # Pillar 2: LLM.txt
    lines.append("PILLAR 2 — LLM.TXT [SITE-LEVEL]")
    lines.append("-" * 40)
    for path, info in llm_result.get("llm_txt", llm_result.get("files", {})).items():
        status = "✓ Found" if info["found"] else "✗ Not found"
        lines.append(f"  {path}: {status}")
    lines.append("")

    # Pillar 3: Robots.txt
    lines.append("PILLAR 3 — ROBOTS.TXT & CRAWLER ACCESS [SITE-LEVEL]")
    lines.append("-" * 40)
    if robots_result["found"]:
        lines.append(f"  robots.txt: Found")
        lines.append(f"  Sitemaps: {len(robots_result['sitemaps'])}")
        lines.append(f"  Blocked resources: {', '.join(robots_result['blocked_resources']) or 'None'}")
        exposed = sum(1 for p, r in robots_result["sensitive_paths"].items() if not r.get("blocked", not r.get("accessible_per_robots", False)))
        lines.append(f"  Sensitive paths exposed: {exposed}/{len(robots_result['sensitive_paths'])}")
        lines.append("  AI Agent Access:")
        for bn, info in robots_result.get("ai_agent_results", robots_result.get("ai_results", {})).items():
            allowed_val = info.get("robots_allowed", info.get("allowed"))
            status = "Allowed" if allowed_val is True else "Blocked" if allowed_val is False else "Unknown"
            lines.append(f"    {bn}: {status}")
    else:
        lines.append("  robots.txt: NOT FOUND")
    lines.append("")

    # Pillar 4: Schema
    lines.append("PILLAR 4 — SCHEMA / STRUCTURED DATA [PAGE-LEVEL]")
    lines.append("-" * 40)
    for test_url, sr in schema_results.items():
        label = url_labels.get(test_url, test_url)
        if sr.get("error"):
            lines.append(f"  {label}: ERROR")
            continue
        schema_data = sr.get("schema", {})
        schemas = schema_data.get("schemas", [])
        types = schema_data.get("types", [])
        validations = schema_data.get("validations", [])
        grade = sr.get("grade", {})
        grade_letter = grade.get("letter", "?") if isinstance(grade, dict) else "?"
        lines.append(f"  {label}: {sr.get('score', 0)}/100 ({grade_letter}) — {len(schemas)} schema item(s)")
        if types:
            lines.append(f"    Types: {', '.join(types)}")
        for v in validations:
            if v.get("missing"):
                lines.append(f"    {v.get('type','?')}: {v.get('completeness',0)}% — Missing: {', '.join(v['missing'])}")
    lines.append("")

    # Bot crawl
    if bot_crawl_results:
        lines.append("LIVE BOT CRAWL RESULTS")
        lines.append("-" * 40)
        for bn, r in bot_crawl_results.items():
            if r["error"]:
                lines.append(f"  {bn}: ERROR — {r['error']}")
            else:
                status = "Allowed" if r["is_allowed"] else "BLOCKED"
                lines.append(f"  {bn} ({r['company']}): {status} — HTTP {r['status_code']} — {r['content_length']:,} chars — {r['load_time']}s")
        lines.append("")

    # Recommendations
    lines.append("PRIORITY RECOMMENDATIONS")
    lines.append("-" * 40)
    for i, (status, pillar, text) in enumerate(recs, 1):
        icon = "🔴" if status == "danger" else "🟡"
        lines.append(f"  {i}. [{pillar}] {text}")
    lines.append("")

    lines.append("=" * 70)
    lines.append("Report generated by Pattern LLM Access Checker")
    lines.append("https://pattern.com")
    lines.append("=" * 70)

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI — PATTERN BRANDED
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown(f"""
<style>
    .stApp {{ background-color: {BRAND['bg_dark']}; }}
    .stApp > header {{ background-color: {BRAND['bg_dark']}; }}
    .stApp, .stApp p, .stApp span, .stApp li, .stApp div {{ color: {BRAND['white']}; }}
    h1, h2, h3, h4 {{ color: {BRAND['white']} !important; }}
    .stCaption, .stCaption p {{ color: {BRAND['text_secondary']} !important; }}
    div[data-testid="stExpander"] {{ background: {BRAND['bg_card']}; border: 1px solid {BRAND['border']}; border-radius: 12px; margin-bottom: 0.5rem; }}
    div[data-testid="stExpander"] details {{ border: none !important; }}
    div[data-testid="stExpander"] summary {{ color: {BRAND['white']}; }}
    div[data-testid="stExpander"] summary:hover {{ color: {BRAND['primary']}; }}
    div[data-testid="stMetric"] {{ background: {BRAND['bg_surface']}; border: 1px solid {BRAND['border']}; border-radius: 10px; padding: 12px 16px; }}
    div[data-testid="stMetric"] label {{ color: {BRAND['text_secondary']} !important; }}
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {{ color: {BRAND['white']} !important; }}
    .stButton > button[kind="primary"], button[data-testid="stBaseButton-primary"] {{ background: linear-gradient(135deg, {BRAND['purple']}, {BRAND['primary']}) !important; color: {BRAND['white']} !important; border: none !important; border-radius: 8px !important; font-weight: 600 !important; }}
    .stTextInput > div > div > input {{ background: {BRAND['bg_surface']} !important; border: 1px solid {BRAND['border']} !important; color: {BRAND['white']} !important; border-radius: 8px !important; }}
    .stTextInput > div > div > input:focus {{ border-color: {BRAND['primary']} !important; }}
    .stTextArea > div > div > textarea {{ background: {BRAND['bg_surface']} !important; border: 1px solid {BRAND['border']} !important; color: {BRAND['white']} !important; border-radius: 8px !important; }}
    .stProgress > div > div > div {{ background: linear-gradient(90deg, {BRAND['purple']}, {BRAND['primary']}) !important; }}
    .stAlert {{ background: {BRAND['bg_surface']} !important; border: 1px solid {BRAND['border']} !important; border-radius: 10px !important; }}
    hr {{ border-color: {BRAND['border']} !important; }}
    .section-divider {{ border-top: 1px solid {BRAND['border']}; margin: 2rem 0 1.5rem 0; }}
    .p-score-card {{ background: {BRAND['bg_card']}; border: 1px solid {BRAND['border']}; border-radius: 14px; padding: 1.2rem 0.8rem; text-align: center; }}
    .p-score-num {{ font-size: 2rem; font-weight: 800; line-height: 1.1; color: {BRAND['white']}; }}
    .p-score-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.5px; color: {BRAND['text_secondary']}; margin-top: 6px; }}
</style>
""", unsafe_allow_html=True)


# ── HEADER (Pattern logo + LLM Access Checker) ───────────────────────────────
st.markdown(f'<div style="text-align:center;padding:1.5rem 0 0.3rem 0;">{PATTERN_LOGO_SVG}</div>', unsafe_allow_html=True)
st.markdown(f'<div style="text-align:center;padding:0.3rem 0;"><span style="font-size:1.4rem;font-weight:700;color:{BRAND["white"]};">LLM Access Checker</span></div>', unsafe_allow_html=True)
st.markdown(f'<div style="text-align:center;color:{BRAND["text_secondary"]};font-size:0.9rem;margin-bottom:1.5rem;">Full LLM Access Audit · JavaScript Rendering · LLM.txt · Robots.txt · Schema</div>', unsafe_allow_html=True)

# ── SHARED LINK: load audit from ?audit=<id> query param ─────────────────────
_qp_audit_id = st.query_params.get("audit")
if _qp_audit_id and "_audit" not in st.session_state:
    _qp_row = load_audit_by_id(_qp_audit_id)
    if _qp_row and _qp_row.get("full_results"):
        _fr = _qp_row["full_results"]
        st.session_state["_audit"] = _fr
        _d = _qp_row.get("domain", "?")
        _dt = (_qp_row.get("audited_at") or "")[:10]
        _sc = _qp_row.get("overall_score", 0)
        st.session_state["_loaded_from_history"] = f"{_d} · {_dt} · {_sc}%"

tab_audit, tab_history = st.tabs(["\U0001f50d  New Audit", "\U0001f4cb  Past Audits"])
with tab_audit:
    # ── INPUT: Mandatory URL structure ────────────────────────────────────────────
    st.markdown(f'<div style="font-weight:600;color:{BRAND["white"]};margin-bottom:8px;">Enter the URLs to audit (minimum 7 pages required)</div>', unsafe_allow_html=True)

    col_home, _ = st.columns([3, 1])
    with col_home:
        home_url = st.text_input("Homepage URL", placeholder="https://example.com", key="home")

    col_cat, col_blog, col_prod = st.columns(3)
    with col_cat:
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:4px;">Category / Collection Pages (2 required)</div>', unsafe_allow_html=True)
        cat_url_1 = st.text_input("Category Page 1", placeholder="https://example.com/collections/all", key="cat1", label_visibility="collapsed")
        cat_url_2 = st.text_input("Category Page 2", placeholder="https://example.com/collections/shoes", key="cat2", label_visibility="collapsed")

    with col_blog:
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:4px;">Blog / Content Pages (2 required)</div>', unsafe_allow_html=True)
        blog_url_1 = st.text_input("Blog Page 1", placeholder="https://example.com/blog/post-1", key="blog1", label_visibility="collapsed")
        blog_url_2 = st.text_input("Blog Page 2", placeholder="https://example.com/blog/post-2", key="blog2", label_visibility="collapsed")

    with col_prod:
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};margin-bottom:4px;">Product Pages (2 required)</div>', unsafe_allow_html=True)
        prod_url_1 = st.text_input("Product Page 1", placeholder="https://example.com/products/item-1", key="prod1", label_visibility="collapsed")
        prod_url_2 = st.text_input("Product Page 2", placeholder="https://example.com/products/item-2", key="prod2", label_visibility="collapsed")

    with st.expander("⚙️  Advanced Options"):
        run_bot_crawl = st.checkbox("Run live bot crawl test (sends requests as each AI bot)", value=True)

    run_audit = st.button("Run Audit", type="primary", use_container_width=True)

    # Collect and validate URLs
    all_url_inputs = {
        "Homepage": home_url,
        "Category 1": cat_url_1, "Category 2": cat_url_2,
        "Blog 1": blog_url_1, "Blog 2": blog_url_2,
        "Product 1": prod_url_1, "Product 2": prod_url_2,
    }

with tab_history:
    _hist_all = load_audit_history(limit=50)
    st.markdown(f'<div style="font-size:22px;font-weight:800;color:{BRAND["white"]};margin-bottom:4px;">Past Audits</div><div style="height:2px;background:linear-gradient(90deg,{BRAND["purple"]},{BRAND["primary"]},transparent);margin-bottom:20px;"></div>', unsafe_allow_html=True)

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

        # ── Load Report buttons ─────────────────────────────────────────────
        st.markdown(f'<div style="margin-top:16px;color:{BRAND["text_secondary"]};font-size:12px;margin-bottom:6px;">Load or share a full report:</div>', unsafe_allow_html=True)
        for _row in _rows:
            _fr = _row.get("full_results")
            _dom  = _row.get("domain", "—")
            _date = (_row.get("audited_at") or "")[:10]
            _sc   = _row.get("overall_score", 0)
            _label = f"{_dom} · {_date} · {_sc}%"
            _has_full = _fr is not None and isinstance(_fr, dict) and "js_results" in _fr
            _audit_id = _row.get("id")
            _btn_col, _share_col, _del_col, _info_col = st.columns([3, 1, 1, 4])
            with _btn_col:
                if st.button(f"📋 {_label}", key=f"load_{_audit_id or _label}", disabled=not _has_full, use_container_width=True):
                    st.session_state["_audit"] = _fr
                    st.session_state["_loaded_from_history"] = _label
                    if _audit_id:
                        st.query_params["audit"] = str(_audit_id)
                    st.rerun()
            with _share_col:
                if _audit_id and _has_full:
                    if st.button("🔗", key=f"share_{_audit_id}", help="Set shareable link in address bar"):
                        st.query_params["audit"] = str(_audit_id)
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


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

if run_audit or "_audit" in st.session_state:
    if run_audit:
        st.session_state.pop("_audit", None)
        # Validate all 7 URLs are provided
        missing = [name for name, u in all_url_inputs.items() if not u or not u.strip()]
        if missing:
            st.error(f"Please provide all required URLs. Missing: {', '.join(missing)}")
            st.stop()

        all_test_urls = [normalise_url(u.strip()) for u in all_url_inputs.values() if u and u.strip()]
        url = all_test_urls[0]  # homepage
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # URL labels for display
        url_labels = {}
        for name, u in all_url_inputs.items():
            if u and u.strip():
                url_labels[normalise_url(u.strip())] = name

        # ── ESTIMATED TIME BREAKDOWN ──────────────────────────────────────────
        n_pages = len(all_test_urls)
        has_js_api = any(get_secret(k, "") for k in ["SCRAPINGBEE_API_KEY", "SCRAPFLY_API_KEY", "BROWSERLESS_API_KEY"])
        has_bifrost = bool(get_secret("BIFROST_API_KEY", ""))

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

        # ── PILLAR 1: JS RENDERING (all pages) ────────────────────────────────
        progress.progress(3, text=f"[1/6] JS Rendering — checking {n_pages} pages… (est. {js_label.split('(')[0].strip()})")
        js_results = {}
        for i, test_url in enumerate(all_test_urls):
            elapsed = round(time.time() - audit_start)
            label = url_labels.get(test_url, test_url)
            progress.progress(3 + round(14 * (i / n_pages)),
                text=f"[1/6] JS Rendering — {label} ({i+1}/{n_pages}) · {elapsed}s elapsed")
            js_results[test_url] = check_js_rendering(test_url, get_secret)
        js_score = round(sum(r.get("score", 0) for r in js_results.values()) / len(js_results))

        # ── PILLAR 2: ROBOTS & CRAWLABILITY (site-level) ──────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(18, text=f"[2/6] Robots & Crawlability — fetching robots.txt + Cloudflare check… · {elapsed}s elapsed")
        homepage_resp, _ = fetch(url)
        homepage_html = homepage_resp.text if homepage_resp else ""
        progress.progress(20, text=f"[2/6] Robots & Crawlability — running 16 live bot crawl tests… · {elapsed}s elapsed")
        robots_result = check_robots_crawlability(base_url, homepage_html)
        robots_score = robots_result.get("score", 0)

        # ── PILLAR 3: SCHEMA & ENTITY (all pages) ─────────────────────────────
        schema_results = {}
        for i, test_url in enumerate(all_test_urls):
            elapsed = round(time.time() - audit_start)
            label = url_labels.get(test_url, test_url)
            progress.progress(38 + round(14 * (i / n_pages)),
                text=f"[3/6] Schema & Entity — {label} ({i+1}/{n_pages}) · {elapsed}s elapsed")
            schema_results[test_url] = check_schema_meta(test_url)
        schema_score = round(sum(r.get("score", 0) for r in schema_results.values()) / len(schema_results))

        # ── PILLAR 4: AI DISCOVERABILITY (site-level) ──────────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(55, text=f"[4/7] AI Discoverability — llm.txt, AI info page, well-known files… · {elapsed}s elapsed")
        llm_result = check_llm_discoverability(base_url, homepage_html)
        llm_score = llm_result.get("score", 0)

        # ── SEMANTIC HIERARCHY (all pages) ────────────────────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(62, text=f"[5/7] Semantic Hierarchy — checking heading structure… · {elapsed}s elapsed")
        semantic_results = {}
        for test_url in all_test_urls:
            semantic_results[test_url] = check_semantic_hierarchy(test_url)

        # ── SECURITY CHECK (separate score) ───────────────────────────────────
        elapsed = round(time.time() - audit_start)
        progress.progress(67, text=f"[6/7] Security Check — probing sensitive paths as AI bots… · {elapsed}s elapsed (this step takes ~{t_security}s)")
        security_result = check_security_exposure(
            base_url,
            robots_raw=robots_result.get("raw", ""),
            homepage_html=homepage_html,
        )
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
        }

    # ── Unpack results (fresh audit or cached) ────────────────────────────
    _a              = st.session_state["_audit"]
    all_test_urls   = _a["all_test_urls"]
    url_labels      = _a["url_labels"]
    js_results      = _a["js_results"]
    js_score        = _a["js_score"]
    robots_result   = _a["robots_result"]
    robots_score    = _a["robots_score"]
    schema_results  = _a["schema_results"]
    schema_score    = _a["schema_score"]
    llm_result      = _a["llm_result"]
    llm_score       = _a["llm_score"]
    semantic_results = _a["semantic_results"]
    security_result = _a["security_result"]
    security_score  = _a["security_score"]
    bot_crawl_results = _a["bot_crawl_results"]
    overall         = _a["overall"]
    overall_grade   = _a["overall_grade"]
    overall_result  = _a["overall_result"]
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

    # ── Save new audit to Supabase (fresh runs only) ──────────────────────
    if run_audit:
        save_audit_to_db(
            domain=parsed.netloc,
            overall=overall,
            pillar_scores_dict={
                "JS Rendering":       js_score,
                "Robots & Crawl":     robots_score,
                "Schema & Entity":    schema_score,
                "AI Discoverability": llm_score,
                "Semantic Hierarchy": semantic_score,
                "Security":           security_score,
            },
            audited_urls=all_test_urls,
            full_results={
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
            },
        )

    with tab_audit:
        # ══════════════════════════════════════════════════════════════════════
        # RESULTS
        # ══════════════════════════════════════════════════════════════════════

        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)

        # ── GAUGE + SCORE CARDS ───────────────────────────────────────────────
        col_gauge, col_pillars = st.columns([1, 2])

        with col_gauge:
            gauge_svg = generate_gauge_svg(overall, label="LLM Readiness Score", size=220)
            st.markdown(f'<div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:{BRAND["text_secondary"]};text-align:center;margin-bottom:8px;">LLM Access Audit</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="text-align:center;">{gauge_svg}</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};text-align:center;margin-top:4px;">{parsed.netloc}</div>', unsafe_allow_html=True)

        with col_pillars:
            overall_grade = overall_result.get("grade", {})
            grade_letter = overall_grade.get("letter", "?") if isinstance(overall_grade, dict) else "?"
            grade_label = overall_grade.get("label", "") if isinstance(overall_grade, dict) else ""

            pillar_items = [
                ("JS Rendering", js_score),
                ("Robots & Crawl", robots_score),
                ("Schema & Entity", schema_score),
                ("AI Discovery", llm_score),
            ]
            p_cols = st.columns(5)
            for i, (label, sc) in enumerate(pillar_items):
                color = BRAND["teal"] if sc >= 75 else BRAND["primary"] if sc >= 50 else BRAND["warning"] if sc >= 35 else BRAND["danger"]
                p_cols[i].markdown(f'<div class="p-score-card"><div class="p-score-num" style="color:{color};font-size:1.6rem;">{sc}<span style="font-size:12px;opacity:0.4;">%</span></div><div class="p-score-label" style="font-size:0.6rem;">{label}</div></div>', unsafe_allow_html=True)
            # Security as separate card
            sec_color = BRAND["teal"] if security_score >= 80 else BRAND["warning"] if security_score >= 50 else BRAND["danger"]
            p_cols[4].markdown(f'<div class="p-score-card" style="border-color:{sec_color}40;"><div class="p-score-num" style="color:{sec_color};font-size:1.6rem;">{security_score}<span style="font-size:12px;opacity:0.4;">%</span></div><div class="p-score-label" style="font-size:0.6rem;">Security</div></div>', unsafe_allow_html=True)

            # Summary row
            st.markdown("")
            sub_cols = st.columns(4)
            with sub_cols[0]:
                st.metric("Pages Tested", len(all_test_urls))
            with sub_cols[1]:
                allowed_bots = sum(1 for r in bot_crawl_results.values() if r.get("is_allowed")) if bot_crawl_results else "—"
                total_bots = len(bot_crawl_results) if bot_crawl_results else "—"
                st.metric("Bot Access", f"{allowed_bots}/{total_bots}")
            with sub_cols[2]:
                exposed_count = sum(1 for p, r in robots_result.get("sensitive_paths", {}).items() if not r.get("blocked", not r.get("accessible_per_robots", False)))
                st.metric("Paths Exposed", exposed_count)
            with sub_cols[3]:
                st.metric("Overall Grade", f"{grade_letter} ({grade_label})")

        # ── STRONGEST / WEAKEST PILLAR ────────────────────────────────────────
        pillar_scores = {
            "JS Rendering":       js_score,
            "Robots & Crawl":     robots_score,
            "Schema & Entity":    schema_score,
            "AI Discoverability": llm_score,
            "Semantic Hierarchy": semantic_score,
            "Security":           security_score,
        }
        sorted_pillars = sorted(pillar_scores.items(), key=lambda x: x[1])
        weakest_name, weakest_sc = sorted_pillars[0]
        strongest_name, strongest_sc = sorted_pillars[-1]
        weak_color = BRAND["danger"] if weakest_sc < 40 else BRAND["warning"]
        strong_color = BRAND["teal"] if strongest_sc >= 70 else BRAND["primary"]

        st.markdown("")
        sw_cols = st.columns(2)
        with sw_cols[0]:
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:14px 18px;border-left:3px solid {strong_color};"><div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;">Strongest Pillar</div><div style="font-size:18px;font-weight:700;color:{strong_color};">{strongest_name} — {strongest_sc}%</div></div>', unsafe_allow_html=True)
        with sw_cols[1]:
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:14px 18px;border-left:3px solid {weak_color};"><div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;">Weakest Pillar — Priority Focus</div><div style="font-size:18px;font-weight:700;color:{weak_color};">{weakest_name} — {weakest_sc}%</div></div>', unsafe_allow_html=True)

        # ── PER-PAGE SUMMARY TABLE ────────────────────────────────────────────
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Per-Page Results")

        for test_url in all_test_urls:
            label = url_labels.get(test_url, test_url)
            js_s = js_results.get(test_url, {}).get("score", "—")
            sc_s = schema_results.get(test_url, {}).get("score", "—")
            js_color = BRAND["teal"] if isinstance(js_s, int) and js_s >= 70 else BRAND["warning"] if isinstance(js_s, int) and js_s >= 40 else BRAND["danger"]
            sc_color = BRAND["teal"] if isinstance(sc_s, int) and sc_s >= 70 else BRAND["warning"] if isinstance(sc_s, int) and sc_s >= 40 else BRAND["danger"]
            st.markdown(f'<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:1px solid {BRAND["border"]};"><div style="color:{BRAND["white"]};font-size:13px;"><strong>{label}</strong> — <span style="color:{BRAND["text_secondary"]};font-size:12px;">{test_url}</span></div><div style="display:flex;gap:16px;"><span style="color:{js_color};font-weight:700;">JS: {js_s}</span><span style="color:{sc_color};font-weight:700;">Schema: {sc_s}</span></div></div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 1: JS RENDERING
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(1, "JavaScript Rendering", js_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("PAGE-LEVEL", BRAND["primary"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked on each of your {len(all_test_urls)} pages</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(js_score), unsafe_allow_html=True)
        pillar_explainer("js_rendering")

        for test_url, js_r in js_results.items():
            label = url_labels.get(test_url, test_url)
            if js_r.get("error"):
                st.error(f"Could not fetch {label}: {js_r['error']}")
                continue

            comp = js_r.get("comparison")
            provider = js_r.get("js_provider")
            js_err = js_r.get("js_error")

            with st.expander(f"{label} — Score: {js_r['score']}/100" + (f" (via {provider})" if provider else "")):

                # Frameworks detected
                if js_r["frameworks"]:
                    st.markdown("**JS Frameworks Detected:**")
                    for name, severity, note in js_r["frameworks"]:
                        st.markdown(brand_status(f"**{name}** ({severity}) — {note}", "danger" if severity == "high" else "warning"), unsafe_allow_html=True)

                # === COMPARISON TABLE (if JS rendering API was available) ===
                if comp:
                    st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:12px 0 8px 0;">HTML vs JavaScript — What AI Crawlers Miss:</div>', unsafe_allow_html=True)

                    # Table header
                    st.markdown(f'<div style="display:flex;padding:8px 12px;background:{BRAND["bg_surface"]};border-radius:8px 8px 0 0;font-weight:600;font-size:12px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;"><div style="flex:2;">Content</div><div style="flex:1;text-align:center;">HTML (Crawler)</div><div style="flex:1;text-align:center;">JS (Browser)</div><div style="flex:2;">Impact</div></div>', unsafe_allow_html=True)

                    for c in comp["comparison"]:
                        # Guard against pre-fix rows where strings were stored as null
                        if not c.get("name"):
                            continue
                        html_v = str(c["html_val"])
                        js_v = str(c["js_val"])
                        if c["status"] == "missing":
                            row_bg = f"{BRAND['danger']}15"
                            impact_html = f'<span style="color:{BRAND["danger"]};font-size:12px;">{c["impact"]}</span>'
                            html_color = BRAND["danger"]
                            js_color = BRAND["teal"]
                        elif c["status"] == "warn":
                            row_bg = f"{BRAND['warning']}10"
                            impact_html = f'<span style="color:{BRAND["warning"]};font-size:12px;">Minor JS dependency (&lt;10% gap)</span>'
                            html_color = BRAND["warning"]
                            js_color = BRAND["teal"]
                        else:
                            row_bg = "transparent"
                            impact_html = f'<span style="color:{BRAND["teal"]};font-size:12px;">OK</span>'
                            html_color = BRAND["teal"]
                            js_color = BRAND["teal"]

                        st.markdown(f'<div style="display:flex;padding:6px 12px;border-bottom:1px solid {BRAND["border"]};background:{row_bg};align-items:center;"><div style="flex:2;color:{BRAND["white"]};font-size:13px;">{c["name"]}</div><div style="flex:1;text-align:center;color:{html_color};font-weight:700;font-size:13px;">{html_v}</div><div style="flex:1;text-align:center;color:{js_color};font-size:13px;">{js_v}</div><div style="flex:2;">{impact_html}</div></div>', unsafe_allow_html=True)

                    # Text content gap highlight
                    html_text = comp["html_summary"]["text_content_length"]
                    js_text = comp["js_summary"]["text_content_length"]
                    if js_text > html_text:
                        pct = round(html_text / max(js_text, 1) * 100)
                        gap_color = BRAND["danger"] if pct < 30 else BRAND["warning"] if pct < 70 else BRAND["teal"]
                        st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:10px;padding:14px 18px;margin:12px 0;"><div style="font-size:11px;color:{BRAND["text_secondary"]};text-transform:uppercase;letter-spacing:1px;">Content Visibility</div><div style="font-size:20px;font-weight:700;color:{gap_color};">{pct}% <span style="font-size:14px;opacity:0.5;">of content visible to AI</span></div><div style="font-size:12px;color:{BRAND["text_secondary"]};">HTML: {html_text:,} chars · JS-rendered: {js_text:,} chars · Hidden: {js_text - html_text:,} chars</div></div>', unsafe_allow_html=True)

                    # AI Analysis
                    ai_analysis = ai_analyse_js_gap(test_url, comp, label, get_secret)
                    if ai_analysis:
                        st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
                        st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{ai_analysis}</div>', unsafe_allow_html=True)

                else:
                    # Fallback display when no JS rendering API available
                    if js_err:
                        st.markdown(brand_status(f"JS rendering not available: {js_err}", "info"), unsafe_allow_html=True)
                        st.caption("Configure API keys in Streamlit Secrets for full HTML vs JS comparison.")

                    if js_r["risk_factors"]:
                        st.markdown("**Risk Factors (estimated from HTML analysis):**")
                        for rf in js_r["risk_factors"]:
                            st.markdown(brand_status(rf, "warning"), unsafe_allow_html=True)

                    c = js_r["content"]
                    st.markdown("**Content Visible in Raw HTML:**")
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.markdown(brand_status(f"Title: {c['title'] or 'Missing'}", "success" if c["title"] else "danger"), unsafe_allow_html=True)
                        st.markdown(brand_status(f"Meta Desc: {'Present' if c['meta_description'] else 'Missing'}", "success" if c["meta_description"] else "danger"), unsafe_allow_html=True)
                        st.markdown(brand_status(f"H1 Tags: {len(c['h1_tags'])}", "success" if c["h1_tags"] else "warning"), unsafe_allow_html=True)
                        st.markdown(brand_status(f"Prices: {len(c['prices'])} found", "success" if c["prices"] else "info"), unsafe_allow_html=True)
                    with col_b:
                        st.markdown(brand_status(f"Nav Links: {c['nav_links']}", "success" if c["nav_links"] else "warning"), unsafe_allow_html=True)
                        st.markdown(brand_status(f"Total Links: {c['total_links']}", "success" if c["total_links"] else "warning"), unsafe_allow_html=True)
                        st.markdown(brand_status(f"Images (alt): {c['images_with_alt']} / (no alt): {c['images_without_alt']}", "success" if not c["images_without_alt"] else "warning"), unsafe_allow_html=True)
                        st.markdown(brand_status(f"Text: {c['text_content_length']:,} chars", "success" if c["text_content_length"] > 500 else "warning"), unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 2: ROBOTS & CRAWLABILITY
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(2, "Robots.txt & Crawler Access", robots_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked once — controls all crawler access</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(robots_score), unsafe_allow_html=True)
        pillar_explainer("robots_txt")

        if robots_result.get("found"):
            robots_url = robots_result.get("robots", {}).get("url", robots_result.get("url", ""))
            st.markdown(brand_status(f"robots.txt found at {robots_url}", "success"), unsafe_allow_html=True)
            st.markdown(f"**AI Agent Access:**")
            for company in AI_BOTS:
                company_bots = {k: v for k, v in robots_result.get("ai_agent_results", robots_result.get("ai_results", {})).items() if v["company"] == company}
                if company_bots:
                    with st.expander(f"{company} ({len(company_bots)} agents)"):
                        for bot_name, info in company_bots.items():
                            allowed_val = info.get("robots_allowed", info.get("allowed"))
                            if allowed_val is True:
                                st.markdown(brand_status(f"**{bot_name}**: Allowed", "success"), unsafe_allow_html=True)
                            elif allowed_val is False:
                                st.markdown(brand_status(f"**{bot_name}**: Blocked", "danger"), unsafe_allow_html=True)
                            else:
                                st.markdown(brand_status(f"**{bot_name}**: Unknown", "warning"), unsafe_allow_html=True)
            if robots_result["sitemaps"]:
                with st.expander(f"Sitemaps ({len(robots_result['sitemaps'])} found)"):
                    for sm in robots_result["sitemaps"]:
                        st.markdown(brand_status(sm, "success"), unsafe_allow_html=True)
            else:
                st.markdown(brand_status("No sitemaps in robots.txt", "warning"), unsafe_allow_html=True)
            if robots_result["blocked_resources"]:
                st.markdown(brand_status(f"Blocked resources: {', '.join(robots_result['blocked_resources'])}", "danger"), unsafe_allow_html=True)
            else:
                st.markdown(brand_status("CSS/JS not blocked — AI agents can render pages", "success"), unsafe_allow_html=True)
            exposed = [(p, r) for p, r in robots_result.get("sensitive_paths", {}).items() if not r.get("blocked", not r.get("accessible_per_robots", False))]
            blocked = [(p, r) for p, r in robots_result.get("sensitive_paths", {}).items() if r.get("blocked", not r.get("accessible_per_robots", True))]
            with st.expander(f"Sensitive Path Scan — {len(exposed)} exposed, {len(blocked)} blocked"):
                if exposed:
                    for path, r in exposed:
                        st.markdown(brand_status(f"`{path}`", "warning"), unsafe_allow_html=True)
                if blocked:
                    for path, r in blocked[:10]:
                        st.markdown(brand_status(f"`{path}`", "success"), unsafe_allow_html=True)
                    if len(blocked) > 10:
                        st.caption(f"…and {len(blocked) - 10} more")
            with st.expander("Raw robots.txt"):
                st.code((robots_result.get("raw") or "")[:8000], language="text")
        else:
            robots_url = robots_result.get("robots", {}).get("url", robots_result.get("url", ""))
            st.markdown(brand_status(f"No robots.txt found at {robots_url}", "danger"), unsafe_allow_html=True)

        # AI Analysis — What This Means
        robots_ai = analyse_robots_access(parsed.netloc, robots_result, get_secret)
        if robots_ai:
            st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{robots_ai}</div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 3: SCHEMA & ENTITY (page-level)
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(3, "Schema & Entity", schema_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("PAGE-LEVEL", BRAND["primary"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked on each of your {len(all_test_urls)} pages</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(schema_score), unsafe_allow_html=True)
        pillar_explainer("schema")

        for test_url, sr in schema_results.items():
            label = url_labels.get(test_url, test_url)
            if sr.get("error"):
                st.error(f"Could not check {label}: {sr['error']}")
                continue

            schema_data = sr.get("schema", {})
            meta_data = sr.get("meta", {})
            entity_data = sr.get("entity", {})
            schemas = schema_data.get("schemas", [])
            types_found = schema_data.get("types", [])
            validations = schema_data.get("validations", [])
            grade = sr.get("grade", {})
            grade_letter = grade.get("letter", "?") if isinstance(grade, dict) else "?"

            with st.expander(f"{label} — {len(schemas)} schema item(s), Score: {sr.get('score', 0)}/100 ({grade_letter})"):
                # Schema types as pills
                if types_found:
                    pills = " ".join(brand_pill(t, BRAND["chart"][i % len(BRAND["chart"])]) for i, t in enumerate(types_found))
                    st.markdown(f'<div style="margin:8px 0;">{pills}</div>', unsafe_allow_html=True)

                # Essential types
                ess_found = schema_data.get("essential_found", [])
                ess_missing = schema_data.get("essential_missing", [])
                if ess_found or ess_missing:
                    found_str = ", ".join(ess_found) if ess_found else "None"
                    missing_str = ", ".join(ess_missing) if ess_missing else "None"
                    st.markdown(brand_status(f"Essential types — Found: {found_str} | Missing: {missing_str}", "success" if len(ess_missing) <= 1 else "warning"), unsafe_allow_html=True)

                # Speakable & sameAs
                if schema_data.get("has_speakable"):
                    st.markdown(brand_status("Speakable markup found", "success"), unsafe_allow_html=True)
                if schema_data.get("has_sameas"):
                    st.markdown(brand_status("sameAs references found", "success"), unsafe_allow_html=True)

                # Field validations
                if validations:
                    st.markdown("**Field Completeness:**")
                    for v in validations:
                        comp = v.get("completeness", 0)
                        s = "success" if comp >= 80 else "warning" if comp >= 50 else "danger"
                        st.markdown(brand_status(f"**{v.get('type', '?')}** — {comp}% complete", s), unsafe_allow_html=True)
                        if v.get("missing"):
                            st.caption(f"Missing: {', '.join(v['missing'])}")

                # Meta info
                if meta_data:
                    st.markdown("**Meta:**")
                    title = meta_data.get("title", "")
                    st.markdown(brand_status(f"Title ({len(title)} chars): {title[:70]}", "success" if title else "danger"), unsafe_allow_html=True)
                    desc = meta_data.get("desc", "")
                    desc_len = meta_data.get("desc_len", len(desc))
                    st.markdown(brand_status(f"Description ({desc_len} chars)", "success" if 100 <= desc_len <= 160 else "warning" if desc else "danger"), unsafe_allow_html=True)
                    canon = meta_data.get("canonical", "")
                    st.markdown(brand_status(f"Canonical: {canon[:80] or 'Missing'}", "success" if canon else "warning"), unsafe_allow_html=True)
                    og = meta_data.get("og_tags", {})
                    st.markdown(brand_status(f"OG tags: {len(og)}", "success" if len(og) >= 3 else "warning"), unsafe_allow_html=True)

                # Entity
                if entity_data:
                    st.markdown(brand_status(f"Author: {'Found' if entity_data.get('has_author') else 'Missing'}", "success" if entity_data.get("has_author") else "warning"), unsafe_allow_html=True)
                    st.markdown(brand_status(f"Publication date: {'Found' if entity_data.get('has_date') else 'Missing'}", "success" if entity_data.get("has_date") else "warning"), unsafe_allow_html=True)

                # ScoreBuilder rubric items
                items = sr.get("items", [])
                if items:
                    with st.expander("View scoring rubric"):
                        for item in items:
                            pts = item.get("points", 0)
                            lbl = item.get("label", "")
                            s = "success" if pts > 0 else "warning" if "missing" in lbl.lower() or "no " in lbl.lower() else "info"
                            st.markdown(brand_status(f"+{pts} pts — {lbl}", s), unsafe_allow_html=True)

                # Raw schema data
                for s_item in schemas:
                    if s_item.get("data"):
                        with st.expander(f"View `{s_item.get('type', '?')}` data"):
                            st.json(s_item["data"])

                if not schemas:
                    st.markdown(brand_status("No Schema.org structured data found on this page", "warning"), unsafe_allow_html=True)

                # AI Analysis — What This Means
                schema_ai = analyse_schema_quality(test_url, schemas, get_secret)
                if schema_ai:
                    st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
                    st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{schema_ai}</div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # PILLAR 4: AI DISCOVERABILITY
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(pillar_header(4, "AI Discoverability", llm_score), unsafe_allow_html=True)
        st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">llm.txt files + AI Info Page</span>', unsafe_allow_html=True)
        st.markdown(brand_score_bar(llm_score), unsafe_allow_html=True)
        pillar_explainer("llm_txt")

        # llm.txt files
        st.markdown(f'<div style="font-weight:600;color:{BRAND["white"]};margin:12px 0 8px;">llm.txt Files:</div>', unsafe_allow_html=True)
        llm_txt_data = llm_result.get("llm_txt", llm_result.get("files", {}))
        any_llm = any(v.get("found") for v in llm_txt_data.values()) if llm_txt_data else False
        if any_llm:
            for path, info in llm_txt_data.items():
                if info.get("found"):
                    st.markdown(brand_status(f"Found: {path}", "success"), unsafe_allow_html=True)
                    q = info.get("quality", {})
                    if q:
                        q_cols = st.columns(4)
                        q_cols[0].metric("Lines", q.get("line_count", q.get("lines", "—")))
                        q_cols[1].metric("Chars", q.get("char_count", q.get("chars", "—")))
                        q_cols[2].metric("Links", "Yes" if q.get("has_links") else "No")
                        q_cols[3].metric("Sections", "Yes" if q.get("has_sections") else "No")
                    with st.expander(f"View contents of {path}"):
                        st.code(info.get("content", ""), language="markdown")
                else:
                    st.caption(f"— {path} not found")
        else:
            st.markdown(brand_status("No llm.txt files found", "warning"), unsafe_allow_html=True)
            st.info("💡 **llm.txt** provides direct guidance to AI bots on what to prioritise. [Learn more →](https://llmstxt.org)")

        # AI Info Page
        ai_info = llm_result.get("ai_info_page", {})
        st.markdown(f'<div style="font-weight:600;color:{BRAND["white"]};margin:16px 0 8px;">AI Info Page:</div>', unsafe_allow_html=True)
        if ai_info.get("found"):
            st.markdown(brand_status(f"AI Info Page found: {ai_info.get('url', '')}", "success"), unsafe_allow_html=True)
            st.markdown(brand_status(f"Linked from footer: {'Yes' if ai_info.get('linked_from_footer') else 'No — critical for discoverability'}", "success" if ai_info.get("linked_from_footer") else "danger"), unsafe_allow_html=True)
            if "indexable" in ai_info:
                st.markdown(brand_status(f"Indexable: {'Yes' if ai_info['indexable'] else 'No — has noindex'}", "success" if ai_info.get("indexable") else "danger"), unsafe_allow_html=True)
            if "has_updated_date" in ai_info:
                st.markdown(brand_status(f"'Last Updated' date: {'Found' if ai_info['has_updated_date'] else 'Missing — add for freshness'}", "success" if ai_info.get("has_updated_date") else "warning"), unsafe_allow_html=True)
            if "is_simple_html" in ai_info:
                st.markdown(brand_status(f"Simple HTML: {'Yes' if ai_info['is_simple_html'] else 'Heavy JS — should be simple for AI'}", "success" if ai_info.get("is_simple_html") else "warning"), unsafe_allow_html=True)
        else:
            st.markdown(brand_status("No AI Info Page found at /ai-info, /llm-info, or similar", "warning"), unsafe_allow_html=True)
            st.info("💡 Create an **AI Info Page** at `/ai-info` — your brand's official fact sheet for AI. Include brand basics, key products, FAQs, and a 'Last Updated' date. Link it from your footer. Keep it simple HTML.")

        # ScoreBuilder rubric
        llm_items = llm_result.get("items", [])
        if llm_items:
            with st.expander("View AI Discoverability scoring rubric"):
                for item in llm_items:
                    pts = item.get("points", 0)
                    lbl = item.get("label", "")
                    s = "success" if pts > 0 else "info"
                    st.markdown(brand_status(f"+{pts} pts — {lbl}", s), unsafe_allow_html=True)

        # AI Analysis — What This Means
        llm_ai = analyse_llm_discoverability(parsed.netloc, llm_result, get_secret)
        if llm_ai:
            st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{llm_ai}</div>', unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # LIVE BOT CRAWL
        # ══════════════════════════════════════════════════════════════════════
        if bot_crawl_results:
            st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
            st.markdown("### Live Bot Crawl Results")
            st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Tested against homepage</span>', unsafe_allow_html=True)
            pillar_explainer("bot_crawl")
            allowed_count = sum(1 for r in bot_crawl_results.values() if r["is_allowed"])
            total_bots = len(bot_crawl_results)
            st.markdown(f'<div style="font-size:14px;color:{BRAND["text_secondary"]};margin-bottom:12px;"><span style="color:{BRAND["teal"]};font-weight:700;">{allowed_count}</span> allowed · <span style="color:{BRAND["danger"]};font-weight:700;">{total_bots - allowed_count}</span> blocked · {total_bots} total</div>', unsafe_allow_html=True)
            for company in list(dict.fromkeys(r["company"] for r in bot_crawl_results.values())):
                cr = {k: v for k, v in bot_crawl_results.items() if v["company"] == company}
                ca = sum(1 for r in cr.values() if r["is_allowed"])
                with st.expander(f"{company} — {ca}/{len(cr)} allowed"):
                    for bn, r in cr.items():
                        if r["error"]:
                            st.markdown(brand_status(f"**{bn}**: Error — {r['error']}", "danger"), unsafe_allow_html=True)
                        else:
                            st.markdown(brand_status(f"**{bn}**: {'Allowed' if r['is_allowed'] else 'BLOCKED'}", "success" if r["is_allowed"] else "danger"), unsafe_allow_html=True)
                            st.caption(f"HTTP {r['status_code']} · Robots: {'✓' if r['robots_allowed'] else '✗'} · Meta: {r['robots_meta']} · {r['content_length']:,} chars · {r['load_time']}s")

        # ══════════════════════════════════════════════════════════════════════
        # SEMANTIC HIERARCHY & OTHER CHECKS (replaces Supplementary)
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Semantic Hierarchy & Content Structure")
        st.markdown(f'{brand_pill("PAGE-LEVEL", BRAND["primary"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Heading structure, semantic HTML, meta directives — checked per page</span>', unsafe_allow_html=True)
        pillar_explainer("semantic_content")

        for test_url, sem_r in semantic_results.items():
            label = url_labels.get(test_url, test_url)
            if sem_r.get("error"):
                st.error(f"Could not check {label}: {sem_r['error']}")
                continue

            with st.expander(f"{label}"):
                col_left, col_right = st.columns(2)

                with col_left:
                    st.markdown("**Heading Hierarchy:**")
                    if sem_r["headings"]:
                        hierarchy_status = "success" if sem_r["hierarchy_ok"] else "warning"
                        st.markdown(brand_status(f"Hierarchy: {'Valid — no skipped levels' if sem_r['hierarchy_ok'] else 'Issues — skipped heading levels detected'}", hierarchy_status), unsafe_allow_html=True)
                        for h in sem_r["headings"][:20]:
                            indent = "&nbsp;" * (h["level"] - 1) * 4
                            st.markdown(f'<div style="color:{BRAND["text_secondary"]};font-size:12px;">{indent}H{h["level"]}: {h["text"][:80]}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(brand_status("No headings found", "danger"), unsafe_allow_html=True)

                    st.markdown("**Semantic Elements:**")
                    if sem_r["semantic_elements"]:
                        for tag, count in sem_r["semantic_elements"].items():
                            st.markdown(brand_status(f"<{tag}>: {count}", "success"), unsafe_allow_html=True)
                    else:
                        st.markdown(brand_status("No semantic HTML5 elements found", "warning"), unsafe_allow_html=True)

                with col_right:
                    st.markdown("**Meta Directives:**")
                    if sem_r["meta_tags"]:
                        for tag in sem_r["meta_tags"]:
                            st.markdown(brand_status(f'{tag["name"]}: {tag["content"]}', "info"), unsafe_allow_html=True)
                    else:
                        st.caption("No robots meta tags")
                    if sem_r.get("x_robots_tag"):
                        st.markdown(brand_status(f"X-Robots-Tag: {sem_r['x_robots_tag']}", "info"), unsafe_allow_html=True)
                    st.markdown(brand_status(f"data-nosnippet: {sem_r.get('nosnippet_elements', 0)} element(s)", "info"), unsafe_allow_html=True)
                    html_len = sem_r.get("html_length", 0)
                    text_len = sem_r.get("text_length", 0)
                    if html_len > 0:
                        ratio = text_len / html_len * 100
                        st.markdown(brand_status(f"Text-to-HTML ratio: {ratio:.1f}%", "success" if ratio >= 15 else "warning"), unsafe_allow_html=True)

                # AI Analysis — What This Means
                sem_ai = analyse_semantic_hierarchy(test_url, sem_r, label, get_secret)
                if sem_ai:
                    st.markdown(f'<div style="font-weight:700;color:{BRAND["white"]};font-size:15px;margin:16px 0 8px 0;">AI Analysis — What This Means:</div>', unsafe_allow_html=True)
                    st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-left:3px solid {BRAND["primary"]};border-radius:0 10px 10px 0;padding:14px 18px;color:{BRAND["white"]};font-size:13px;line-height:1.7;white-space:pre-wrap;">{sem_ai}</div>', unsafe_allow_html=True)

        # Well-known AI files (site-level)
        st.markdown(f'<div style="margin:16px 0 8px 0;">{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="font-weight:600;color:{BRAND["white"]};">AI Policy Files:</span></div>', unsafe_allow_html=True)
        wellknown_result = llm_result.get("wellknown", {})
        for path, info in wellknown_result.items():
            if info.get("found"):
                st.markdown(brand_status(f"Found: {path}", "success"), unsafe_allow_html=True)
            else:
                st.caption(f"— {path} not found")

        # ══════════════════════════════════════════════════════════════════════
        # RECOMMENDATIONS
        # ══════════════════════════════════════════════════════════════════════
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Priority Recommendations")

        recs = []

        # ── BAISOM L1: Cloudflare (CRITICAL — silent AI blocker) ──────────────────
        cf_result = robots_result.get("cloudflare", {}) if isinstance(robots_result, dict) else {}
        if cf_result.get("bot_fight_mode_likely"):
            blocked = cf_result.get("blocked_bots", [])
            recs.append(("danger", "Cloudflare", f"Bot Fight Mode is blocking key AI crawlers: {', '.join(blocked)}. Disable it or allowlist AI user-agents in Cloudflare dashboard. This overrides your robots.txt."))
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
                recs.append(("danger", "Robots.txt", "No robots.txt found — the foundational control for all crawler access. Create one immediately that explicitly allows GPTBot, ClaudeBot, and PerplexityBot."))
            else:
                if not robots_result.get("sitemaps"):
                    recs.append(("warning", "Robots.txt", "No sitemap referenced in robots.txt. Add 'Sitemap: https://yourdomain.com/sitemap.xml' so AI crawlers can discover all pages."))
                if robots_result.get("blocked_resources"):
                    recs.append(("danger", "Robots.txt", f"CSS/JS blocked in robots.txt: {', '.join(robots_result['blocked_resources'][:3])}. This prevents AI from understanding page structure — remove these Disallow rules."))
                ai_r = robots_result.get("ai_agent_results", robots_result.get("ai_results", {}))
                explicitly_blocked = [n for n, r in ai_r.items()
                                      if r.get("allowed") is False and n in ["GPTBot", "ClaudeBot", "PerplexityBot", "ChatGPT-User"]]
                if explicitly_blocked:
                    recs.append(("danger", "Robots.txt", f"AI crawlers explicitly blocked: {', '.join(explicitly_blocked)}. Add Allow rules for these bots to restore AI visibility."))
                sensitive = robots_result.get("sensitive_paths", robots_result.get("sensitive", {}))
                critical_exposed = [p for p, r in sensitive.items()
                                    if not r.get("blocked", not r.get("accessible_per_robots", r.get("exposed", False)))
                                    and any(x in p for x in ["/admin", "/api", "/.env", "/config", "/database"])]
                if critical_exposed:
                    recs.append(("danger", "Security", f"Critical paths exposed: {', '.join(critical_exposed[:4])}. Add Disallow rules immediately."))

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
                recs.append(("warning", "Product Schema", "Product pages lack GTIN/MPN identifiers. Research shows 60% of catalogs missing GTINs are downgraded or excluded by AI shopping agents. Add gtin13 or mpn to all Product schema."))
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

        if not recs:
            st.markdown(brand_status("Excellent! Your site scores well across all pillars.", "success"), unsafe_allow_html=True)
        else:
            seen = set()
            for status, pillar, text in recs:
                key = f"{pillar}:{text[:60]}"
                if key in seen: continue
                seen.add(key)
                color = BRAND["danger"] if status == "danger" else BRAND["warning"]
                st.markdown(f'<div style="background:{BRAND["bg_card"]};border-left:3px solid {color};border-radius:0 10px 10px 0;padding:14px 18px;margin:6px 0;"><div style="margin-bottom:6px;">{brand_pill(pillar, color)}</div><div style="color:{BRAND["white"]};font-size:14px;">{text}</div></div>', unsafe_allow_html=True)

        # ── PATTERN BRAIN AI ANALYSIS ─────────────────────────────────────────────
        bifrost_key = get_secret("BIFROST_API_KEY", "")
        if bifrost_key:
            st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
            st.markdown(f'### {brand_pill("PATTERN BRAIN", BRAND["purple"])} AI Analysis', unsafe_allow_html=True)
            st.caption("Powered by Pattern's AI via Bifrost · openai/gpt-4o-mini")

            with st.spinner("Generating Pattern Brain analysis..."):
                from checks import pattern_brain_analysis

                # Build compact results dict for the brain
                all_results_for_brain = {
                    "robots": robots_result if isinstance(robots_result, dict) else {},
                    "cloudflare": (robots_result.get("cloudflare", {}) if isinstance(robots_result, dict) else {}),
                    "schema_summary": {
                        "types_found": [t for sr in schema_results.values() for t in sr.get("schema", {}).get("types", [])],
                        "has_org_sameas": any(sr.get("entity", {}).get("has_org_sameas") for sr in schema_results.values()),
                        "has_author": any(sr.get("entity", {}).get("has_author") for sr in schema_results.values()),
                        "has_date_published": any(sr.get("entity", {}).get("has_date_published") for sr in schema_results.values()),
                    },
                    "ecommerce_summary": {
                        "has_gtin": any(sr.get("ecommerce", {}).get("has_gtin_or_mpn") for sr in schema_results.values()),
                        "has_return_policy": any(sr.get("ecommerce", {}).get("has_return_policy_schema") for sr in schema_results.values()),
                    },
                    "llm_discoverability": {
                        "has_llm_txt": llm_result.get("score", 0) > 25,
                        "ai_info_found": bool(llm_result.get("ai_info_page", {}).get("found")),
                        "has_ucp": bool(llm_result.get("wellknown", {}).get("has_ucp")),
                        "has_mcp": bool(llm_result.get("wellknown", {}).get("has_mcp")),
                    },
                    "semantic_summary": {
                        "has_lead_paragraph": False,
                        "cluster_count": 0,
                        "auth_citations": 0,
                        "vague_phrases": 0,
                    },
                    "pillar_scores": {
                        "overall": overall,
                        "js": js_score,
                        "robots": robots_score,
                        "schema": schema_score,
                        "llm": llm_score,
                    },
                }

                brain_analysis = pattern_brain_analysis(parsed.netloc, all_results_for_brain, get_secret)

            if brain_analysis:
                st.markdown(f'<div style="background:{BRAND["bg_card"]};border:1px solid {BRAND["border"]};border-radius:12px;padding:20px 24px;margin:8px 0;"><div style="color:{BRAND["white"]};font-size:14px;line-height:1.7;">{_md_to_html(brain_analysis)}</div></div>', unsafe_allow_html=True)
            else:
                st.caption("Pattern Brain analysis unavailable — check BIFROST_API_KEY in Streamlit secrets.")

        # ── DOWNLOAD REPORT ──────────────────────────────────────────────────
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Download Report")

        pillar_scores_dict = {
            "JS Rendering":       js_score,
            "Robots & Crawl":     robots_score,
            "Schema & Entity":    schema_score,
            "AI Discoverability": llm_score,
            "Semantic Hierarchy": semantic_score,
            "Security":           security_score,
        }
        report_text = generate_report_text(
            parsed.netloc, overall, pillar_scores_dict, url_labels,
            js_results, llm_result, robots_result, schema_results,
            bot_crawl_results, recs,
        )
        report_html = generate_report_html(
            parsed.netloc, overall, pillar_scores_dict, url_labels,
            js_results, llm_result, robots_result, schema_results,
            semantic_results, bot_crawl_results, recs,
        )
        domain_slug = parsed.netloc.replace(".", "_")
        date_slug   = time.strftime("%Y%m%d")

        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button(
                label="⬇ Download Offline PDF Report (HTML)",
                data=report_html,
                file_name=f"llm_access_audit_{domain_slug}_{date_slug}.html",
                mime="text/html",
                use_container_width=True,
                type="primary",
            )
            st.caption("Opens in browser — use Ctrl/Cmd+P to save as PDF. All sections expanded.")
        with dl_col2:
            st.download_button(
                label="⬇ Download Plain Text Report (.txt)",
                data=report_text,
                file_name=f"llm_access_audit_{domain_slug}_{date_slug}.txt",
                mime="text/plain",
                use_container_width=True,
            )
            st.caption("Plain text — open in any editor.")

        # ── FOOTER ────────────────────────────────────────────────────────────
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown(f'<div style="text-align:center;padding:1rem 0;">{PATTERN_LOGO_SVG}<div style="color:{BRAND["text_secondary"]};font-size:12px;margin-top:8px;">Pattern LLM Access Checker — Full LLM Access Audit</div></div>', unsafe_allow_html=True)
