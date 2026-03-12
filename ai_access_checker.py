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
        "what": "We load each page and analyse the raw HTML source (without executing JavaScript). We compare what a simple AI crawler would see versus what needs JavaScript to render. We check for JS frameworks (React, Vue, Angular), empty root containers, missing prices/navigation, and noscript warnings.",
        "why": "Most AI crawlers (GPTBot, ClaudeBot, PerplexityBot) do not execute JavaScript. If your product prices, descriptions, navigation, or pagination only appear after JavaScript runs, AI agents see an empty or incomplete page. This means your products won't appear in AI-generated answers, and AI may fill gaps with inaccurate third-party data.",
    },
    "llm_txt": {
        "what": "We check for the presence and quality of llm.txt files at /llm.txt, /llms.txt, /llms-full.txt, and /.well-known/llm.txt. We evaluate whether the file has a title, description, links to key pages, and clear section structure.",
        "why": "llm.txt is an emerging standard that gives AI agents explicit guidance about your site — what to prioritise, what content matters most, and how to interpret your brand. Without it, AI crawlers must guess which pages are important. Early adopters gain a competitive advantage in how AI systems represent their brand.",
    },
    "robots_txt": {
        "what": "We fetch and parse your robots.txt, testing access rules against 16+ AI bot user agents (GPTBot, ClaudeBot, Google-Extended, PerplexityBot, etc.). We check for sitemaps, blocked CSS/JS resources, and scan 25+ sensitive paths (/admin, /account, /checkout, /api, /.env) for exposure. We also perform live crawl tests — sending actual HTTP requests as each AI bot.",
        "why": "robots.txt is the foundational control for who can access your site. Without AI-specific rules, you're either invisible to AI (blocking too much) or exposing sensitive data (blocking too little). A 'smart access' policy feeds AI your public marketing content while protecting customer data, admin panels, and proprietary information.",
    },
    "schema": {
        "what": "On each page, we parse all JSON-LD and Microdata structured data. We validate against expected schema types per page template (Organisation/WebSite/WebPage/BreadcrumbList for site-wide; Product/Offer/Brand for product pages; Article/FAQ for content). We check key field completeness (name, price, availability, image, etc.) and flag missing or incomplete markup.",
        "why": "Schema is how you tell AI exactly what's on your page in a machine-readable format. Without it, AI must infer meaning from raw text — often incorrectly. With complete Product schema, AI can accurately surface your prices, availability, and reviews. Without it, AI may show wrong prices, miss that items are in stock, or attribute your products to competitors.",
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
# PILLAR 1: JAVASCRIPT RENDERING (logic unchanged)
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
        frameworks.append(("JavaScript Required", "high", f"{len(noscript_warnings)} noscript warning(s)"))
    scripts = soup.find_all("script", src=True)
    bundled = [s for s in scripts if any(x in (s.get("src", "") or "") for x in ["chunk", "bundle", "webpack", "main.", "app."])]
    if len(bundled) > 3:
        frameworks.append(("Bundled JS (Webpack/Vite)", "medium", f"{len(bundled)} bundled script(s)"))
    return frameworks


def analyse_html_content(html: str):
    soup = BeautifulSoup(html, "html.parser")
    results = {"title": "", "meta_description": "", "h1_tags": [], "h2_tags": [], "prices": [], "images_with_alt": 0, "images_without_alt": 0, "nav_links": 0, "product_elements": 0, "text_content_length": 0, "total_links": 0, "pagination": False}
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
            if txt: results["prices"].append(txt)
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
        score -= 10; risk_factors.append("No <title> tag in raw HTML")
    if not content["h1_tags"]:
        score -= 10; risk_factors.append("No <h1> tags found in raw HTML")
    if content["product_elements"] > 0 and not content["prices"]:
        score -= 15; risk_factors.append("Product elements detected but no prices in HTML")
    if content["text_content_length"] < 200:
        score -= 20; risk_factors.append(f"Very little text content ({content['text_content_length']} chars)")
    elif content["text_content_length"] < 500:
        score -= 10; risk_factors.append(f"Low text content ({content['text_content_length']} chars)")
    if content["nav_links"] == 0:
        score -= 10; risk_factors.append("No navigation links in raw HTML")
    if not content["pagination"] and content["product_elements"] > 5:
        score -= 5; risk_factors.append("Product listing but no pagination in HTML")
    if [f for f in frameworks if f[0] == "JavaScript Required"]:
        score -= 15
    return {"score": max(0, min(100, score)), "frameworks": frameworks, "content": content, "risk_factors": risk_factors, "html_length": len(html), "error": None}


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 2: LLM.TXT (logic unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

def check_llm_txt(base_url: str):
    results = {}
    for path in ["/llm.txt", "/llms.txt", "/llms-full.txt", "/.well-known/llm.txt"]:
        url = urljoin(base_url, path)
        resp, err = fetch(url, timeout=10)
        found = False; content = ""; quality = {}
        if resp and resp.status_code == 200:
            text = resp.text.strip()
            if len(text) > 10 and not text.startswith("<!DOCTYPE") and not text.startswith("<html"):
                found = True; content = text[:5000]
                quality = {"has_title": bool(re.search(r'^#\s+', text, re.M)), "has_description": len(text) > 100, "has_links": bool(re.search(r'https?://', text)), "has_sections": text.count("\n\n") > 2, "char_count": len(text), "line_count": len(text.splitlines())}
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
# PILLAR 3: ROBOTS.TXT (logic unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

def check_robots(base_url: str):
    robots_url = urljoin(base_url, "/robots.txt")
    resp, err = fetch(robots_url)
    if err or resp is None or resp.status_code != 200:
        return {"found": False, "url": robots_url, "error": err, "raw": "", "parser": None, "sitemaps": [], "ai_agent_results": {}, "sensitive_paths": {}, "blocked_resources": [], "score": 0}
    raw = resp.text
    try: parser = Protego.parse(raw)
    except Exception: parser = None
    sitemaps = []
    for line in raw.splitlines():
        stripped = line.split("#")[0].strip()
        if stripped.lower().startswith("sitemap:"):
            sitemaps.append(stripped.split(":", 1)[1].strip())
    ai_agent_results = {}
    test_url = base_url + "/"
    for company, bots in AI_BOTS.items():
        for bot_name, ua_string in bots.items():
            allowed = None
            if parser:
                try: allowed = parser.can_fetch(ua_string, test_url)
                except Exception: pass
            ai_agent_results[bot_name] = {"company": company, "ua_string": ua_string, "robots_allowed": allowed}
    sensitive_results = {}
    for path in SENSITIVE_PATHS:
        full_path = base_url + path
        exposed = True
        if parser:
            try: exposed = parser.can_fetch(BROWSER_UA, full_path)
            except Exception: pass
        sensitive_results[path] = {"accessible_per_robots": exposed, "mentioned_in_robots": path.lower() in raw.lower()}
    blocked_resources = []
    for ext_pattern in [".css", ".js", "/css/", "/js/", "/static/", "/assets/"]:
        if parser:
            try:
                if not parser.can_fetch(BROWSER_UA, base_url + ext_pattern): blocked_resources.append(ext_pattern)
            except Exception: pass
    score = 50
    ai_specific = sum(1 for name, r in ai_agent_results.items() if r["robots_allowed"] is not None)
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
    return {"found": True, "url": robots_url, "raw": raw, "parser": parser, "sitemaps": sitemaps, "ai_agent_results": ai_agent_results, "sensitive_paths": sensitive_results, "blocked_resources": blocked_resources, "score": max(0, min(100, score))}


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 4: SCHEMA (logic unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

def flatten_schema_types(data, types_found=None):
    if types_found is None: types_found = []
    if isinstance(data, dict):
        t = data.get("@type")
        if t:
            if isinstance(t, list): types_found.extend(t)
            else: types_found.append(t)
        for v in data.values(): flatten_schema_types(v, types_found)
    elif isinstance(data, list):
        for item in data: flatten_schema_types(item, types_found)
    return types_found

def validate_schema_fields(schema_type, data):
    expected = SCHEMA_KEY_FIELDS.get(schema_type, [])
    if not expected: return {"expected": [], "present": [], "missing": [], "completeness": 100}
    present = [f for f in expected if f in data and data[f]]
    missing = [f for f in expected if f not in data or not data[f]]
    return {"expected": expected, "present": present, "missing": missing, "completeness": round(len(present) / len(expected) * 100) if expected else 100}

def check_schema(url: str):
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"found": False, "error": err, "schemas": [], "types_found": [], "score": 0, "validations": [], "coverage": {}}
    soup = BeautifulSoup(resp.text, "html.parser")
    schemas = []; all_types = []
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            items = data if isinstance(data, list) else [data]
            for item in items:
                if "@graph" in item:
                    for g in item["@graph"]:
                        st_ = g.get("@type", "Unknown")
                        if isinstance(st_, list): st_ = ", ".join(st_)
                        schemas.append({"format": "JSON-LD", "type": st_, "data": g})
                else:
                    st_ = item.get("@type", "Unknown")
                    if isinstance(st_, list): st_ = ", ".join(st_)
                    schemas.append({"format": "JSON-LD", "type": st_, "data": item})
            all_types.extend(flatten_schema_types(data))
        except (json.JSONDecodeError, TypeError):
            schemas.append({"format": "JSON-LD", "type": "Parse Error", "data": {}})
    microdata = soup.find_all(attrs={"itemscope": True})
    for item in microdata[:10]:
        it = item.get("itemtype", "Unknown")
        tn = it.split("/")[-1] if "/" in it else it
        schemas.append({"format": "Microdata", "type": tn, "data": {}})
        all_types.append(tn)
    validations = []
    for s in schemas:
        if s["data"] and s["type"] != "Parse Error":
            pt = s["type"].split(",")[0].strip()
            v = validate_schema_fields(pt, s["data"]); v["type"] = s["type"]; validations.append(v)
    type_set = set(all_types)
    coverage = {}
    for cat, exp_types in EXPECTED_SCHEMA_TYPES.items():
        found = [t for t in exp_types if t in type_set]
        coverage[cat] = {"expected": exp_types, "found": found, "missing": [t for t in exp_types if t not in type_set], "coverage_pct": round(len(found) / len(exp_types) * 100) if exp_types else 0}
    score = 0
    if schemas:
        score = 30
        avg_c = sum(v["completeness"] for v in validations) / len(validations) if validations else 50
        score += round(avg_c * 0.3)
        swc = coverage.get("site_wide", {}).get("coverage_pct", 0)
        score += round(swc * 0.2)
        if len(schemas) >= 3: score += 10
        if any(s["type"] in ("Product", "Offer") for s in schemas): score += 10
    return {"found": len(schemas) > 0, "schemas": schemas, "types_found": list(set(all_types)), "validations": validations, "coverage": coverage, "score": min(score, 100), "error": None}


# ═══════════════════════════════════════════════════════════════════════════════
# LIVE BOT CRAWL (logic unchanged)
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
        title = soup.find("title"); title_text = title.get_text(strip=True) if title else ""
        robots_meta = ""; has_noindex = False
        rt = soup.find("meta", attrs={"name": "robots"})
        if rt: robots_meta = rt.get("content", ""); has_noindex = "noindex" in robots_meta.lower()
        return {"bot_name": bot_name, "status_code": resp.status_code, "robots_allowed": robots_allowed, "robots_meta": robots_meta or "None", "has_noindex": has_noindex, "is_allowed": resp.status_code == 200 and robots_allowed and not has_noindex, "title": title_text, "load_time": round(load_time, 2), "content_length": len(soup.get_text(separator=" ", strip=True)), "error": None}
    except Exception as e:
        return {"bot_name": bot_name, "status_code": None, "robots_allowed": None, "robots_meta": "N/A", "has_noindex": False, "is_allowed": False, "title": "", "load_time": 0, "content_length": 0, "error": str(e)}

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
            result = future.result(); result["company"] = company; results[bot_name] = result
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# SEMANTIC HIERARCHY & OTHER CHECKS (replaces Supplementary)
# ═══════════════════════════════════════════════════════════════════════════════

def check_semantic_hierarchy(url: str):
    """Check heading structure, semantic HTML, meta tags, and content structure."""
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}

    soup = BeautifulSoup(resp.text, "html.parser")
    results = {"headings": [], "hierarchy_ok": True, "semantic_elements": {}, "meta_tags": [], "x_robots_tag": None, "nosnippet_elements": 0, "html_length": len(resp.text), "text_length": 0}

    # Heading hierarchy
    headings = soup.find_all(re.compile(r'^h[1-6]$'))
    for h in headings:
        results["headings"].append({"level": int(h.name[1]), "text": h.get_text(strip=True)[:120]})
    levels = [int(h.name[1]) for h in headings]
    for i in range(1, len(levels)):
        if levels[i] > levels[i-1] + 1:
            results["hierarchy_ok"] = False
            break

    # Semantic elements
    for tag_name in ["article", "section", "nav", "aside", "main", "header", "footer", "figure", "time"]:
        count = len(soup.find_all(tag_name))
        if count: results["semantic_elements"][tag_name] = count

    # Meta tags
    for tag in soup.find_all("meta", attrs={"name": True}):
        name = tag.get("name", "").lower()
        content = tag.get("content", "")
        if name in ("robots", "googlebot", "google-extended", "googlebot-news", "bingbot"):
            results["meta_tags"].append({"name": name, "content": content})

    results["x_robots_tag"] = resp.headers.get("X-Robots-Tag", None)
    results["nosnippet_elements"] = len(soup.find_all(attrs={"data-nosnippet": True}))
    results["text_length"] = len(soup.get_text(separator=" ", strip=True))

    # Well-known AI files (checked once at site level)
    return results


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
        if js_r["risk_factors"]:
            for rf in js_r["risk_factors"]:
                lines.append(f"    ⚠ {rf}")
    lines.append("")

    # Pillar 2: LLM.txt
    lines.append("PILLAR 2 — LLM.TXT [SITE-LEVEL]")
    lines.append("-" * 40)
    for path, info in llm_result["files"].items():
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
        exposed = sum(1 for p, r in robots_result["sensitive_paths"].items() if r["accessible_per_robots"])
        lines.append(f"  Sensitive paths exposed: {exposed}/{len(robots_result['sensitive_paths'])}")
        lines.append("  AI Agent Access:")
        for bn, info in robots_result["ai_agent_results"].items():
            status = "Allowed" if info["robots_allowed"] else "Blocked" if info["robots_allowed"] is False else "Unknown"
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
        lines.append(f"  {label}: {sr['score']}/100 — {len(sr['schemas'])} schema item(s)")
        if sr["types_found"]:
            lines.append(f"    Types: {', '.join(sr['types_found'])}")
        for v in sr.get("validations", []):
            if v["missing"]:
                lines.append(f"    {v['type']}: {v['completeness']}% — Missing: {', '.join(v['missing'])}")
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


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

if run_audit:
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

    progress = st.progress(0, text="Starting audit…")

    # ── PILLAR 1: JS RENDERING (all pages) ────────────────────────────────
    progress.progress(5, text="Pillar 1/4 — JavaScript Rendering Assessment…")
    js_results = {}
    for test_url in all_test_urls:
        js_results[test_url] = check_js_rendering(test_url)
    js_score = round(sum(r.get("score", 0) for r in js_results.values()) / len(js_results))

    # ── PILLAR 2: LLM.TXT (site-level) ───────────────────────────────────
    progress.progress(20, text="Pillar 2/4 — LLM.txt Discovery…")
    llm_result = check_llm_txt(base_url)
    llm_score = llm_result["score"]

    # ── PILLAR 3: ROBOTS.TXT (site-level) ─────────────────────────────────
    progress.progress(35, text="Pillar 3/4 — Robots.txt & Crawler Access…")
    robots_result = check_robots(base_url)
    robots_score = robots_result["score"]

    # ── PILLAR 4: SCHEMA (all pages — page-level) ─────────────────────────
    progress.progress(50, text="Pillar 4/4 — Schema Structured Data (per page)…")
    schema_results = {}
    for test_url in all_test_urls:
        schema_results[test_url] = check_schema(test_url)
    schema_score = round(sum(r.get("score", 0) for r in schema_results.values()) / len(schema_results))

    # ── SEMANTIC HIERARCHY (all pages) ────────────────────────────────────
    progress.progress(65, text="Checking Semantic Hierarchy & Structure…")
    semantic_results = {}
    for test_url in all_test_urls:
        semantic_results[test_url] = check_semantic_hierarchy(test_url)
    wellknown_result = check_wellknown(base_url)

    # ── LIVE BOT CRAWL (homepage) ─────────────────────────────────────────
    bot_crawl_results = {}
    if run_bot_crawl:
        progress.progress(80, text="Live Bot Crawl — Testing as each AI agent…")
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

    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)

    # ── GAUGE + SCORE CARDS ───────────────────────────────────────────────
    col_gauge, col_pillars = st.columns([1, 2])

    with col_gauge:
        gauge_svg = generate_gauge_svg(overall, label="LLM Readiness Score", size=220)
        st.markdown(f'<div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:{BRAND["text_secondary"]};text-align:center;margin-bottom:8px;">LLM Access Audit</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="text-align:center;">{gauge_svg}</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="font-size:13px;color:{BRAND["text_secondary"]};text-align:center;margin-top:4px;">{parsed.netloc}</div>', unsafe_allow_html=True)

    with col_pillars:
        pillar_items = [
            ("JS Rendering", js_score),
            ("LLM.txt", llm_score),
            ("Robots.txt", robots_score),
            ("Schema", schema_score),
        ]
        p_cols = st.columns(4)
        for i, (label, sc) in enumerate(pillar_items):
            color = BRAND["teal"] if sc >= 75 else BRAND["primary"] if sc >= 50 else BRAND["warning"] if sc >= 35 else BRAND["danger"]
            p_cols[i].markdown(f'<div class="p-score-card"><div class="p-score-num" style="color:{color};">{sc}<span style="font-size:14px;opacity:0.4;">%</span></div><div class="p-score-label">{label}</div></div>', unsafe_allow_html=True)

        # Summary row
        st.markdown("")
        sub_cols = st.columns(3)
        with sub_cols[0]:
            st.metric("Pages Tested", len(all_test_urls))
        with sub_cols[1]:
            allowed_bots = sum(1 for r in bot_crawl_results.values() if r.get("is_allowed")) if bot_crawl_results else "—"
            total_bots = len(bot_crawl_results) if bot_crawl_results else "—"
            st.metric("Bot Access", f"{allowed_bots}/{total_bots}")
        with sub_cols[2]:
            exposed_count = sum(1 for p, r in robots_result.get("sensitive_paths", {}).items() if r["accessible_per_robots"])
            st.metric("Paths Exposed", exposed_count)

    # ── STRONGEST / WEAKEST PILLAR ────────────────────────────────────────
    pillar_scores = {"JS Rendering": js_score, "LLM.txt": llm_score, "Robots.txt": robots_score, "Schema": schema_score}
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
        with st.expander(f"{label} — Score: {js_r['score']}/100"):
            if js_r["frameworks"]:
                st.markdown("**JS Frameworks / Indicators:**")
                for name, severity, note in js_r["frameworks"]:
                    st.markdown(brand_status(f"**{name}** ({severity}) — {note}", "danger" if severity == "high" else "warning"), unsafe_allow_html=True)
            else:
                st.markdown(brand_status("No JS-heavy framework indicators — content accessible to simple crawlers", "success"), unsafe_allow_html=True)
            if js_r["risk_factors"]:
                st.markdown("**Risk Factors:**")
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
    # PILLAR 2: LLM.TXT
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(pillar_header(2, "LLM.txt Discovery", llm_score), unsafe_allow_html=True)
    st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked once at domain root</span>', unsafe_allow_html=True)
    st.markdown(brand_score_bar(llm_score), unsafe_allow_html=True)
    pillar_explainer("llm_txt")

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
        st.markdown(brand_status("No llm.txt files found", "warning"), unsafe_allow_html=True)
        st.info("💡 **llm.txt** is an emerging standard providing direct guidance to AI bots on what to prioritise. [Learn more →](https://llmstxt.org)")

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 3: ROBOTS.TXT
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(pillar_header(3, "Robots.txt & Crawler Access", robots_score), unsafe_allow_html=True)
    st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked once — controls all crawler access</span>', unsafe_allow_html=True)
    st.markdown(brand_score_bar(robots_score), unsafe_allow_html=True)
    pillar_explainer("robots_txt")

    if robots_result["found"]:
        st.markdown(brand_status(f"robots.txt found at {robots_result['url']}", "success"), unsafe_allow_html=True)
        st.markdown(f"**AI Agent Access:**")
        for company in AI_BOTS:
            company_bots = {k: v for k, v in robots_result["ai_agent_results"].items() if v["company"] == company}
            if company_bots:
                with st.expander(f"{company} ({len(company_bots)} agents)"):
                    for bot_name, info in company_bots.items():
                        if info["robots_allowed"] is True:
                            st.markdown(brand_status(f"**{bot_name}**: Allowed", "success"), unsafe_allow_html=True)
                        elif info["robots_allowed"] is False:
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
        exposed = [(p, r) for p, r in robots_result["sensitive_paths"].items() if r["accessible_per_robots"]]
        blocked = [(p, r) for p, r in robots_result["sensitive_paths"].items() if not r["accessible_per_robots"]]
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
            st.code(robots_result["raw"][:8000], language="text")
    else:
        st.markdown(brand_status(f"No robots.txt found at {robots_result['url']}", "danger"), unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 4: SCHEMA (page-level)
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(pillar_header(4, "Schema — Structured Data", schema_score), unsafe_allow_html=True)
    st.markdown(f'{brand_pill("PAGE-LEVEL", BRAND["primary"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Checked on each of your {len(all_test_urls)} pages</span>', unsafe_allow_html=True)
    st.markdown(brand_score_bar(schema_score), unsafe_allow_html=True)
    pillar_explainer("schema")

    for test_url, sr in schema_results.items():
        label = url_labels.get(test_url, test_url)
        if sr.get("error"):
            st.error(f"Could not check {label}: {sr['error']}")
            continue
        with st.expander(f"{label} — {len(sr['schemas'])} schema item(s), Score: {sr['score']}/100"):
            if sr["found"]:
                pills = " ".join(brand_pill(t, BRAND["chart"][i % len(BRAND["chart"])]) for i, t in enumerate(sr["types_found"]))
                st.markdown(f'<div style="margin:8px 0;">{pills}</div>', unsafe_allow_html=True)
                st.markdown("**Coverage by Category:**")
                for cat, cov in sr["coverage"].items():
                    if cov["found"]:
                        st.markdown(brand_status(f"**{cat.replace('_', ' ').title()}** — Found: {', '.join(cov['found'])} | Missing: {', '.join(cov['missing']) or 'None'}", "success"), unsafe_allow_html=True)
                    else:
                        st.markdown(brand_status(f"**{cat.replace('_', ' ').title()}** — None found", "warning"), unsafe_allow_html=True)
                if sr["validations"]:
                    st.markdown("**Field Completeness:**")
                    for v in sr["validations"]:
                        s = "success" if v["completeness"] >= 80 else "warning" if v["completeness"] >= 50 else "danger"
                        st.markdown(brand_status(f"**{v['type']}** — {v['completeness']}% complete", s), unsafe_allow_html=True)
                        if v["missing"]:
                            st.caption(f"Missing: {', '.join(v['missing'])}")
                for s in sr["schemas"]:
                    if s["data"]:
                        with st.expander(f"View `{s['type']}` data"):
                            st.json(s["data"])
            else:
                st.markdown(brand_status("No Schema.org structured data found on this page", "warning"), unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════════════
    # LIVE BOT CRAWL
    # ══════════════════════════════════════════════════════════════════════
    if bot_crawl_results:
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### Live Bot Crawl Results")
        st.markdown(f'{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="color:{BRAND["text_secondary"]};font-size:12px;">Tested against homepage</span>', unsafe_allow_html=True)
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

    # Well-known AI files (site-level)
    st.markdown(f'<div style="margin:16px 0 8px 0;">{brand_pill("SITE-LEVEL", BRAND["purple"])} <span style="font-weight:600;color:{BRAND["white"]};">AI Policy Files:</span></div>', unsafe_allow_html=True)
    for path, info in wellknown_result.items():
        if info["found"]:
            st.markdown(brand_status(f"Found: {path}", "success"), unsafe_allow_html=True)
        else:
            st.caption(f"— {path} not found")

    # ══════════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### Priority Recommendations")

    recs = []
    if js_score < 60:
        recs.append(("danger", "JS Rendering", "Critical content may be invisible to AI crawlers. Implement server-side rendering (SSR) for key product and marketing pages."))
    elif js_score < 80:
        recs.append(("warning", "JS Rendering", "Some content may require JavaScript. Review product pages to ensure prices, specs, and pagination are in raw HTML."))
    if llm_score == 0:
        recs.append(("warning", "LLM.txt", "Create an llm.txt file to give AI agents a curated summary of your site, key pages, and content priorities."))
    if not robots_result["found"]:
        recs.append(("danger", "Robots.txt", "Create a robots.txt file — the foundational control for managing all crawler access."))
    else:
        if not robots_result["sitemaps"]:
            recs.append(("warning", "Robots.txt", "Add sitemap references so AI crawlers can discover important pages."))
        if robots_result["blocked_resources"]:
            recs.append(("danger", "Robots.txt", f"CSS/JS blocked ({', '.join(robots_result['blocked_resources'])}). This prevents AI agents from rendering pages."))
        exposed = [(p, r) for p, r in robots_result["sensitive_paths"].items() if r["accessible_per_robots"]]
        critical = [p for p, r in exposed if any(x in p for x in ["/admin", "/api", "/.env", "/config", "/database"])]
        if critical:
            recs.append(("danger", "Security", f"Sensitive paths exposed: {', '.join(critical[:5])}. Add Disallow rules or gate these paths."))
    if schema_score < 30:
        recs.append(("danger", "Schema", "Add JSON-LD schema: Organisation, WebSite, BreadcrumbList site-wide. Product/Offer/Brand on product pages."))
    elif schema_score < 60:
        all_missing = []
        for sr in schema_results.values():
            for v in sr.get("validations", []):
                all_missing.extend(v.get("missing", []))
        if all_missing:
            recs.append(("warning", "Schema", f"Incomplete fields: {', '.join(list(set(all_missing))[:8])}. Complete these for accurate AI extraction."))

    if not recs:
        st.markdown(brand_status("Excellent! Your site scores well across all four pillars.", "success"), unsafe_allow_html=True)
    else:
        seen = set()
        for status, pillar, text in recs:
            key = f"{pillar}:{text}"
            if key in seen: continue
            seen.add(key)
            color = BRAND["danger"] if status == "danger" else BRAND["warning"]
            st.markdown(f'<div style="background:{BRAND["bg_card"]};border-left:3px solid {color};border-radius:0 10px 10px 0;padding:14px 18px;margin:6px 0;"><div style="margin-bottom:6px;">{brand_pill(pillar, color)}</div><div style="color:{BRAND["white"]};font-size:14px;">{text}</div></div>', unsafe_allow_html=True)

    # ── DOWNLOAD REPORT ──────────────────────────────────────────────────
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### Download Report")

    pillar_scores_dict = {"JS Rendering": js_score, "LLM.txt": llm_score, "Robots.txt": robots_score, "Schema": schema_score}
    report_text = generate_report_text(
        parsed.netloc, overall, pillar_scores_dict, url_labels,
        js_results, llm_result, robots_result, schema_results,
        bot_crawl_results, recs,
    )
    report_filename = f"llm_access_audit_{parsed.netloc.replace('.', '_')}_{time.strftime('%Y%m%d')}.txt"

    st.download_button(
        label="Download Full Audit Report",
        data=report_text,
        file_name=report_filename,
        mime="text/plain",
        use_container_width=True,
    )
    st.caption("Plain-text report — open in any editor or print to PDF via your browser (Ctrl/Cmd + P)")

    # ── FOOTER ────────────────────────────────────────────────────────────
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown(f'<div style="text-align:center;padding:1rem 0;">{PATTERN_LOGO_SVG}<div style="color:{BRAND["text_secondary"]};font-size:12px;margin-top:8px;">Pattern LLM Access Checker — Full LLM Access Audit</div></div>', unsafe_allow_html=True)
