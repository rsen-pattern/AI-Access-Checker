# -*- coding: utf-8 -*-
"""
checks.py — Pattern LLM Access Checker  v4.0
==============================================
Single source of truth. ai_access_checker.py is UI only and imports from here.

ARCHITECTURE
  Pillar 1 · JS Rendering          (25% of overall)
  Pillar 2 · Robots & Crawlability (25% of overall)
  Pillar 3 · Schema & Entity       (35% of overall)
  Pillar 4 · AI Discoverability    (15% of overall)
  Security Score                   (separate — not mixed into overall)

GRADING SCALE  A: 85+  B: 70+  C: 50+  D: 35+  F: <35
HARD CAP GATES — applied before weighting:
  · robots.txt missing          → OVERALL capped at 40
  · Cloudflare blocks 2+ bots   → Robots pillar capped at 50
  · JS gap severity > 50%       → JS pillar capped at 40
  · Zero schema across all pages → Schema pillar capped at 20

SECURITY SCORE (0–100, separate display)
  Critical paths exposed  (-25 each)
  Backend paths exposed   (-15 each)
  Customer paths exposed  (-10 each)
  Sensitive HTML in HTML  (-10)
  robots.txt AI allowlist of sensitive paths (-15)
"""

import re
import json
import time
import random
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from protego import Protego
from concurrent.futures import ThreadPoolExecutor, as_completed

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ─── GRADE THRESHOLDS ─────────────────────────────────────────────────────────
GRADE_THRESHOLDS = [
    (85, "A", "Excellent"),
    (70, "B", "Good"),
    (50, "C", "Needs Work"),
    (35, "D", "Poor"),
    (0,  "F", "Critical"),
]

def get_grade(score: int) -> dict:
    for threshold, letter, label in GRADE_THRESHOLDS:
        if score >= threshold:
            return {"letter": letter, "label": label, "threshold": threshold}
    return {"letter": "F", "label": "Critical", "threshold": 0}


# ─── AI BOT DEFINITIONS ───────────────────────────────────────────────────────
AI_BOTS = {
    "OpenAI": {
        "GPTBot":        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
        "ChatGPT-User":  "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
        "OAI-SearchBot": "OAI-SearchBot/1.0; +https://openai.com/searchbot",
    },
    "Anthropic": {
        "ClaudeBot":   "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
        "Claude-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
    },
    "Google": {
        "Google-Extended": "Mozilla/5.0 (compatible; Google-Extended)",
        "Googlebot":       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    },
    "Perplexity": {
        "PerplexityBot":   "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
        "Perplexity-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
    },
    "Other AI": {
        "CCBot":              "CCBot/2.0 (https://commoncrawl.org/faq/)",
        "Bytespider":         "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
        "Meta-ExternalAgent": "Mozilla/5.0 (compatible; Meta-ExternalAgent/1.0; +https://developers.facebook.com/docs/sharing/webmasters/crawler)",
        "Amazonbot":          "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
        "Applebot-Extended":  "Mozilla/5.0 (Applebot-Extended/0.3; +http://www.apple.com/go/applebot)",
        "Cohere-ai":          "Mozilla/5.0 (compatible; cohere-ai)",
    },
}

# Bot type classification — relevant for robots.txt strategy advice
BOT_TYPES = {
    "GPTBot": "training", "ClaudeBot": "training", "CCBot": "training",
    "Bytespider": "training", "Cohere-ai": "training", "Applebot-Extended": "training",
    "Google-Extended": "training", "Amazonbot": "training",
    "ChatGPT-User": "user_agent", "Claude-User": "user_agent",
    "Perplexity-User": "user_agent", "OAI-SearchBot": "search",
    "PerplexityBot": "search", "Googlebot": "search", "Meta-ExternalAgent": "social",
}

# Key bots used in hard cap and access calculations
KEY_AI_BOTS = ["GPTBot", "ChatGPT-User", "ClaudeBot", "PerplexityBot", "Claude-User"]


# ─── SENSITIVE PATH CATEGORIES ────────────────────────────────────────────────
# Used for BOTH robots.txt analysis AND security scoring
SENSITIVE_PATHS = {
    "critical": [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/.env", "/config", "/debug", "/phpmyadmin", "/adminer",
        "/database", "/wp-content/debug.log",
    ],
    "backend": [
        "/api", "/api/v1", "/graphql", "/wp-json", "/rest/V1",
        "/xmlrpc.php", "/backend", "/cms", "/panel", "/dashboard",
    ],
    "customer": [
        "/account", "/my-account", "/user", "/profile",
        "/checkout", "/cart", "/payment", "/orders",
        "/account/login", "/account/register",
    ],
    "dev": [
        "/staging", "/preview", "/dev", "/test",
        "/env", "/feed", "/trackback",
    ],
}

# Flat list for robots.txt parsing
ALL_SENSITIVE_PATHS = [p for paths in SENSITIVE_PATHS.values() for p in paths]


# ─── CMS PROFILES ─────────────────────────────────────────────────────────────
CMS_PROFILES = {
    "shopify": {
        "name": "Shopify",
        "must_block": ["/cart", "/checkouts", "/account"],
        "must_allow": ["/collections/", "/products/", "/pages/"],
        "note": "Shopify Plus stores should also block /account/addresses and /account/orders",
    },
    "woocommerce": {
        "name": "WooCommerce",
        "must_block": ["/wp-admin", "/wp-login.php", "/my-account"],
        "must_allow": ["/product/", "/product-category/", "/shop/"],
        "note": "Block /wp-json/ for WooCommerce REST API privacy",
    },
    "magento": {
        "name": "Magento",
        "must_block": ["/customer/", "/checkout/", "/admin"],
        "must_allow": ["/catalog/product/", "/catalog/category/"],
        "note": "Block /graphql and /rest/V1/ endpoints",
    },
    "bigcommerce": {
        "name": "BigCommerce",
        "must_block": ["/cart.php", "/login.php", "/account.php"],
        "must_allow": ["/products/", "/categories/", "/brands/"],
        "note": "Block /api/storefront/ and /internalapi/",
    },
}


# ─── SCHEMA FIELD RUBRIC ──────────────────────────────────────────────────────
# Every field listed here is a scorable check.
# Ecommerce-critical fields (GTIN, return policy, sameAs) carry penalties if absent.
SCHEMA_KEY_FIELDS = {
    "Product": [
        "name", "description", "image", "sku", "brand", "offers",
        "gtin", "gtin13", "gtin8", "mpn",            # AI shopping agent identifiers
        "color", "material", "aggregateRating",       # conversational matching
    ],
    "Offer": [
        "price", "priceCurrency", "availability", "url",
        "hasMerchantReturnPolicy",                    # trust signal for AI agents
        "shippingDetails",                            # required for AI commerce
    ],
    "MerchantReturnPolicy": [
        "returnPolicyCategory", "merchantReturnDays", "returnMethod",
    ],
    "Organization": [
        "name", "url", "logo", "description",
        "sameAs",                                     # critical for brand entity consistency
        "contactPoint",
    ],
    "WebSite":       ["name", "url", "potentialAction"],
    "BreadcrumbList": ["itemListElement"],
    "FAQPage":       ["mainEntity"],
    "Article":       ["headline", "author", "datePublished", "dateModified", "image"],
    "BlogPosting":   ["headline", "author", "datePublished", "dateModified", "image"],
    "AggregateRating": ["ratingValue", "reviewCount", "bestRating", "worstRating"],
    "Review":        ["author", "reviewRating", "reviewBody", "datePublished"],
    "LocalBusiness": ["name", "address", "telephone", "openingHours"],
    "ItemList":      ["itemListElement", "numberOfItems"],
    "Person":        ["name", "jobTitle", "url", "sameAs"],
}

EXPECTED_SCHEMA_TYPES = {
    "site_wide": ["Organization", "WebSite", "WebPage", "BreadcrumbList"],
    "product":   ["Product", "Offer", "AggregateRating", "Review", "MerchantReturnPolicy"],
    "article":   ["Article", "NewsArticle", "BlogPosting"],
    "faq":       ["FAQPage"],
    "local":     ["LocalBusiness"],
    "collection": ["ItemList", "CollectionPage"],
}

# Domains whose citation boosts AI trust (Princeton KDD 2024: +115% for lower-ranked sites)
AUTHORITATIVE_DOMAINS = [
    "gartner.com", "forrester.com", "mckinsey.com", "deloitte.com",
    "statista.com", "nielsen.com", "pwc.com", "bcg.com",
    "harvard.edu", "mit.edu", "stanford.edu", "oxford.ac.uk",
    "gov.au", "abs.gov.au", "accc.gov.au", "wikipedia.org", "schema.org",
    "ibm.com", "microsoft.com/research", "google.com/research",
]


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ScoreBuilder:
    """
    Transparent scoring builder. Every point awarded or deducted is recorded
    with a reason and category so the UI can show a full marking rubric.
    """
    def __init__(self, name: str, max_score: int = 100):
        self.name = name
        self.max_score = max_score
        self._score = 0
        self.items: list = []          # {"label", "points", "status", "category"}
        self.hard_cap: int | None = None
        self.hard_cap_reason: str = ""

    def add(self, points: int, label: str, category: str = "general", condition: bool = True):
        if condition:
            self._score += points
            self.items.append({
                "label": label, "points": points,
                "status": "pass" if points >= 0 else "fail",
                "category": category,
            })

    def deduct(self, points: int, label: str, category: str = "general", condition: bool = True):
        """Points should be positive — function applies the negative."""
        self.add(-abs(points), label, category, condition)

    def cap(self, cap_value: int, reason: str):
        self.hard_cap = cap_value
        self.hard_cap_reason = reason

    @property
    def score(self) -> int:
        raw = max(0, min(self.max_score, self._score))
        if self.hard_cap is not None and raw > self.hard_cap:
            return self.hard_cap
        return raw

    @property
    def grade(self) -> dict:
        return get_grade(self.score)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "raw_score": self._score,
            "grade": self.grade,
            "items": self.items,
            "hard_cap": self.hard_cap,
            "hard_cap_reason": self.hard_cap_reason,
            "hard_cap_applied": self.hard_cap is not None and self._score > self.hard_cap,
        }


def compute_overall(pillar_scores: dict, robots_missing: bool = False) -> dict:
    """
    Weighted overall score.
    pillar_scores: {"js": int, "robots": int, "schema": int, "llm": int}
    If robots.txt is missing the robots pillar should already be 0 (set by caller),
    which naturally drags the weighted score down by 25% — no artificial cap needed.
    Returns: {"score": int, "grade": dict, "hard_cap_applied": bool, "hard_cap_reason": str}
    """
    weights = {"js": 0.25, "robots": 0.25, "schema": 0.35, "llm": 0.15}
    raw = sum(pillar_scores.get(k, 0) * w for k, w in weights.items())
    overall = round(raw)

    return {
        "score": overall,
        "grade": get_grade(overall),
        "hard_cap_applied": False,
        "hard_cap_reason": "",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def fetch(url, timeout=15, user_agent=None):
    headers = {"User-Agent": user_agent or BROWSER_UA}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r, None
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            return r, "SSL warning (certificate issue)"
        except Exception as e:
            return None, str(e)
    except Exception as e:
        return None, str(e)


def extract_jsonld(soup):
    items = []
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            if isinstance(data, list): items.extend(data)
            elif "@graph" in data: items.extend(data["@graph"])
            else: items.append(data)
        except (json.JSONDecodeError, TypeError):
            pass
    return items


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


def normalise_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def detect_cms(html, url=""):
    soup = BeautifulSoup(html, "html.parser")
    scores = {"shopify": 0, "woocommerce": 0, "magento": 0, "bigcommerce": 0}
    if "cdn.shopify.com" in html: scores["shopify"] += 5
    if soup.find("meta", attrs={"name": "shopify-digital-wallet"}): scores["shopify"] += 3
    if re.search(r'Shopify\.(shop|theme)', html): scores["shopify"] += 3
    if "woocommerce" in html.lower(): scores["woocommerce"] += 3
    if soup.find("body", class_=re.compile(r'woocommerce', re.I)): scores["woocommerce"] += 3
    if "/wp-content/" in html: scores["woocommerce"] += 2
    if soup.find("script", string=re.compile(r'require\.config|Magento_', re.I)): scores["magento"] += 4
    if "bigcommerce" in html.lower(): scores["bigcommerce"] += 4
    best = max(scores, key=scores.get)
    return (best, scores[best]) if scores[best] >= 3 else (None, 0)


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 1: JS RENDERING
# Max: 100 | Hard cap: 40 if gap_severity > 0.5
# Rubric:
#   Base score: 100
#   gap_severity ≥ 0.6:  -50  (hard cap activates at this level)
#   gap_severity ≥ 0.3:  -30
#   gap_severity ≥ 0.1:  -15
#   Critical missing — Product Prices, Navigation Links: -10 each (warn: -5 each)
#   Text visibility <20%: -15
#   No JS render API (framework-only fallback):
#     High-risk framework: -30 | No title: -10 | No H1: -10
#     Product elements but no prices: -15 | Very little text: -20
#     No navigation: -10
#
# Delta thresholds (compare_html_vs_js):
#   <5% JS vs HTML difference  → "ok"     (negligible, no impact shown)
#   5–10% JS vs HTML difference → "warn"   (minor JS dependency)
#   ≥10% JS vs HTML difference  → "missing" (significant JS dependency)
#   gap_severity = Σ(1.0 × missing + 0.5 × warn) / total_numeric_metrics
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_js_rendered(url, get_secret):
    """Cascading JS render: ScrapingBee → Scrapfly → Browserless."""
    key = get_secret("SCRAPINGBEE_API_KEY", "")
    if key:
        try:
            r = requests.get("https://app.scrapingbee.com/api/v1/",
                params={"api_key": key, "url": url, "render_js": "true", "premium_proxy": "false"},
                timeout=45)
            if r.status_code == 200 and len(r.text) > 200:
                return r.text, "ScrapingBee", None
        except Exception: pass

    key = get_secret("SCRAPFLY_API_KEY", "")
    if key:
        try:
            r = requests.get("https://api.scrapfly.io/scrape",
                params={"key": key, "url": url, "render_js": "true", "asp": "false"}, timeout=45)
            if r.status_code == 200:
                html = r.json().get("result", {}).get("content", "")
                if html and len(html) > 200: return html, "Scrapfly", None
        except Exception: pass

    key = get_secret("BROWSERLESS_API_KEY", "")
    if key:
        try:
            r = requests.post(f"https://chrome.browserless.io/content?token={key}",
                json={"url": url, "waitFor": 3000}, timeout=45)
            if r.status_code == 200 and len(r.text) > 200:
                return r.text, "Browserless", None
        except Exception: pass

    return None, None, "No JS rendering API key configured. Add SCRAPINGBEE_API_KEY, SCRAPFLY_API_KEY, or BROWSERLESS_API_KEY."


def analyse_html_content(html):
    """Extract all measurable content elements from an HTML string."""
    soup = BeautifulSoup(html, "html.parser")
    r = {}
    t = soup.find("title"); r["title"] = t.get_text(strip=True) if t else ""
    md = soup.find("meta", attrs={"name": "description"})
    r["meta_description"] = md.get("content", "") if md else ""
    r["h1_tags"] = [h.get_text(strip=True) for h in soup.find_all("h1")][:10]
    r["h2_tags"] = [h.get_text(strip=True) for h in soup.find_all("h2")][:20]
    page_text = soup.get_text()
    r["prices"] = list(set(re.findall(r'[\$£€A\$]\s?\d+[\.,]?\d*', page_text)))[:20]
    pe = (soup.find_all(class_=re.compile(r'price|cost|amount', re.I)) +
          soup.find_all(attrs={"itemprop": "price"}))
    if pe and not r["prices"]:
        for el in pe[:10]:
            txt = el.get_text(strip=True)
            if txt: r["prices"].append(txt)
    imgs = soup.find_all("img")
    r["images_total"] = len(imgs)
    r["images_with_alt"] = sum(1 for i in imgs if i.get("alt", "").strip())
    r["images_without_alt"] = sum(1 for i in imgs if not i.get("alt", "").strip())
    r["images_with_dimensions"] = sum(1 for i in imgs if i.get("width") and i.get("height"))
    navs = soup.find_all("nav")
    r["nav_links"] = sum(len(n.find_all("a")) for n in navs)
    r["total_links"] = len(soup.find_all("a", href=True))
    r["product_elements"] = len(soup.find_all(class_=re.compile(r'product|item|card', re.I)))
    pag = soup.find_all(class_=re.compile(r'pagination|pager|page-nav', re.I))
    r["pagination"] = (len(pag) > 0 or
                       bool(soup.find("a", string=re.compile(r'^(next|›|»|→)', re.I))))
    r["text_content_length"] = len(soup.get_text(separator=" ", strip=True))
    r["html_length"] = len(html)
    r["reviews"] = len(soup.find_all(class_=re.compile(r'review|testimonial|rating', re.I)))
    r["forms"] = len(soup.find_all("form"))
    r["variants"] = len(soup.find_all("select",
        class_=re.compile(r'variant|option|size|color', re.I)))
    r["add_to_cart"] = len(soup.find_all("button",
        string=re.compile(r'add.to.cart|add.to.bag|buy.now', re.I)))
    r["product_cards"] = len(soup.find_all(
        class_=re.compile(r'product-card|product-item|product-grid-item', re.I)))
    r["filters"] = len(soup.find_all(class_=re.compile(r'filter|facet|refine', re.I)))
    r["article_body"] = len(soup.find_all("article"))
    r["author_elements"] = len(soup.find_all(class_=re.compile(r'author|byline', re.I)))
    r["date_elements"] = len(soup.find_all("time", attrs={"datetime": True}))
    r["search_form"] = 1 if (soup.find("form", attrs={"role": "search"}) or
                             soup.find("input", attrs={"type": "search"})) else 0
    head = soup.find("head")
    r["head_blocking_scripts"] = len([
        s for s in (head.find_all("script", src=True) if head else [])
        if not s.get("defer") and not s.get("async")
    ])
    return r


def detect_js_frameworks(html):
    soup = BeautifulSoup(html, "html.parser")
    fw = []
    root = soup.find(id="root") or soup.find(id="__next") or soup.find(id="app")
    if root and len(root.get_text(strip=True)) < 50:
        fw.append(("React / Next.js", "high", "Empty root container — content is client-side only"))
    if soup.find(id="__nuxt") or soup.find(attrs={"data-v-app": True}):
        fw.append(("Vue.js / Nuxt", "high", "Vue app container detected"))
    if soup.find(attrs={"ng-app": True}) or soup.find("app-root"):
        fw.append(("Angular", "high", "Angular root detected"))
    ns = [n for n in soup.find_all("noscript") if "javascript" in n.get_text().lower()]
    if ns:
        fw.append(("JS Required", "high",
                   f"{len(ns)} noscript warning(s) — site requires JavaScript to render content"))
    scripts = soup.find_all("script", src=True)
    bundled = [s for s in scripts
               if any(x in (s.get("src", "") or "")
                      for x in ["chunk", "bundle", "webpack", "main.", "app."])]
    if len(bundled) > 3:
        fw.append(("Bundled JS (Webpack/Vite)", "medium",
                   f"{len(bundled)} bundled scripts — likely heavy client-side rendering"))
    return fw


def compare_html_vs_js(html_str, js_str, page_type="homepage"):
    """Side-by-side comparison of raw HTML vs JS-rendered content."""
    html = analyse_html_content(html_str)
    js = analyse_html_content(js_str)

    metrics = [
        ("Page Title",           html["title"] or "Missing", js["title"] or "Missing",
         "AI can't identify the page topic"),
        ("Text Content (chars)", html["text_content_length"], js["text_content_length"],
         "AI sees very little content about your brand"),
        ("H1 Headings",          len(html["h1_tags"]), len(js["h1_tags"]),
         "AI can't identify the page topic"),
        ("Navigation Links",     html["nav_links"], js["nav_links"],
         "AI can't discover other pages from here"),
        ("Total Links",          html["total_links"], js["total_links"],
         "Reduces AI crawl paths across the site"),
        ("Images",               html["images_total"], js["images_total"],
         "No visual context for AI agents"),
        ("Images with Alt Text", html["images_with_alt"], js["images_with_alt"],
         "AI can't interpret images without alt text"),
        ("Images with Dimensions", html["images_with_dimensions"], js["images_with_dimensions"],
         "Missing dimensions causes agent screenshot instability"),
    ]

    if page_type == "product":
        metrics += [
            ("Product Prices",    len(html["prices"]), len(js["prices"]),
             "AI cannot surface your pricing in recommendations"),
            ("Variants/Options",  html["variants"], js["variants"],
             "AI can't see product options (size, colour, etc.)"),
            ("Add-to-Cart",       html["add_to_cart"], js["add_to_cart"],
             "Agentic shopping agents can't find the purchase path"),
            ("Reviews/Ratings",   html["reviews"], js["reviews"],
             "AI won't surface social proof for your products"),
        ]
    elif page_type == "category":
        metrics += [
            ("Product Cards",  html["product_cards"], js["product_cards"],
             "AI sees an empty collection page"),
            ("Product Prices", len(html["prices"]), len(js["prices"]),
             "AI can't compare prices across your range"),
            ("Filters/Facets", html["filters"], js["filters"],
             "AI can't use faceted navigation to find relevant products"),
            ("Pagination",     1 if html["pagination"] else 0, 1 if js["pagination"] else 0,
             "AI only sees the first page of products"),
        ]
    elif page_type == "blog":
        metrics += [
            ("Article Elements", html["article_body"], js["article_body"],
             "AI can't find the article content"),
            ("Author Info",      html["author_elements"], js["author_elements"],
             "No E-E-A-T author signal — AI may not trust/cite this content"),
            ("Date Elements",    html["date_elements"], js["date_elements"],
             "AI can't determine content freshness"),
        ]
    else:  # homepage
        metrics += [
            ("Product Elements", html["product_elements"], js["product_elements"],
             "AI can't see your featured products"),
            ("Search Form",      html["search_form"], js["search_form"],
             "AI can't interact with site search"),
        ]

    comparison = []
    for name, hv, jv, impact in metrics:
        is_str = isinstance(hv, str)
        if is_str:
            status = "ok" if hv != "Missing" else "missing"
            delta = 0
        else:
            delta = jv - hv if jv > hv else 0
            if jv > hv:
                delta_ratio = delta / max(jv, 1)
                if delta_ratio >= 0.10:
                    status = "missing"      # ≥10% more content needs JS
                elif delta_ratio >= 0.05:
                    status = "warn"         # 5–10% minor JS dependency
                else:
                    status = "ok"           # <5% negligible difference
            else:
                status = "ok"
        comparison.append({
            "name": name, "html_val": hv, "js_val": jv,
            "status": status, "delta": delta,
            "impact": impact if status == "missing" else "",
        })

    numeric = [c for c in comparison if not isinstance(c["html_val"], str)]
    # "missing" counts fully; "warn" counts as half — produces a fair gap_severity
    total_missing = sum(1 for c in numeric if c["status"] == "missing")
    gap_severity = (
        sum(1.0 if c["status"] == "missing" else 0.5 if c["status"] == "warn" else 0.0
            for c in numeric)
        / max(len(numeric), 1)
    )

    return {
        "comparison": comparison,
        "html_summary": html,
        "js_summary": js,
        "gap_severity": gap_severity,
        "total_missing": total_missing,
        "provider": None,
    }


def check_js_rendering(url, get_secret, page_type="general"):
    """
    Pillar 1 full check. Returns ScoreBuilder.to_dict() plus raw data.
    Hard cap: 40 if gap_severity > 0.5
    """
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}",
                "score": 0, "grade": get_grade(0), "items": []}

    raw_html = resp.text
    frameworks = detect_js_frameworks(raw_html)
    html_content = analyse_html_content(raw_html)

    js_html, js_provider, js_error = fetch_js_rendered(url, get_secret)
    comparison = None
    if js_html:
        comparison = compare_html_vs_js(raw_html, js_html, page_type=page_type)
        comparison["provider"] = js_provider

    sb = ScoreBuilder("JS Rendering", max_score=100)
    sb.add(100, "Base score — raw HTML accessible")

    if comparison:
        gap = comparison["gap_severity"]
        if gap >= 0.6:
            sb.deduct(50, f"Severe JS gap — {comparison['total_missing']} content categories hidden behind JavaScript", "js_gap")
            sb.cap(40, "More than 60% of key content is behind JavaScript — AI sees a near-empty page")
        elif gap >= 0.3:
            sb.deduct(30, f"Significant JS gap — {comparison['total_missing']} categories hidden behind JavaScript", "js_gap")
        elif gap >= 0.1:
            sb.deduct(15, f"Minor JS gap — {comparison['total_missing']} categories differ between HTML and JS", "js_gap")
        else:
            sb.add(0, "No significant JS gap detected — content accessible without JavaScript", "js_gap")

        for c in comparison["comparison"]:
            # Only penalise critical fields when the gap is genuinely significant (≥10%)
            if c["status"] == "missing" and c["name"] in ("Product Prices", "Navigation Links"):
                sb.deduct(10, f"{c['name']} not visible without JS — {c['impact']}", "critical_content")
            elif c["status"] == "warn" and c["name"] in ("Product Prices", "Navigation Links"):
                sb.deduct(5, f"{c['name']} partially hidden behind JS (minor gap) — {c['impact']}", "critical_content")

        html_t = comparison["html_summary"]["text_content_length"]
        js_t = comparison["js_summary"]["text_content_length"]
        if js_t > 0:
            ratio = html_t / max(js_t, 1)
            if ratio < 0.2:
                sb.deduct(15, f"Only {round(ratio*100)}% of text content visible without JavaScript", "text_visibility")
            elif ratio < 0.5:
                sb.deduct(8, f"{round(ratio*100)}% of text content visible without JavaScript", "text_visibility")
            else:
                sb.add(0, f"{round(ratio*100)}% text visible without JavaScript — acceptable", "text_visibility")

        # Images with dimensions (BAISOM L2: prevents agent screenshot instability)
        imgs_total = comparison["html_summary"].get("images_total", 0)
        imgs_dims = comparison["html_summary"].get("images_with_dimensions", 0)
        if imgs_total > 0 and imgs_dims < imgs_total * 0.5:
            sb.deduct(5, f"Only {imgs_dims}/{imgs_total} images have width/height — causes agent screenshot instability", "renderability")

    else:
        # Fallback: HTML-only heuristics when no JS render API is available
        high_risk = [f for f in frameworks if f[1] == "high"]
        if high_risk:
            sb.deduct(30, f"JS framework detected ({', '.join(f[0] for f in high_risk)}) — content likely hidden from AI", "framework")
        if not html_content["title"]:
            sb.deduct(10, "No <title> tag in raw HTML — AI can't identify this page", "critical_content")
        if not html_content["h1_tags"]:
            sb.deduct(10, "No H1 tags in raw HTML — AI can't determine page topic", "critical_content")
        if html_content["product_elements"] > 0 and not html_content["prices"]:
            sb.deduct(15, "Product elements visible but no prices in HTML — AI can't surface pricing", "critical_content")
        if html_content["text_content_length"] < 200:
            sb.deduct(20, f"Very little text in raw HTML ({html_content['text_content_length']} chars) — AI sees near-empty page", "text_visibility")
        elif html_content["text_content_length"] < 500:
            sb.deduct(10, f"Low text content ({html_content['text_content_length']} chars) — AI has limited context", "text_visibility")
        if html_content["nav_links"] == 0:
            sb.deduct(10, "No navigation links in raw HTML — AI can't discover other pages", "critical_content")
        if [f for f in frameworks if f[0] == "JS Required"]:
            sb.deduct(15, "Site explicitly requires JavaScript — most AI crawlers cannot access content", "framework")

    result = sb.to_dict()
    result.update({
        "frameworks": frameworks,
        "content": html_content,
        "comparison": comparison,
        "js_provider": js_provider,
        "js_error": js_error,
        "html_length": len(raw_html),
        "error": None,
    })
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CHECK (separate score — not mixed into overall)
# Rubric:
#   Start: 100
#   Critical paths accessible (/admin, /.env, /config etc): -25 each, max -50
#   Backend paths accessible (/api, /graphql, /wp-json):    -15 each, max -30
#   Customer paths accessible (/account, /checkout, /cart): -10 each, max -20
#   robots.txt explicitly allows sensitive paths to AI bots: -15
#   Sensitive content in raw HTML without auth:              -10
#   CSS/JS blocked (prevents AI from understanding site):   noted separately
# ═══════════════════════════════════════════════════════════════════════════════

def check_security_exposure(base_url, robots_raw: str = "", homepage_html: str = ""):
    """
    Standalone security score — checks whether sensitive data is exposed to AI bots.
    Covers all 4 security check types as specified.
    Returns score + detailed findings.
    """
    sb = ScoreBuilder("Security", max_score=100)
    sb.add(100, "Base score — no exposure detected")
    findings = {"critical": [], "backend": [], "customer": [], "dev": [],
                "html_exposure": [], "robots_allowlist": []}

    # ── 1–3. Sensitive path probing (parallelized) ──────────────────────────
    _path_tasks = []
    for path in SENSITIVE_PATHS["critical"]:
        _path_tasks.append(("critical", path, AI_BOTS["OpenAI"]["ChatGPT-User"]))
    for path in SENSITIVE_PATHS["backend"]:
        _path_tasks.append(("backend", path, AI_BOTS["OpenAI"]["ChatGPT-User"]))
    for path in SENSITIVE_PATHS["customer"]:
        _path_tasks.append(("customer", path, AI_BOTS["Anthropic"]["Claude-User"]))

    def _probe_path(category, path, ua):
        resp, err = fetch(base_url + path, timeout=8, user_agent=ua)
        return category, path, resp

    _path_results = []
    with ThreadPoolExecutor(max_workers=6) as _pool:
        for cat, path, resp in _pool.map(lambda t: _probe_path(*t), _path_tasks):
            _path_results.append((cat, path, resp))

    _exposed_counts = {"critical": 0, "backend": 0, "customer": 0}
    _deductions = {"critical": 25, "backend": 15, "customer": 10}
    _caps = {"critical": 2, "backend": 2, "customer": 2}
    _risks = {
        "critical": "Critical — this path may expose admin or environment data to AI bots",
        "backend": "High — API/backend endpoint accessible to AI bots may expose product data or internal structure",
        "customer": "Medium — customer area accessible to AI bots",
    }

    for cat, path, resp in _path_results:
        if resp and resp.status_code not in (403, 404, 401, 410):
            finding = {"path": path, "status": resp.status_code, "risk": _risks[cat], "size": len(resp.text)}
            if cat == "customer":
                soup_c = BeautifulSoup(resp.text, "html.parser")
                finding["contains_sensitive_content"] = any(
                    kw in soup_c.get_text().lower()
                    for kw in ["order", "address", "credit card", "password", "account details", "billing"])
            findings[cat].append(finding)
            if _exposed_counts[cat] < _caps[cat]:
                sb.deduct(_deductions[cat], f"{cat.title()} path accessible to AI bots: {path} (HTTP {resp.status_code})", f"{cat}_exposure")
                _exposed_counts[cat] += 1

    # ── 4. robots.txt explicitly allows sensitive paths to AI bots ───────────
    if robots_raw:
        robots_lower = robots_raw.lower()
        # Check if AI-specific agents are given explicit allow rules for sensitive paths
        ai_agent_blocks = []
        for bot_name in KEY_AI_BOTS:
            bot_lower = bot_name.lower()
            # Find the agent block
            pattern = rf'user-agent:\s*{re.escape(bot_lower)}(.*?)(?:user-agent:|$)'
            agent_block = re.search(pattern, robots_lower, re.S)
            if agent_block:
                block_text = agent_block.group(1)
                for path_cat, paths in SENSITIVE_PATHS.items():
                    for path in paths:
                        if f"allow: {path.lower()}" in block_text:
                            ai_agent_blocks.append({
                                "bot": bot_name, "path": path, "category": path_cat
                            })

        if ai_agent_blocks:
            findings["robots_allowlist"] = ai_agent_blocks
            sb.deduct(15, f"robots.txt explicitly allows {len(ai_agent_blocks)} sensitive path(s) for AI bots", "robots_allowlist")

    # ── 5. Sensitive HTML content exposed without authentication ─────────────
    if homepage_html:
        soup = BeautifulSoup(homepage_html, "html.parser")
        page_text = soup.get_text().lower()
        # Check for accidentally exposed sensitive content in raw HTML
        exposed_patterns = []
        # Email patterns
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', page_text)
        # Note: one email (contact/info) is normal, multiple internal ones might be accidental
        if len(emails) > 5:
            exposed_patterns.append(f"{len(emails)} email addresses in homepage HTML")
        # API keys / tokens pattern
        if re.search(r'(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}',
                     homepage_html, re.I):
            exposed_patterns.append("Potential API key or secret token visible in HTML source")
        # Database connection strings
        if re.search(r'(mysql|postgres|mongodb|redis)://', homepage_html, re.I):
            exposed_patterns.append("Database connection string visible in HTML source")

        if exposed_patterns:
            findings["html_exposure"] = exposed_patterns
            sb.deduct(10, f"Sensitive content found in raw HTML: {'; '.join(exposed_patterns)}", "html_exposure")

    result = sb.to_dict()
    result["findings"] = findings
    result["total_exposed"] = (len(findings["critical"]) + len(findings["backend"]) +
                               len(findings["customer"]))
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 2: ROBOTS & CRAWLABILITY
# Max: 100 | Hard cap: 50 if Cloudflare blocks 2+ key AI bots
# Rubric:
#   robots.txt found:              +25
#   Sitemaps declared:             +10
#   CSS/JS not blocked:            +10 (blocked: -10)
#   Key AI bots allowed (3+):      +15 | (1+): +8
#   Key bots explicitly allowed:   +5 bonus
#   50%+ sensitive paths blocked:  +10
#   CMS compliance checks:         up to +15
#   DOM size < 1500:               +5
#   Head-blocking scripts < 5:     +5
# ═══════════════════════════════════════════════════════════════════════════════

def check_cloudflare_bot_protection(base_url):
    """
    Detect if Cloudflare Bot Fight Mode is silently blocking AI crawlers.
    BAISOM Quick Win: 'Check Cloudflare is not already blocking AI bots for you.'
    """
    result = {"cloudflare_detected": False, "bot_fight_mode_likely": False,
              "blocked_bots": [], "details": {}}
    resp, err = fetch(base_url)
    if err or not resp: return result

    cf_ray = resp.headers.get("cf-ray", "")
    cf_server = resp.headers.get("server", "")
    result["cloudflare_detected"] = bool(cf_ray) or "cloudflare" in cf_server.lower()
    result["details"]["cf_ray"] = cf_ray
    result["details"]["server"] = cf_server
    if not result["cloudflare_detected"]: return result

    test_bots = {
        "GPTBot":        AI_BOTS["OpenAI"]["GPTBot"],
        "ChatGPT-User":  AI_BOTS["OpenAI"]["ChatGPT-User"],
        "ClaudeBot":     AI_BOTS["Anthropic"]["ClaudeBot"],
        "PerplexityBot": AI_BOTS["Perplexity"]["PerplexityBot"],
    }
    blocked = []
    for bot_name, ua in test_bots.items():
        try:
            r = requests.get(base_url + "/", headers={"User-Agent": ua},
                             timeout=15, allow_redirects=True)
            is_blocked = (r.status_code in (403, 503, 429) or
                          "challenge" in r.text[:500].lower() or
                          "cf-mitigated" in r.headers or
                          "just a moment" in r.text[:300].lower())
            result["details"][bot_name] = {"status": r.status_code, "blocked": is_blocked}
            if is_blocked: blocked.append(bot_name)
        except Exception as e:
            result["details"][bot_name] = {"status": None, "blocked": False, "error": str(e)}

    result["blocked_bots"] = blocked
    result["bot_fight_mode_likely"] = len(blocked) >= 2
    return result


def check_robots_crawlability(base_url, homepage_html):
    """
    Pillar 2: robots.txt + CMS + live bot crawl + Cloudflare + performance.
    Hard cap: 50 if Cloudflare blocks 2+ key AI bots.
    """
    sb = ScoreBuilder("Robots & Crawlability", max_score=100)
    raw_data = {"robots": {}, "bot_crawl": {}, "cms": {}, "performance": {},
                "cloudflare": {}}

    # ── robots.txt ────────────────────────────────────────────────────────────
    robots_url = urljoin(base_url, "/robots.txt")
    resp, err = fetch(robots_url)
    robots_found = False
    parser = None
    sitemaps = []
    ai_results = {}
    sensitive_blocked = {}
    blocked_resources = []
    raw_robots = ""

    if not err and resp and resp.status_code == 200:
        robots_found = True
        raw_robots = resp.text
        try: parser = Protego.parse(raw_robots)
        except Exception: pass

        sitemaps = [line.split(":", 1)[1].strip() for line in raw_robots.splitlines()
                    if line.split("#")[0].strip().lower().startswith("sitemap:")]

        for company, bots in AI_BOTS.items():
            for bot_name, ua in bots.items():
                allowed = None
                if parser:
                    try: allowed = parser.can_fetch(ua, base_url + "/")
                    except Exception: pass
                ai_results[bot_name] = {"company": company, "allowed": allowed,
                                        "bot_type": BOT_TYPES.get(bot_name, "unknown")}

        for path in ALL_SENSITIVE_PATHS:
            blocked = False
            if parser:
                try: blocked = not parser.can_fetch(BROWSER_UA, base_url + path)
                except Exception: pass
            sensitive_blocked[path] = {"blocked": blocked, "mentioned": path.lower() in raw_robots.lower()}

        for ext in [".css", ".js", "/css/", "/js/", "/static/", "/assets/"]:
            if parser:
                try:
                    if not parser.can_fetch(BROWSER_UA, base_url + ext):
                        blocked_resources.append(ext)
                except Exception: pass

        raw_data["robots"] = {
            "found": True, "url": robots_url, "status_code": 200,
            "raw": raw_robots, "parser": parser, "sitemaps": sitemaps,
            "ai_results": ai_results, "sensitive_blocked": sensitive_blocked,
            "blocked_resources": blocked_resources,
        }
        sb.add(25, "robots.txt found and accessible", "robots_found")
    else:
        raw_data["robots"] = {
            "found": False, "url": robots_url,
            "error": err or f"HTTP {resp.status_code if resp else '?'}", "raw": "",
        }
        sb.add(0, "robots.txt not found — AI crawlers have no access instructions", "robots_found")

    # Sitemaps
    if sitemaps:
        sb.add(10, f"Sitemap(s) declared in robots.txt: {', '.join(sitemaps[:2])}", "sitemaps")
    elif robots_found:
        sb.deduct(0, "No sitemap declared in robots.txt — AI can't discover your full page inventory", "sitemaps")

    # CSS/JS blocking
    if blocked_resources:
        sb.deduct(10, f"CSS/JS resources blocked: {', '.join(blocked_resources[:3])} — prevents AI from understanding page structure", "resource_blocking")
    elif robots_found:
        sb.add(10, "CSS/JS resources not blocked — AI can fully parse page styles and scripts", "resource_blocking")

    # AI bot access from robots.txt rules
    if ai_results:
        key_allowed = sum(1 for n, r in ai_results.items()
                          if r["allowed"] is True and n in KEY_AI_BOTS)
        key_blocked = [n for n in KEY_AI_BOTS
                       if ai_results.get(n, {}).get("allowed") is False]
        if key_allowed >= 4:
            sb.add(15, f"All key AI bots allowed in robots.txt ({key_allowed}/5 checked)", "bot_access")
        elif key_allowed >= 2:
            sb.add(10, f"{key_allowed} key AI bots allowed in robots.txt", "bot_access")
        elif key_allowed >= 1:
            sb.add(8, f"{key_allowed} key AI bot allowed in robots.txt", "bot_access")
        else:
            sb.add(0, "No key AI bots explicitly allowed in robots.txt", "bot_access")

        if key_blocked:
            sb.deduct(0, f"Key AI bots explicitly blocked: {', '.join(key_blocked)} — these agents cannot train on or cite your content", "bot_access")

        # Bonus: explicit Allow rules for user-agent AI bots (real-time RAG access)
        rag_bots = ["ChatGPT-User", "Claude-User", "Perplexity-User"]
        rag_allowed = sum(1 for n in rag_bots if ai_results.get(n, {}).get("allowed") is True)
        if rag_allowed >= 2:
            sb.add(5, f"Real-time AI user agents allowed ({rag_allowed} of {len(rag_bots)}) — enables live RAG access to your content", "bot_access")

    # Sensitive path protection
    if sensitive_blocked:
        blocked_count = sum(1 for s in sensitive_blocked.values() if s["blocked"])
        pct = blocked_count / len(sensitive_blocked)
        if pct > 0.5:
            sb.add(10, f"{blocked_count}/{len(sensitive_blocked)} sensitive paths blocked — good protection of private areas", "sensitive_paths")
        elif pct > 0.2:
            sb.add(5, f"{blocked_count}/{len(sensitive_blocked)} sensitive paths blocked — some gaps remain", "sensitive_paths")
        else:
            sb.add(0, f"Only {blocked_count}/{len(sensitive_blocked)} sensitive paths blocked — AI bots can access many private areas", "sensitive_paths")

    # CMS-specific compliance
    cms_id, cms_score_val = detect_cms(homepage_html, base_url)
    cms_checks = []
    if cms_id and cms_id in CMS_PROFILES:
        profile = CMS_PROFILES[cms_id]
        robots_lower = raw_robots.lower()
        for path in profile["must_block"]:
            blocked = f"disallow: {path.lower()}" in robots_lower
            cms_checks.append({"path": path, "should_block": True, "is_blocked": blocked})
        for path in profile["must_allow"]:
            allowed = f"disallow: {path.lower()}" not in robots_lower
            cms_checks.append({"path": path, "should_block": False, "is_blocked": not allowed})
        if cms_checks:
            correct = sum(1 for c in cms_checks
                          if (c["should_block"] and c["is_blocked"]) or
                             (not c["should_block"] and not c["is_blocked"]))
            score_pct = correct / len(cms_checks)
            if score_pct >= 0.8:
                sb.add(15, f"{profile['name']} robots.txt — {correct}/{len(cms_checks)} platform rules correctly configured", "cms_compliance")
            elif score_pct >= 0.5:
                sb.add(8, f"{profile['name']} robots.txt — {correct}/{len(cms_checks)} platform rules correct, some gaps", "cms_compliance")
            else:
                sb.add(3, f"{profile['name']} robots.txt — only {correct}/{len(cms_checks)} platform rules correct", "cms_compliance")

    raw_data["cms"] = {"id": cms_id, "name": CMS_PROFILES.get(cms_id, {}).get("name") if cms_id else None,
                       "checks": cms_checks}

    # Performance (BAISOM L2)
    soup = BeautifulSoup(homepage_html, "html.parser")
    head = soup.find("head")
    imgs = soup.find_all("img")
    head_blocking = [s for s in (head.find_all("script", src=True) if head else [])
                     if not s.get("defer") and not s.get("async")]
    dom_size = len(soup.find_all())
    perf = {
        "dom_size": dom_size,
        "scripts": len(soup.find_all("script", src=True)),
        "stylesheets": len(soup.find_all("link", rel="stylesheet")),
        "head_blocking": len(head_blocking),
        "images": len(imgs),
        "lazy_images": len([i for i in imgs if i.get("loading") == "lazy"]),
        "lazy_above_fold_risk": len([i for i in imgs[:5] if i.get("loading") == "lazy"]),
        "imgs_with_dimensions": len([i for i in imgs if i.get("width") and i.get("height")]),
        "iframes": len(soup.find_all("iframe")),
    }
    raw_data["performance"] = perf

    # DOM size scoring: ratio-based (elements per KB of text content)
    _body_text_len = max(len(soup.get_text(strip=True)), 1)
    _dom_ratio = dom_size / (_body_text_len / 1024)  # elements per KB of text
    if dom_size < 2000 or _dom_ratio < 50:
        sb.add(5, f"Lean DOM ({dom_size} elements, {_dom_ratio:.0f} el/KB) — AI agents can parse HTML efficiently", "performance")
    elif dom_size < 4000 or _dom_ratio < 100:
        sb.add(2, f"Moderate DOM ({dom_size} elements, {_dom_ratio:.0f} el/KB) — acceptable for AI parsing", "performance")
    else:
        sb.add(0, f"Heavy DOM ({dom_size} elements, {_dom_ratio:.0f} el/KB) — bloated HTML increases AI parsing cost", "performance")

    if len(head_blocking) < 5:
        sb.add(5, f"Few render-blocking scripts ({len(head_blocking)}) — content accessible quickly", "performance")
    else:
        sb.deduct(5, f"{len(head_blocking)} render-blocking scripts in <head> — delays content visibility for AI agents", "performance")

    # Live bot crawl
    def _crawl_bot(url, name, ua, parser):
        try:
            r_allowed = True
            if parser:
                try: r_allowed = parser.can_fetch(ua, url)
                except: r_allowed = None
            start = time.time()
            r = requests.get(url, headers={"User-Agent": ua}, timeout=20, allow_redirects=True)
            lt = time.time() - start
            soup_r = BeautifulSoup(r.text, "html.parser")
            rm = soup_r.find("meta", attrs={"name": "robots"})
            rm_content = rm.get("content", "") if rm else ""
            is_cf = (r.status_code in (403, 503) or "challenge" in r.text[:300].lower()
                     or "cf-mitigated" in r.headers)
            return {
                "bot": name, "status": r.status_code, "robots_allowed": r_allowed,
                "meta": rm_content or "None", "noindex": "noindex" in rm_content.lower(),
                "allowed": (r.status_code == 200 and r_allowed is not False
                            and "noindex" not in rm_content.lower() and not is_cf),
                "cloudflare_blocked": is_cf,
                "size": len(r.text), "time": round(lt, 2), "error": None,
                "bot_type": BOT_TYPES.get(name, "unknown"),
            }
        except Exception as e:
            return {"bot": name, "status": None, "robots_allowed": None, "meta": "N/A",
                    "noindex": False, "allowed": False, "cloudflare_blocked": False,
                    "size": 0, "time": 0, "error": str(e), "bot_type": BOT_TYPES.get(name, "unknown")}

    bot_results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(_crawl_bot, base_url + "/", name, ua, parser): (company, name)
                for company, bots in AI_BOTS.items() for name, ua in bots.items()}
        for f in as_completed(futs):
            company, name = futs[f]
            r = f.result(); r["company"] = company; bot_results[name] = r
    raw_data["bot_crawl"] = bot_results

    # Cloudflare check + hard cap
    cf = check_cloudflare_bot_protection(base_url)
    raw_data["cloudflare"] = cf
    if cf.get("bot_fight_mode_likely"):
        sb.deduct(0, f"Cloudflare Bot Fight Mode detected — blocking: {', '.join(cf['blocked_bots'])}", "cloudflare")
        sb.cap(50, f"Cloudflare is blocking {len(cf['blocked_bots'])} key AI crawlers "
                   f"({', '.join(cf['blocked_bots'])}). This overrides all robots.txt settings.")

    result = sb.to_dict()
    result.update(raw_data)
    result["sitemaps"] = sitemaps
    result["ai_results"] = ai_results
    result["sensitive_paths"] = sensitive_blocked
    result["blocked_resources"] = blocked_resources
    result["found"] = robots_found
    result["raw"] = raw_robots
    result["parser"] = parser
    return result


# Backwards-compatible alias used by main app
def run_live_bot_crawl(url, robots_parser):
    results = {}
    def _crawl(url, bot_name, ua_string, parser):
        try:
            robots_allowed = True
            if parser:
                try: robots_allowed = parser.can_fetch(ua_string, url)
                except: robots_allowed = None
            start = time.time()
            resp = requests.get(url, headers={"User-Agent": ua_string}, timeout=20, allow_redirects=True)
            lt = time.time() - start
            soup = BeautifulSoup(resp.text, "html.parser")
            t = soup.find("title"); tt = t.get_text(strip=True) if t else ""
            rm = soup.find("meta", attrs={"name": "robots"}); rmc = rm.get("content", "") if rm else ""
            return {"bot_name": bot_name, "status_code": resp.status_code,
                    "robots_allowed": robots_allowed, "robots_meta": rmc or "None",
                    "has_noindex": "noindex" in rmc.lower(),
                    "is_allowed": resp.status_code == 200 and robots_allowed and not "noindex" in rmc.lower(),
                    "title": tt, "load_time": round(lt, 2),
                    "content_length": len(soup.get_text(separator=" ", strip=True)), "error": None}
        except Exception as e:
            return {"bot_name": bot_name, "status_code": None, "robots_allowed": None,
                    "robots_meta": "N/A", "has_noindex": False, "is_allowed": False,
                    "title": "", "load_time": 0, "content_length": 0, "error": str(e)}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for company, bots in AI_BOTS.items():
            for bot_name, ua_string in bots.items():
                f = executor.submit(_crawl, url, bot_name, ua_string, robots_parser)
                futures[f] = (company, bot_name)
        for future in as_completed(futures):
            company, bot_name = futures[future]
            result = future.result(); result["company"] = company; results[bot_name] = result
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 3: SCHEMA & ENTITY
# Max: 100 | Hard cap: 20 if zero schema across all pages
# Rubric:
#   Any schema found:                    +20
#   Essential types (3+ of 4):           +15 | (1-2): +8
#   Average field completeness ×0.15:    up to +15
#   Title tag:         +8  | Description: +5 | Canonical: +5
#   OG tags (3+):      +5
#   Author attribution: +5
#   Date published:    +3  | Date modified: +2
#   Organisation schema: +5 | sameAs: +4
#   Authoritative citations: +4
#   GTIN/MPN present:  +5  | Return policy schema: +3
#   Review schema depth: +3
# PENALTIES (product pages):
#   No GTIN/MPN:         -15
#   No return policy:     -5
#   No org sameAs:        -8
# ═══════════════════════════════════════════════════════════════════════════════

def validate_schema_fields(schema_type, data):
    expected = SCHEMA_KEY_FIELDS.get(schema_type, [])
    if not expected:
        return {"expected": [], "present": [], "missing": [], "completeness": 100}
    present = [f for f in expected if f in data and data[f]]
    missing = [f for f in expected if f not in data or not data[f]]
    return {"expected": expected, "present": present, "missing": missing,
            "completeness": round(len(present) / len(expected) * 100) if expected else 100}


_ESSENTIAL_BY_PAGE_TYPE = {
    "homepage": {"Organization", "WebSite", "WebPage", "BreadcrumbList"},
    "blog":     {"Article",  "BreadcrumbList", "WebPage"},
    "category": {"ItemList", "BreadcrumbList", "WebPage"},
    "product":  {"Product",  "Offer", "BreadcrumbList", "WebPage"},
    "content":  {"Organization", "WebPage", "BreadcrumbList"},  # About/Contact/Story
    "general":  {"WebPage",  "BreadcrumbList"},
}


def check_schema_meta(url, page_type="general"):
    """Pillar 3: schema, meta, entity, ecommerce fields, authority signals."""
    resp, err = fetch(url)
    if err or not resp or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}",
                "score": 0, "grade": get_grade(0), "items": []}

    # Track whether the request was redirected (e.g. homepage → different page)
    final_url = resp.url if resp.url else url
    was_redirected = bool(resp.history) and final_url.rstrip("/") != url.rstrip("/")

    soup = BeautifulSoup(resp.text, "html.parser")
    sb = ScoreBuilder("Schema & Entity", max_score=100)

    # ── Extract all schema ────────────────────────────────────────────────────
    jsonld = extract_jsonld(soup)
    schemas = []
    all_types = []
    for item in jsonld:
        t = item.get("@type", "Unknown")
        if isinstance(t, list): t = ", ".join(t)
        schemas.append({"type": t, "data": item})
        flatten_schema_types(item, all_types)
    for md in soup.find_all(attrs={"itemscope": True})[:10]:
        it = md.get("itemtype", "Unknown")
        tn = it.split("/")[-1] if "/" in it else it
        schemas.append({"type": tn, "data": {}})
        all_types.append(tn)

    type_set = set(all_types)

    validations = []
    for s in schemas:
        if s["data"] and s["type"] not in ("Unknown", "Parse Error"):
            pt = s["type"].split(",")[0].strip()
            v = validate_schema_fields(pt, s["data"])
            v["type"] = s["type"]
            validations.append(v)

    coverage = {}
    for cat, exp_types in EXPECTED_SCHEMA_TYPES.items():
        found = [t for t in exp_types if t in type_set]
        coverage[cat] = {"expected": exp_types, "found": found,
                         "missing": [t for t in exp_types if t not in type_set],
                         "coverage_pct": round(len(found) / len(exp_types) * 100) if exp_types else 0}

    # Schema presence
    if schemas:
        sb.add(20, f"{len(schemas)} schema item(s) found — machine-readable structured data present", "schema_presence")
    else:
        sb.add(0, "No schema found — AI has to guess what your pages are about", "schema_presence")
        sb.cap(20, "Zero schema markup detected across all pages — AI cannot reliably understand your content")

    # Essential schema types — requirements vary by page type
    essential = _ESSENTIAL_BY_PAGE_TYPE.get(page_type, _ESSENTIAL_BY_PAGE_TYPE["general"])
    found_essential = essential & type_set
    missing_essential = essential - type_set
    _page_type_label = page_type.replace("content", "About/Contact").replace("blog", "editorial").capitalize()
    if len(found_essential) >= len(essential) - 1:
        sb.add(15, f"Essential schema types present ({_page_type_label} page): {', '.join(sorted(found_essential))}", "essential_types")
    elif found_essential:
        sb.add(8, f"Some essential schema present ({_page_type_label} page): {', '.join(sorted(found_essential))} — missing: {', '.join(sorted(missing_essential))}", "essential_types")
    else:
        sb.add(0, f"No essential schema types ({_page_type_label} page) — missing all of: {', '.join(sorted(missing_essential))}", "essential_types")

    # Field completeness
    if validations:
        avg_c = sum(v["completeness"] for v in validations) / len(validations)
        points = round(avg_c * 0.15)
        if avg_c >= 80:
            sb.add(points, f"Schema field completeness: {round(avg_c)}% — well-populated structured data", "field_completeness")
        elif avg_c >= 50:
            sb.add(points, f"Schema field completeness: {round(avg_c)}% — several required fields missing", "field_completeness")
        else:
            sb.add(points, f"Schema field completeness: {round(avg_c)}% — most required fields are missing", "field_completeness")

    # ── Meta & Discoverability ────────────────────────────────────────────────
    title = soup.find("title"); title_text = title.get_text(strip=True) if title else ""
    meta_desc = soup.find("meta", attrs={"name": "description"})
    desc_text = meta_desc.get("content", "") if meta_desc else ""
    canonical = soup.find("link", rel="canonical")
    canon_href = canonical.get("href", "") if canonical else ""
    og = {m.get("property"): m.get("content", "")
          for m in soup.find_all("meta", attrs={"property": re.compile(r'^og:')})}
    tw = {m.get("name"): m.get("content", "")
          for m in soup.find_all("meta", attrs={"name": re.compile(r'^twitter:')})}
    robots_meta = soup.find("meta", attrs={"name": "robots"})
    robots_content = robots_meta.get("content", "") if robots_meta else ""

    if title_text:
        sb.add(8, f"Title tag present ({len(title_text)} chars): \"{title_text[:60]}\"", "meta")
    else:
        sb.add(0, "No title tag — AI can't identify this page topic", "meta")

    if desc_text:
        sb.add(5, f"Meta description present ({len(desc_text)} chars)", "meta")
    else:
        sb.add(0, "No meta description — missed opportunity for AI context", "meta")

    if canon_href:
        sb.add(5, f"Canonical URL set: {canon_href[:80]}", "meta")
    else:
        sb.add(0, "No canonical URL — risk of AI citing duplicate versions of this page", "meta")

    if len(og) >= 3:
        sb.add(5, f"Open Graph tags present ({len(og)} properties) — social/AI sharing context", "meta")

    # ── Entity & Authority (BAISOM L7) ────────────────────────────────────────
    author_schema = any("author" in json.dumps(d).lower() for d in jsonld)
    author_el = soup.find(class_=re.compile(r'author|byline', re.I))
    date_schema = any("datePublished" in json.dumps(d) for d in jsonld)
    date_modified = any("dateModified" in json.dumps(d) for d in jsonld)
    org_schema = any(d.get("@type") in ("Organization", "Corporation", "LocalBusiness") for d in jsonld)
    org_sameas = any(d.get("@type") in ("Organization", "Corporation") and "sameAs" in d for d in jsonld)
    has_review = any(d.get("@type") in ("Review", "AggregateRating") for d in jsonld)
    has_sameas_anywhere = any("sameAs" in d for d in jsonld)

    # Author and publication date are only relevant for editorial/blog content.
    # Penalising product pages or category pages for missing these is misleading.
    is_article_page = any(d.get("@type") in ("Article", "BlogPosting", "NewsArticle", "TechArticle", "WebPage") for d in jsonld)
    is_ecommerce_page = any("Product" in str(d.get("@type", "")) for d in jsonld)

    if author_schema or author_el:
        sb.add(5, "Author attribution present — E-E-A-T signal for AI trust scoring", "entity")
    elif is_article_page and not is_ecommerce_page:
        sb.add(0, "No author attribution — AI may not trust or cite anonymous editorial content", "entity")

    if date_schema:
        sb.add(3, "Publication date in schema — AI can assess content freshness", "entity")
    elif is_article_page and not is_ecommerce_page:
        sb.add(0, "No publication date in schema — AI cannot assess freshness of this content", "entity")
    if date_modified:
        sb.add(2, "Date modified in schema — AI knows content is actively maintained", "entity")

    if org_schema:
        sb.add(5, "Organisation schema present — brand entity signal for AI knowledge graph", "entity")
    if org_sameas:
        sb.add(4, "Organisation sameAs present — connects brand to LinkedIn, Wikipedia, social profiles", "entity")
    elif org_schema:
        sb.add(0, "Organisation schema found but no sameAs — AI can't verify this entity across the web", "entity")

    # Outbound authority citations (Princeton KDD 2024: +115% AI visibility uplift)
    links = soup.find_all("a", href=True)
    auth_citations = [l.get("href", "") for l in links
                      if any(domain in l.get("href", "") for domain in AUTHORITATIVE_DOMAINS)]
    if len(auth_citations) >= 3:
        sb.add(4, f"{len(auth_citations)} citations to authoritative sources (Gartner, Forrester, etc.) — boosts AI trust and citability", "authority")
    elif len(auth_citations) >= 1:
        sb.add(2, f"{len(auth_citations)} citation(s) to authoritative sources", "authority")
    else:
        sb.add(0, "No citations to authoritative sources — AI has no external trust anchors to verify your claims", "authority")

    # Legal pages (trust signal)
    links_href = [a.get("href", "").lower() for a in links]
    links_text_list = [a.get_text(strip=True).lower() for a in links]
    found_legal = [k for k in ["privacy", "terms", "returns", "shipping"]
                   if any(k in l for l in links_href) or any(k in t for t in links_text_list)]
    if len(found_legal) >= 3:
        sb.add(0, f"Trust pages present: {', '.join(found_legal)} — policy transparency signal", "trust")

    # ── Ecommerce-specific schema ─────────────────────────────────────────────
    product_schemas = [s for s in schemas if "Product" in s["type"]]
    offer_schemas = [s for s in schemas if "Offer" in s["type"]]
    has_gtin = any(any(f in s["data"] for f in ["gtin", "gtin13", "gtin8", "gtin14", "mpn"])
                   for s in product_schemas if s["data"])
    has_sku = any("sku" in s["data"] for s in product_schemas if s["data"])
    has_return_policy = ("MerchantReturnPolicy" in type_set or
                         any("hasMerchantReturnPolicy" in s["data"]
                             for s in offer_schemas if s["data"]))
    has_shipping = any("shippingDetails" in s["data"] for s in offer_schemas if s["data"])
    schema_price = next((str(s["data"].get("price", "")) for s in offer_schemas
                         if s["data"].get("price")), None)
    price_in_html = bool(re.search(r'[\$£€A\$]\s?\d+[\.,]?\d*', soup.get_text()))

    is_product_page = len(product_schemas) > 0
    if is_product_page:
        if has_gtin:
            sb.add(5, "GTIN/MPN present in Product schema — AI shopping agents can identify and cite this product", "ecommerce")
        elif has_sku:
            sb.deduct(4, "Product has SKU but no GTIN/MPN — AI agents can identify it, but global product databases prefer GTINs", "ecommerce")
        else:
            sb.deduct(8, "Product page missing GTIN/MPN/SKU — AI shopping agents may exclude or downrank unidentifiable products", "ecommerce")

        if has_return_policy:
            sb.add(3, "MerchantReturnPolicy schema present — AI agents use this when building shopping recommendations", "ecommerce")
        else:
            sb.deduct(5, "No MerchantReturnPolicy schema on product page — AI agents factor return policy into recommendations", "ecommerce")

        if has_review:
            sb.add(3, "Review/AggregateRating schema present — AI surfaces social proof in recommendations", "ecommerce")
        else:
            sb.add(0, "No review schema — AI can't surface ratings in product recommendations", "ecommerce")

        if not org_sameas:
            sb.deduct(8, "Organisation sameAs missing — AI can't reliably attribute products to your brand entity", "ecommerce")

        # Price/schema consistency check
        if schema_price and price_in_html:
            sb.add(0, "Price visible in both HTML and schema — consistent signals for AI", "ecommerce")
        elif schema_price and not price_in_html:
            sb.add(0, "Price in schema but not clearly visible in HTML — check for JS-hidden pricing", "ecommerce")
        elif not schema_price and price_in_html:
            sb.add(0, "Price visible in HTML but not in schema — add price to Offer schema for AI shopping agents", "ecommerce")

    result = sb.to_dict()
    result.update({
        "schema": {
            "schemas": schemas, "types": list(type_set), "validations": validations,
            "types_found": list(type_set), "coverage": coverage,
            "essential_found": list(found_essential), "essential_missing": list(missing_essential),
            "has_speakable": any("speakable" in json.dumps(d).lower() for d in jsonld),
            "has_sameas": has_sameas_anywhere,
            "has_review_schema": has_review, "count": len(schemas),
        },
        "meta": {"title": title_text, "title_len": len(title_text), "desc": desc_text,
                 "desc_len": len(desc_text), "canonical": canon_href,
                 "canonical_matches_url": bool(canon_href) and canon_href.rstrip("/") == url.rstrip("/"),
                 "final_url": final_url, "was_redirected": was_redirected,
                 "og_tags": og, "twitter_tags": tw,
                 "hreflangs": len(soup.find_all("link", rel="alternate", hreflang=True)),
                 "robots_meta": robots_content, "has_noindex": "noindex" in robots_content.lower()},
        "entity": {"has_author": bool(author_schema or author_el), "has_author_schema": author_schema,
                   "has_date_published": date_schema, "has_date_modified": date_modified,
                   "has_org_schema": org_schema, "has_org_sameas": org_sameas,
                   "authoritative_citations": len(auth_citations), "legal_pages": found_legal},
        "ecommerce": {"is_product_page": is_product_page, "has_gtin_or_mpn": has_gtin, "has_sku": has_sku,
                      "has_return_policy_schema": has_return_policy, "has_shipping_schema": has_shipping,
                      "schema_price": schema_price, "price_in_html": price_in_html,
                      "review_schema_depth": has_review, "product_schema_count": len(product_schemas)},
        "error": None,
    })
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 4: AI DISCOVERABILITY
# Max: 100 | No hard cap — purely additive
# Rubric:
#   llm.txt found (any variant):     +30
#     Quality: title +5, description +5, links +5, sections +5
#   AI Info Page found:              +20
#     Linked from footer:  +8
#     Indexable (no noindex): +5
#     Has updated date:    +5
#     Simple HTML:         +4
#   Well-known files (informational, zero score weight — shown but not scored):
#     UCP, WebMCP, tdmrep, ai-plugin (deprecated — noted)
# ═══════════════════════════════════════════════════════════════════════════════

def check_llm_discoverability(base_url, homepage_html):
    """
    Pillar 4: llm.txt + AI Info Page + well-known files (informational only).

    SCORING:  llm.txt = up to 50pts | AI Info Page = up to 42pts
    Well-known files are displayed for future readiness but carry NO score weight.

    Notes on well-known files:
    - ai-plugin.json: DEPRECATED by OpenAI April 2024 — shown with deprecation notice
    - tdmrep.json: EU/academic publishers only, ~0.003% web adoption — informational
    - UCP, mcp.json: Too early to mandate — shown as future readiness indicators
    """
    sb = ScoreBuilder("AI Discoverability", max_score=100)
    raw_data = {"llm_txt": {}, "ai_info_page": {}, "wellknown": {}}

    # ── 1. llm.txt variants ───────────────────────────────────────────────────
    llm_paths = ["/llm.txt", "/llms.txt", "/llms-full.txt", "/.well-known/llm.txt"]
    llm_found = None
    for path in llm_paths:
        u = urljoin(base_url, path)
        r, e = fetch(u, timeout=10)
        found = False; content = ""; quality = {}
        if r and r.status_code == 200:
            text = r.text.strip()
            if len(text) > 10 and not text.startswith(("<!DOCTYPE", "<html")):
                found = True
                content = text[:5000]
                _word_count = len(text.split())
                quality = {
                    "has_title":       bool(re.search(r'^#\s+\S', text, re.M)),
                    "has_description": len(text) > 200 and _word_count >= 20,
                    "has_links":       bool(re.search(r'https?://\S+', text)),
                    "has_sections":    text.count("\n\n") > 2 and _word_count >= 30,
                    "chars":           len(text),
                    "lines":           len(text.splitlines()),
                    "words":           _word_count,
                }
                if llm_found is None:
                    llm_found = {"path": path, "url": u, "quality": quality, "content": content}
        raw_data["llm_txt"][path] = {"found": found, "url": u, "content": content, "quality": quality}

    if llm_found:
        sb.add(30, f"llm.txt found at {llm_found['path']} — AI agents have explicit guidance about your site", "llm_txt")
        q = llm_found["quality"]
        if q.get("has_title"):
            sb.add(5, "llm.txt has a title — clear brand identification for AI agents", "llm_txt_quality")
        else:
            sb.add(0, "llm.txt lacks a title — add # BrandName at the top", "llm_txt_quality")
        if q.get("has_description"):
            sb.add(5, "llm.txt has a description — context for AI about what your brand does", "llm_txt_quality")
        if q.get("has_links"):
            sb.add(5, "llm.txt contains links to key pages — AI agents can prioritise your most important content", "llm_txt_quality")
        else:
            sb.add(0, "llm.txt has no links — add URLs to your most important pages", "llm_txt_quality")
        if q.get("has_sections"):
            sb.add(5, "llm.txt is well-structured with multiple sections", "llm_txt_quality")
    else:
        sb.add(0, "No llm.txt found at any standard path — AI crawlers can't receive explicit site guidance", "llm_txt")

    # ── 2. AI Info Page ───────────────────────────────────────────────────────
    ai_paths = ["/ai-info", "/llm-info", "/ai-information", "/llm-information",
                "/ai-info-page", "/for-ai", "/ai-policy", "/robots-ai"]
    ai_page_found = None
    for path in ai_paths:
        u = urljoin(base_url, path)
        r, e = fetch(u, timeout=10)
        if r and r.status_code == 200:
            # Reject if the server redirected us away from the intended path.
            # requests follows redirects by default, so r.url is the final URL.
            # If it no longer contains the path we requested, the page doesn't
            # exist — it just redirected to the homepage or a catch-all.
            if r.history:
                final_path = r.url.split("?")[0].rstrip("/")
                expected_path = u.split("?")[0].rstrip("/")
                if not final_path.endswith(path.rstrip("/")):
                    continue  # redirected away — not a real AI info page
            text = r.text.strip()
            if len(text) > 500 and "404" not in text[:200].lower():
                ai_page_found = {"url": u, "path": path}
                break

    # Check footer links for AI info page
    soup = BeautifulSoup(homepage_html, "html.parser")
    footer = soup.find("footer")
    ai_linked_footer = False
    if footer:
        for a in footer.find_all("a", href=True):
            href = a.get("href", ""); text = a.get_text(strip=True).lower()
            if any(kw in href.lower() or kw in text
                   for kw in ["ai-info", "llm-info", "for-ai", "ai information", "ai policy"]):
                if not ai_page_found:
                    ai_page_found = {"url": urljoin(base_url, href), "path": href}
                ai_linked_footer = True
                break
            if ai_page_found and ai_page_found["path"] in href:
                ai_linked_footer = True

    ai_info = {"found": ai_page_found is not None,
               "url": ai_page_found["url"] if ai_page_found else None,
               "linked_from_footer": ai_linked_footer}

    if ai_page_found:
        sb.add(20, f"AI Info Page found at {ai_page_found['path']} — brand controls its AI narrative", "ai_info_page")
        r, e = fetch(ai_page_found["url"])
        # Guard against footer-discovered URLs that redirect (e.g. /ai-info → homepage).
        if r and r.history:
            final = r.url.split("?")[0].rstrip("/")
            expected_suffix = ai_page_found["path"].rstrip("/")
            if not final.endswith(expected_suffix):
                # Page redirects away — treat as not found.
                ai_info["found"] = False
                ai_info["url"] = None
                ai_info["redirects"] = True
                sb.add(0, "No AI Info Page found — quick win: create /ai-info page describing your brand for AI agents", "ai_info_page")
                raw_data["ai_info_page"] = ai_info
                # Skip quality scoring for this page
                r = None
        if r and r.status_code == 200:
            ai_soup = BeautifulSoup(r.text, "html.parser")
            ai_text = ai_soup.get_text(separator=" ", strip=True)
            rm = ai_soup.find("meta", attrs={"name": "robots"})
            is_indexable = not (rm and "noindex" in rm.get("content", "").lower())
            has_updated = bool(re.search(
                r'(last\s+updated|updated\s+on|reviewed\s+on)\s*:?\s*\d', ai_text, re.I))
            is_simple = len(ai_soup.find_all("script", src=True)) < 5
            ai_info.update({
                "indexable": is_indexable,
                "has_updated_date": has_updated,
                "text_length": len(ai_text),
                "is_simple_html": is_simple,
            })
            if ai_linked_footer:
                sb.add(8, "AI Info Page linked from footer — easily discoverable by AI crawlers", "ai_info_page_quality")
            else:
                sb.add(0, "AI Info Page exists but not linked from footer — add a footer link for discoverability", "ai_info_page_quality")
            if is_indexable:
                sb.add(5, "AI Info Page is indexable — search engines and AI crawlers can index it", "ai_info_page_quality")
            else:
                sb.deduct(5, "AI Info Page has noindex meta tag — AI crawlers can't index it", "ai_info_page_quality")
            if has_updated:
                sb.add(5, "AI Info Page shows a last-updated date — AI agents know the information is current", "ai_info_page_quality")
            else:
                sb.add(0, "AI Info Page has no last-updated date — add a review date to signal freshness", "ai_info_page_quality")
            if is_simple:
                sb.add(4, "AI Info Page uses simple HTML — AI crawlers can parse it without JavaScript", "ai_info_page_quality")
    else:
        sb.add(0, "No AI Info Page found — quick win: create /ai-info page describing your brand for AI agents", "ai_info_page")

    raw_data["ai_info_page"] = ai_info

    # ── 3. Well-Known Files — small bonus for emerging standards ────────────
    # Each found+valid file earns +2 pts (max +8 from 4 files) to fill the
    # pillar ceiling to 100.  Deprecated files earn 0.
    wellknown_checks = {
        "/.well-known/ucp": {
            "description": "Universal Commerce Protocol — allows AI shopping agents to discover checkout capabilities",
            "status": "emerging",
            "note": "Jan 2026 launch. Shopify, Walmart, Target adopters. Consider for future.",
        },
        "/.well-known/mcp.json": {
            "description": "WebMCP — enables web apps to expose tools to AI agents (Microsoft/Google spec, Aug 2025)",
            "status": "emerging",
            "note": "Early standard. Not yet widespread. Monitor for adoption.",
        },
        "/.well-known/tdmrep.json": {
            "description": "TDM Reservation Protocol — declares text/data mining rights",
            "status": "niche",
            "note": "~0.003% web adoption (Common Crawl 2023). Used by EU publishers, academic journals. Not relevant for DTC ecommerce.",
        },
        "/.well-known/ai-plugin.json": {
            "description": "OpenAI ChatGPT Plugin manifest",
            "status": "deprecated",
            "note": "DEPRECATED April 2024 — ChatGPT Plugins shut down. Do not implement.",
        },
    }
    for path, meta in wellknown_checks.items():
        u = urljoin(base_url, path)
        r, e = fetch(u, timeout=6)
        found = False; valid = None
        if r and r.status_code == 200:
            text = r.text.strip()
            if text and not text.startswith(("<!DOCTYPE", "<html")):
                found = True
                try: json.loads(text); valid = True
                except: valid = False
        # Emerging/niche standards earn +2 if found+valid; deprecated earn 0
        pts = 0
        if found and meta["status"] in ("emerging", "niche"):
            pts = 2
            sb.add(2, f"{path} found — early adopter of {meta['description'].split('—')[0].strip()}", "wellknown")
        raw_data["wellknown"][path] = {
            "found": found, "url": u, "valid_json": valid,
            "description": meta["description"], "status": meta["status"],
            "note": meta["note"],
            "score_contribution": pts,
        }

    result = sb.to_dict()
    result.update(raw_data)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PATTERN BRAIN — AI ANALYSIS VIA BIFROST
# Calls:
#   1. pattern_brain_analysis()     — overall audit summary + quick wins
#   2. analyse_schema_quality()     — semantic schema issues (price=0, thin desc)
#   3. analyse_content_clarity()    — answer-first paragraph assessment
#   4. analyse_entity_coherence()   — Organisation sameAs + name consistency
#
# API key: stored as BIFROST_API_KEY in Streamlit secrets — never hardcoded.
# Base URL: https://bifrost.pattern.com/v1 (OpenAI-compatible)
# Model: openai/gpt-4o-mini
# ═══════════════════════════════════════════════════════════════════════════════

def _bifrost_call(api_key: str, prompt: str, max_tokens: int = 700) -> str | None:
    """Shared helper for all Bifrost API calls."""
    try:
        resp = requests.post(
            "https://bifrost.pattern.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "openai/gpt-4o-mini", "max_tokens": max_tokens,
                  "temperature": 0.3, "messages": [
                      {"role": "system", "content": "You write in Australian English. Use Australian spelling and vocabulary throughout (e.g. optimise, analyse, catalogue, organisation, colour, prioritise)."},
                      {"role": "user", "content": prompt},
                  ]},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
    except Exception:
        pass
    return None


def pattern_brain_analysis(url, all_results, get_secret) -> str | None:
    """
    Call 1: Overall audit summary — executive summary, top issues, quick wins, strategic recommendation.
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key: return None

    scores = all_results.get("pillar_scores", {})
    cf = all_results.get("cloudflare", {})
    ecomm = all_results.get("ecommerce_summary", {})
    llm = all_results.get("llm_discoverability", {})
    schema = all_results.get("schema_summary", {})
    semantic = all_results.get("semantic_summary", {})
    security = all_results.get("security_summary", {})

    summary = "\n".join([
        f"Website: {url}",
        f"Overall AI Readiness: {scores.get('overall', '?')}% | Grade: {scores.get('overall_grade', '?')}",
        f"JS Rendering: {scores.get('js', '?')}% | Robots: {scores.get('robots', '?')}% | Schema: {scores.get('schema', '?')}% | AI Discoverability: {scores.get('llm', '?')}%",
        f"Security Score (separate): {scores.get('security', '?')}%",
        "",
        "KEY FINDINGS:",
        f"Cloudflare blocking AI bots: {cf.get('bot_fight_mode_likely', False)} — blocked: {cf.get('blocked_bots', [])}",
        f"robots.txt missing: {not all_results.get('robots_found', True)}",
        f"Schema types present: {schema.get('types_found', [])}",
        f"Organisation sameAs: {schema.get('has_org_sameas', False)}",
        f"Has author attribution: {schema.get('has_author', False)}",
        f"Has publication date: {schema.get('has_date_published', False)}",
        f"GTIN/MPN present: {ecomm.get('has_gtin', False)}",
        f"Return policy schema: {ecomm.get('has_return_policy', False)}",
        f"llm.txt found: {llm.get('has_llm_txt', False)}",
        f"AI info page found: {llm.get('ai_info_found', False)}",
        f"Answer-first paragraph: {semantic.get('has_lead_paragraph', False)}",
        f"Topic clusters: {semantic.get('cluster_count', 0)}",
        f"Authoritative citations: {semantic.get('auth_citations', 0)}",
        f"Sensitive paths exposed to AI: {security.get('total_exposed', 0)}",
    ])

    return _bifrost_call(api_key, f"""You are an AI Search Visibility expert at Pattern, an ecommerce growth agency.
Analyse this website's AI readiness audit data and write a clear, actionable summary for a brand manager.

{summary}

Provide exactly:
1. EXECUTIVE SUMMARY (2 sentences max): Overall AI readiness status and single biggest risk
2. TOP 3 CRITICAL ISSUES: What's actively losing AI visibility right now. Be specific — name the exact fix.
3. TOP 3 QUICK WINS THIS WEEK: Actions completable in under 2 hours each. Be specific and practical.
4. STRATEGIC RECOMMENDATION: One higher-effort initiative for this quarter with expected impact.

Be direct and specific. No jargon. One concrete action per point. Focus on business impact.""")


def analyse_schema_quality(url, schema_data, get_secret) -> str | None:
    """
    Call 2: Semantic schema quality check — flags issues pure code can't detect
    (e.g. price=0.00, 3-word organisation description, missing vs empty fields).
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key or not schema_data: return None

    # Compact schema dump — truncate to avoid token limits
    schema_str = json.dumps(schema_data[:5], indent=2)[:3000]

    return _bifrost_call(api_key, f"""You are a Schema.org expert reviewing structured data from {url}.

Here is the JSON-LD schema found on the page:
{schema_str}

Identify up to 5 SEMANTIC issues — not missing fields (those are already checked), but problems with the VALUES:
- Prices that are 0.00 or suspiciously low/high
- Descriptions under 20 words (too thin for AI to use)
- Names that are generic ("Product", "Page", "Item")
- sameAs URLs that look incorrect or mismatched
- Availability values that are unusual
- AggregateRating with fewer than 3 reviews (low trust signal)
- datePublished that is very old (>2 years) with no dateModified

For each issue found: state the field, the problem, and the 1-line fix.
If no semantic issues found, say "Schema values look semantically correct."
Keep total response under 200 words. Use plain English.""", max_tokens=300)


def analyse_content_clarity(url, lead_paragraph, page_type, get_secret) -> str | None:
    """
    Call 3: BAISOM L6 clarity assessment — is the lead paragraph answer-ready for AI?
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key or not lead_paragraph: return None

    return _bifrost_call(api_key, f"""You are an AI Search Visibility expert assessing whether content is "answer-ready" for AI citation.

Page URL: {url}
Page type: {page_type}
Lead paragraph: "{lead_paragraph}"

Rate this paragraph on two dimensions (1-5 each):
1. ANSWER-FIRST: Does it lead with a specific, direct answer an AI could extract and cite? (1=vague marketing, 5=specific and citable)
2. SPECIFICITY: Does it contain concrete facts (numbers, named products, prices, timeframes, named people)? (1=all generalities, 5=rich with specifics)

Then write ONE sentence of actionable advice to improve it.
Format:
Answer-First: X/5 — [one-line reason]
Specificity: X/5 — [one-line reason]
Advice: [concrete one-sentence improvement]""", max_tokens=200)


def analyse_entity_coherence(base_url, org_schema_data, sameas_links, get_secret) -> str | None:
    """
    Call 4: Brand entity consistency check — are the Organisation schema, sameAs links,
    and site description all referring to the same entity coherently?
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key or not org_schema_data: return None

    org_str = json.dumps(org_schema_data, indent=2)[:1000]
    sameas_str = "\n".join(sameas_links[:10]) if sameas_links else "None found"

    return _bifrost_call(api_key, f"""You are a brand entity expert checking whether a website's Organisation schema is coherent for AI knowledge graphs.

Domain: {base_url}
Organisation schema:
{org_str}

sameAs links:
{sameas_str}

Check for:
1. Does the organisation name match what you'd expect from the domain?
2. Are the sameAs URLs pointing to the same organisation (not a competitor, parent company, or unrelated entity)?
3. Is the description specific enough for AI to categorise this brand? (Minimum: what they sell, who they serve, where they operate)
4. Any obvious inconsistencies between the name, description, and linked profiles?

Give a verdict (Coherent / Needs Review / Inconsistent) with 2-3 specific observations.
Keep under 150 words.""", max_tokens=250)


def analyse_semantic_hierarchy(url, sem_r, page_label, get_secret) -> str | None:
    """
    AI analysis of per-page semantic hierarchy results — heading structure,
    semantic HTML elements, and meta directives — explaining what it means for AI visibility.
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key or not sem_r:
        return None

    headings = sem_r.get("headings", [])
    hierarchy_ok = sem_r.get("hierarchy_ok", True)
    semantic_elements = sem_r.get("semantic_elements", {})
    meta_tags = sem_r.get("meta_tags", [])
    nosnippet = sem_r.get("nosnippet_elements", 0)
    html_len = sem_r.get("html_length", 0)
    text_len = sem_r.get("text_length", 0)
    ratio = (text_len / html_len * 100) if html_len > 0 else 0

    heading_lines = [f"H{h['level']}: {h['text'][:80]}" for h in headings[:15]]
    meta_lines = [f"{t['name']}: {t['content']}" for t in meta_tags] if meta_tags else ["No robots meta tags found"]
    sem_elem_lines = [f"<{tag}>: {count}" for tag, count in semantic_elements.items()] if semantic_elements else ["No semantic HTML5 elements found"]

    prompt = f"""You are an AI Search Visibility expert at Pattern, analysing how well a webpage's structure supports AI crawler indexing and citation.

URL: {url}
Page type: {page_label}

HEADING STRUCTURE:
Hierarchy valid (no skipped levels): {hierarchy_ok}
Headings found:
{chr(10).join(heading_lines) if heading_lines else "No headings found"}

SEMANTIC HTML5 ELEMENTS:
{chr(10).join(sem_elem_lines)}

META DIRECTIVES:
{chr(10).join(meta_lines)}
data-nosnippet elements: {nosnippet}
Text-to-HTML ratio: {ratio:.1f}%

Write 4-6 bullet points (use • character) for a brand manager explaining:
1. What the heading and semantic structure issues mean for how AI crawlers understand this page
2. The business impact — what happens when AI can't interpret page structure correctly
3. What the meta directives allow or restrict AI crawlers from doing
4. One clear, practical recommendation to fix the most impactful issue

Keep it concise and non-technical. Plain language a brand manager would understand. No markdown headers."""

    return _bifrost_call(api_key, prompt, max_tokens=500)


def analyse_robots_access(base_url, robots_result, get_secret) -> str | None:
    """
    AI analysis of robots.txt and crawler access — explains what the configuration
    means for AI bot visibility in plain language for a brand manager.
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key or not robots_result:
        return None

    found = robots_result.get("found", False)
    ai_results = robots_result.get("ai_agent_results", robots_result.get("ai_results", {}))
    sitemaps = robots_result.get("sitemaps", [])
    blocked_resources = robots_result.get("blocked_resources", [])
    sensitive_paths = robots_result.get("sensitive_paths", {})

    blocked_bots = [name for name, r in ai_results.items() if r.get("robots_allowed") is False or r.get("allowed") is False]
    allowed_bots = [name for name, r in ai_results.items() if r.get("robots_allowed") is True or r.get("allowed") is True]
    exposed_paths = [p for p, r in sensitive_paths.items() if not r.get("blocked", not r.get("accessible_per_robots", False))]

    lines = [
        f"Website: {base_url}",
        f"robots.txt present: {found}",
        f"AI bots explicitly allowed: {', '.join(allowed_bots) if allowed_bots else 'None'}",
        f"AI bots blocked: {', '.join(blocked_bots) if blocked_bots else 'None'}",
        f"Sitemaps declared: {len(sitemaps)} ({', '.join(sitemaps[:3]) if sitemaps else 'None'})",
        f"CSS/JS resources blocked: {', '.join(blocked_resources) if blocked_resources else 'None'}",
        f"Sensitive paths exposed to crawlers: {len(exposed_paths)} ({', '.join(exposed_paths[:5]) if exposed_paths else 'None'})",
    ]

    prompt = f"""You are an AI Search Visibility expert at Pattern analysing a website's robots.txt configuration.

{chr(10).join(lines)}

Write 4-6 bullet points (use • character) for a brand manager explaining:
1. What the current robots.txt setup means for AI crawler access (GPTBot, ClaudeBot, PerplexityBot)
2. The business impact of any blocked AI bots — what visibility is being lost
3. Whether the sitemap and resource access configuration helps or hurts AI indexing
4. Any security risks from exposed paths
5. One clear, priority recommendation to improve AI crawler access

Keep it concise and non-technical. Plain language a brand manager would understand. No markdown headers."""

    return _bifrost_call(api_key, prompt, max_tokens=500)


def analyse_llm_discoverability(base_url, llm_result, get_secret) -> str | None:
    """
    AI analysis of llm.txt and AI Info Page — explains what the discoverability
    setup means for how AI agents find and understand the brand.
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key or not llm_result:
        return None

    llm_txt_data = llm_result.get("llm_txt", llm_result.get("files", {}))
    ai_info = llm_result.get("ai_info_page", {})
    wellknown = llm_result.get("wellknown", {})

    found_files = [path for path, info in llm_txt_data.items() if info.get("found")] if llm_txt_data else []
    any_llm = bool(found_files)

    first_quality = {}
    if found_files:
        first_quality = llm_txt_data[found_files[0]].get("quality", {})

    wellknown_found = [path for path, info in wellknown.items() if info.get("found")] if wellknown else []

    lines = [
        f"Website: {base_url}",
        f"llm.txt files found: {', '.join(found_files) if found_files else 'None'}",
        f"llm.txt quality (first file): lines={first_quality.get('line_count', first_quality.get('lines', '?'))}, has_links={first_quality.get('has_links', '?')}, has_sections={first_quality.get('has_sections', '?')}",
        f"AI Info Page found: {ai_info.get('found', False)} at {ai_info.get('url', 'N/A')}",
        f"AI Info Page linked from footer: {ai_info.get('linked_from_footer', False)}",
        f"AI Info Page indexable: {ai_info.get('indexable', 'unknown')}",
        f"Well-known AI files found: {', '.join(wellknown_found) if wellknown_found else 'None'}",
    ]

    prompt = f"""You are an AI Search Visibility expert at Pattern analysing how discoverable a brand is to AI agents.

{chr(10).join(lines)}

Write 4-6 bullet points (use • character) for a brand manager explaining:
1. What llm.txt and the AI Info Page do — and whether this site has them set up correctly
2. The business impact of missing or incomplete AI guidance files — what AI agents do when they can't find this information
3. How the current setup affects whether AI assistants (ChatGPT, Perplexity, Claude) can accurately describe the brand
4. One clear, priority action to most improve AI discoverability this week

Keep it concise and non-technical. Plain language a brand manager would understand. No markdown headers."""

    return _bifrost_call(api_key, prompt, max_tokens=500)


def ai_analyse_js_gap(url, comparison, page_label, get_secret) -> str | None:
    """
    JS gap AI analysis via Bifrost (BIFROST_API_KEY).
    Generates a client-friendly explanation of HTML vs JS content gaps per page.
    """
    api_key = get_secret("BIFROST_API_KEY", "")
    if not api_key or not comparison:
        return None

    comp_lines = []
    for c in comparison.get("comparison", []):
        status = "MISSING" if c["status"] == "missing" else "OK"
        comp_lines.append(f"- {c['name']}: HTML={c['html_val']}, JS-rendered={c['js_val']} ({status})")

    html_len = comparison.get("html_summary", {}).get("text_content_length", 0)
    js_len   = comparison.get("js_summary", {}).get("text_content_length", 0)

    prompt = f"""You are an AI SEO expert analysing a website's AI-readiness.
A page was loaded twice: once as raw HTML (what AI crawlers see) and once with JavaScript rendered (what a browser sees).

URL: {url}
Page type: {page_label}

CONTENT COMPARISON:
{chr(10).join(comp_lines)}

HTML text content: {html_len:,} chars
JS-rendered text: {js_len:,} chars
Hidden behind JS: {max(0, js_len - html_len):,} chars

Write 4-6 bullet points (use • character) for a brand manager explaining:
1. What critical content AI crawlers are MISSING on this page
2. The business impact — what happens when AI can't see this (be specific to the page type)
3. One clear recommendation to fix the biggest gap

Keep it concise and non-technical. Plain language a brand manager would understand. No markdown headers."""

    return _bifrost_call(api_key, prompt, max_tokens=500)
