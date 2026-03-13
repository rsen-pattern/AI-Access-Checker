# -*- coding: utf-8 -*-
"""
checks.py — LLM Access Checker Audit Logic
5 Pillars: JS Rendering · Robots & Security · Schema & Meta · Semantic & Content · LLM Discoverability
All V2 categories integrated.
"""

import re
import json
import time
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from protego import Protego
from concurrent.futures import ThreadPoolExecutor, as_completed

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

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

SENSITIVE_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/account", "/my-account", "/user", "/profile",
    "/checkout", "/cart", "/payment",
    "/api", "/api/v1", "/graphql",
    "/staging", "/preview", "/dev", "/test",
    "/cms", "/backend", "/dashboard", "/panel",
    "/config", "/env", "/.env", "/debug",
    "/phpmyadmin", "/adminer", "/database",
    "/wp-json", "/xmlrpc.php", "/feed", "/trackback",
]

CMS_PROFILES = {
    "shopify": {
        "name": "Shopify",
        "customer_paths": ["/account", "/account/login", "/account/register", "/account/addresses", "/account/orders"],
        "must_block": ["/cart", "/checkouts", "/account"],
        "must_allow": ["/collections/", "/products/", "/pages/"],
        "extra_sensitive": ["/checkout/", "/account/addresses", "/account/orders"],
    },
    "woocommerce": {
        "name": "WooCommerce",
        "customer_paths": ["/my-account/", "/my-account/orders/", "/my-account/edit-account/", "/checkout/"],
        "must_block": ["/wp-admin", "/wp-login.php", "/my-account"],
        "must_allow": ["/product/", "/product-category/", "/shop/"],
        "extra_sensitive": ["/wp-json/", "/xmlrpc.php", "/wp-content/debug.log"],
    },
    "magento": {
        "name": "Magento",
        "customer_paths": ["/customer/account/", "/customer/account/login/", "/checkout/", "/checkout/cart/"],
        "must_block": ["/customer/", "/checkout/", "/admin"],
        "must_allow": ["/catalog/product/", "/catalog/category/"],
        "extra_sensitive": ["/graphql", "/rest/V1/", "/pub/media/"],
    },
    "bigcommerce": {
        "name": "BigCommerce",
        "customer_paths": ["/account.php", "/login.php", "/account.php?action=order_status"],
        "must_block": ["/cart.php", "/login.php", "/account.php"],
        "must_allow": ["/products/", "/categories/", "/brands/"],
        "extra_sensitive": ["/api/storefront/", "/internalapi/"],
    },
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
}


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def fetch(url, timeout=15, user_agent=None):
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


def extract_jsonld(soup):
    items = []
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            if isinstance(data, list):
                items.extend(data)
            elif "@graph" in data:
                items.extend(data["@graph"])
            else:
                items.append(data)
        except (json.JSONDecodeError, TypeError):
            pass
    return items


def normalise_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")): url = "https://" + url
    return url


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 1: JS RENDERING — API CASCADE + COMPARISON
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_js_rendered(url, get_secret):
    """Cascading JS render: ScrapingBee → Scrapfly → Browserless."""
    providers = [
        ("ScrapingBee", "SCRAPINGBEE_API_KEY", lambda key: requests.get(
            "https://app.scrapingbee.com/api/v1/",
            params={"api_key": key, "url": url, "render_js": "true", "premium_proxy": "false"}, timeout=45)),
        ("Scrapfly", "SCRAPFLY_API_KEY", None),
        ("Browserless", "BROWSERLESS_API_KEY", None),
    ]
    errors = []
    # ScrapingBee
    key = get_secret("SCRAPINGBEE_API_KEY", "")
    if key:
        try:
            resp = requests.get("https://app.scrapingbee.com/api/v1/",
                params={"api_key": key, "url": url, "render_js": "true", "premium_proxy": "false"}, timeout=45)
            if resp.status_code == 200 and len(resp.text) > 200:
                return resp.text, "ScrapingBee", None
            errors.append(f"ScrapingBee: HTTP {resp.status_code}")
        except Exception as e:
            errors.append(f"ScrapingBee: {e}")
    # Scrapfly
    key = get_secret("SCRAPFLY_API_KEY", "")
    if key:
        try:
            resp = requests.get("https://api.scrapfly.io/scrape",
                params={"key": key, "url": url, "render_js": "true", "asp": "false"}, timeout=45)
            if resp.status_code == 200:
                html = resp.json().get("result", {}).get("content", "")
                if html and len(html) > 200:
                    return html, "Scrapfly", None
            errors.append(f"Scrapfly: HTTP {resp.status_code}")
        except Exception as e:
            errors.append(f"Scrapfly: {e}")
    # Browserless
    key = get_secret("BROWSERLESS_API_KEY", "")
    if key:
        try:
            resp = requests.post(f"https://chrome.browserless.io/content?token={key}",
                json={"url": url, "waitFor": 3000}, timeout=45)
            if resp.status_code == 200 and len(resp.text) > 200:
                return resp.text, "Browserless", None
            errors.append(f"Browserless: HTTP {resp.status_code}")
        except Exception as e:
            errors.append(f"Browserless: {e}")

    if errors:
        return None, None, f"All providers failed: {'; '.join(errors)}"
    return None, None, "No JS rendering API keys configured. Add keys in Streamlit Secrets."


def analyse_content(html):
    """Extract key content elements from HTML string."""
    soup = BeautifulSoup(html, "html.parser")
    r = {}
    t = soup.find("title"); r["title"] = t.get_text(strip=True) if t else ""
    md = soup.find("meta", attrs={"name": "description"}); r["meta_description"] = md.get("content", "") if md else ""
    r["h1_tags"] = [h.get_text(strip=True) for h in soup.find_all("h1")][:10]
    r["h2_tags"] = [h.get_text(strip=True) for h in soup.find_all("h2")][:20]
    text = soup.get_text()
    r["prices"] = list(set(re.findall(r'[\$£€]\s?\d+[\.,]?\d*', text)))[:20]
    pe = soup.find_all(class_=re.compile(r'price|cost|amount', re.I)) + soup.find_all(attrs={"itemprop": "price"})
    if pe and not r["prices"]:
        for el in pe[:10]:
            txt = el.get_text(strip=True)
            if txt: r["prices"].append(txt)
    imgs = soup.find_all("img")
    r["images_total"] = len(imgs)
    r["images_with_alt"] = sum(1 for i in imgs if i.get("alt", "").strip())
    r["images_without_alt"] = sum(1 for i in imgs if not i.get("alt", "").strip())
    navs = soup.find_all("nav")
    r["nav_links"] = sum(len(n.find_all("a")) for n in navs)
    r["total_links"] = len(soup.find_all("a", href=True))
    r["product_elements"] = len(soup.find_all(class_=re.compile(r'product|item|card', re.I)))
    pag = soup.find_all(class_=re.compile(r'pagination|pager|page-nav', re.I))
    r["pagination"] = len(pag) > 0 or bool(soup.find("a", string=re.compile(r'^(next|›|»|→)', re.I)))
    r["text_length"] = len(soup.get_text(separator=" ", strip=True))
    r["html_length"] = len(html)
    r["reviews"] = len(soup.find_all(class_=re.compile(r'review|testimonial|rating', re.I)))
    r["forms"] = len(soup.find_all("form"))
    # Page-type specific
    r["variants"] = len(soup.find_all("select", class_=re.compile(r'variant|option|size|color', re.I))) + len(soup.find_all(class_=re.compile(r'swatch|variant-option', re.I)))
    r["add_to_cart"] = len(soup.find_all("button", string=re.compile(r'add.to.cart|add.to.bag|buy.now', re.I))) + len(soup.find_all("form", attrs={"action": re.compile(r'cart|basket', re.I)}))
    r["product_cards"] = len(soup.find_all(class_=re.compile(r'product-card|product-item|product-grid-item|product-tile', re.I)))
    filter_els = soup.find_all(class_=re.compile(r'filter|facet|refine', re.I))
    r["filters"] = len(filter_els)
    r["sort_options"] = len(soup.find_all(class_=re.compile(r'sort-by|sort-option|sorting', re.I))) + len(soup.find_all("select", id=re.compile(r'sort', re.I)))
    r["article_body"] = len(soup.find_all("article"))
    r["author_elements"] = len(soup.find_all(class_=re.compile(r'author', re.I)))
    r["date_elements"] = len(soup.find_all("time", attrs={"datetime": True}))
    r["search_form"] = 1 if (soup.find("form", attrs={"role": "search"}) or soup.find("input", attrs={"type": "search"})) else 0
    return r


def build_comparison(html_str, js_str, page_type="homepage"):
    """Compare HTML vs JS content, customised by page type."""
    h = analyse_content(html_str)
    j = analyse_content(js_str)

    # Common metrics
    metrics = [
        ("Page Title", h["title"] or "Missing", j["title"] or "Missing", "AI can't identify page topic"),
        ("Text Content", h["text_length"], j["text_length"], "AI sees very little about your page"),
        ("H1 Headings", len(h["h1_tags"]), len(j["h1_tags"]), "AI can't identify page topic"),
        ("Navigation Links", h["nav_links"], j["nav_links"], "AI can't discover other pages"),
        ("Total Links", h["total_links"], j["total_links"], "Reduces crawl paths for AI"),
        ("Images", h["images_total"], j["images_total"], "No visual context for AI"),
        ("Images with Alt", h["images_with_alt"], j["images_with_alt"], "AI can't understand images"),
    ]

    # Page-type specific
    if page_type == "product":
        metrics.extend([
            ("Product Prices", len(h["prices"]), len(j["prices"]), "AI cannot show your pricing"),
            ("Variants/Options", h["variants"], j["variants"], "AI can't see product options"),
            ("Add-to-Cart", h["add_to_cart"], j["add_to_cart"], "Action engines can't find purchase path"),
            ("Reviews/Ratings", h["reviews"], j["reviews"], "AI won't surface your social proof"),
        ])
    elif page_type == "category":
        metrics.extend([
            ("Product Cards", h["product_cards"], j["product_cards"], "AI sees empty collection"),
            ("Product Prices", len(h["prices"]), len(j["prices"]), "AI can't compare your prices"),
            ("Filters/Facets", h["filters"], j["filters"], "AI can't refine product selection"),
            ("Sort Options", h["sort_options"], j["sort_options"], "AI can't organise products"),
            ("Pagination", 1 if h["pagination"] else 0, 1 if j["pagination"] else 0, "AI only sees first page"),
        ])
    elif page_type == "blog":
        metrics.extend([
            ("Article Elements", h["article_body"], j["article_body"], "AI can't find article content"),
            ("Author Info", h["author_elements"], j["author_elements"], "AI can't attribute content"),
            ("Date Elements", h["date_elements"], j["date_elements"], "AI can't determine freshness"),
        ])
    else:  # homepage
        metrics.extend([
            ("Product Elements", h["product_elements"], j["product_elements"], "AI can't see featured products"),
            ("Search Form", h["search_form"], j["search_form"], "AI can't search your site"),
            ("Forms", h["forms"], j["forms"], "AI can't interact with your site"),
        ])

    comparison = []
    for name, hv, jv, impact in metrics:
        is_str = isinstance(hv, str)
        if is_str:
            status = "ok" if hv != "Missing" else "missing"
            delta = 0
        else:
            status = "missing" if jv > hv else "ok"
            delta = jv - hv if jv > hv else 0
        comparison.append({"name": name, "html_val": hv, "js_val": jv, "status": status, "delta": delta, "impact": impact if status == "missing" else ""})

    # Text ratio
    text_ratio = round(h["text_length"] / max(j["text_length"], 1) * 100)
    html_ratio = round(h["text_length"] / max(h["html_length"], 1) * 100, 1)
    total_missing = sum(1 for c in comparison if c["status"] == "missing")
    gap_severity = total_missing / max(len(comparison), 1)

    return {"comparison": comparison, "html": h, "js": j, "text_ratio": text_ratio, "html_text_ratio": html_ratio, "gap_severity": gap_severity, "total_missing": total_missing}


def detect_js_frameworks(html):
    soup = BeautifulSoup(html, "html.parser")
    fw = []
    root = soup.find(id="root") or soup.find(id="__next") or soup.find(id="app")
    if root and len(root.get_text(strip=True)) < 50:
        fw.append(("React / Next.js", "high", "Empty root container"))
    if soup.find(id="__nuxt") or soup.find(attrs={"data-v-app": True}):
        fw.append(("Vue.js / Nuxt", "high", "Vue app container"))
    if soup.find(attrs={"ng-app": True}) or soup.find("app-root"):
        fw.append(("Angular", "high", "Angular root"))
    ns = [n for n in soup.find_all("noscript") if "javascript" in n.get_text().lower()]
    if ns: fw.append(("JS Required", "high", f"{len(ns)} noscript warning(s)"))
    scripts = soup.find_all("script", src=True)
    bundled = [s for s in scripts if any(x in (s.get("src","") or "") for x in ["chunk","bundle","webpack","main.","app."])]
    if len(bundled) > 3: fw.append(("Bundled JS", "medium", f"{len(bundled)} bundled scripts"))
    return fw


def check_js_rendering(url, page_type, get_secret):
    """Full JS rendering check with API cascade."""
    resp, err = fetch(url)
    if err or not resp or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}

    raw_html = resp.text
    frameworks = detect_js_frameworks(raw_html)
    html_content = analyse_content(raw_html)
    js_html, provider, js_err = fetch_js_rendered(url, get_secret)

    comparison = None
    if js_html:
        comparison = build_comparison(raw_html, js_html, page_type)
        comparison["provider"] = provider

    # Score
    score = 100
    risk_factors = []
    if comparison:
        gap = comparison["gap_severity"]
        if gap >= 0.6: score -= 50; risk_factors.append(f"Severe: {comparison['total_missing']} content types hidden behind JS")
        elif gap >= 0.3: score -= 30; risk_factors.append(f"Significant: {comparison['total_missing']} content types hidden behind JS")
        elif gap >= 0.1: score -= 15; risk_factors.append(f"Minor: {comparison['total_missing']} content types differ")
        for c in comparison["comparison"]:
            if c["status"] == "missing" and c["name"] in ("Product Prices", "Navigation Links", "Product Cards", "Add-to-Cart"):
                score -= 10; risk_factors.append(f"{c['name']}: {c['html_val']} in HTML vs {c['js_val']} with JS")
        if comparison["text_ratio"] < 20:
            score -= 15; risk_factors.append(f"Only {comparison['text_ratio']}% of text visible without JS")
    else:
        # HTML-only fallback scoring
        high = [f for f in frameworks if f[1] == "high"]
        if high: score -= 30; risk_factors.append(f"JS framework: {', '.join(f[0] for f in high)}")
        if not html_content["title"]: score -= 10; risk_factors.append("No title in HTML")
        if not html_content["h1_tags"]: score -= 10; risk_factors.append("No H1 in HTML")
        if html_content["text_length"] < 200: score -= 20; risk_factors.append(f"Only {html_content['text_length']} chars text")
        if html_content["nav_links"] == 0: score -= 10; risk_factors.append("No nav links in HTML")

    return {"score": max(0, min(100, score)), "frameworks": frameworks, "content": html_content,
            "comparison": comparison, "provider": provider, "js_error": js_err,
            "risk_factors": risk_factors, "error": None}


def ai_analyse_gap(url, comparison, page_label, get_secret):
    """Claude API analysis of JS gap."""
    key = get_secret("ANTHROPIC_API_KEY", "")
    if not key or not comparison: return None
    comp_lines = [f"- {c['name']}: HTML={c['html_val']}, JS={c['js_val']} ({'MISSING' if c['status']=='missing' else 'OK'})" for c in comparison["comparison"]]
    prompt = f"""You are an AI SEO expert. A page was loaded as raw HTML and with JavaScript. Compare:
URL: {url} | Page type: {page_label}
{chr(10).join(comp_lines)}
HTML text: {comparison['html']['text_length']} chars, JS text: {comparison['js']['text_length']} chars
Write 4-6 bullet points (use • character) for a brand manager explaining: what AI crawlers miss, the business impact, and the top fix. Keep it concise and non-technical."""
    try:
        r = requests.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-sonnet-4-20250514", "max_tokens": 500, "messages": [{"role": "user", "content": prompt}]}, timeout=30)
        if r.status_code == 200: return r.json()["content"][0]["text"]
    except Exception: pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 2: ROBOTS, SECURITY & CRAWLABILITY
# ═══════════════════════════════════════════════════════════════════════════════

def detect_cms(html, url):
    soup = BeautifulSoup(html, "html.parser")
    scores = {"shopify": 0, "woocommerce": 0, "magento": 0, "bigcommerce": 0}
    if "cdn.shopify.com" in html: scores["shopify"] += 5
    if soup.find("meta", attrs={"name": "shopify-digital-wallet"}): scores["shopify"] += 3
    if re.search(r'Shopify\.(shop|theme)', html): scores["shopify"] += 3
    if "woocommerce" in html.lower(): scores["woocommerce"] += 3
    if soup.find("body", class_=re.compile(r'woocommerce', re.I)): scores["woocommerce"] += 3
    if "/wp-content/" in html: scores["woocommerce"] += 2
    if soup.find("script", string=re.compile(r'require\.config|Magento_', re.I)): scores["magento"] += 4
    if soup.find("body", class_=re.compile(r'catalog-', re.I)): scores["magento"] += 3
    if "bigcommerce" in html.lower(): scores["bigcommerce"] += 4
    best = max(scores, key=scores.get)
    return (best, scores[best]) if scores[best] >= 3 else (None, 0)


def check_robots_security(base_url, homepage_html):
    """Combined robots.txt, security, bot crawl, CMS, and crawlability check."""
    results = {"robots": {}, "bot_crawl": {}, "security": {}, "cms": {}, "performance": {}, "score": 0}

    # ── Robots.txt ────────────────────────────────────────────────────────
    robots_url = urljoin(base_url, "/robots.txt")
    resp, err = fetch(robots_url)

    if err or not resp:
        results["robots"] = {"found": False, "url": robots_url, "error": err, "status_code": None, "raw": ""}
    elif resp.status_code != 200:
        # Flag non-200 responses
        results["robots"] = {"found": False, "url": robots_url, "status_code": resp.status_code,
            "error": f"robots.txt returned HTTP {resp.status_code}" + (" — access forbidden, check server config" if resp.status_code == 403 else " — server error" if resp.status_code >= 500 else ""), "raw": ""}
    else:
        raw = resp.text
        try: parser = Protego.parse(raw)
        except Exception: parser = None

        sitemaps = []
        for line in raw.splitlines():
            s = line.split("#")[0].strip()
            if s.lower().startswith("sitemap:"): sitemaps.append(s.split(":", 1)[1].strip())

        # AI bot access
        ai_results = {}
        for company, bots in AI_BOTS.items():
            for bot_name, ua in bots.items():
                allowed = None
                if parser:
                    try: allowed = parser.can_fetch(ua, base_url + "/")
                    except Exception: pass
                ai_results[bot_name] = {"company": company, "allowed": allowed}

        # Sensitive paths
        sensitive = {}
        for path in SENSITIVE_PATHS:
            exposed = True
            if parser:
                try: exposed = parser.can_fetch(BROWSER_UA, base_url + path)
                except Exception: pass
            sensitive[path] = {"exposed": exposed, "mentioned": path.lower() in raw.lower()}

        # Blocked CSS/JS
        blocked_res = []
        for ext in [".css", ".js", "/css/", "/js/", "/static/", "/assets/"]:
            if parser:
                try:
                    if not parser.can_fetch(BROWSER_UA, base_url + ext): blocked_res.append(ext)
                except Exception: pass

        results["robots"] = {"found": True, "url": robots_url, "status_code": 200, "raw": raw,
            "parser": parser, "sitemaps": sitemaps, "ai_results": ai_results,
            "sensitive": sensitive, "blocked_resources": blocked_res}

    # ── CMS Detection ─────────────────────────────────────────────────────
    cms_id, cms_score = detect_cms(homepage_html, base_url)
    results["cms"] = {"id": cms_id, "name": CMS_PROFILES.get(cms_id, {}).get("name", "Unknown") if cms_id else None, "score": cms_score}

    # CMS-specific security checks
    cms_checks = []
    if cms_id and cms_id in CMS_PROFILES:
        profile = CMS_PROFILES[cms_id]
        robots_raw = results["robots"].get("raw", "").lower()
        for path in profile["must_block"]:
            blocked = f"disallow: {path}" in robots_raw
            cms_checks.append({"path": path, "should_block": True, "is_blocked": blocked})
        for path in profile["must_allow"]:
            blocked = f"disallow: {path}" in robots_raw
            cms_checks.append({"path": path, "should_block": False, "is_blocked": blocked})
        for path in profile["customer_paths"]:
            blocked = f"disallow: {path}" in robots_raw
            cms_checks.append({"path": path, "should_block": True, "is_blocked": blocked, "is_customer": True})
    results["cms"]["checks"] = cms_checks

    # ── Live Bot Crawl ────────────────────────────────────────────────────
    def _crawl_bot(url, name, ua, parser):
        try:
            r_allowed = True
            if parser:
                try: r_allowed = parser.can_fetch(ua, url)
                except: r_allowed = None
            start = time.time()
            r = requests.get(url, headers={"User-Agent": ua}, timeout=20, allow_redirects=True)
            lt = time.time() - start
            soup = BeautifulSoup(r.text, "html.parser")
            rm = soup.find("meta", attrs={"name": "robots"})
            rm_content = rm.get("content", "") if rm else ""
            return {"bot": name, "status": r.status_code, "robots_allowed": r_allowed,
                    "meta": rm_content or "None", "noindex": "noindex" in rm_content.lower(),
                    "allowed": r.status_code == 200 and r_allowed and "noindex" not in rm_content.lower(),
                    "size": len(r.text), "time": round(lt, 2), "error": None}
        except Exception as e:
            return {"bot": name, "status": None, "robots_allowed": None, "meta": "N/A",
                    "noindex": False, "allowed": False, "size": 0, "time": 0, "error": str(e)}

    parser = results["robots"].get("parser")
    bot_results = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {}
        for company, bots in AI_BOTS.items():
            for name, ua in bots.items():
                f = ex.submit(_crawl_bot, base_url + "/", name, ua, parser)
                futs[f] = (company, name)
        for f in as_completed(futs):
            company, name = futs[f]
            r = f.result(); r["company"] = company; bot_results[name] = r
    results["bot_crawl"] = bot_results

    # ── Performance & Crawlability (from homepage HTML) ───────────────────
    soup = BeautifulSoup(homepage_html, "html.parser")
    head = soup.find("head")
    scripts = soup.find_all("script", src=True)
    head_blocking = [s for s in (head.find_all("script", src=True) if head else []) if not s.get("defer") and not s.get("async")]
    stylesheets = soup.find_all("link", rel="stylesheet")
    all_els = soup.find_all()
    imgs = soup.find_all("img")
    lazy = [i for i in imgs if i.get("loading") == "lazy"]
    iframes = soup.find_all("iframe")

    results["performance"] = {
        "dom_size": len(all_els),
        "scripts": len(scripts),
        "stylesheets": len(stylesheets),
        "head_blocking": len(head_blocking),
        "images": len(imgs),
        "lazy_images": len(lazy),
        "imgs_with_dimensions": len([i for i in imgs if i.get("width") and i.get("height")]),
        "iframes": len(iframes),
        "inline_styles": len(soup.find_all(style=True)),
        "font_display": bool(re.search(r'font-display\s*:', homepage_html)),
    }

    # ── Well-known AI files ───────────────────────────────────────────────
    wk = {}
    for path in ["/.well-known/ai-plugin.json", "/.well-known/aip.json", "/.well-known/tdmrep.json"]:
        u = urljoin(base_url, path)
        r, e = fetch(u, timeout=8)
        found = r and r.status_code == 200 and not r.text.strip().startswith("<!DOCTYPE")
        wk[path] = {"found": found, "url": u}
    results["wellknown"] = wk

    # ── Score ─────────────────────────────────────────────────────────────
    score = 0
    rob = results["robots"]
    if rob.get("found"):
        score += 30
        if rob.get("sitemaps"): score += 10
        if not rob.get("blocked_resources"): score += 10
        else: score -= 10
        ai_r = rob.get("ai_results", {})
        specific = sum(1 for r in ai_r.values() if r["allowed"] is not None)
        if specific > 3: score += 10
        sens = rob.get("sensitive", {})
        blocked_count = sum(1 for s in sens.values() if not s["exposed"])
        if blocked_count > len(SENSITIVE_PATHS) * 0.5: score += 10
    elif rob.get("status_code") in (403, 500, 502, 503):
        score += 10  # exists but errored

    # CMS checks
    if cms_checks:
        correct = sum(1 for c in cms_checks if (c["should_block"] and c["is_blocked"]) or (not c["should_block"] and not c["is_blocked"]))
        score += round(correct / len(cms_checks) * 20)

    # Performance
    perf = results["performance"]
    if perf["dom_size"] < 1500: score += 5
    if perf["head_blocking"] < 5: score += 5

    results["score"] = min(100, max(0, score))
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 3: SCHEMA & META (page-level)
# ═══════════════════════════════════════════════════════════════════════════════

def check_schema_meta(url):
    """Combined schema, meta, and entity/authority check per page."""
    resp, err = fetch(url)
    if err or not resp or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}

    soup = BeautifulSoup(resp.text, "html.parser")
    result = {"schema": {}, "meta": {}, "entity": {}, "score": 0}

    # ── Schema ────────────────────────────────────────────────────────────
    jsonld = extract_jsonld(soup)
    schemas = []
    all_types = []
    for item in jsonld:
        t = item.get("@type", "Unknown")
        if isinstance(t, list): t = ", ".join(t)
        schemas.append({"type": t, "data": item})
        if isinstance(item.get("@type"), list): all_types.extend(item["@type"])
        elif item.get("@type"): all_types.append(item["@type"])

    # Microdata
    for md in soup.find_all(attrs={"itemscope": True})[:10]:
        it = md.get("itemtype", "Unknown")
        tn = it.split("/")[-1] if "/" in it else it
        schemas.append({"type": tn, "data": {}})
        all_types.append(tn)

    # Validations
    validations = []
    for s in schemas:
        if s["data"] and s["type"] != "Unknown":
            pt = s["type"].split(",")[0].strip()
            exp = SCHEMA_KEY_FIELDS.get(pt, [])
            if exp:
                present = [f for f in exp if f in s["data"] and s["data"][f]]
                missing = [f for f in exp if f not in s["data"] or not s["data"][f]]
                validations.append({"type": s["type"], "present": present, "missing": missing, "completeness": round(len(present)/len(exp)*100)})

    type_set = set(all_types)
    essential = {"Organization", "WebSite", "WebPage", "BreadcrumbList"}
    found_essential = essential & type_set
    missing_essential = essential - type_set

    # Speakable & sameAs
    has_speakable = any("speakable" in json.dumps(d).lower() for d in jsonld)
    has_sameas = any("sameAs" in d for d in jsonld)

    result["schema"] = {"schemas": schemas, "types": list(type_set), "validations": validations,
        "essential_found": list(found_essential), "essential_missing": list(missing_essential),
        "has_speakable": has_speakable, "has_sameas": has_sameas, "count": len(schemas)}

    # ── Meta & Discoverability ────────────────────────────────────────────
    title = soup.find("title"); title_text = title.get_text(strip=True) if title else ""
    meta_desc = soup.find("meta", attrs={"name": "description"}); desc_text = meta_desc.get("content", "") if meta_desc else ""
    canonical = soup.find("link", rel="canonical"); canon_href = canonical.get("href", "") if canonical else ""
    og = {m.get("property"): m.get("content", "") for m in soup.find_all("meta", attrs={"property": re.compile(r'^og:')})}
    tw = {m.get("name"): m.get("content", "") for m in soup.find_all("meta", attrs={"name": re.compile(r'^twitter:')})}
    hreflangs = soup.find_all("link", rel="alternate", hreflang=True)
    robots_meta = soup.find("meta", attrs={"name": "robots"})
    robots_content = robots_meta.get("content", "") if robots_meta else ""

    result["meta"] = {"title": title_text, "title_len": len(title_text), "desc": desc_text, "desc_len": len(desc_text),
        "canonical": canon_href, "og_tags": og, "twitter_tags": tw, "hreflangs": len(hreflangs),
        "robots_meta": robots_content, "has_noindex": "noindex" in robots_content.lower()}

    # ── Entity & Authority ────────────────────────────────────────────────
    author_meta = soup.find("meta", attrs={"name": "author"})
    author_schema = any("author" in json.dumps(d).lower() for d in jsonld)
    author_el = soup.find(class_=re.compile(r'author', re.I))
    date_meta = soup.find("meta", attrs={"property": "article:published_time"})
    date_time = soup.find("time", attrs={"datetime": True})
    date_schema = any("datePublished" in json.dumps(d) for d in jsonld)
    org_schema = any(d.get("@type") in ("Organization", "Corporation", "LocalBusiness") for d in jsonld)
    links_text = [a.get_text(strip=True).lower() for a in soup.find_all("a", href=True)]
    links_href = [a.get("href", "").lower() for a in soup.find_all("a", href=True)]
    legal_kw = ["privacy", "terms", "legal", "cookie", "about"]
    found_legal = [k for k in legal_kw if any(k in l for l in links_href) or any(k in t for t in links_text)]

    result["entity"] = {"has_author": bool(author_meta or author_schema or author_el),
        "has_date": bool(date_meta or date_time or date_schema), "has_org_schema": org_schema,
        "legal_pages": found_legal}

    # ── Score ─────────────────────────────────────────────────────────────
    score = 0
    if schemas: score += 20
    if len(found_essential) >= 3: score += 15
    elif found_essential: score += 8
    if validations:
        avg_c = sum(v["completeness"] for v in validations) / len(validations)
        score += round(avg_c * 0.15)
    if title_text: score += 8
    if desc_text: score += 5
    if canon_href: score += 5
    if len(og) >= 3: score += 5
    if result["entity"]["has_author"]: score += 5
    if result["entity"]["has_date"]: score += 5
    if org_schema: score += 5
    if has_sameas: score += 3
    if has_speakable: score += 4

    result["score"] = min(100, score)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 4: SEMANTIC STRUCTURE & CONTENT QUALITY (page-level)
# ═══════════════════════════════════════════════════════════════════════════════

def check_semantic_content(url):
    """Combined semantic HTML, accessibility, internal linking, and citability."""
    resp, err = fetch(url)
    if err or not resp or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}

    soup = BeautifulSoup(resp.text, "html.parser")
    html = resp.text
    parsed = urlparse(url)
    result = {"headings": {}, "semantic": {}, "accessibility": {}, "linking": {}, "citability": {}, "score": 0}

    # ── Headings ──────────────────────────────────────────────────────────
    all_h = soup.find_all(re.compile(r'^h[1-6]$'))
    h_list = [{"level": int(h.name[1]), "text": h.get_text(strip=True)[:120]} for h in all_h]
    levels = [h["level"] for h in h_list]
    hierarchy_ok = True
    for i in range(1, len(levels)):
        if levels[i] > levels[i-1] + 1: hierarchy_ok = False; break
    h1_count = sum(1 for h in h_list if h["level"] == 1)

    result["headings"] = {"list": h_list, "h1_count": h1_count, "total": len(h_list), "hierarchy_ok": hierarchy_ok and len(h_list) > 0}

    # ── Semantic Elements ─────────────────────────────────────────────────
    sem_tags = {}
    for tag in ["article", "section", "nav", "aside", "main", "header", "footer", "figure", "time"]:
        c = len(soup.find_all(tag))
        if c: sem_tags[tag] = c
    text_len = len(soup.get_text(separator=" ", strip=True))
    html_len = len(html)
    ratio = round(text_len / max(html_len, 1) * 100, 1)

    result["semantic"] = {"elements": sem_tags, "count": len(sem_tags), "text_len": text_len, "html_len": html_len, "text_ratio": ratio}

    # ── Accessibility for Agents ──────────────────────────────────────────
    html_tag = soup.find("html"); lang = html_tag.get("lang", "") if html_tag else ""
    imgs = soup.find_all("img")
    imgs_alt = sum(1 for i in imgs if i.get("alt") is not None)
    imgs_good_alt = sum(1 for i in imgs if i.get("alt", "").strip())
    landmarks = soup.find_all(["header", "nav", "main", "aside", "footer"])
    links = soup.find_all("a", href=True)
    bad_links = [l for l in links if l.get_text(strip=True).lower() in ("click here", "here", "read more", "more", "link", "")]
    inputs = [i for i in soup.find_all(["input", "select", "textarea"]) if i.get("type") not in ("hidden", "submit", "button")]
    unlabeled = [i for i in inputs if not (soup.find("label", attrs={"for": i.get("id", "")}) if i.get("id") else False) and not i.get("aria-label")]

    result["accessibility"] = {"lang": lang, "images": len(imgs), "images_with_alt": imgs_alt, "images_good_alt": imgs_good_alt,
        "landmarks": len(landmarks), "bad_link_texts": len(bad_links), "total_links": len(links),
        "unlabeled_inputs": len(unlabeled)}

    # ── Internal Linking ──────────────────────────────────────────────────
    internal = []; external = []; anchors = []
    for a in links:
        href = a.get("href", "")
        if href.startswith("#"): anchors.append(href)
        elif href.startswith(("http://", "https://")):
            if urlparse(href).netloc == parsed.netloc: internal.append(href)
            else: external.append(href)
        elif href.startswith("/") or not href.startswith(("mailto:", "tel:", "javascript:")): internal.append(href)
    navs = soup.find_all("nav"); nav_links = sum(len(n.find_all("a")) for n in navs)
    breadcrumb = soup.find(class_=re.compile(r'breadcrumb', re.I)) or soup.find(attrs={"aria-label": re.compile(r'breadcrumb', re.I)})
    ids_on_page = len(soup.find_all(id=True))

    result["linking"] = {"internal": len(internal), "external": len(external), "anchors": len(anchors),
        "navs": len(navs), "nav_links": nav_links, "has_breadcrumb": bool(breadcrumb), "anchor_targets": ids_on_page}

    # ── Citability & Answer-Readiness ─────────────────────────────────────
    jsonld = extract_jsonld(soup)
    faq_schema = any(d.get("@type") == "FAQPage" for d in jsonld)
    faq_els = soup.find_all(class_=re.compile(r'faq|accordion', re.I))
    tables = soup.find_all("table"); tables_th = [t for t in tables if t.find("th")]
    dl_lists = soup.find_all("dl")
    paras = soup.find_all("p")
    lead_p = None
    for p in paras[:5]:
        txt = p.get_text(strip=True)
        if len(txt) > 50: lead_p = txt[:150]; break
    ols = soup.find_all("ol"); uls = soup.find_all("ul")
    headings_with_id = [h for h in all_h if h.get("id") or (h.parent and h.parent.get("id"))]
    blockquotes = soup.find_all("blockquote")

    result["citability"] = {"has_faq": faq_schema or bool(faq_els), "tables": len(tables), "tables_with_headers": len(tables_th),
        "dl_lists": len(dl_lists), "lead_paragraph": lead_p, "ordered_lists": len(ols), "unordered_lists": len(uls),
        "deep_linkable_headings": len(headings_with_id), "total_headings": len(all_h), "blockquotes": len(blockquotes)}

    # ── Score ─────────────────────────────────────────────────────────────
    score = 0
    if h1_count == 1: score += 10
    elif h1_count > 0: score += 5
    if hierarchy_ok and h_list: score += 10
    if len(sem_tags) >= 4: score += 10
    elif sem_tags: score += 5
    if ratio >= 20: score += 8
    elif ratio >= 10: score += 4
    if lang: score += 5
    if imgs and imgs_alt == len(imgs): score += 5
    elif imgs_good_alt: score += 3
    if len(landmarks) >= 3: score += 5
    if not bad_links: score += 5
    if len(internal) >= 5: score += 5
    elif internal: score += 3
    if breadcrumb: score += 5
    if ids_on_page >= 3: score += 3
    if faq_schema or faq_els: score += 5
    if lead_p: score += 5
    if headings_with_id: score += 4
    if nav_links > 0: score += 5
    if not unlabeled: score += 5

    result["score"] = min(100, score)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 5: LLM.TXT & AI DISCOVERABILITY
# ═══════════════════════════════════════════════════════════════════════════════

def check_llm_discoverability(base_url, homepage_html):
    """Check llm.txt variants + AI Info Page."""
    result = {"llm_txt": {}, "ai_info_page": {}, "score": 0}

    # ── llm.txt variants ──────────────────────────────────────────────────
    for path in ["/llm.txt", "/llms.txt", "/llms-full.txt", "/.well-known/llm.txt"]:
        u = urljoin(base_url, path)
        r, e = fetch(u, timeout=10)
        found = False; content = ""; quality = {}
        if r and r.status_code == 200:
            text = r.text.strip()
            if len(text) > 10 and not text.startswith(("<!DOCTYPE", "<html")):
                found = True; content = text[:5000]
                quality = {"has_title": bool(re.search(r'^#\s+', text, re.M)), "has_desc": len(text) > 100,
                    "has_links": bool(re.search(r'https?://', text)), "has_sections": text.count("\n\n") > 2,
                    "chars": len(text), "lines": len(text.splitlines())}
        result["llm_txt"][path] = {"found": found, "url": u, "content": content, "quality": quality}

    # ── AI Info Page check ────────────────────────────────────────────────
    ai_paths = ["/ai-info", "/llm-info", "/ai-information", "/llm-information", "/ai-info-page", "/for-ai"]
    ai_page_found = None
    for path in ai_paths:
        u = urljoin(base_url, path)
        r, e = fetch(u, timeout=10)
        if r and r.status_code == 200:
            text = r.text.strip()
            if len(text) > 500 and not "404" in text[:200].lower():
                ai_page_found = {"url": u, "path": path}
                break

    # Check if AI info page linked from footer
    soup = BeautifulSoup(homepage_html, "html.parser")
    footer = soup.find("footer")
    ai_linked_footer = False
    if footer and ai_page_found:
        footer_links = [a.get("href", "").lower() for a in footer.find_all("a", href=True)]
        ai_linked_footer = any(ai_page_found["path"] in l for l in footer_links)

    # Also check if any link in footer points to known AI info paths
    if footer and not ai_page_found:
        footer_links = [a.get("href", "") for a in footer.find_all("a", href=True)]
        footer_text = [a.get_text(strip=True).lower() for a in footer.find_all("a", href=True)]
        for href, text in zip(footer_links, footer_text):
            if any(kw in href.lower() or kw in text for kw in ["ai-info", "llm-info", "for-ai", "ai information"]):
                ai_page_found = {"url": urljoin(base_url, href), "path": href}
                ai_linked_footer = True
                break

    ai_info = {"found": ai_page_found is not None, "url": ai_page_found["url"] if ai_page_found else None,
        "linked_from_footer": ai_linked_footer}

    # If found, analyse the page
    if ai_page_found:
        r, e = fetch(ai_page_found["url"])
        if r and r.status_code == 200:
            ai_soup = BeautifulSoup(r.text, "html.parser")
            ai_text = ai_soup.get_text(separator=" ", strip=True)
            robots_m = ai_soup.find("meta", attrs={"name": "robots"})
            is_indexable = not (robots_m and "noindex" in robots_m.get("content", "").lower())
            has_updated = bool(re.search(r'(last\s+updated|updated\s+on|reviewed\s+on)\s*:?\s*\d', ai_text, re.I))

            ai_info["indexable"] = is_indexable
            ai_info["has_updated_date"] = has_updated
            ai_info["text_length"] = len(ai_text)
            ai_info["is_simple_html"] = len(ai_soup.find_all("script", src=True)) < 5

    result["ai_info_page"] = ai_info

    # ── Score ─────────────────────────────────────────────────────────────
    score = 0
    any_llm = any(v["found"] for v in result["llm_txt"].values())
    if any_llm:
        score += 30
        best = next(v for v in result["llm_txt"].values() if v["found"])
        q = best.get("quality", {})
        if q.get("has_title"): score += 5
        if q.get("has_desc"): score += 5
        if q.get("has_links"): score += 8
        if q.get("has_sections"): score += 5
        if q.get("chars", 0) > 500: score += 3

    if ai_info.get("found"):
        score += 20
        if ai_info.get("linked_from_footer"): score += 10
        if ai_info.get("indexable"): score += 5
        if ai_info.get("has_updated_date"): score += 5
        if ai_info.get("is_simple_html"): score += 4

    result["score"] = min(100, score)
    return result
