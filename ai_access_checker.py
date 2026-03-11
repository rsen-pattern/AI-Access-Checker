# -*- coding: utf-8 -*-
"""
AI Accessibility Checker — Full LLM Access Audit
Matches all 4 pillars from the Pattern blog:
  1. JavaScript Rendering
  2. LLM.txt
  3. Robots.txt & Crawler Access
  4. Schema (Structured Data)
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
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── CONFIG ───────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Accessibility Checker",
    page_icon="🤖",
    layout="wide",
)

# ─── AI BOT DEFINITIONS (from original script + expanded) ────────────────────
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

# Sensitive paths to scan (from blog: /admin, /account, /checkout, CMS backends, staging)
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

# Expected schema types per page template (from blog)
EXPECTED_SCHEMA_TYPES = {
    "site_wide": ["Organization", "WebSite", "WebPage", "BreadcrumbList"],
    "product": ["Product", "Offer", "Brand", "AggregateRating", "Review"],
    "article": ["Article", "NewsArticle", "BlogPosting"],
    "faq": ["FAQPage", "Question", "Answer"],
    "local": ["LocalBusiness", "Store", "Place"],
    "collection": ["ItemList", "CollectionPage", "ProductCollection"],
}

# Key fields per schema type
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

# Industry benchmarks from blog
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
    """Return (response, error_string)."""
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


# ═══════════════════════════════════════════════════════════════════════════════
# PILLAR 1: JAVASCRIPT RENDERING
# ═══════════════════════════════════════════════════════════════════════════════

def detect_js_frameworks(html: str):
    """Detect JS frameworks that indicate JS-dependent rendering."""
    soup = BeautifulSoup(html, "html.parser")
    frameworks = []

    # React
    if soup.find(id="root") or soup.find(id="__next") or soup.find(id="app"):
        root_el = soup.find(id="root") or soup.find(id="__next") or soup.find(id="app")
        if root_el and len(root_el.get_text(strip=True)) < 50:
            frameworks.append(("React / Next.js", "high", "Empty root container detected — content likely rendered client-side"))

    # Vue
    if soup.find(id="__nuxt") or soup.find(attrs={"data-v-app": True}):
        frameworks.append(("Vue.js / Nuxt", "high", "Vue app container detected"))

    # Angular
    if soup.find(attrs={"ng-app": True}) or soup.find("app-root"):
        frameworks.append(("Angular", "high", "Angular app root detected"))

    # Generic SPA indicators
    noscript_tags = soup.find_all("noscript")
    noscript_warnings = [ns for ns in noscript_tags if "enable javascript" in ns.get_text().lower() or "requires javascript" in ns.get_text().lower()]
    if noscript_warnings:
        frameworks.append(("JavaScript Required", "high", f"Found {len(noscript_warnings)} <noscript> warning(s)"))

    # Webpack/bundled JS
    scripts = soup.find_all("script", src=True)
    bundled = [s for s in scripts if any(x in (s.get("src", "") or "") for x in ["chunk", "bundle", "webpack", "main.", "app."])]
    if len(bundled) > 3:
        frameworks.append(("Bundled JS (Webpack/Vite)", "medium", f"{len(bundled)} bundled script(s) detected"))

    return frameworks


def analyse_html_content(html: str):
    """Extract key content elements from raw HTML (what a simple crawler sees)."""
    soup = BeautifulSoup(html, "html.parser")

    results = {
        "title": "",
        "meta_description": "",
        "h1_tags": [],
        "h2_tags": [],
        "prices": [],
        "images_with_alt": 0,
        "images_without_alt": 0,
        "nav_links": 0,
        "product_elements": [],
        "text_content_length": 0,
        "total_links": 0,
        "pagination": False,
    }

    # Title
    title = soup.find("title")
    results["title"] = title.get_text(strip=True) if title else ""

    # Meta description
    meta_desc = soup.find("meta", attrs={"name": "description"})
    results["meta_description"] = meta_desc.get("content", "") if meta_desc else ""

    # Headings
    results["h1_tags"] = [h.get_text(strip=True) for h in soup.find_all("h1")][:10]
    results["h2_tags"] = [h.get_text(strip=True) for h in soup.find_all("h2")][:20]

    # Prices (common patterns)
    text = soup.get_text()
    price_patterns = re.findall(r'[\$£€]\s?\d+[\.,]?\d*', text)
    results["prices"] = list(set(price_patterns))[:20]

    # Also check for price-related attributes/classes
    price_elements = soup.find_all(class_=re.compile(r'price|cost|amount', re.I))
    price_elements += soup.find_all(attrs={"itemprop": "price"})
    if price_elements and not results["prices"]:
        for el in price_elements[:10]:
            txt = el.get_text(strip=True)
            if txt:
                results["prices"].append(txt)

    # Images
    images = soup.find_all("img")
    results["images_with_alt"] = sum(1 for img in images if img.get("alt", "").strip())
    results["images_without_alt"] = sum(1 for img in images if not img.get("alt", "").strip())

    # Navigation
    nav = soup.find_all("nav")
    nav_links = sum(len(n.find_all("a")) for n in nav)
    results["nav_links"] = nav_links

    # Total links
    results["total_links"] = len(soup.find_all("a", href=True))

    # Product-specific elements
    product_indicators = soup.find_all(class_=re.compile(r'product|item|card', re.I))
    results["product_elements"] = len(product_indicators)

    # Pagination
    pagination = soup.find_all(class_=re.compile(r'pagination|pager|page-nav', re.I))
    results["pagination"] = len(pagination) > 0 or bool(soup.find("a", string=re.compile(r'^(next|›|»|→)', re.I)))

    # Text content
    results["text_content_length"] = len(soup.get_text(separator=" ", strip=True))

    return results


def check_js_rendering(url: str):
    """
    Compare what's in raw HTML vs what would need JS.
    We fetch HTML-only and analyse what a simple crawler can see.
    """
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"error": err or f"HTTP {resp.status_code if resp else '?'}"}

    html = resp.text
    frameworks = detect_js_frameworks(html)
    content = analyse_html_content(html)

    # Calculate JS rendering risk score
    risk_factors = []
    score = 100  # start at 100, subtract for issues

    # Framework detection
    high_risk_frameworks = [f for f in frameworks if f[1] == "high"]
    if high_risk_frameworks:
        score -= 30
        risk_factors.append(f"JS framework detected: {', '.join(f[0] for f in high_risk_frameworks)}")

    # Missing title
    if not content["title"]:
        score -= 10
        risk_factors.append("No <title> tag in raw HTML")

    # Missing H1
    if not content["h1_tags"]:
        score -= 10
        risk_factors.append("No <h1> tags found in raw HTML")

    # No prices visible (on product-like pages)
    if content["product_elements"] > 0 and not content["prices"]:
        score -= 15
        risk_factors.append("Product elements detected but no prices visible in HTML — likely JS-rendered")

    # Very low text content
    if content["text_content_length"] < 200:
        score -= 20
        risk_factors.append(f"Very little text content in raw HTML ({content['text_content_length']} chars)")
    elif content["text_content_length"] < 500:
        score -= 10
        risk_factors.append(f"Low text content in raw HTML ({content['text_content_length']} chars)")

    # No navigation in HTML
    if content["nav_links"] == 0:
        score -= 10
        risk_factors.append("No navigation links found in raw HTML")

    # No pagination
    if not content["pagination"] and content["product_elements"] > 5:
        score -= 5
        risk_factors.append("Product listing page but no pagination in raw HTML")

    # <noscript> warnings
    noscript_fw = [f for f in frameworks if f[0] == "JavaScript Required"]
    if noscript_fw:
        score -= 15

    score = max(0, min(100, score))

    return {
        "score": score,
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
            # Validate it's actually an llm.txt (not a 404 page served as 200)
            if len(text) > 10 and not text.startswith("<!DOCTYPE") and not text.startswith("<html"):
                found = True
                content = text[:5000]
                # Assess quality
                quality = {
                    "has_title": bool(re.search(r'^#\s+', text, re.M)),
                    "has_description": len(text) > 100,
                    "has_links": bool(re.search(r'https?://', text)),
                    "has_sections": text.count("\n\n") > 2,
                    "char_count": len(text),
                    "line_count": len(text.splitlines()),
                }

        results[path] = {"found": found, "url": url, "content": content, "quality": quality}

    # Calculate pillar score
    any_found = any(v["found"] for v in results.values())
    if not any_found:
        score = 0
    else:
        score = 50  # base for having one
        found_items = [v for v in results.values() if v["found"]]
        best = found_items[0]
        q = best.get("quality", {})
        if q.get("has_title"):
            score += 10
        if q.get("has_description"):
            score += 10
        if q.get("has_links"):
            score += 15
        if q.get("has_sections"):
            score += 10
        if q.get("char_count", 0) > 500:
            score += 5

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

    # Extract sitemaps
    sitemaps = []
    for line in raw.splitlines():
        stripped = line.split("#")[0].strip()
        if stripped.lower().startswith("sitemap:"):
            sitemap_url = stripped.split(":", 1)[1].strip()
            sitemaps.append(sitemap_url)

    # Check each AI bot against robots.txt using Protego
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
                "company": company,
                "ua_string": ua_string,
                "robots_allowed": allowed,
            }

    # Sensitive path exposure scan
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

        # Also check if the path is explicitly mentioned (Disallow or Allow) in robots.txt
        mentioned = path.lower() in raw.lower()
        sensitive_results[path] = {
            "accessible_per_robots": exposed,
            "mentioned_in_robots": mentioned,
        }

    # Check for blocked CSS/JS
    blocked_resources = []
    for ext_pattern in [".css", ".js", "/css/", "/js/", "/static/", "/assets/"]:
        test_path = base_url + ext_pattern
        if parser:
            try:
                can_access = parser.can_fetch(BROWSER_UA, test_path)
                if not can_access:
                    blocked_resources.append(ext_pattern)
            except Exception:
                pass

    # Score calculation
    score = 50  # base for having robots.txt
    ai_specific_mentioned = sum(1 for name, r in ai_agent_results.items() if r["robots_allowed"] is not None and name != "*")
    if ai_specific_mentioned > 3:
        score += 15
    elif ai_specific_mentioned > 0:
        score += 10

    if sitemaps:
        score += 10

    # Sensitive paths that are properly blocked
    properly_blocked = sum(1 for p, r in sensitive_results.items() if not r["accessible_per_robots"])
    if properly_blocked > len(SENSITIVE_PATHS) * 0.5:
        score += 10
    elif properly_blocked > 0:
        score += 5

    if not blocked_resources:
        score += 10  # CSS/JS not blocked is good
    else:
        score -= 10  # blocking CSS/JS hurts rendering

    exposed_sensitive = sum(1 for p, r in sensitive_results.items() if r["accessible_per_robots"] and r["mentioned_in_robots"])
    if exposed_sensitive > 3:
        score -= 10

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
    """Recursively extract all @type values from nested schema."""
    if types_found is None:
        types_found = []
    if isinstance(data, dict):
        t = data.get("@type")
        if t:
            if isinstance(t, list):
                types_found.extend(t)
            else:
                types_found.append(t)
        for v in data.values():
            flatten_schema_types(v, types_found)
    elif isinstance(data, list):
        for item in data:
            flatten_schema_types(item, types_found)
    return types_found


def validate_schema_fields(schema_type: str, data: dict):
    """Check if key fields are present for a given schema type."""
    expected = SCHEMA_KEY_FIELDS.get(schema_type, [])
    if not expected:
        return {"expected": [], "present": [], "missing": [], "completeness": 100}

    present = [f for f in expected if f in data and data[f]]
    missing = [f for f in expected if f not in data or not data[f]]
    completeness = round(len(present) / len(expected) * 100) if expected else 100

    return {
        "expected": expected,
        "present": present,
        "missing": missing,
        "completeness": completeness,
    }


def check_schema(url: str):
    resp, err = fetch(url)
    if err or resp is None or resp.status_code != 200:
        return {"found": False, "error": err, "schemas": [], "types_found": [], "score": 0, "validations": []}

    soup = BeautifulSoup(resp.text, "html.parser")
    schemas = []
    all_types = []

    # JSON-LD
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            items = data if isinstance(data, list) else [data]
            for item in items:
                # Handle @graph
                if "@graph" in item:
                    for graph_item in item["@graph"]:
                        schema_type = graph_item.get("@type", "Unknown")
                        if isinstance(schema_type, list):
                            schema_type = ", ".join(schema_type)
                        schemas.append({"format": "JSON-LD", "type": schema_type, "data": graph_item})
                else:
                    schema_type = item.get("@type", "Unknown")
                    if isinstance(schema_type, list):
                        schema_type = ", ".join(schema_type)
                    schemas.append({"format": "JSON-LD", "type": schema_type, "data": item})
            all_types.extend(flatten_schema_types(data))
        except (json.JSONDecodeError, TypeError):
            schemas.append({"format": "JSON-LD", "type": "Parse Error", "data": {}})

    # Microdata
    microdata_items = soup.find_all(attrs={"itemscope": True})
    for item in microdata_items[:10]:
        item_type = item.get("itemtype", "Unknown")
        type_name = item_type.split("/")[-1] if "/" in item_type else item_type
        schemas.append({"format": "Microdata", "type": type_name, "data": {}})
        all_types.append(type_name)

    # Validate each schema
    validations = []
    for s in schemas:
        if s["data"] and s["type"] != "Parse Error":
            # Handle comma-separated types
            primary_type = s["type"].split(",")[0].strip()
            v = validate_schema_fields(primary_type, s["data"])
            v["type"] = s["type"]
            validations.append(v)

    # Check which expected categories are covered
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

    # Score
    score = 0
    if schemas:
        score = 30
        avg_completeness = sum(v["completeness"] for v in validations) / len(validations) if validations else 50
        score += round(avg_completeness * 0.3)  # up to 30 more
        site_wide_coverage = coverage.get("site_wide", {}).get("coverage_pct", 0)
        score += round(site_wide_coverage * 0.2)  # up to 20 more
        if len(schemas) >= 3:
            score += 10
        if any(s["type"] in ("Product", "Offer") for s in schemas):
            score += 10

    return {
        "found": len(schemas) > 0,
        "schemas": schemas,
        "types_found": list(set(all_types)),
        "validations": validations,
        "coverage": coverage,
        "score": min(score, 100),
        "error": None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# LIVE BOT CRAWL TEST (from original script)
# ═══════════════════════════════════════════════════════════════════════════════

def crawl_as_bot(url: str, bot_name: str, ua_string: str, robots_parser):
    """Actually send a request AS the bot and compare results."""
    try:
        robots_allowed = True
        if robots_parser:
            try:
                robots_allowed = robots_parser.can_fetch(ua_string, url)
            except Exception:
                robots_allowed = None

        headers = {"User-Agent": ua_string}
        start = time.time()
        resp = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
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
        text_len = len(soup.get_text(separator=" ", strip=True))

        return {
            "bot_name": bot_name,
            "status_code": resp.status_code,
            "robots_allowed": robots_allowed,
            "robots_meta": robots_meta or "None",
            "has_noindex": has_noindex,
            "is_allowed": is_allowed,
            "title": title_text,
            "load_time": round(load_time, 2),
            "content_length": text_len,
            "error": None,
        }
    except Exception as e:
        return {
            "bot_name": bot_name,
            "status_code": None,
            "robots_allowed": None,
            "robots_meta": "N/A",
            "has_noindex": False,
            "is_allowed": False,
            "title": "",
            "load_time": 0,
            "content_length": 0,
            "error": str(e),
        }


def run_live_bot_crawl(url: str, robots_parser):
    """Run crawl tests with all bots in parallel."""
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
# META TAGS & HEADERS (supplementary)
# ═══════════════════════════════════════════════════════════════════════════════

def check_page_meta(url: str):
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

    x_robots = resp.headers.get("X-Robots-Tag", None)
    nosnippet_count = len(soup.find_all(attrs={"data-nosnippet": True}))
    html_length = len(resp.text)
    text_length = len(soup.get_text(separator=" ", strip=True))

    return {
        "meta_tags": meta_tags,
        "x_robots_tag": x_robots,
        "nosnippet_elements": nosnippet_count,
        "html_length": html_length,
        "text_length": text_length,
        "error": None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# WELL-KNOWN AI FILES (supplementary)
# ═══════════════════════════════════════════════════════════════════════════════

def check_wellknown(base_url: str):
    results = {}
    paths = ["/.well-known/ai-plugin.json", "/.well-known/aip.json", "/.well-known/tdmrep.json"]
    for path in paths:
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


# ═══════════════════════════════════════════════════════════════════════════════
# OVERALL SCORING
# ═══════════════════════════════════════════════════════════════════════════════

def compute_overall(js_score, llm_score, robots_score, schema_score):
    overall = round(js_score * 0.25 + llm_score * 0.15 + robots_score * 0.30 + schema_score * 0.30)
    return overall


def score_color(score):
    if score >= 75:
        return "🟢"
    elif score >= 50:
        return "🟡"
    else:
        return "🔴"


def score_bar(score, benchmark=None):
    """Return HTML for a score bar with optional benchmark marker."""
    color = "#00c853" if score >= 75 else "#ffd600" if score >= 50 else "#ff1744"
    benchmark_html = ""
    if benchmark is not None:
        benchmark_html = f'<div style="position:absolute;left:{benchmark}%;top:-2px;bottom:-2px;width:3px;background:#fff;border:1px solid #333;border-radius:2px;" title="Industry Benchmark: {benchmark}%"></div>'
    return f'''
    <div style="position:relative;background:#2a2a3e;border-radius:8px;height:16px;overflow:visible;margin:4px 0;">
        <div style="width:{score}%;background:{color};height:100%;border-radius:8px;transition:width 0.5s;"></div>
        {benchmark_html}
    </div>
    '''


# ═══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
    .score-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
        color: white;
        border: 1px solid #0f3460;
    }
    .score-number { font-size: 2.5rem; font-weight: 800; line-height: 1.1; }
    .score-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; opacity: 0.8; margin-top: 0.2rem; }
    .benchmark-note { font-size: 0.7rem; opacity: 0.6; margin-top: 0.3rem; }
    .section-divider { border-top: 2px solid #e0e0e0; margin: 1.5rem 0; }
    .bot-allowed { color: #00c853; font-weight: 600; }
    .bot-blocked { color: #ff1744; font-weight: 600; }
    .bot-unknown { color: #ffd600; font-weight: 600; }
    div[data-testid="stExpander"] { border: 1px solid #e0e0e0; border-radius: 8px; margin-bottom: 0.4rem; }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 style='text-align:center;'>🤖 AI Accessibility Checker</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;opacity:0.7;'>Full LLM Access Audit — JavaScript Rendering · LLM.txt · Robots.txt · Schema · Live Bot Crawl</p>", unsafe_allow_html=True)

col_input, col_btn = st.columns([4, 1])
with col_input:
    url_input = st.text_input("Enter website URL", placeholder="example.com", label_visibility="collapsed")
with col_btn:
    run_audit = st.button("Run Audit", type="primary", use_container_width=True)

# Optional: additional test URLs
with st.expander("⚙️ Advanced Options"):
    extra_urls_raw = st.text_area(
        "Additional page URLs to test (one per line)",
        placeholder="https://example.com/product/example\nhttps://example.com/blog/example",
        height=80,
    )
    run_bot_crawl = st.checkbox("Run live bot crawl test (sends requests as each AI bot)", value=True)
    extra_urls = [u.strip() for u in extra_urls_raw.strip().splitlines() if u.strip()] if extra_urls_raw else []


if run_audit and url_input:
    url = normalise_url(url_input)
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    all_test_urls = [url] + [normalise_url(u) for u in extra_urls]

    progress = st.progress(0, text="Starting audit…")

    # ── PILLAR 1: JS RENDERING ────────────────────────────────────────────
    progress.progress(5, text="Pillar 1/4 — JavaScript Rendering Assessment…")
    js_results = {}
    for test_url in all_test_urls:
        js_results[test_url] = check_js_rendering(test_url)
    js_score = round(sum(r.get("score", 0) for r in js_results.values()) / len(js_results))

    # ── PILLAR 2: LLM.TXT ────────────────────────────────────────────────
    progress.progress(20, text="Pillar 2/4 — LLM.txt Discovery…")
    llm_result = check_llm_txt(base_url)
    llm_score = llm_result["score"]

    # ── PILLAR 3: ROBOTS.TXT ─────────────────────────────────────────────
    progress.progress(35, text="Pillar 3/4 — Robots.txt & Crawler Access…")
    robots_result = check_robots(base_url)
    robots_score = robots_result["score"]

    # ── PILLAR 4: SCHEMA ──────────────────────────────────────────────────
    progress.progress(50, text="Pillar 4/4 — Schema Structured Data…")
    schema_results = {}
    for test_url in all_test_urls:
        schema_results[test_url] = check_schema(test_url)
    schema_score = round(sum(r.get("score", 0) for r in schema_results.values()) / len(schema_results))

    # ── SUPPLEMENTARY: META, WELL-KNOWN ───────────────────────────────────
    progress.progress(65, text="Supplementary — Meta Tags & Well-Known Files…")
    meta_result = check_page_meta(url)
    wellknown_result = check_wellknown(base_url)

    # ── LIVE BOT CRAWL ────────────────────────────────────────────────────
    bot_crawl_results = {}
    if run_bot_crawl:
        progress.progress(75, text="Live Bot Crawl — Testing as each AI agent…")
        bot_crawl_results = run_live_bot_crawl(url, robots_result.get("parser"))

    # ── SCORING ───────────────────────────────────────────────────────────
    progress.progress(95, text="Generating report…")
    overall = compute_overall(js_score, llm_score, robots_score, schema_score)
    time.sleep(0.3)
    progress.progress(100, text="Audit complete!")
    time.sleep(0.4)
    progress.empty()

    # ══════════════════════════════════════════════════════════════════════
    # RESULTS
    # ══════════════════════════════════════════════════════════════════════

    st.markdown("---")
    st.subheader(f"Results for `{base_url}`")

    # ── SCORE CARDS (4 pillars + overall) ─────────────────────────────────
    c0, c1, c2, c3, c4 = st.columns(5)
    pillar_data = [
        (c0, "Overall", overall, None),
        (c1, "JS Rendering", js_score, BENCHMARKS["js_rendering"]),
        (c2, "LLM.txt", llm_score, BENCHMARKS["llm_txt"]),
        (c3, "Robots.txt", robots_score, BENCHMARKS["robots_txt"]),
        (c4, "Schema", schema_score, BENCHMARKS["schema"]),
    ]
    for col, label, sc, bench in pillar_data:
        emoji = score_color(sc)
        bench_html = f'<div class="benchmark-note">Benchmark: {bench}%</div>' if bench is not None else ""
        col.markdown(f"""
        <div class="score-card">
            <div class="score-number">{emoji} {sc}</div>
            <div class="score-label">{label}</div>
            {bench_html}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")
    st.caption("⬜ White markers on bars below = industry benchmark (Pattern Q1 2025 AU DTC audit)")

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 1: JS RENDERING
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### ⚡ Pillar 1 — JavaScript Rendering Assessment")
    st.markdown(f"**Pillar Score: {js_score}/100**  |  Industry Benchmark: {BENCHMARKS['js_rendering']}%")
    st.markdown(score_bar(js_score, BENCHMARKS["js_rendering"]), unsafe_allow_html=True)

    for test_url, js_r in js_results.items():
        if js_r.get("error"):
            st.error(f"❌ Could not fetch `{test_url}`: {js_r['error']}")
            continue

        with st.expander(f"📄 `{test_url}` — Score: {js_r['score']}/100"):
            # Frameworks
            if js_r["frameworks"]:
                st.markdown("**JS Frameworks / Indicators Detected:**")
                for name, severity, note in js_r["frameworks"]:
                    icon = "🔴" if severity == "high" else "🟡"
                    st.markdown(f"{icon} **{name}** ({severity} risk) — {note}")
            else:
                st.success("✅ No JS-heavy framework indicators detected — content likely accessible to simple crawlers")

            # Risk factors
            if js_r["risk_factors"]:
                st.markdown("**Risk Factors:**")
                for rf in js_r["risk_factors"]:
                    st.markdown(f"⚠️ {rf}")

            # Content summary
            c = js_r["content"]
            st.markdown("**Content Visible in Raw HTML:**")
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(f"- **Title:** {c['title'] or '❌ Missing'}")
                st.markdown(f"- **Meta Description:** {'✅ Present' if c['meta_description'] else '❌ Missing'}")
                st.markdown(f"- **H1 Tags:** {len(c['h1_tags'])} found")
                st.markdown(f"- **H2 Tags:** {len(c['h2_tags'])} found")
                st.markdown(f"- **Prices in HTML:** {len(c['prices'])} found")
            with col_b:
                st.markdown(f"- **Nav Links:** {c['nav_links']}")
                st.markdown(f"- **Total Links:** {c['total_links']}")
                st.markdown(f"- **Images (with alt):** {c['images_with_alt']}")
                st.markdown(f"- **Images (no alt):** {c['images_without_alt']}")
                st.markdown(f"- **Pagination:** {'✅ Found' if c['pagination'] else '❌ Not found'}")
                st.markdown(f"- **Text Content:** {c['text_content_length']:,} chars")

            if c["prices"]:
                st.caption(f"Prices found: {', '.join(c['prices'][:10])}")

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 2: LLM.TXT
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### 📖 Pillar 2 — LLM.txt Discovery")
    st.markdown(f"**Pillar Score: {llm_score}/100**  |  Industry Benchmark: {BENCHMARKS['llm_txt']}%")
    st.markdown(score_bar(llm_score, BENCHMARKS["llm_txt"]), unsafe_allow_html=True)

    any_llm = any(v["found"] for v in llm_result["files"].values())
    if any_llm:
        for path, info in llm_result["files"].items():
            if info["found"]:
                st.success(f"✅ Found: `{path}`")
                q = info.get("quality", {})
                if q:
                    cols = st.columns(4)
                    cols[0].metric("Lines", q.get("line_count", "?"))
                    cols[1].metric("Characters", q.get("char_count", "?"))
                    cols[2].metric("Has Links", "✅" if q.get("has_links") else "❌")
                    cols[3].metric("Has Sections", "✅" if q.get("has_sections") else "❌")
                with st.expander(f"View contents of `{path}`"):
                    st.code(info["content"], language="markdown")
            else:
                st.caption(f"— `{path}` not found")
    else:
        st.warning("⚠️ No llm.txt files found. Adoption is still extremely rare (industry benchmark: 0%).")
        st.info("💡 **llm.txt** is an emerging standard providing direct guidance to AI bots on what to prioritise. [Learn more →](https://llmstxt.org)")

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 3: ROBOTS.TXT
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### 📋 Pillar 3 — Robots.txt & Crawler Access")
    st.markdown(f"**Pillar Score: {robots_score}/100**  |  Industry Benchmark: {BENCHMARKS['robots_txt']}%")
    st.markdown(score_bar(robots_score, BENCHMARKS["robots_txt"]), unsafe_allow_html=True)

    if robots_result["found"]:
        st.success(f"✅ robots.txt found at `{robots_result['url']}`")

        # AI Agent Access Table
        st.markdown("**AI Agent Access (from robots.txt rules):**")
        for company in AI_BOTS:
            company_bots = {k: v for k, v in robots_result["ai_agent_results"].items() if v["company"] == company}
            if company_bots:
                with st.expander(f"🏢 **{company}** ({len(company_bots)} agents)"):
                    for bot_name, info in company_bots.items():
                        if info["robots_allowed"] is True:
                            st.markdown(f'<span class="bot-allowed">✅ {bot_name}: Allowed</span>', unsafe_allow_html=True)
                        elif info["robots_allowed"] is False:
                            st.markdown(f'<span class="bot-blocked">🚫 {bot_name}: Blocked</span>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<span class="bot-unknown">❓ {bot_name}: Unknown</span>', unsafe_allow_html=True)

        # Sitemaps
        if robots_result["sitemaps"]:
            with st.expander(f"🗺️ Sitemaps ({len(robots_result['sitemaps'])} found)"):
                for sm in robots_result["sitemaps"]:
                    st.markdown(f"- `{sm}`")
        else:
            st.warning("⚠️ No sitemaps referenced in robots.txt")

        # Blocked CSS/JS
        if robots_result["blocked_resources"]:
            st.warning(f"⚠️ **Blocked resources detected:** {', '.join(robots_result['blocked_resources'])} — This can prevent AI agents from rendering your pages correctly")
        else:
            st.success("✅ CSS/JS resources are not blocked — AI agents can render pages properly")

        # Sensitive Path Exposure
        exposed_paths = [(p, r) for p, r in robots_result["sensitive_paths"].items() if r["accessible_per_robots"]]
        blocked_paths = [(p, r) for p, r in robots_result["sensitive_paths"].items() if not r["accessible_per_robots"]]

        with st.expander(f"🔐 Sensitive Path Scan — {len(exposed_paths)} exposed, {len(blocked_paths)} blocked"):
            if exposed_paths:
                st.markdown("**⚠️ Paths accessible to crawlers:**")
                for path, r in exposed_paths:
                    mention = " (mentioned in robots.txt)" if r["mentioned_in_robots"] else ""
                    st.markdown(f"- 🟡 `{path}`{mention}")
            if blocked_paths:
                st.markdown("**✅ Paths blocked by robots.txt:**")
                for path, r in blocked_paths[:10]:
                    st.markdown(f"- ✅ `{path}`")
                if len(blocked_paths) > 10:
                    st.caption(f"...and {len(blocked_paths) - 10} more")

        with st.expander("📄 Raw robots.txt"):
            st.code(robots_result["raw"][:8000], language="text")
    else:
        st.error(f"❌ No robots.txt found at `{robots_result['url']}`")

    # ══════════════════════════════════════════════════════════════════════
    # PILLAR 4: SCHEMA
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### 🧩 Pillar 4 — Schema (Structured Data)")
    st.markdown(f"**Pillar Score: {schema_score}/100**  |  Industry Benchmark: {BENCHMARKS['schema']}%")
    st.markdown(score_bar(schema_score, BENCHMARKS["schema"]), unsafe_allow_html=True)

    for test_url, sr in schema_results.items():
        if sr.get("error"):
            st.error(f"❌ Could not check `{test_url}`: {sr['error']}")
            continue

        with st.expander(f"📄 `{test_url}` — {'✅' if sr['found'] else '❌'} {len(sr['schemas'])} schema item(s)"):
            if sr["found"]:
                # Types found
                st.markdown(f"**Types Found:** {', '.join(sr['types_found'])}")

                # Coverage against expected types
                st.markdown("**Coverage by Category:**")
                for cat, cov in sr["coverage"].items():
                    if cov["found"]:
                        st.markdown(f"- ✅ **{cat.replace('_', ' ').title()}** — Found: {', '.join(cov['found'])} | Missing: {', '.join(cov['missing']) or 'None'}")
                    else:
                        missing_str = ", ".join(cov["missing"])
                        st.caption(f"- ❌ **{cat.replace('_', ' ').title()}** — None found (expected: {missing_str})")

                # Validation details
                if sr["validations"]:
                    st.markdown("**Field Completeness:**")
                    for v in sr["validations"]:
                        completeness = v["completeness"]
                        icon = "✅" if completeness >= 80 else "🟡" if completeness >= 50 else "🔴"
                        st.markdown(f"{icon} **{v['type']}** — {completeness}% complete")
                        if v["missing"]:
                            st.caption(f"   Missing: {', '.join(v['missing'])}")

                # Raw schema data
                for i, s in enumerate(sr["schemas"]):
                    if s["data"]:
                        with st.expander(f"View `{s['type']}` data"):
                            st.json(s["data"])
            else:
                st.warning("No Schema.org structured data found on this page.")
                st.info("💡 Adding JSON-LD schema helps AI agents understand your content. Expected types include: Organisation, WebSite, WebPage, BreadcrumbList, Product, Offer, FAQPage")

    # ══════════════════════════════════════════════════════════════════════
    # LIVE BOT CRAWL TEST
    # ══════════════════════════════════════════════════════════════════════
    if bot_crawl_results:
        st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
        st.markdown("### 🕷️ Live Bot Crawl Test")
        st.caption("Actual HTTP requests sent as each AI bot user agent")

        # Summary table
        allowed_count = sum(1 for r in bot_crawl_results.values() if r["is_allowed"])
        blocked_count = sum(1 for r in bot_crawl_results.values() if not r["is_allowed"])
        total_bots = len(bot_crawl_results)
        st.markdown(f"**{allowed_count}/{total_bots}** bots can access this page  |  **{blocked_count}** blocked")

        # Group by company
        companies_seen = []
        for bot_name, r in bot_crawl_results.items():
            if r["company"] not in companies_seen:
                companies_seen.append(r["company"])

        for company in companies_seen:
            company_results = {k: v for k, v in bot_crawl_results.items() if v["company"] == company}
            with st.expander(f"🏢 **{company}** — {sum(1 for r in company_results.values() if r['is_allowed'])}/{len(company_results)} allowed"):
                for bot_name, r in company_results.items():
                    if r["error"]:
                        st.markdown(f"❌ **{bot_name}**: Error — {r['error']}")
                    else:
                        status_icon = "✅" if r["is_allowed"] else "🚫"
                        status_text = "Allowed" if r["is_allowed"] else "BLOCKED"
                        st.markdown(f"{status_icon} **{bot_name}**: {status_text}")
                        st.caption(
                            f"HTTP {r['status_code']} · "
                            f"Robots.txt: {'Allowed' if r['robots_allowed'] else 'Blocked'} · "
                            f"Meta: {r['robots_meta']} · "
                            f"Content: {r['content_length']:,} chars · "
                            f"Load: {r['load_time']}s"
                        )

    # ══════════════════════════════════════════════════════════════════════
    # SUPPLEMENTARY: META TAGS & WELL-KNOWN
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### 🏷️ Supplementary — Meta Tags, HTTP Headers & AI Policy Files")

    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("**Page-Level Meta Tags**")
        if meta_result.get("error"):
            st.error(f"Could not fetch: {meta_result['error']}")
        else:
            if meta_result["meta_tags"]:
                for tag in meta_result["meta_tags"]:
                    st.markdown(f"- `<meta name=\"{tag['name']}\" content=\"{tag['content']}\">`")
            else:
                st.caption("No robots meta tags found")

            if meta_result.get("x_robots_tag"):
                st.markdown(f"- **X-Robots-Tag:** `{meta_result['x_robots_tag']}`")

            st.markdown(f"- **data-nosnippet elements:** {meta_result.get('nosnippet_elements', 0)}")

            html_len = meta_result.get("html_length", 0)
            text_len = meta_result.get("text_length", 0)
            if html_len > 0:
                ratio = text_len / html_len * 100
                st.markdown(f"- **Text-to-HTML ratio:** {ratio:.1f}% ({text_len:,} / {html_len:,} chars)")

    with col_right:
        st.markdown("**Well-Known AI Policy Files**")
        any_wk = any(v["found"] for v in wellknown_result.values())
        if any_wk:
            for path, info in wellknown_result.items():
                if info["found"]:
                    st.success(f"✅ `{path}`")
                else:
                    st.caption(f"— `{path}` not found")
        else:
            st.caption("No well-known AI policy files detected (ai-plugin.json, aip.json, tdmrep.json)")

    # ══════════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("<div class='section-divider'></div>", unsafe_allow_html=True)
    st.markdown("### 💡 Priority Recommendations")

    recs = []

    # JS Rendering
    if js_score < 60:
        recs.append(("🔴", "JS Rendering", "Critical content may be invisible to AI crawlers. Consider server-side rendering (SSR) or static generation for key product and marketing pages so prices, specs, and navigation are available in raw HTML."))
    elif js_score < 80:
        recs.append(("🟡", "JS Rendering", "Some content elements may require JavaScript. Review product pages to ensure prices, specifications, and pagination are visible in raw HTML."))

    # LLM.txt
    if llm_score == 0:
        recs.append(("🟡", "LLM.txt", "Create an llm.txt file to provide AI agents with a curated summary of your site, key pages, and content priorities. This is an emerging standard — early adoption gives you a competitive edge."))
    elif llm_score < 70:
        recs.append(("🟡", "LLM.txt", "Your llm.txt could be improved. Add clear sections, links to key pages, and descriptive content about your brand and products."))

    # Robots.txt
    if not robots_result["found"]:
        recs.append(("🔴", "Robots.txt", "Create a robots.txt file. This is the foundational control for managing all crawler access to your site."))
    else:
        if not robots_result["sitemaps"]:
            recs.append(("🟡", "Robots.txt", "Add sitemap references to your robots.txt so AI crawlers can discover all your important pages efficiently."))
        if robots_result["blocked_resources"]:
            recs.append(("🔴", "Robots.txt", f"CSS/JS resources are blocked ({', '.join(robots_result['blocked_resources'])}). This prevents AI agents from properly rendering your pages."))
        exposed = [(p, r) for p, r in robots_result["sensitive_paths"].items() if r["accessible_per_robots"]]
        critical_exposed = [p for p, r in exposed if any(x in p for x in ["/admin", "/api", "/.env", "/config", "/database"])]
        if critical_exposed:
            recs.append(("🔴", "Security", f"Sensitive paths are exposed to crawlers: {', '.join(critical_exposed[:5])}. Add Disallow rules or ensure these paths are properly gated."))

    # Schema
    if schema_score < 30:
        recs.append(("🔴", "Schema", "No or minimal structured data found. Add JSON-LD schema markup for Organisation, WebSite, BreadcrumbList at minimum. For product pages, add Product, Offer, and Brand schema with complete fields."))
    elif schema_score < 60:
        # Find missing fields
        all_missing = []
        for sr in schema_results.values():
            for v in sr.get("validations", []):
                all_missing.extend(v.get("missing", []))
        if all_missing:
            recs.append(("🟡", "Schema", f"Schema markup is incomplete. Key missing fields: {', '.join(set(all_missing)[:8])}. Complete these to help AI agents accurately extract your product data."))
        else:
            recs.append(("🟡", "Schema", "Expand your schema coverage. Consider adding FAQPage, Review, and AggregateRating types to give AI more structured data to work with."))

    if not recs:
        st.success("🎉 Excellent! Your site scores well across all four pillars. Continue monitoring as AI standards evolve.")
    else:
        for priority, pillar, text in recs:
            st.markdown(f"{priority} **{pillar}:** {text}")

    # ══════════════════════════════════════════════════════════════════════
    # FOOTER
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.caption("AI Accessibility Checker — Full LLM Access Audit matching Pattern's 4-pillar methodology. Benchmarks based on Pattern's Q1 2025 Australian DTC website audit. Results are based on publicly available data and standard HTTP requests.")

elif run_audit and not url_input:
    st.warning("Please enter a URL to audit.")
