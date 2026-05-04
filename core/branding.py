# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — branding constants.

Pure constants only. No imports beyond stdlib. Both UI entry points
(ai_access_checker.py and pages/7_🔒_LLM_Access_Checker.py) import from
here so brand colours, logos, and pillar copy live in one place.
"""

# ─── BRAND COLOURS ────────────────────────────────────────────────────────────
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

# ─── LOGOS / FAVICON ──────────────────────────────────────────────────────────
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

FAVICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 28 22"><path fill-rule="evenodd" clip-rule="evenodd" d="M0.197401 16.3997L16.2682 0.835708C16.5314 0.580806 16.9649 0.580806 17.2281 0.835708L21.1839 4.66673C21.4471 4.92913 21.4471 5.34148 21.1839 5.59638L5.11308 21.1604C4.84214 21.4153 4.41637 21.4153 4.15317 21.1604L0.197401 17.3294C-0.0658005 17.0745 -0.0658005 16.6546 0.197401 16.3997ZM13.4348 16.3997L22.8869 7.24577C23.1501 6.99086 23.5836 6.99086 23.8468 7.24577L27.8026 11.0768C28.0658 11.3392 28.0658 11.7515 27.8026 12.0064L18.3505 21.1604C18.0796 21.4153 17.6538 21.4153 17.3906 21.1604L13.4348 17.3294C13.1716 17.0745 13.1716 16.6546 13.4348 16.3997Z" fill="%23009bff"/></svg>'

# ─── PILLAR EXPLANATIONS ──────────────────────────────────────────────────────
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
        "what": "We parse all JSON-LD and Microdata per page. We validate field completeness including ecommerce-critical fields: GTIN/MPN (product identifiers required by AI shopping agents), MerchantReturnPolicy, shippingDetails, AggregateRating depth, and Organisation sameAs. We also check for price/schema consistency and outbound citations to authoritative domains.",
        "why": "Schema is the machine-readable 'entity card' that feeds both Google's Knowledge Graph and LLM entity understanding. Products without GTINs are excluded or deprioritised by AI shopping agents — research shows 60% of ecommerce catalogues have missing GTINs. Organisation sameAs connects your site to your LinkedIn, Wikipedia, and social profiles, creating the consistent entity presence AI systems use to verify and trust your brand.",
    },
    "semantic_content": {
        "what": "We check page structure signals that AI models rely on: heading hierarchy (H1→H2→H3 in logical order), semantic HTML elements (article, section, nav), accessibility attributes (alt text, lang, ARIA landmarks), whether pages open with a clear summary paragraph, and content quality (specific facts and figures vs vague marketing language). Each page in your audit is checked individually.",
        "why": "AI models read pages top-down and decide what to cite within the first few hundred tokens. A clear heading hierarchy tells the model what a page is about before it reads the body. Pages that open with a concise summary are significantly more likely to be quoted in AI responses. Princeton KDD research found that pages with specific statistics see up to 41% higher AI visibility — vague claims get skipped.",
    },
    "bot_crawl": {
        "what": "We simulate live HTTP requests to your homepage impersonating each major AI crawler user-agent — GPTBot, ClaudeBot, PerplexityBot, Google-Extended, and 11 others. We record the HTTP response code, content length, load time, robots.txt compliance, and any meta robots directives returned.",
        "why": "A site can look open in robots.txt but still block AI bots via Cloudflare, WAF rules, or server-level rate limiting. The only way to know if AI crawlers can actually reach your content is to send a request as them. A 403 or empty response here means AI systems are silently unable to index your site — regardless of your SEO setup.",
    },
}

# ─── HTTP / CRAWLER CONSTANTS ─────────────────────────────────────────────────
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

# ─── SCHEMA RUBRICS (UI-side copies) ──────────────────────────────────────────
# core/llm_access_checks.py has the canonical versions used during audit
# scoring. These are the simpler UI copies used at module scope in the
# entry-point files.
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
