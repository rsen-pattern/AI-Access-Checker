# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — render and utility helpers.

Shared between both UI entry points (ai_access_checker.py and
pages/7_🔒_LLM_Access_Checker.py). Contains pure utility functions,
HTTP fetch, and HTML component builders.
"""

import math
import re

import requests
import streamlit as st

from core.branding import BRAND, BROWSER_UA, PILLAR_INFO


# ─── JSON SERIALISATION ───────────────────────────────────────────────────────

def _make_json_safe(obj):
    """Recursively convert non-JSON-serializable types to safe equivalents."""
    if isinstance(obj, dict):
        return {k: _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(v) for v in obj]
    if isinstance(obj, set):
        return [_make_json_safe(v) for v in sorted(obj, key=str)]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    # Numpy scalars or other numeric-like types
    try:
        return int(obj)
    except (TypeError, ValueError):
        pass
    try:
        return float(obj)
    except (TypeError, ValueError):
        pass
    return str(obj)


# ─── URL UTILITIES ────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _page_type_from_label(label: str) -> str:
    """Map a URL label ('Blog 1', 'Content 1', 'Product 2', …) to a page_type key."""
    l = label.lower()
    if "homepage" in l:  return "homepage"
    if "blog" in l:      return "blog"
    if "content" in l or "about" in l or "contact" in l or "story" in l: return "content"
    if "category" in l or "collection" in l: return "category"
    if "product" in l:   return "product"
    return "general"


# ─── HTTP FETCH ───────────────────────────────────────────────────────────────

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


# ─── GAUGE SVG ────────────────────────────────────────────────────────────────

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


# ─── UI COMPONENT HELPERS ─────────────────────────────────────────────────────

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
