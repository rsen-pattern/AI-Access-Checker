# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — Supabase persistence + auth helpers.

Centralises the database layer used by both UI entry points. All Supabase
client construction goes through get_supabase(), and all DB writes pass
through _sanitise_for_db() to truncate long strings and drop non-
serializable values (like Protego parser objects).
"""

import json
import time

import streamlit as st


# ─── SECRETS / CLIENT ─────────────────────────────────────────────────────────

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


# ─── AUTH ─────────────────────────────────────────────────────────────────────

def auth_sign_in(email, password):
    """Sign in with Supabase email/password. Returns (user_email, error_str)."""
    try:
        from supabase import create_client
        url = get_secret("SUPABASE_URL", "")
        key = get_secret("SUPABASE_KEY", "")
        if not url or not key:
            return None, "Supabase not configured"
        sb = create_client(url, key)
        res = sb.auth.sign_in_with_password({"email": email, "password": password})
        return res.user.email, None
    except Exception as e:
        return None, str(e)


def is_history_authenticated():
    return st.session_state.get("_history_user") is not None


# ─── DB SANITISATION ──────────────────────────────────────────────────────────

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


# ─── AUDIT CRUD ───────────────────────────────────────────────────────────────

def save_audit_to_db(domain, overall, pillar_scores_dict, audited_urls, full_results=None):
    """Persist full audit results to Supabase. Returns (id, error_str)."""
    sb = get_supabase()
    if not sb:
        return None, None  # Not configured — caller handles messaging
    try:
        row = {
            "domain":        domain,
            "overall_score": overall,
            "pillar_scores": json.dumps(pillar_scores_dict),
            "urls":          audited_urls,
        }
        if full_results is not None:
            row["full_results"] = _sanitise_for_db(full_results)
        result = sb.table("audits").insert(row).execute()
        if result.data:
            return result.data[0].get("id"), None
    except Exception as e:
        return None, str(e)  # Surface the error — never crash the app
    return None, "Insert returned no data"


def update_audit_in_db(audit_id, overall, pillar_scores_dict, audited_urls, full_results=None):
    """Overwrite an existing audit row with fresh results. Returns (id, error_str)."""
    sb = get_supabase()
    if not sb:
        return None, None
    try:
        row = {
            "overall_score": overall,
            "pillar_scores": json.dumps(pillar_scores_dict),
            "urls":          audited_urls,
            "audited_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if full_results is not None:
            row["full_results"] = _sanitise_for_db(full_results)
        result = sb.table("audits").update(row).eq("id", str(audit_id)).execute()
        if result.data:
            return result.data[0].get("id"), None
    except Exception as e:
        return None, str(e)
    return None, "Update returned no data"


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
