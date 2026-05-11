# -*- coding: utf-8 -*-
"""
Pattern LLM Access Checker — severity vocabulary.

Single source of truth for the three-tier severity system used across
recommendations, status indicators, and PDF kicker labels.

Migration note: the legacy "critical" and "danger" strings (used by older
callsites in ui_recommendations.py) both map to ERROR. "info" maps to OK.
"""

from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARN  = "warn"
    OK    = "ok"


# Normalise any legacy or variant string to a Severity member.
_LEGACY_MAP: dict[str, Severity] = {
    "critical":   Severity.ERROR,
    "danger":     Severity.ERROR,
    "error":      Severity.ERROR,
    "warning":    Severity.WARN,
    "warn":       Severity.WARN,
    "info":       Severity.OK,
    "success":    Severity.OK,
    "ok":         Severity.OK,
}


def normalise(value: str) -> Severity:
    """Map any legacy severity string to the canonical Severity enum."""
    return _LEGACY_MAP.get((value or "warn").lower().strip(), Severity.WARN)


# UI render properties keyed by Severity — colour hex, label, non-colour cue.
SEVERITY_META: dict[Severity, dict] = {
    Severity.ERROR: {
        "color":  "#e53e51",   # BRAND['danger']
        "label":  "CRITICAL",
        "icon":   "✗",
        "status": "danger",
    },
    Severity.WARN: {
        "color":  "#ffb548",   # BRAND['warning']
        "label":  "WARNING",
        "icon":   "!",
        "status": "warning",
    },
    Severity.OK: {
        "color":  "#4cc3ae",   # BRAND['teal']
        "label":  "OK",
        "icon":   "✓",
        "status": "success",
    },
}
