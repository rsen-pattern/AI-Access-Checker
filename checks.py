# -*- coding: utf-8 -*-
# Canonical source has moved to core/llm_access_checks.py.
# This shim preserves backward-compatibility for existing imports.
from core.llm_access_checks import *  # noqa: F401, F403
from core.llm_access_checks import pattern_brain_analysis  # noqa: F401 (explicit for lazy imports)
