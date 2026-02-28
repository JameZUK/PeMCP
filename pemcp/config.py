"""
Central configuration hub — re-exports constants, imports, and wires up global state.

Other modules should continue to ``from pemcp.config import ...`` as before.
The actual definitions now live in:
  - ``pemcp.constants`` — pure constants (no side effects)
  - ``pemcp.imports``   — optional library imports & availability flags
"""
import logging

from typing import Dict, Any, Optional, List, Tuple, Set, Union, Type  # noqa: F401 — re-exported for consumers

# Re-export everything from sub-modules so existing imports keep working.
from pemcp.constants import *  # noqa: F401,F403
from pemcp.imports import *    # noqa: F401,F403

# Underscore-prefixed names used by tool modules — not covered by wildcard
# re-exports above, so they need explicit imports.
from pemcp.imports import (  # noqa: E402,F401
    _SPEAKEASY_VENV_PYTHON, _SPEAKEASY_RUNNER, _check_speakeasy_available,
    _UNIPACKER_VENV_PYTHON, _UNIPACKER_RUNNER, _check_unipacker_available,
    _QILING_VENV_PYTHON, _QILING_RUNNER, _QILING_DEFAULT_ROOTFS, _check_qiling_available,
    _speakeasy_check_lock, _unipacker_check_lock, _qiling_check_lock,
)

from pemcp.state import AnalyzerState, StateProxy
from pemcp.user_config import get_config_value

# --- Logging (frequently imported from config) ---
logger = logging.getLogger("PeMCP")

# --- Global State Instance ---
# StateProxy delegates to a per-session AnalyzerState via contextvars.
# In stdio mode (single client) this is equivalent to a plain AnalyzerState.
# In HTTP mode each MCP session transparently gets its own state.
state = StateProxy()

# --- Analysis Cache Instance ---
from pemcp.cache import AnalysisCache  # noqa: E402

_cache_enabled = get_config_value("cache_enabled")
_cache_max_mb = get_config_value("cache_max_size_mb")
try:
    _cache_max_mb_int = int(_cache_max_mb) if _cache_max_mb else 500
except (ValueError, TypeError):
    _cache_max_mb_int = 500
analysis_cache = AnalysisCache(
    max_size_mb=_cache_max_mb_int,
    enabled=(_cache_enabled.lower() not in ("false", "0", "no")) if _cache_enabled else True,
)
