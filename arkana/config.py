"""
Central configuration hub — re-exports constants, imports, and wires up global state.

Other modules should continue to ``from arkana.config import ...`` as before.
The actual definitions now live in:
  - ``arkana.constants`` — pure constants (no side effects)
  - ``arkana.imports``   — optional library imports & availability flags
"""
import logging

from typing import Dict, Any, Optional, List, Tuple, Set, Union, Type  # noqa: F401 — re-exported for consumers

# Re-export everything from sub-modules so existing imports keep working.
from arkana.constants import *  # noqa: F401,F403
from arkana.imports import *    # noqa: F401,F403

# Underscore-prefixed names used by tool modules — not covered by wildcard
# re-exports above, so they need explicit imports.
from arkana.imports import (  # noqa: E402,F401
    _SPEAKEASY_VENV_PYTHON, _SPEAKEASY_RUNNER, _check_speakeasy_available,
    _UNIPACKER_VENV_PYTHON, _UNIPACKER_RUNNER, _check_unipacker_available,
    _QILING_VENV_PYTHON, _QILING_RUNNER, _QILING_DEFAULT_ROOTFS, _check_qiling_available,
    _speakeasy_check_lock, _unipacker_check_lock, _qiling_check_lock,
)

from arkana.state import AnalyzerState, StateProxy

# --- Auto-migrate ~/.pemcp/ → ~/.arkana/ before any config/cache access ---
from arkana.migration import migrate_data_dir  # noqa: E402
try:
    migrate_data_dir()
except Exception:
    logging.getLogger("Arkana").warning("migrate_data_dir() failed at import time", exc_info=True)

from arkana.user_config import get_config_value

# --- Logging (frequently imported from config) ---
logger = logging.getLogger("Arkana")

# --- Global State Instance ---
# StateProxy delegates to a per-session AnalyzerState via contextvars.
# In stdio mode (single client) this is equivalent to a plain AnalyzerState.
# In HTTP mode each MCP session transparently gets its own state.
state = StateProxy()

# --- Analysis Cache Instance ---
from arkana.cache import AnalysisCache  # noqa: E402

_cache_enabled = get_config_value("cache_enabled")
_cache_max_mb = get_config_value("cache_max_size_mb")
try:
    _cache_max_mb_int = int(_cache_max_mb) if _cache_max_mb else 500
except (ValueError, TypeError):
    _cache_max_mb_int = 500
_cache_max_mb_int = max(1, min(_cache_max_mb_int, 50000))  # Clamp to 1 MB – 50 GB
analysis_cache = AnalysisCache(
    max_size_mb=_cache_max_mb_int,
    enabled=(str(_cache_enabled).lower() not in ("false", "0", "no")) if _cache_enabled else True,
)
