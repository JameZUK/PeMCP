"""
User configuration persistence.

Stores API keys and preferences in ~/.arkana/config.json so they
persist across sessions. Environment variables always take priority.
"""
import os
import json
import logging
import tempfile
import time

from pathlib import Path
from typing import Optional, Dict, Any, List

logger = logging.getLogger("Arkana")

CONFIG_DIR = Path.home() / ".arkana"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Maps config keys to their corresponding environment variable names.
# Each key checks ARKANA_* first, then falls back to PEMCP_* for backward compat.
_ENV_VAR_MAP = {
    "vt_api_key": ("VT_API_KEY",),
    "cache_enabled": ("ARKANA_CACHE_ENABLED", "PEMCP_CACHE_ENABLED"),
    "cache_max_size_mb": ("ARKANA_CACHE_MAX_SIZE_MB", "PEMCP_CACHE_MAX_SIZE_MB"),
    "dashboard_theme": ("ARKANA_DASHBOARD_THEME",),
    # Analysis timeouts
    "angr_cfg_soft_timeout": ("ARKANA_ANGR_CFG_SOFT_TIMEOUT",),
    "background_task_soft_timeout": ("ARKANA_BACKGROUND_TASK_SOFT_TIMEOUT",),
    "overtime_stall_kill": ("ARKANA_OVERTIME_STALL_KILL",),
    "overtime_max_runtime": ("ARKANA_OVERTIME_MAX_RUNTIME",),
    "pe_analysis_soft_timeout": ("ARKANA_PE_ANALYSIS_SOFT_TIMEOUT",),
    "pe_analysis_max_runtime": ("ARKANA_PE_ANALYSIS_MAX_RUNTIME",),
    "capa_analysis_timeout": ("ARKANA_CAPA_ANALYSIS_TIMEOUT",),
    "floss_analysis_timeout": ("ARKANA_FLOSS_ANALYSIS_TIMEOUT",),
    # Enrichment
    "auto_enrichment": ("ARKANA_AUTO_ENRICHMENT",),
    "enrichment_max_decompile": ("ARKANA_ENRICHMENT_MAX_DECOMPILE",),
    "max_enrichment_blocks": ("ARKANA_MAX_ENRICHMENT_BLOCKS",),
    "bsim_auto_index": ("ARKANA_BSIM_AUTO_INDEX",),
    # Resource limits
    "max_file_size_mb": ("ARKANA_MAX_FILE_SIZE_MB",),
    "dashboard_threads": ("ARKANA_DASHBOARD_THREADS",),
    "resource_memory_high_mb": ("ARKANA_RESOURCE_MEMORY_HIGH_MB",),
    "resource_memory_critical_mb": ("ARKANA_RESOURCE_MEMORY_CRITICAL_MB",),
    # Debug / Emulation
    "debug_command_timeout": ("ARKANA_DEBUG_COMMAND_TIMEOUT",),
    "debug_session_ttl": ("ARKANA_DEBUG_SESSION_TTL",),
    "max_debug_sessions": ("ARKANA_MAX_DEBUG_SESSIONS",),
}

# Keys that contain sensitive values (masked in get_config output)
_SENSITIVE_KEYS = {"vt_api_key"}

# Valid theme names
VALID_THEMES = ("crt", "professional", "midnight", "highcontrast", "light", "lightwarm")

# ---------------------------------------------------------------------------
#  Settings registry — defines all dashboard-configurable settings
# ---------------------------------------------------------------------------
# Each entry: (config_key, label, group, type, default, min, max, unit, description)
# type: "int", "bool", "choice"
# For "bool": default is "1" or "0" (string). min/max ignored.
# For "choice": min is a list of valid choices. max ignored.

SETTINGS_REGISTRY: List[Dict[str, Any]] = [
    # --- Theme ---
    {
        "key": "dashboard_theme", "label": "Dashboard Theme", "group": "Appearance",
        "type": "choice", "default": "crt", "choices": list(VALID_THEMES),
        "unit": "", "description": "Visual theme for the web dashboard",
        "restart": False,
    },
    # --- Analysis Timeouts ---
    {
        "key": "angr_cfg_soft_timeout", "label": "CFG Soft Timeout", "group": "Analysis Timeouts",
        "type": "int", "default": 900, "min": 30, "max": 86400,
        "unit": "s", "description": "Seconds before CFG build enters overtime",
        "restart": True,
    },
    {
        "key": "background_task_soft_timeout", "label": "Background Task Soft Timeout", "group": "Analysis Timeouts",
        "type": "int", "default": 300, "min": 10, "max": 86400,
        "unit": "s", "description": "Seconds before background tasks enter overtime",
        "restart": True,
    },
    {
        "key": "overtime_stall_kill", "label": "Overtime Stall Kill", "group": "Analysis Timeouts",
        "type": "int", "default": 300, "min": 30, "max": 86400,
        "unit": "s", "description": "Kill task after this many seconds of zero progress",
        "restart": True,
    },
    {
        "key": "overtime_max_runtime", "label": "Overtime Max Runtime", "group": "Analysis Timeouts",
        "type": "int", "default": 21600, "min": 300, "max": 172800,
        "unit": "s", "description": "Absolute ceiling for any background task",
        "restart": True,
    },
    {
        "key": "pe_analysis_soft_timeout", "label": "PE Analysis Soft Timeout", "group": "Analysis Timeouts",
        "type": "int", "default": 300, "min": 30, "max": 7200,
        "unit": "s", "description": "Seconds before PE analysis enters overtime",
        "restart": True,
    },
    {
        "key": "pe_analysis_max_runtime", "label": "PE Analysis Max Runtime", "group": "Analysis Timeouts",
        "type": "int", "default": 3600, "min": 60, "max": 86400,
        "unit": "s", "description": "Absolute ceiling for PE analysis",
        "restart": True,
    },
    {
        "key": "capa_analysis_timeout", "label": "Capa Analysis Timeout", "group": "Analysis Timeouts",
        "type": "int", "default": 300, "min": 30, "max": 3600,
        "unit": "s", "description": "Timeout for capa capability detection",
        "restart": True,
    },
    {
        "key": "floss_analysis_timeout", "label": "FLOSS Analysis Timeout", "group": "Analysis Timeouts",
        "type": "int", "default": 300, "min": 30, "max": 3600,
        "unit": "s", "description": "Timeout for FLOSS string extraction",
        "restart": True,
    },
    # --- Enrichment ---
    {
        "key": "auto_enrichment", "label": "Auto-Enrichment", "group": "Enrichment",
        "type": "bool", "default": "1",
        "unit": "", "description": "Run background enrichment after open_file",
        "restart": True,
    },
    {
        "key": "enrichment_max_decompile", "label": "Max Decompile Functions", "group": "Enrichment",
        "type": "int", "default": 100, "min": 0, "max": 10000,
        "unit": "", "description": "Max functions to decompile during enrichment sweep",
        "restart": True,
    },
    {
        "key": "max_enrichment_blocks", "label": "Max Enrichment Blocks", "group": "Enrichment",
        "type": "int", "default": 300, "min": 10, "max": 10000,
        "unit": "", "description": "Skip functions with more basic blocks than this",
        "restart": True,
    },
    {
        "key": "bsim_auto_index", "label": "BSim Auto-Index", "group": "Enrichment",
        "type": "bool", "default": "1",
        "unit": "", "description": "Auto-index functions into signature DB",
        "restart": True,
    },
    # --- Resource Limits ---
    {
        "key": "cache_enabled", "label": "Disk Cache", "group": "Resource Limits",
        "type": "bool", "default": "1",
        "unit": "", "description": "Enable gzip-compressed LRU disk cache",
        "restart": True,
    },
    {
        "key": "cache_max_size_mb", "label": "Cache Max Size", "group": "Resource Limits",
        "type": "int", "default": 500, "min": 1, "max": 50000,
        "unit": "MB", "description": "Maximum disk cache size",
        "restart": True,
    },
    {
        "key": "max_file_size_mb", "label": "Max File Size", "group": "Resource Limits",
        "type": "int", "default": 256, "min": 1, "max": 4096,
        "unit": "MB", "description": "Maximum file size for open_file",
        "restart": True,
    },
    {
        "key": "dashboard_threads", "label": "Dashboard Threads", "group": "Resource Limits",
        "type": "int", "default": 4, "min": 1, "max": 32,
        "unit": "", "description": "Thread pool size for dashboard operations",
        "restart": True,
    },
    {
        "key": "resource_memory_high_mb", "label": "Memory Warning Threshold", "group": "Resource Limits",
        "type": "int", "default": 4096, "min": 512, "max": 65536,
        "unit": "MB", "description": "RSS threshold for memory warning",
        "restart": True,
    },
    {
        "key": "resource_memory_critical_mb", "label": "Memory Critical Threshold", "group": "Resource Limits",
        "type": "int", "default": 8192, "min": 1024, "max": 131072,
        "unit": "MB", "description": "RSS threshold for memory critical alert",
        "restart": True,
    },
    # --- Debug / Emulation ---
    {
        "key": "debug_command_timeout", "label": "Debug Command Timeout", "group": "Debug / Emulation",
        "type": "int", "default": 300, "min": 10, "max": 3600,
        "unit": "s", "description": "Per-command timeout for debug operations",
        "restart": True,
    },
    {
        "key": "debug_session_ttl", "label": "Debug Session TTL", "group": "Debug / Emulation",
        "type": "int", "default": 1800, "min": 60, "max": 86400,
        "unit": "s", "description": "Idle timeout for debug sessions",
        "restart": True,
    },
    {
        "key": "max_debug_sessions", "label": "Max Debug Sessions", "group": "Debug / Emulation",
        "type": "int", "default": 3, "min": 1, "max": 10,
        "unit": "", "description": "Maximum concurrent debug sessions",
        "restart": True,
    },
]

# Index by key for fast lookup
_SETTINGS_BY_KEY = {s["key"]: s for s in SETTINGS_REGISTRY}


def _ensure_config_dir() -> None:
    """Create ~/.arkana/ directory if it does not exist, with restrictive permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Tighten permissions if directory already existed with loose perms
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass


def load_user_config() -> Dict[str, Any]:
    """Read ~/.arkana/config.json and return its contents as a dict."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("User config at %s is not a JSON object, ignoring.", CONFIG_FILE)
            return {}
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read user config from %s: %s", CONFIG_FILE, e)
        return {}


def save_user_config(config: Dict[str, Any]) -> None:
    """Write config dict to ~/.arkana/config.json, creating the directory if needed.

    Uses atomic write (temp file + rename) to prevent partial writes from
    corrupting the config file on crash or power loss.
    Invalidates the theme cache so callers see the new value immediately.
    """
    _ensure_config_dir()
    _invalidate_theme_cache()
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(CONFIG_FILE.parent), suffix='.tmp')
        try:
            os.chmod(fd, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, sort_keys=True)
            os.replace(tmp_path, str(CONFIG_FILE))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("Failed to write user config to %s: %s", CONFIG_FILE, e)
        raise


def get_config_value(key: str) -> Optional[str]:
    """
    Retrieve a config value with environment variable priority.

    Resolution order:
      1. Environment variable (e.g. ARKANA_CACHE_ENABLED, then PEMCP_CACHE_ENABLED)
      2. ~/.arkana/config.json
      3. None
    """
    # Check environment variables first (with fallback chain)
    env_vars = _ENV_VAR_MAP.get(key, ())
    for env_var in env_vars:
        env_val = os.getenv(env_var)
        if env_val:
            return env_val

    # Fall back to config file
    config = load_user_config()
    val = config.get(key)
    return str(val) if val is not None else None


def set_config_value(key: str, value: str) -> None:
    """Store a config value in ~/.arkana/config.json."""
    config = load_user_config()
    config[key] = value
    save_user_config(config)
    logger.info("Config key '%s' saved to %s", key, CONFIG_FILE)


def delete_config_value(key: str) -> bool:
    """Remove a config key from ~/.arkana/config.json. Returns True if key existed."""
    config = load_user_config()
    if key in config:
        del config[key]
        save_user_config(config)
        logger.info("Config key '%s' removed from %s", key, CONFIG_FILE)
        return True
    return False


def get_masked_config() -> Dict[str, Any]:
    """
    Return the full config with sensitive values masked.
    Useful for displaying config to users without exposing secrets.
    """
    config = load_user_config()
    masked = {}
    for k, v in config.items():
        if k in _SENSITIVE_KEYS and isinstance(v, str) and len(v) > 6:
            masked[k] = v[:3] + "*" * (len(v) - 6) + v[-3:]
        else:
            masked[k] = v

    # Also note which keys are overridden by environment variables
    overrides = {}
    for key, env_vars in _ENV_VAR_MAP.items():
        for env_var in env_vars:
            if os.getenv(env_var):
                overrides[key] = f"(overridden by ${env_var} environment variable)"
                break
    if overrides:
        masked["_env_overrides"] = overrides

    return masked


# Theme cache: (value, timestamp).  Avoids reading config.json from disk
# on every page render while still picking up changes within 2 seconds.
_theme_cache: tuple = ("crt", 0.0)
_THEME_CACHE_TTL = 2.0  # seconds


def get_dashboard_theme() -> str:
    """Return the current dashboard theme name, cached for 2s."""
    global _theme_cache
    now = time.monotonic()
    cached_val, cached_at = _theme_cache
    if now - cached_at < _THEME_CACHE_TTL:
        return cached_val
    val = get_config_value("dashboard_theme")
    result = val if val and val in VALID_THEMES else "crt"
    _theme_cache = (result, now)
    return result


def _invalidate_theme_cache() -> None:
    """Force the next ``get_dashboard_theme()`` call to re-read from disk."""
    global _theme_cache
    _theme_cache = ("crt", 0.0)


def _resolve_setting(spec: Dict[str, Any], raw: Optional[str]) -> Any:
    """Cast a raw string value to the correct type for *spec*.

    Shared by ``get_setting_value`` (single key) and ``get_all_settings``
    (bulk) so the casting logic lives in one place.
    """
    if raw is not None:
        if spec["type"] == "int":
            try:
                val = int(raw)
                if "min" in spec:
                    val = max(spec["min"], val)
                if "max" in spec:
                    val = min(spec["max"], val)
                return val
            except (ValueError, TypeError):
                return spec["default"]
        if spec["type"] == "bool":
            return raw.lower() in ("1", "true", "yes", "on")
        if spec["type"] == "choice":
            return raw if raw in spec.get("choices", []) else spec["default"]
        return raw
    return spec["default"]


def get_setting_value(key: str) -> Any:
    """Return the effective value for a registered setting.

    Resolution: env var > config.json > registry default.
    Returns the value cast to the correct type (int for "int", str for others).
    """
    spec = _SETTINGS_BY_KEY.get(key)
    if not spec:
        return get_config_value(key)

    raw = get_config_value(key)
    return _resolve_setting(spec, raw)


def get_all_settings() -> List[Dict[str, Any]]:
    """Return all registered settings with current effective values and metadata.

    Each entry includes: key, label, group, type, default, current_value,
    source (env/config/default), env_override, unit, description, restart.

    Loads the config file once and resolves all values in-memory to avoid
    redundant disk reads (previously N+1 for N settings).
    """
    config = load_user_config()
    results = []
    for spec in SETTINGS_REGISTRY:
        key = spec["key"]
        entry = {
            "key": key,
            "label": spec["label"],
            "group": spec["group"],
            "type": spec["type"],
            "default": spec["default"],
            "unit": spec.get("unit", ""),
            "description": spec.get("description", ""),
            "restart": spec.get("restart", False),
        }
        if spec["type"] == "choice":
            entry["choices"] = spec.get("choices", [])
        if spec["type"] == "int":
            entry["min"] = spec.get("min")
            entry["max"] = spec.get("max")

        # Determine source and resolve effective value using the single
        # config dict already loaded — no additional disk reads.
        env_vars = _ENV_VAR_MAP.get(key, ())
        env_override = None
        raw = None
        for env_var in env_vars:
            env_val = os.getenv(env_var)
            if env_val:
                env_override = env_var
                raw = env_val
                break

        if env_override:
            entry["source"] = "env"
            entry["env_var"] = env_override
        elif key in config:
            entry["source"] = "config"
            raw = str(config[key])
        else:
            entry["source"] = "default"

        entry["current_value"] = _resolve_setting(spec, raw)
        results.append(entry)
    return results


def save_settings(settings: Dict[str, Any]) -> Dict[str, str]:
    """Save multiple settings at once. Returns dict of key -> error for invalid keys.

    Only saves keys that are in the SETTINGS_REGISTRY.
    Validates types and ranges before saving.
    """
    config = load_user_config()
    errors = {}

    for key, value in settings.items():
        spec = _SETTINGS_BY_KEY.get(key)
        if not spec:
            errors[key] = f"Unknown setting: {str(key)[:50]}"
            continue

        if spec["type"] == "int":
            try:
                int_val = int(value)
            except (ValueError, TypeError):
                errors[key] = f"Expected integer, got: {str(value)[:50]}"
                continue
            if "min" in spec and int_val < spec["min"]:
                errors[key] = f"Minimum value is {spec['min']}"
                continue
            if "max" in spec and int_val > spec["max"]:
                errors[key] = f"Maximum value is {spec['max']}"
                continue
            config[key] = str(int_val)

        elif spec["type"] == "bool":
            if isinstance(value, bool):
                config[key] = "1" if value else "0"
            elif isinstance(value, str):
                config[key] = "1" if value.lower() in ("1", "true", "yes", "on") else "0"
            else:
                config[key] = "1" if value else "0"

        elif spec["type"] == "choice":
            str_val = str(value)
            if str_val not in spec.get("choices", []):
                errors[key] = f"Invalid choice: {str_val[:50]}. Valid: {spec.get('choices', [])}"
                continue
            config[key] = str_val

        else:
            config[key] = str(value)

    if not errors or len(errors) < len(settings):
        save_user_config(config)  # also invalidates theme cache
        logger.info("Saved %d settings to %s", len(settings) - len(errors), CONFIG_FILE)

    return errors


def reset_setting(key: str) -> bool:
    """Remove a setting from config.json, reverting to default. Returns True if existed."""
    return delete_config_value(key)


def reset_all_settings() -> int:
    """Remove all registered settings from config.json in a single load-save cycle.

    Returns the number of keys that were actually removed.
    """
    config = load_user_config()
    count = 0
    for spec in SETTINGS_REGISTRY:
        if spec["key"] in config:
            del config[spec["key"]]
            count += 1
    if count:
        save_user_config(config)  # also invalidates theme cache
        logger.info("Reset %d settings to defaults in %s", count, CONFIG_FILE)
    return count
