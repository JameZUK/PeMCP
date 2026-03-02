"""
User configuration persistence.

Stores API keys and preferences in ~/.arkana/config.json so they
persist across sessions. Environment variables always take priority.
"""
import os
import json
import logging

from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("Arkana")

CONFIG_DIR = Path.home() / ".arkana"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Maps config keys to their corresponding environment variable names.
# Each key checks ARKANA_* first, then falls back to PEMCP_* for backward compat.
_ENV_VAR_MAP = {
    "vt_api_key": ("VT_API_KEY",),
    "cache_enabled": ("ARKANA_CACHE_ENABLED", "PEMCP_CACHE_ENABLED"),
    "cache_max_size_mb": ("ARKANA_CACHE_MAX_SIZE_MB", "PEMCP_CACHE_MAX_SIZE_MB"),
}

# Keys that contain sensitive values (masked in get_config output)
_SENSITIVE_KEYS = {"vt_api_key"}


def _ensure_config_dir() -> None:
    """Create ~/.arkana/ directory if it does not exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


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
    """Write config dict to ~/.arkana/config.json, creating the directory if needed."""
    _ensure_config_dir()
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, sort_keys=True)
        # Restrict permissions to owner only (API keys are sensitive)
        CONFIG_FILE.chmod(0o600)
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
