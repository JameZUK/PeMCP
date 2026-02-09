"""
User configuration persistence.

Stores API keys and preferences in ~/.pemcp/config.json so they
persist across sessions. Environment variables always take priority.
"""
import os
import json
import logging

from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("PeMCP")

CONFIG_DIR = Path.home() / ".pemcp"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Maps config keys to their corresponding environment variable names
_ENV_VAR_MAP = {
    "vt_api_key": "VT_API_KEY",
}

# Keys that contain sensitive values (masked in get_config output)
_SENSITIVE_KEYS = {"vt_api_key"}


def _ensure_config_dir() -> None:
    """Create ~/.pemcp/ directory if it does not exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_user_config() -> Dict[str, Any]:
    """Read ~/.pemcp/config.json and return its contents as a dict."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning(f"User config at {CONFIG_FILE} is not a JSON object, ignoring.")
            return {}
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read user config from {CONFIG_FILE}: {e}")
        return {}


def save_user_config(config: Dict[str, Any]) -> None:
    """Write config dict to ~/.pemcp/config.json, creating the directory if needed."""
    _ensure_config_dir()
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, sort_keys=True)
        # Restrict permissions to owner only (API keys are sensitive)
        CONFIG_FILE.chmod(0o600)
    except OSError as e:
        logger.error(f"Failed to write user config to {CONFIG_FILE}: {e}")
        raise


def get_config_value(key: str) -> Optional[str]:
    """
    Retrieve a config value with environment variable priority.

    Resolution order:
      1. Environment variable (e.g. VT_API_KEY)
      2. ~/.pemcp/config.json
      3. None
    """
    # Check environment variable first
    env_var = _ENV_VAR_MAP.get(key)
    if env_var:
        env_val = os.getenv(env_var)
        if env_val:
            return env_val

    # Fall back to config file
    config = load_user_config()
    val = config.get(key)
    return str(val) if val is not None else None


def set_config_value(key: str, value: str) -> None:
    """Store a config value in ~/.pemcp/config.json."""
    config = load_user_config()
    config[key] = value
    save_user_config(config)
    logger.info(f"Config key '{key}' saved to {CONFIG_FILE}")


def delete_config_value(key: str) -> bool:
    """Remove a config key from ~/.pemcp/config.json. Returns True if key existed."""
    config = load_user_config()
    if key in config:
        del config[key]
        save_user_config(config)
        logger.info(f"Config key '{key}' removed from {CONFIG_FILE}")
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
    for key, env_var in _ENV_VAR_MAP.items():
        if os.getenv(env_var):
            overrides[key] = f"(overridden by ${env_var} environment variable)"
    if overrides:
        masked["_env_overrides"] = overrides

    return masked
