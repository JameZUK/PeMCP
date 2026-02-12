"""Unit tests for pemcp/user_config.py — persistent config management."""
import json
import os
import pytest

from pemcp.user_config import (
    load_user_config,
    save_user_config,
    get_config_value,
    set_config_value,
    delete_config_value,
    get_masked_config,
    _ENV_VAR_MAP,
    _SENSITIVE_KEYS,
)


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Redirect config to a temporary directory."""
    cfg_dir = tmp_path / ".pemcp"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "config.json"
    monkeypatch.setattr("pemcp.user_config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("pemcp.user_config.CONFIG_FILE", cfg_file)
    return cfg_dir, cfg_file


# ---------------------------------------------------------------------------
# load_user_config
# ---------------------------------------------------------------------------

class TestLoadUserConfig:
    def test_missing_file_returns_empty(self, config_dir):
        cfg_dir, cfg_file = config_dir
        # File doesn't exist yet
        assert load_user_config() == {}

    def test_valid_json(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"key": "value"}))
        result = load_user_config()
        assert result == {"key": "value"}

    def test_invalid_json_returns_empty(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text("not valid json {{{")
        result = load_user_config()
        assert result == {}

    def test_non_dict_json_returns_empty(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps(["a", "list"]))
        result = load_user_config()
        assert result == {}


# ---------------------------------------------------------------------------
# save_user_config
# ---------------------------------------------------------------------------

class TestSaveUserConfig:
    def test_save_and_reload(self, config_dir):
        cfg_dir, cfg_file = config_dir
        save_user_config({"test_key": "test_value"})
        assert cfg_file.exists()
        data = json.loads(cfg_file.read_text())
        assert data["test_key"] == "test_value"

    def test_file_permissions(self, config_dir):
        cfg_dir, cfg_file = config_dir
        save_user_config({"secret": "hidden"})
        mode = oct(cfg_file.stat().st_mode & 0o777)
        assert mode == "0o600"


# ---------------------------------------------------------------------------
# get_config_value
# ---------------------------------------------------------------------------

class TestGetConfigValue:
    def test_from_file(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"vt_api_key": "file_key_123"}))
        # Clear any env override
        os.environ.pop("VT_API_KEY", None)
        result = get_config_value("vt_api_key")
        assert result == "file_key_123"

    def test_env_overrides_file(self, config_dir, monkeypatch):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"vt_api_key": "file_key"}))
        monkeypatch.setenv("VT_API_KEY", "env_key")
        result = get_config_value("vt_api_key")
        assert result == "env_key"

    def test_missing_key_returns_none(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({}))
        result = get_config_value("nonexistent_key")
        assert result is None

    def test_unknown_key_no_env(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"custom": "val"}))
        result = get_config_value("custom")
        assert result == "val"


# ---------------------------------------------------------------------------
# set_config_value
# ---------------------------------------------------------------------------

class TestSetConfigValue:
    def test_set_new_key(self, config_dir):
        cfg_dir, cfg_file = config_dir
        set_config_value("new_key", "new_value")
        data = json.loads(cfg_file.read_text())
        assert data["new_key"] == "new_value"

    def test_overwrite_existing(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"existing": "old"}))
        set_config_value("existing", "new")
        data = json.loads(cfg_file.read_text())
        assert data["existing"] == "new"


# ---------------------------------------------------------------------------
# delete_config_value
# ---------------------------------------------------------------------------

class TestDeleteConfigValue:
    def test_delete_existing(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"to_delete": "val", "keep": "val2"}))
        result = delete_config_value("to_delete")
        assert result is True
        data = json.loads(cfg_file.read_text())
        assert "to_delete" not in data
        assert "keep" in data

    def test_delete_nonexistent(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"other": "val"}))
        result = delete_config_value("nonexistent")
        assert result is False


# ---------------------------------------------------------------------------
# get_masked_config
# ---------------------------------------------------------------------------

class TestGetMaskedConfig:
    def test_sensitive_key_masked(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"vt_api_key": "abcdefghijklmnop"}))
        # Clear env override
        os.environ.pop("VT_API_KEY", None)
        masked = get_masked_config()
        assert masked["vt_api_key"] != "abcdefghijklmnop"
        assert masked["vt_api_key"].startswith("abc")
        assert masked["vt_api_key"].endswith("nop")
        assert "*" in masked["vt_api_key"]

    def test_short_sensitive_key_not_masked(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"vt_api_key": "short"}))
        os.environ.pop("VT_API_KEY", None)
        masked = get_masked_config()
        # Keys <= 6 chars are not masked
        assert masked["vt_api_key"] == "short"

    def test_non_sensitive_key_not_masked(self, config_dir):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({"cache_enabled": "true"}))
        masked = get_masked_config()
        assert masked["cache_enabled"] == "true"

    def test_env_overrides_noted(self, config_dir, monkeypatch):
        cfg_dir, cfg_file = config_dir
        cfg_file.write_text(json.dumps({}))
        monkeypatch.setenv("VT_API_KEY", "env_value")
        masked = get_masked_config()
        assert "_env_overrides" in masked
        assert "vt_api_key" in masked["_env_overrides"]
