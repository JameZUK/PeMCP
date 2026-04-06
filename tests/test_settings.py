"""Tests for dashboard settings, themes, and user config extensions."""
import json
import os
import pytest

from arkana.user_config import (
    load_user_config,
    save_user_config,
    get_config_value,
    get_dashboard_theme,
    get_setting_value,
    get_all_settings,
    save_settings,
    reset_setting,
    VALID_THEMES,
    SETTINGS_REGISTRY,
    _SETTINGS_BY_KEY,
)


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Redirect config to a temporary directory."""
    cfg_dir = tmp_path / ".arkana"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "config.json"
    monkeypatch.setattr("arkana.user_config.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("arkana.user_config.CONFIG_FILE", cfg_file)
    return cfg_dir, cfg_file


# ---------------------------------------------------------------------------
#  Theme
# ---------------------------------------------------------------------------

class TestDashboardTheme:
    def test_default_theme_is_crt(self, config_dir):
        assert get_dashboard_theme() == "crt"

    def test_set_and_get_theme(self, config_dir):
        cfg_dir, cfg_file = config_dir
        save_user_config({"dashboard_theme": "professional"})
        assert get_dashboard_theme() == "professional"

    def test_midnight_theme(self, config_dir):
        cfg_dir, cfg_file = config_dir
        save_user_config({"dashboard_theme": "midnight"})
        assert get_dashboard_theme() == "midnight"

    def test_invalid_theme_falls_back_to_crt(self, config_dir):
        cfg_dir, cfg_file = config_dir
        save_user_config({"dashboard_theme": "neon_pink"})
        assert get_dashboard_theme() == "crt"

    def test_env_var_overrides_config(self, config_dir, monkeypatch):
        cfg_dir, cfg_file = config_dir
        save_user_config({"dashboard_theme": "crt"})
        monkeypatch.setenv("ARKANA_DASHBOARD_THEME", "midnight")
        assert get_dashboard_theme() == "midnight"

    def test_highcontrast_theme(self, config_dir):
        save_user_config({"dashboard_theme": "highcontrast"})
        assert get_dashboard_theme() == "highcontrast"

    def test_light_theme(self, config_dir):
        save_user_config({"dashboard_theme": "light"})
        assert get_dashboard_theme() == "light"

    def test_lightwarm_theme(self, config_dir):
        save_user_config({"dashboard_theme": "lightwarm"})
        assert get_dashboard_theme() == "lightwarm"

    def test_valid_themes_tuple(self):
        assert "crt" in VALID_THEMES
        assert "professional" in VALID_THEMES
        assert "midnight" in VALID_THEMES
        assert "highcontrast" in VALID_THEMES
        assert "light" in VALID_THEMES
        assert "lightwarm" in VALID_THEMES


# ---------------------------------------------------------------------------
#  Settings Registry
# ---------------------------------------------------------------------------

class TestSettingsRegistry:
    def test_registry_not_empty(self):
        assert len(SETTINGS_REGISTRY) > 0

    def test_all_entries_have_required_fields(self):
        required = {"key", "label", "group", "type", "default"}
        for spec in SETTINGS_REGISTRY:
            missing = required - set(spec.keys())
            assert not missing, f"Setting {spec.get('key', '?')} missing fields: {missing}"

    def test_all_types_are_valid(self):
        valid_types = {"int", "bool", "choice"}
        for spec in SETTINGS_REGISTRY:
            assert spec["type"] in valid_types, f"{spec['key']} has invalid type {spec['type']}"

    def test_int_settings_have_min_max(self):
        for spec in SETTINGS_REGISTRY:
            if spec["type"] == "int":
                assert "min" in spec, f"{spec['key']} missing min"
                assert "max" in spec, f"{spec['key']} missing max"
                assert spec["min"] <= spec["default"] <= spec["max"], \
                    f"{spec['key']} default {spec['default']} not in [{spec['min']}, {spec['max']}]"

    def test_choice_settings_have_choices(self):
        for spec in SETTINGS_REGISTRY:
            if spec["type"] == "choice":
                assert "choices" in spec, f"{spec['key']} missing choices"
                assert spec["default"] in spec["choices"], \
                    f"{spec['key']} default not in choices"

    def test_by_key_index(self):
        assert len(_SETTINGS_BY_KEY) == len(SETTINGS_REGISTRY)
        for spec in SETTINGS_REGISTRY:
            assert spec["key"] in _SETTINGS_BY_KEY


# ---------------------------------------------------------------------------
#  get_setting_value
# ---------------------------------------------------------------------------

class TestGetSettingValue:
    def test_returns_default_when_no_config(self, config_dir):
        val = get_setting_value("angr_cfg_soft_timeout")
        assert val == 900

    def test_reads_from_config(self, config_dir):
        save_user_config({"angr_cfg_soft_timeout": "600"})
        val = get_setting_value("angr_cfg_soft_timeout")
        assert val == 600

    def test_clamps_to_min(self, config_dir):
        save_user_config({"angr_cfg_soft_timeout": "1"})
        val = get_setting_value("angr_cfg_soft_timeout")
        assert val == 30  # min is 30

    def test_clamps_to_max(self, config_dir):
        save_user_config({"angr_cfg_soft_timeout": "999999"})
        val = get_setting_value("angr_cfg_soft_timeout")
        assert val == 86400  # max is 86400

    def test_bool_setting_true(self, config_dir):
        save_user_config({"auto_enrichment": "1"})
        val = get_setting_value("auto_enrichment")
        assert val is True

    def test_bool_setting_false(self, config_dir):
        save_user_config({"auto_enrichment": "0"})
        val = get_setting_value("auto_enrichment")
        assert val is False

    def test_env_override_takes_priority(self, config_dir, monkeypatch):
        save_user_config({"angr_cfg_soft_timeout": "600"})
        monkeypatch.setenv("ARKANA_ANGR_CFG_SOFT_TIMEOUT", "1200")
        val = get_setting_value("angr_cfg_soft_timeout")
        assert val == 1200

    def test_choice_setting(self, config_dir):
        save_user_config({"dashboard_theme": "midnight"})
        val = get_setting_value("dashboard_theme")
        assert val == "midnight"

    def test_choice_setting_invalid_falls_back(self, config_dir):
        save_user_config({"dashboard_theme": "invalid"})
        val = get_setting_value("dashboard_theme")
        assert val == "crt"

    def test_invalid_int_falls_back_to_default(self, config_dir):
        save_user_config({"angr_cfg_soft_timeout": "not_a_number"})
        val = get_setting_value("angr_cfg_soft_timeout")
        assert val == 900


# ---------------------------------------------------------------------------
#  get_all_settings
# ---------------------------------------------------------------------------

class TestGetAllSettings:
    def test_returns_all_settings(self, config_dir):
        result = get_all_settings()
        assert len(result) == len(SETTINGS_REGISTRY)

    def test_default_source(self, config_dir):
        result = get_all_settings()
        for entry in result:
            assert entry["source"] == "default"

    def test_config_source(self, config_dir):
        save_user_config({"angr_cfg_soft_timeout": "600"})
        result = get_all_settings()
        timeout_entry = next(e for e in result if e["key"] == "angr_cfg_soft_timeout")
        assert timeout_entry["source"] == "config"
        assert timeout_entry["current_value"] == 600

    def test_env_source(self, config_dir, monkeypatch):
        monkeypatch.setenv("ARKANA_ANGR_CFG_SOFT_TIMEOUT", "1200")
        result = get_all_settings()
        timeout_entry = next(e for e in result if e["key"] == "angr_cfg_soft_timeout")
        assert timeout_entry["source"] == "env"
        assert "env_var" in timeout_entry


# ---------------------------------------------------------------------------
#  save_settings
# ---------------------------------------------------------------------------

class TestSaveSettings:
    def test_save_valid_int(self, config_dir):
        errors = save_settings({"angr_cfg_soft_timeout": "600"})
        assert errors == {}
        config = load_user_config()
        assert config["angr_cfg_soft_timeout"] == "600"

    def test_save_invalid_int_returns_error(self, config_dir):
        errors = save_settings({"angr_cfg_soft_timeout": "abc"})
        assert "angr_cfg_soft_timeout" in errors

    def test_save_out_of_range_returns_error(self, config_dir):
        errors = save_settings({"angr_cfg_soft_timeout": "1"})  # min is 30
        assert "angr_cfg_soft_timeout" in errors

    def test_save_bool(self, config_dir):
        errors = save_settings({"auto_enrichment": True})
        assert errors == {}
        config = load_user_config()
        assert config["auto_enrichment"] == "1"

    def test_save_bool_false(self, config_dir):
        errors = save_settings({"auto_enrichment": False})
        assert errors == {}
        config = load_user_config()
        assert config["auto_enrichment"] == "0"

    def test_save_choice(self, config_dir):
        errors = save_settings({"dashboard_theme": "professional"})
        assert errors == {}
        assert get_dashboard_theme() == "professional"

    def test_save_invalid_choice(self, config_dir):
        errors = save_settings({"dashboard_theme": "neon"})
        assert "dashboard_theme" in errors

    def test_save_unknown_key(self, config_dir):
        errors = save_settings({"nonexistent_key": "value"})
        assert "nonexistent_key" in errors

    def test_save_multiple(self, config_dir):
        errors = save_settings({
            "angr_cfg_soft_timeout": "600",
            "auto_enrichment": False,
            "dashboard_theme": "midnight",
        })
        assert errors == {}
        assert get_setting_value("angr_cfg_soft_timeout") == 600
        assert get_setting_value("auto_enrichment") is False
        assert get_dashboard_theme() == "midnight"

    def test_partial_save_on_mixed_valid_invalid(self, config_dir):
        errors = save_settings({
            "angr_cfg_soft_timeout": "600",     # valid
            "unknown_key": "value",              # invalid
        })
        assert "unknown_key" in errors
        assert "angr_cfg_soft_timeout" not in errors
        assert get_setting_value("angr_cfg_soft_timeout") == 600


# ---------------------------------------------------------------------------
#  reset_setting
# ---------------------------------------------------------------------------

class TestResetSetting:
    def test_reset_existing(self, config_dir):
        save_user_config({"dashboard_theme": "midnight"})
        assert reset_setting("dashboard_theme") is True
        assert get_dashboard_theme() == "crt"

    def test_reset_nonexistent(self, config_dir):
        assert reset_setting("nonexistent") is False


# ---------------------------------------------------------------------------
#  _safe_env_int config integration
# ---------------------------------------------------------------------------

class TestSafeEnvIntConfigIntegration:
    def test_reads_from_config_file(self, config_dir, monkeypatch):
        """_safe_env_int should pick up values from config.json."""
        # Reset the cached reverse map so it rebuilds
        import arkana.utils
        monkeypatch.setattr(arkana.utils, "_env_to_config_key", None)

        save_user_config({"angr_cfg_soft_timeout": "1500"})
        from arkana.utils import _safe_env_int
        val = _safe_env_int("ARKANA_ANGR_CFG_SOFT_TIMEOUT", 900)
        assert val == 1500

    def test_env_var_overrides_config(self, config_dir, monkeypatch):
        """Env var should still take priority over config file."""
        import arkana.utils
        monkeypatch.setattr(arkana.utils, "_env_to_config_key", None)

        save_user_config({"angr_cfg_soft_timeout": "1500"})
        monkeypatch.setenv("ARKANA_ANGR_CFG_SOFT_TIMEOUT", "2000")
        from arkana.utils import _safe_env_int
        val = _safe_env_int("ARKANA_ANGR_CFG_SOFT_TIMEOUT", 900)
        assert val == 2000


# ---------------------------------------------------------------------------
#  state_api.get_settings_data
# ---------------------------------------------------------------------------

class TestGetSettingsData:
    def test_returns_theme_and_groups(self, config_dir):
        from arkana.dashboard.state_api import get_settings_data
        data = get_settings_data()
        assert "current_theme" in data
        assert "groups" in data
        assert data["current_theme"] == "crt"

    def test_groups_exclude_appearance(self, config_dir):
        from arkana.dashboard.state_api import get_settings_data
        data = get_settings_data()
        assert "Appearance" not in data["groups"]

    def test_groups_have_items(self, config_dir):
        from arkana.dashboard.state_api import get_settings_data
        data = get_settings_data()
        for group_name, items in data["groups"].items():
            assert len(items) > 0, f"Group {group_name} is empty"
