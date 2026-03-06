"""Tests for FLOSS static-only extraction function."""
import pytest

from arkana.parsers.floss import _parse_floss_static_only
from arkana.config import FLOSS_AVAILABLE


class TestFlossStaticOnly:
    def test_returns_dict_structure(self):
        """Static-only function returns correct structure even on nonexistent file."""
        result = _parse_floss_static_only("/nonexistent/file.exe", min_length=4)
        assert isinstance(result, dict)
        assert "status" in result
        assert "strings" in result
        assert isinstance(result["strings"], dict)
        for key in ("static_strings", "stack_strings", "tight_strings", "decoded_strings"):
            assert key in result["strings"]
        # Stack/tight/decoded should always be empty for static-only
        assert result["strings"]["stack_strings"] == []
        assert result["strings"]["tight_strings"] == []
        assert result["strings"]["decoded_strings"] == []

    @pytest.mark.skipif(not FLOSS_AVAILABLE, reason="FLOSS not installed")
    def test_static_only_does_not_need_vivisect(self):
        """Static-only should work without loading a Vivisect workspace."""
        import tempfile
        import os
        # Create a minimal file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"MZ" + b"\x00" * 50 + b"Hello World\x00" + b"\x00" * 50)
            f.flush()
            try:
                result = _parse_floss_static_only(f.name, min_length=4)
                assert result["error"] is None or "Vivisect" not in str(result.get("error", ""))
                # Status should indicate static-only
                assert "Static" in result["status"] or "static" in result["status"]
            finally:
                os.unlink(f.name)
