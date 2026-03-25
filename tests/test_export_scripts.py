"""Tests for Ghidra and IDA script export tools."""
import hashlib
import os
import tempfile

import pytest

from arkana.state import (
    AnalyzerState, _default_state, set_current_state,
    _current_state_var,
)
import arkana.state as state_mod


@pytest.fixture(autouse=True)
def _setup_state():
    """Set up a minimal state for export tests."""
    saved_default = state_mod._default_state
    saved_ctx_token = _current_state_var.set(None)

    s = AnalyzerState()
    s.filepath = "/tmp/test_sample.exe"
    s.pe_data = {
        "file_hashes": {"sha256": "a" * 64, "md5": "b" * 32},
        "mode": "pe",
    }
    state_mod._default_state = s

    yield s

    state_mod._default_state = saved_default
    _current_state_var.reset(saved_ctx_token)


class TestHelpers:
    """Test helper functions used by both export tools."""

    def test_escape_python_string_basic(self):
        from arkana.mcp.tools_export import _escape_python_string
        assert _escape_python_string("hello") == "hello"
        assert _escape_python_string('say "hi"') == 'say \\"hi\\"'
        assert _escape_python_string("back\\slash") == "back\\\\slash"
        assert _escape_python_string("new\nline") == "new\\nline"

    def test_get_file_metadata(self, _setup_state):
        from arkana.mcp.tools_export import _get_file_metadata
        meta = _get_file_metadata()
        assert meta["sha256"] == "a" * 64
        assert meta["filename"] == "test_sample.exe"
        assert "UTC" in meta["timestamp"]

    def test_collect_function_notes(self):
        from arkana.mcp.tools_export import _collect_function_notes
        notes = [
            {"address": "0x401000", "category": "function", "content": "Main entry point"},
            {"address": "0x401000", "category": "ioc", "content": "Suspicious call"},
            {"address": "0x402000", "category": "function", "content": "Decrypt routine"},
            {"address": None, "category": "general", "content": "No address"},
            {"address": "0x403000", "category": "hypothesis", "content": "Skip this"},
            {"address": "0x404000", "category": "function", "content": ""},
        ]
        result = _collect_function_notes(notes)
        assert "0x401000" in result
        assert "Main entry point" in result["0x401000"]
        assert "Suspicious call" in result["0x401000"]
        assert "0x402000" in result
        # No address notes should be excluded
        assert all(addr is not None for addr in result.keys())
        # hypothesis category not included
        assert "0x403000" not in result
        # Empty content not included
        assert "0x404000" not in result

    def test_collect_function_notes_empty(self):
        from arkana.mcp.tools_export import _collect_function_notes
        assert _collect_function_notes([]) == {}

    def test_collect_bookmarks(self):
        from arkana.mcp.tools_export import _collect_bookmarks
        triage = {
            "0x401000": "flagged",
            "0x402000": "suspicious",
            "0x403000": "clean",
            "0x404000": "unreviewed",
        }
        func_renames = {"0x401000": "malicious_main", "0x403000": "safe_func"}
        bks = _collect_bookmarks(triage, func_renames)
        assert len(bks) == 2
        addrs = {b["address"] for b in bks}
        assert "0x401000" in addrs
        assert "0x402000" in addrs
        # Check label includes function name when available
        flagged = [b for b in bks if b["address"] == "0x401000"][0]
        assert "malicious_main" in flagged["label"]

    def test_collect_bookmarks_empty(self):
        from arkana.mcp.tools_export import _collect_bookmarks
        assert _collect_bookmarks({}, {}) == []

    def test_resolve_output_path_auto(self, _setup_state):
        from arkana.mcp.tools_export import _resolve_output_path
        path = _resolve_output_path("", "_ghidra.py")
        assert path.endswith("test_sample_ghidra.py")

    def test_resolve_output_path_explicit(self, _setup_state):
        from arkana.mcp.tools_export import _resolve_output_path
        with tempfile.TemporaryDirectory() as td:
            explicit = os.path.join(td, "my_script.py")
            path = _resolve_output_path(explicit, "_ghidra.py")
            assert path == os.path.realpath(explicit)


class TestGhidraScriptGeneration:
    """Test Ghidra script generation."""

    def _make_state_data(self):
        return {
            "meta": {
                "sha256": "a" * 64,
                "filename": "test.exe",
                "timestamp": "2026-01-01 00:00:00 UTC",
            },
            "renames": {
                "functions": {"0x401000": "main", "0x402000": "decrypt"},
                "variables": {"0x401000": {"v1": "counter", "v2": "buffer"}},
                "labels": {"0x403000": {"name": "crypto_key", "category": "data"}},
            },
            "notes": [
                {"address": "0x401000", "category": "function", "content": "Entry point"},
            ],
            "types": {
                "structs": {
                    "C2Config": {
                        "fields": [
                            {"name": "magic", "type": "uint32_le"},
                            {"name": "size", "type": "uint16_le"},
                            {"name": "data", "type": "bytes:8"},
                            {"name": "", "type": "padding:2"},
                        ],
                        "size": 16,
                        "created_at": "2026-01-01T00:00:00",
                    }
                },
                "enums": {
                    "CommandID": {
                        "values": {"CMD_PING": 1, "CMD_EXEC": 2, "CMD_UPLOAD": 3},
                        "size": 4,
                        "created_at": "2026-01-01T00:00:00",
                    }
                },
            },
            "triage_status": {
                "0x401000": "flagged",
                "0x402000": "suspicious",
                "0x403000": "clean",
            },
        }

    def test_full_script(self):
        from arkana.mcp.tools_export import _build_ghidra_script
        data = self._make_state_data()
        script = _build_ghidra_script(
            meta=data["meta"],
            renames=data["renames"],
            notes=data["notes"],
            types=data["types"],
            triage_status=data["triage_status"],
            include_renames=True,
            include_comments=True,
            include_types=True,
            include_bookmarks=True,
        )
        assert "# Arkana Analysis Export for Ghidra" in script
        assert "# @category Arkana" in script
        assert "SourceType" in script
        assert '"0x401000": "main"' in script
        assert '"0x402000": "decrypt"' in script
        assert "DecompInterface" in script
        assert "v1" in script
        assert "counter" in script
        assert "crypto_key" in script
        assert "Entry point" in script
        assert "PLATE_COMMENT" in script
        assert "StructureDataType" in script
        assert "C2Config" in script
        assert "UnsignedIntegerDataType" in script
        assert "EnumDataType" in script
        assert "CommandID" in script
        assert "CMD_PING" in script
        assert "BookmarkManager" not in script or "setBookmark" in script
        assert "apply_renames()" in script
        assert "apply_comments()" in script
        assert "apply_types()" in script
        assert "apply_bookmarks()" in script

    def test_empty_state(self):
        from arkana.mcp.tools_export import _build_ghidra_script
        script = _build_ghidra_script(
            meta={"sha256": "x" * 64, "filename": "test.exe", "timestamp": "now"},
            renames={"functions": {}, "variables": {}, "labels": {}},
            notes=[],
            types={"structs": {}, "enums": {}},
            triage_status={},
            include_renames=True,
            include_comments=True,
            include_types=True,
            include_bookmarks=True,
        )
        assert "# Arkana Analysis Export for Ghidra" in script
        assert "pass  # No renames to apply" in script
        assert "pass  # No comments to apply" in script
        assert "pass  # No custom types to apply" in script
        assert "pass  # No bookmarks to apply" in script
        assert "No analysis data to apply" in script

    def test_disable_sections(self):
        from arkana.mcp.tools_export import _build_ghidra_script
        data = self._make_state_data()
        script = _build_ghidra_script(
            meta=data["meta"],
            renames=data["renames"],
            notes=data["notes"],
            types=data["types"],
            triage_status=data["triage_status"],
            include_renames=False,
            include_comments=False,
            include_types=False,
            include_bookmarks=False,
        )
        assert "pass  # No renames to apply" in script
        assert "pass  # No comments to apply" in script
        assert "pass  # No custom types to apply" in script
        assert "pass  # No bookmarks to apply" in script

    def test_struct_field_types(self):
        from arkana.mcp.tools_export import _build_ghidra_script
        types = {
            "structs": {
                "TestStruct": {
                    "fields": [
                        {"name": "byte_field", "type": "uint8"},
                        {"name": "short_field", "type": "int16_le"},
                        {"name": "long_field", "type": "uint64_le"},
                        {"name": "ip", "type": "ipv4"},
                        {"name": "str_field", "type": "cstring"},
                    ],
                    "size": 15,
                    "created_at": "2026-01-01",
                }
            },
            "enums": {},
        }
        script = _build_ghidra_script(
            meta={"sha256": "x" * 64, "filename": "t.exe", "timestamp": "now"},
            renames={"functions": {}, "variables": {}, "labels": {}},
            notes=[],
            types=types,
            triage_status={},
            include_renames=False,
            include_comments=False,
            include_types=True,
            include_bookmarks=False,
        )
        assert "UnsignedByteDataType" in script
        assert "ShortDataType" in script  # signed int16
        assert "UnsignedLongLongDataType" in script
        assert "Pointer32DataType" in script  # ipv4 placeholder
        assert "cstring" in script

    def test_script_is_valid_python_syntax(self):
        """Verify the generated script compiles as valid Python."""
        from arkana.mcp.tools_export import _build_ghidra_script
        data = self._make_state_data()
        script = _build_ghidra_script(
            meta=data["meta"],
            renames=data["renames"],
            notes=data["notes"],
            types=data["types"],
            triage_status=data["triage_status"],
            include_renames=True,
            include_comments=True,
            include_types=True,
            include_bookmarks=True,
        )
        # Should compile without SyntaxError
        # (won't run because Ghidra APIs aren't available, but syntax must be valid)
        compile(script, "<ghidra_script>", "exec")


class TestIDAScriptGeneration:
    """Test IDA script generation."""

    def _make_state_data(self):
        return {
            "meta": {
                "sha256": "b" * 64,
                "filename": "malware.dll",
                "timestamp": "2026-01-01 00:00:00 UTC",
            },
            "renames": {
                "functions": {"0x10001000": "DllMain", "0x10002000": "c2_handler"},
                "variables": {"0x10001000": {"arg0": "hModule"}},
                "labels": {"0x10003000": {"name": "string_table", "category": "data"}},
            },
            "notes": [
                {"address": "0x10001000", "category": "function", "content": "DLL entry point"},
                {"address": "0x10002000", "category": "tool_result", "content": "Network API calls"},
            ],
            "types": {
                "structs": {
                    "PacketHeader": {
                        "fields": [
                            {"name": "length", "type": "uint32_le"},
                            {"name": "cmd_id", "type": "uint16_le"},
                            {"name": "flags", "type": "uint8"},
                            {"name": "", "type": "padding:1"},
                        ],
                        "size": 8,
                        "created_at": "2026-01-01T00:00:00",
                    }
                },
                "enums": {
                    "PacketType": {
                        "values": {"HEARTBEAT": 0, "CMD": 1, "DATA": 2},
                        "size": 2,
                        "created_at": "2026-01-01T00:00:00",
                    }
                },
            },
            "triage_status": {"0x10002000": "flagged"},
        }

    def test_full_script(self):
        from arkana.mcp.tools_export import _build_ida_script
        data = self._make_state_data()
        script = _build_ida_script(
            meta=data["meta"],
            renames=data["renames"],
            notes=data["notes"],
            types=data["types"],
            triage_status=data["triage_status"],
            include_renames=True,
            include_comments=True,
            include_types=True,
        )
        assert "# Arkana Analysis Export for IDA Pro" in script
        assert "import idc" in script
        assert "import ida_name" in script
        assert "ida_name.set_name" in script
        assert '"0x10001000": "DllMain"' in script
        assert '"0x10002000": "c2_handler"' in script
        assert "arg0" in script
        assert "hModule" in script
        assert "string_table" in script
        assert "DLL entry point" in script
        assert "idc.set_func_cmt" in script
        assert "ida_struct" in script
        assert "PacketHeader" in script
        assert "ida_bytes.dword_flag()" in script
        assert "ida_enum" in script
        assert "PacketType" in script
        assert "HEARTBEAT" in script
        assert "apply_renames()" in script
        assert "apply_comments()" in script
        assert "apply_types()" in script

    def test_empty_state(self):
        from arkana.mcp.tools_export import _build_ida_script
        script = _build_ida_script(
            meta={"sha256": "x" * 64, "filename": "test.exe", "timestamp": "now"},
            renames={"functions": {}, "variables": {}, "labels": {}},
            notes=[],
            types={"structs": {}, "enums": {}},
            triage_status={},
            include_renames=True,
            include_comments=True,
            include_types=True,
        )
        assert "pass  # No renames to apply" in script
        assert "pass  # No comments to apply" in script
        assert "pass  # No custom types to apply" in script
        assert "No analysis data to apply" in script

    def test_disable_sections(self):
        from arkana.mcp.tools_export import _build_ida_script
        data = self._make_state_data()
        script = _build_ida_script(
            meta=data["meta"],
            renames=data["renames"],
            notes=data["notes"],
            types=data["types"],
            triage_status=data["triage_status"],
            include_renames=False,
            include_comments=False,
            include_types=False,
        )
        assert "pass  # No renames to apply" in script
        assert "pass  # No comments to apply" in script
        assert "pass  # No custom types to apply" in script

    def test_enum_width(self):
        from arkana.mcp.tools_export import _build_ida_script
        types = {
            "structs": {},
            "enums": {
                "ByteEnum": {"values": {"A": 0, "B": 1}, "size": 1, "created_at": "now"},
                "WordEnum": {"values": {"X": 0}, "size": 2, "created_at": "now"},
                "QwordEnum": {"values": {"Q": 0}, "size": 8, "created_at": "now"},
            },
        }
        script = _build_ida_script(
            meta={"sha256": "x" * 64, "filename": "t.exe", "timestamp": "now"},
            renames={"functions": {}, "variables": {}, "labels": {}},
            notes=[],
            types=types,
            triage_status={},
            include_renames=False,
            include_comments=False,
            include_types=True,
        )
        assert "set_enum_width(eid, 0)" in script  # byte
        assert "set_enum_width(eid, 1)" in script  # word
        assert "set_enum_width(eid, 3)" in script  # qword

    def test_script_is_valid_python_syntax(self):
        """Verify the generated script compiles as valid Python."""
        from arkana.mcp.tools_export import _build_ida_script
        data = self._make_state_data()
        script = _build_ida_script(
            meta=data["meta"],
            renames=data["renames"],
            notes=data["notes"],
            types=data["types"],
            triage_status=data["triage_status"],
            include_renames=True,
            include_comments=True,
            include_types=True,
        )
        compile(script, "<ida_script>", "exec")

    def test_variable_renames_as_comments(self):
        """IDA variable renames should be exported as comments."""
        from arkana.mcp.tools_export import _build_ida_script
        script = _build_ida_script(
            meta={"sha256": "x" * 64, "filename": "t.exe", "timestamp": "now"},
            renames={
                "functions": {},
                "variables": {"0x401000": {"old_var": "new_var"}},
                "labels": {},
            },
            notes=[],
            types={"structs": {}, "enums": {}},
            triage_status={},
            include_renames=True,
            include_comments=False,
            include_types=False,
        )
        assert "[Arkana vars]" in script
        assert "idc.set_func_cmt" in script


class TestWriteScriptAndRegister:
    """Test the _write_script_and_register helper."""

    def test_write_and_register(self, _setup_state):
        from arkana.mcp.tools_export import _write_script_and_register
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "test_script.py")
            result = _write_script_and_register(
                path, "# test script\nprint('hello')\n",
                "test_tool", "Test description",
            )
            assert result["path"] == os.path.realpath(path)
            assert result["size"] > 0
            assert "sha256" in result
            assert "artifact_id" in result
            assert os.path.isfile(path)
            with open(path) as f:
                content = f.read()
            assert "print('hello')" in content

    def test_write_too_large(self, _setup_state):
        from arkana.mcp.tools_export import _write_script_and_register, _MAX_SCRIPT_SIZE
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "big_script.py")
            big_text = "x" * (_MAX_SCRIPT_SIZE + 1)
            with pytest.raises(RuntimeError, match="too large"):
                _write_script_and_register(path, big_text, "test", "test")


class TestSpecialCharacterHandling:
    """Test that special characters in names are properly escaped."""

    def test_ghidra_special_chars_in_names(self):
        from arkana.mcp.tools_export import _build_ghidra_script
        renames = {
            "functions": {"0x401000": 'func_with_"quotes"'},
            "variables": {},
            "labels": {"0x402000": {"name": "label\\with\\backslash", "category": "data"}},
        }
        script = _build_ghidra_script(
            meta={"sha256": "x" * 64, "filename": "test.exe", "timestamp": "now"},
            renames=renames,
            notes=[],
            types={"structs": {}, "enums": {}},
            triage_status={},
            include_renames=True,
            include_comments=False,
            include_types=False,
            include_bookmarks=False,
        )
        # Should still be valid Python
        compile(script, "<test>", "exec")
        assert '\\"quotes\\"' in script
        assert "\\\\backslash" in script

    def test_ida_special_chars_in_names(self):
        from arkana.mcp.tools_export import _build_ida_script
        renames = {
            "functions": {"0x401000": 'func_with_"quotes"'},
            "variables": {},
            "labels": {"0x402000": {"name": "label\\with\\backslash", "category": "data"}},
        }
        script = _build_ida_script(
            meta={"sha256": "x" * 64, "filename": "test.exe", "timestamp": "now"},
            renames=renames,
            notes=[],
            types={"structs": {}, "enums": {}},
            triage_status={},
            include_renames=True,
            include_comments=False,
            include_types=False,
        )
        compile(script, "<test>", "exec")
        assert '\\"quotes\\"' in script
        assert "\\\\backslash" in script

    def test_notes_with_newlines(self):
        from arkana.mcp.tools_export import _build_ghidra_script
        notes = [
            {"address": "0x401000", "category": "function", "content": "Line1\nLine2\nLine3"},
        ]
        script = _build_ghidra_script(
            meta={"sha256": "x" * 64, "filename": "test.exe", "timestamp": "now"},
            renames={"functions": {}, "variables": {}, "labels": {}},
            notes=notes,
            types={"structs": {}, "enums": {}},
            triage_status={},
            include_renames=False,
            include_comments=True,
            include_types=False,
            include_bookmarks=False,
        )
        compile(script, "<test>", "exec")
        assert "\\n" in script
