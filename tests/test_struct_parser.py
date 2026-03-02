"""Unit tests for parse_binary_struct tool."""
import struct

import pytest


# ---------------------------------------------------------------------------
#  _parse_fields — the core parsing function
# ---------------------------------------------------------------------------

class TestParseFields:
    """Tests for the binary struct parsing logic."""

    def test_uint8(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = bytes([0x42])
        fields, consumed = _parse_fields(data, [{"name": "val", "type": "uint8"}])
        assert fields["val"] == 0x42
        assert consumed == 1

    def test_int8_negative(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = bytes([0xFF])
        fields, consumed = _parse_fields(data, [{"name": "val", "type": "int8"}])
        assert fields["val"] == -1
        assert consumed == 1

    def test_uint16_le(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = struct.pack("<H", 0x1234)
        fields, consumed = _parse_fields(data, [{"name": "val", "type": "uint16_le"}])
        assert fields["val"] == 0x1234
        assert consumed == 2

    def test_uint16_be(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = struct.pack(">H", 0x1234)
        fields, consumed = _parse_fields(data, [{"name": "val", "type": "uint16_be"}])
        assert fields["val"] == 0x1234
        assert consumed == 2

    def test_uint32_le(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = struct.pack("<I", 0xDEADBEEF)
        fields, consumed = _parse_fields(data, [{"name": "val", "type": "uint32_le"}])
        assert fields["val"] == 0xDEADBEEF
        assert consumed == 4

    def test_uint32_be(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = struct.pack(">I", 0xDEADBEEF)
        fields, consumed = _parse_fields(data, [{"name": "val", "type": "uint32_be"}])
        assert fields["val"] == 0xDEADBEEF
        assert consumed == 4

    def test_uint64_le(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = struct.pack("<Q", 0x0102030405060708)
        fields, consumed = _parse_fields(data, [{"name": "val", "type": "uint64_le"}])
        assert fields["val"] == 0x0102030405060708
        assert consumed == 8

    def test_cstring(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = b"hello\x00world\x00"
        schema = [
            {"name": "s1", "type": "cstring"},
            {"name": "s2", "type": "cstring"},
        ]
        fields, consumed = _parse_fields(data, schema)
        assert fields["s1"] == "hello"
        assert fields["s2"] == "world"
        assert consumed == 12

    def test_cstring_no_null(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = b"noterminator"
        fields, consumed = _parse_fields(data, [{"name": "s", "type": "cstring"}])
        assert fields["s"] == "noterminator"
        assert consumed == len(data)

    def test_wstring(self):
        from arkana.mcp.tools_struct import _parse_fields
        text = "hi"
        data = text.encode("utf-16-le") + b"\x00\x00"
        fields, consumed = _parse_fields(data, [{"name": "s", "type": "wstring"}])
        assert fields["s"] == "hi"

    def test_bytes_n(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = b"\xAA\xBB\xCC\xDD\xEE"
        fields, consumed = _parse_fields(data, [{"name": "raw", "type": "bytes:3"}])
        assert fields["raw"] == "aabbcc"
        assert consumed == 3

    def test_padding(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = struct.pack("<BxH", 1, 0x1234)  # uint8 + 1 byte pad + uint16
        schema = [
            {"name": "a", "type": "uint8"},
            {"type": "padding:1"},
            {"name": "b", "type": "uint16_le"},
        ]
        fields, consumed = _parse_fields(data, schema)
        assert fields["a"] == 1
        assert fields["b"] == 0x1234
        assert consumed == 4

    def test_ipv4(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = bytes([192, 168, 1, 100])
        fields, consumed = _parse_fields(data, [{"name": "ip", "type": "ipv4"}])
        assert fields["ip"] == "192.168.1.100"
        assert consumed == 4

    def test_mixed_schema(self):
        """Test a schema mimicking AdaptixC2 config header."""
        from arkana.mcp.tools_struct import _parse_fields
        data = struct.pack("<IBI", 1, 0, 2) + b"192.168.1.1:443\x00"
        schema = [
            {"name": "agent_type", "type": "uint32_le"},
            {"name": "ssl", "type": "uint8"},
            {"name": "server_count", "type": "uint32_le"},
            {"name": "server", "type": "cstring"},
        ]
        fields, consumed = _parse_fields(data, schema)
        assert fields["agent_type"] == 1
        assert fields["ssl"] == 0
        assert fields["server_count"] == 2
        assert fields["server"] == "192.168.1.1:443"

    def test_insufficient_data(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = bytes([0x01])  # Only 1 byte
        with pytest.raises(ValueError, match="Insufficient data"):
            _parse_fields(data, [{"name": "val", "type": "uint32_le"}])

    def test_unknown_type(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = bytes([0x00] * 8)
        with pytest.raises(ValueError, match="Unknown type"):
            _parse_fields(data, [{"name": "val", "type": "float128"}])

    def test_missing_name(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = bytes([0x00])
        with pytest.raises(ValueError, match="missing 'name'"):
            _parse_fields(data, [{"type": "uint8"}])

    def test_remaining_bytes_tracked(self):
        from arkana.mcp.tools_struct import _parse_fields
        data = bytes(10)
        fields, consumed = _parse_fields(data, [{"name": "a", "type": "uint8"}])
        assert consumed == 1
        remaining = len(data) - consumed
        assert remaining == 9
