"""Unit tests for expanded refinery pipeline steps and bitwise operations.

These tests exercise _run_pipeline_single directly with synthetic data.
Bitwise ops, pad, and terminate delegate to Binary Refinery native units;
slicing (snip, chop, pick) and nop are custom Python implementations.
All tests require Binary Refinery to be installed.
"""
import struct

import pytest


def _skip_if_no_refinery():
    """Skip test if Binary Refinery is not installed."""
    try:
        from pemcp.imports import REFINERY_AVAILABLE
        if not REFINERY_AVAILABLE:
            pytest.skip("binary-refinery not installed")
    except ImportError:
        pytest.skip("pemcp.imports not available")


# ---------------------------------------------------------------------------
#  Slicing operations
# ---------------------------------------------------------------------------

class TestSnipStep:
    """Tests for the snip pipeline step."""

    def test_snip_from_start(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"ABCDEFGHIJ"
        result, log = _run_pipeline_single(data, ["snip:3"])
        assert result == b"DEFGHIJ"

    def test_snip_range(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"ABCDEFGHIJ"
        result, log = _run_pipeline_single(data, ["snip:2:5"])
        assert result == b"CDE"

    def test_snip_negative_index(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"ABCDEFGHIJ"
        result, log = _run_pipeline_single(data, ["snip:-3:"])
        assert result == b"HIJ"

    def test_snip_negative_range(self):
        """Extract key from last 16 bytes — the AdaptixC2 pattern."""
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"A" * 20 + b"K" * 16
        result, log = _run_pipeline_single(data, ["snip:-16:"])
        assert result == b"K" * 16

    def test_snip_middle(self):
        """Extract ciphertext skipping first 4 and last 16 bytes."""
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"SIZE" + b"C" * 20 + b"K" * 16
        result, log = _run_pipeline_single(data, ["snip:4:-16"])
        assert result == b"C" * 20

    def test_snip_no_args(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"UNCHANGED"
        result, log = _run_pipeline_single(data, ["snip"])
        assert result == data


class TestChopStep:
    def test_chop_first_chunk(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"AAAABBBBCCCC"
        result, log = _run_pipeline_single(data, ["chop:4"])
        assert result == b"AAAA"

    def test_chop_indexed(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"AAAABBBBCCCC"
        result, log = _run_pipeline_single(data, ["chop:4:2"])
        assert result == b"CCCC"

    def test_chop_no_size_raises(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        with pytest.raises(ValueError, match="chop requires"):
            _run_pipeline_single(b"data", ["chop"])


class TestPickStep:
    def test_pick_first_n(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"ABCDEFGHIJ"
        result, log = _run_pipeline_single(data, ["pick:4"])
        assert result == b"ABCD"


# ---------------------------------------------------------------------------
#  Padding / termination
# ---------------------------------------------------------------------------

class TestPadStep:
    def test_pad_to_block_size(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"ABC"  # 3 bytes, pad to 16
        result, log = _run_pipeline_single(data, ["pad:16"])
        assert len(result) == 16
        assert result[:3] == b"ABC"
        assert result[3:] == b"\x00" * 13

    def test_pad_already_aligned(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"A" * 16
        result, log = _run_pipeline_single(data, ["pad:16"])
        assert len(result) == 16


class TestTerminateStep:
    def test_strip_nulls(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"hello\x00\x00\x00"
        result, log = _run_pipeline_single(data, ["terminate"])
        assert result == b"hello"

    def test_add_null(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"hello"
        result, log = _run_pipeline_single(data, ["terminate:add"])
        assert result == b"hello\x00"


class TestNopStep:
    def test_nop(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"unchanged"
        result, log = _run_pipeline_single(data, ["nop"])
        assert result == data


# ---------------------------------------------------------------------------
#  Bitwise operations
# ---------------------------------------------------------------------------

class TestBitwiseRor:
    def test_ror_byte(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        # ROR 1 bit: 0b10000000 -> 0b01000000
        data = bytes([0x80])
        result, log = _run_pipeline_single(data, ["ror:1"])
        assert result == bytes([0x40])

    def test_ror_dword(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        val = 0x80000000
        data = struct.pack("<I", val)
        result, log = _run_pipeline_single(data, ["ror:1:dword"])
        expected = ((val >> 1) | (val << 31)) & 0xFFFFFFFF
        assert struct.unpack("<I", result)[0] == expected


class TestBitwiseRol:
    def test_rol_byte(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0x01])
        result, log = _run_pipeline_single(data, ["rol:1"])
        assert result == bytes([0x02])

    def test_rol_dword(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        val = 0x00000001
        data = struct.pack("<I", val)
        result, log = _run_pipeline_single(data, ["rol:1:dword"])
        assert struct.unpack("<I", result)[0] == 0x00000002


class TestBitwiseShift:
    def test_shl(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0x01])
        result, log = _run_pipeline_single(data, ["shl:4"])
        assert result == bytes([0x10])

    def test_shr(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0x80])
        result, log = _run_pipeline_single(data, ["shr:4"])
        assert result == bytes([0x08])


class TestBitwiseLogic:
    def test_and(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0xFF, 0xAB])
        result, log = _run_pipeline_single(data, ["and:0F"])
        assert result == bytes([0x0F, 0x0B])

    def test_or(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0x00, 0x0F])
        result, log = _run_pipeline_single(data, ["or:F0"])
        assert result == bytes([0xF0, 0xFF])

    def test_not(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0x00, 0xFF])
        result, log = _run_pipeline_single(data, ["not"])
        assert result == bytes([0xFF, 0x00])


class TestBitwiseArithmetic:
    def test_add(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0x01, 0xFE])
        result, log = _run_pipeline_single(data, ["add:2"])
        assert result == bytes([0x03, 0x00])  # 0xFE + 2 = 0x100, wraps to 0x00

    def test_sub(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = bytes([0x05, 0x01])
        result, log = _run_pipeline_single(data, ["sub:3"])
        assert result == bytes([0x02, 0xFE])  # 0x01 - 3 = -2, wraps to 0xFE


# ---------------------------------------------------------------------------
#  Pipeline chaining
# ---------------------------------------------------------------------------

class TestPipelineChaining:
    def test_snip_then_not(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"\x00\xFF\x00\xFF"
        result, log = _run_pipeline_single(data, ["snip:1:3", "not"])
        assert result == bytes([0x00, 0xFF])  # snip → [0xFF, 0x00], not → [0x00, 0xFF]

    def test_step_log_tracking(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        data = b"A" * 20
        result, log = _run_pipeline_single(data, ["snip:0:10", "nop"])
        assert len(log) == 3  # input + 2 steps
        assert log[0]["step"] == "input"
        assert log[0]["size"] == 20
        assert log[1]["size"] == 10  # after snip
        assert log[2]["size"] == 10  # after nop

    def test_unknown_step_raises(self):
        _skip_if_no_refinery()
        from pemcp.mcp.tools_refinery import _run_pipeline_single
        with pytest.raises(ValueError, match="Unknown pipeline unit"):
            _run_pipeline_single(b"data", ["nonexistent_unit"])
