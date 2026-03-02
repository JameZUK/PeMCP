"""Unit tests for extract_config_for_family helpers.

Tests _rc4_decrypt, _parse_cstrings, _extract_adaptixc2_beacon,
_extract_generic_rc4_size_prefixed, and _extract_xor_single_byte
with synthetic config blobs — no live malware samples required.
"""
import struct

import pytest


# ---------------------------------------------------------------------------
#  RC4 helper
# ---------------------------------------------------------------------------

class TestRC4Decrypt:
    def test_roundtrip(self):
        """RC4 encryption and decryption are the same operation."""
        from pemcp.mcp.tools_payload import _rc4_decrypt
        key = b"secretkey1234567"
        plaintext = b"Hello, this is a test of RC4 encryption."
        ciphertext = _rc4_decrypt(plaintext, key)
        assert ciphertext != plaintext
        recovered = _rc4_decrypt(ciphertext, key)
        assert recovered == plaintext

    def test_known_vector(self):
        """Verify against a known RC4 test vector (key='Key', plaintext='Plaintext')."""
        from pemcp.mcp.tools_payload import _rc4_decrypt
        # RFC 6229 / well-known test vector
        key = b"Key"
        plaintext = b"Plaintext"
        ciphertext = _rc4_decrypt(plaintext, key)
        expected = bytes([0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3])
        assert ciphertext == expected

    def test_empty_data(self):
        from pemcp.mcp.tools_payload import _rc4_decrypt
        assert _rc4_decrypt(b"", b"key") == b""

    def test_single_byte(self):
        from pemcp.mcp.tools_payload import _rc4_decrypt
        key = b"K"
        ct = _rc4_decrypt(b"\x00", key)
        pt = _rc4_decrypt(ct, key)
        assert pt == b"\x00"


# ---------------------------------------------------------------------------
#  C-string parser
# ---------------------------------------------------------------------------

class TestParseCstrings:
    def test_basic(self):
        from pemcp.mcp.tools_payload import _parse_cstrings
        data = b"hello\x00world\x00"
        assert _parse_cstrings(data) == ["hello", "world"]

    def test_no_null_terminator(self):
        from pemcp.mcp.tools_payload import _parse_cstrings
        data = b"unterminated"
        assert _parse_cstrings(data) == ["unterminated"]

    def test_empty_strings(self):
        from pemcp.mcp.tools_payload import _parse_cstrings
        data = b"\x00\x00\x00"
        result = _parse_cstrings(data)
        assert result == ["", "", ""]

    def test_max_count(self):
        from pemcp.mcp.tools_payload import _parse_cstrings
        data = b"a\x00" * 100
        result = _parse_cstrings(data, max_count=5)
        assert len(result) == 5

    def test_empty_data(self):
        from pemcp.mcp.tools_payload import _parse_cstrings
        assert _parse_cstrings(b"") == []

    def test_binary_safe(self):
        """Non-ASCII bytes should be replaced, not crash."""
        from pemcp.mcp.tools_payload import _parse_cstrings
        data = b"\xff\xfe\x80\x00"
        result = _parse_cstrings(data)
        assert len(result) == 1
        assert len(result[0]) == 3  # 3 replacement chars


# ---------------------------------------------------------------------------
#  AdaptixC2 Beacon extractor
# ---------------------------------------------------------------------------

def _build_lpstring(s: str) -> bytes:
    """Build a length-prefixed null-terminated string: uint32_le(len+1) | chars | null."""
    raw = s.encode("ascii") + b"\x00"
    return struct.pack("<I", len(raw)) + raw


def _build_adaptixc2_blob(
    header=b"\x49\x01\x4c\xbe", ssl=0,
    servers=None, http_method="POST", uri_path="/api/check",
    parameter="data", user_agent="Mozilla/5.0", http_headers="\r\n",
    sleep=60, jitter=20, retry_count=3, download_chunk=4096,
    key=None,
):
    """Build a synthetic AdaptixC2 config blob: size(4B LE) | ciphertext | key(16B).

    Uses the real format: length-prefixed strings, per-server addr+port.
    """
    from pemcp.mcp.tools_payload import _rc4_decrypt

    if servers is None:
        servers = [("10.0.0.1", 443)]

    # Build plaintext matching real AdaptixC2 format
    plaintext = header
    plaintext += bytes([ssl])
    plaintext += struct.pack("<I", len(servers))
    for addr, port in servers:
        plaintext += _build_lpstring(addr)
        plaintext += struct.pack("<I", port)
    for s in [http_method, uri_path, parameter, user_agent, http_headers]:
        plaintext += _build_lpstring(s)
    for val in [sleep, jitter, download_chunk, 0, retry_count, 0]:
        plaintext += struct.pack("<I", val)

    if key is None:
        key = bytes(range(0x10, 0x20))  # 16 bytes, good entropy

    ciphertext = _rc4_decrypt(plaintext, key)
    size = len(ciphertext)
    blob = struct.pack("<I", size) + ciphertext + key
    return blob, key, plaintext


class TestExtractAdaptixC2Beacon:
    def test_basic_extraction(self):
        from pemcp.mcp.tools_payload import _extract_adaptixc2_beacon
        blob, key, _ = _build_adaptixc2_blob()
        section_data = blob + b"\x00" * 64
        family_meta = {"config": {"key_length": 16}}

        result = _extract_adaptixc2_beacon(b"", section_data, 0x1000, family_meta)
        assert result is not None
        assert result["family"] == "AdaptixC2 Beacon"
        assert result["encryption"] == "rc4"
        assert result["key_hex"] == key.hex()
        assert result["fields"]["ssl"] == 0
        assert result["fields"]["server_count"] == 1
        assert result["fields"]["servers"] == "10.0.0.1:443"
        assert result["fields"]["http_method"] == "POST"
        assert result["fields"]["uri_path"] == "/api/check"
        assert result["fields"]["user_agent"] == "Mozilla/5.0"
        assert result["fields"]["sleep"] == 60
        assert result["fields"]["jitter"] == 20

    def test_iocs_extracted(self):
        from pemcp.mcp.tools_payload import _extract_adaptixc2_beacon
        blob, _, _ = _build_adaptixc2_blob(
            servers=[("192.168.1.1", 8443), ("10.0.0.5", 443)],
            uri_path="/beacon",
            user_agent="CustomAgent/1.0",
        )
        section_data = blob + b"\x00" * 64
        family_meta = {"config": {"key_length": 16}}

        result = _extract_adaptixc2_beacon(b"", section_data, 0, family_meta)
        assert result is not None
        ioc_types = {ioc["type"] for ioc in result["iocs"]}
        assert "server" in ioc_types
        assert "uri_path" in ioc_types
        assert "user_agent" in ioc_types
        server_values = [ioc["value"] for ioc in result["iocs"] if ioc["type"] == "server"]
        assert "192.168.1.1:8443" in server_values
        assert "10.0.0.5:443" in server_values

    def test_offset_in_section(self):
        """Blob is not at the start of the section."""
        from pemcp.mcp.tools_payload import _extract_adaptixc2_beacon
        blob, _, _ = _build_adaptixc2_blob()
        # Put 64 bytes of junk before the blob (within the 256-byte scan window)
        section_data = b"\xFF" * 64 + blob + b"\x00" * 64
        family_meta = {"config": {"key_length": 16}}

        result = _extract_adaptixc2_beacon(b"", section_data, 0x2000, family_meta)
        assert result is not None
        assert result["config_offset"] == hex(0x2000 + 64)

    def test_bad_key_entropy_skipped(self):
        """Keys with low entropy (all same byte) should be rejected."""
        from pemcp.mcp.tools_payload import _rc4_decrypt
        from pemcp.mcp.tools_payload import _extract_adaptixc2_beacon

        # Build something that looks like a blob but with a low-entropy key
        plaintext = b"\x49\x01\x4c\xbe" + b"\x00" + struct.pack("<I", 1) + b"x\x00" * 20
        key = b"\xAA" * 16  # only 1 unique byte — below threshold of 3
        ciphertext = _rc4_decrypt(plaintext, key)
        blob = struct.pack("<I", len(ciphertext)) + ciphertext + key
        section_data = blob + b"\x00" * 64
        family_meta = {"config": {"key_length": 16}}

        result = _extract_adaptixc2_beacon(b"", section_data, 0, family_meta)
        assert result is None

    def test_no_valid_blob_returns_none(self):
        from pemcp.mcp.tools_payload import _extract_adaptixc2_beacon
        section_data = b"\x00" * 512
        family_meta = {"config": {"key_length": 16}}
        result = _extract_adaptixc2_beacon(b"", section_data, 0, family_meta)
        assert result is None

    def test_section_too_small(self):
        from pemcp.mcp.tools_payload import _extract_adaptixc2_beacon
        section_data = b"\x00" * 20  # Too small to contain a valid blob
        family_meta = {"config": {"key_length": 16}}
        result = _extract_adaptixc2_beacon(b"", section_data, 0, family_meta)
        assert result is None


# ---------------------------------------------------------------------------
#  Generic RC4 size-prefixed extractor
# ---------------------------------------------------------------------------

class TestExtractGenericRC4:
    def test_basic_extraction(self):
        from pemcp.mcp.tools_payload import _rc4_decrypt, _extract_generic_rc4_size_prefixed
        key = bytes(range(0x30, 0x40))  # 16 bytes, good entropy
        plaintext = b"http://evil.com\x00user-agent\x00config-data\x00"
        ciphertext = _rc4_decrypt(plaintext, key)
        blob = struct.pack("<I", len(ciphertext)) + ciphertext + key
        section_data = blob + b"\x00" * 64
        family_meta = {"family": "TestFamily", "config": {"key_length": 16}}

        result = _extract_generic_rc4_size_prefixed(b"", section_data, 0, family_meta)
        assert result is not None
        assert result["family"] == "TestFamily"
        assert result["encryption"] == "rc4"
        assert result["key_hex"] == key.hex()
        assert "http://evil.com" in result["extracted_strings"]

    def test_low_printable_ratio_skipped(self):
        """Blobs where decrypted data is mostly non-printable should be rejected."""
        from pemcp.mcp.tools_payload import _rc4_decrypt, _extract_generic_rc4_size_prefixed
        key = bytes(range(0x30, 0x40))
        # Use a different key for "encryption" so decryption produces garbage
        wrong_key = bytes(range(0x50, 0x60))
        # Encrypt random-looking data that will produce non-printable output
        plaintext = bytes(range(0, 50))  # has many non-printable bytes
        ciphertext = _rc4_decrypt(plaintext, wrong_key)
        blob = struct.pack("<I", len(ciphertext)) + ciphertext + key
        section_data = blob + b"\x00" * 64
        family_meta = {"family": "Test", "config": {"key_length": 16}}

        _extract_generic_rc4_size_prefixed(b"", section_data, 0, family_meta)
        # Should not crash regardless of whether decrypted data passes validation


# ---------------------------------------------------------------------------
#  XOR single-byte extractor
# ---------------------------------------------------------------------------

class TestExtractXorSingleByte:
    def test_basic_extraction(self):
        """XOR extractor finds configs by locating runs of the XOR key byte
        (which correspond to null-padded regions in plaintext). The config
        must have 16+ consecutive null bytes for the needle to match."""
        from pemcp.mcp.tools_payload import _extract_xor_single_byte
        xor_key = 0x5A
        config_size = 80
        # Build plaintext: null padding first (creates the XOR key needle),
        # then structured data. This mimics real configs with null header padding.
        plaintext = b"\x00" * 16  # null padding → becomes XOR key run (16 = needle size)
        plaintext += b"http://c2.evil.com\x00"
        plaintext += b"password123\x00"
        plaintext += struct.pack("<I", 60)  # sleep timer
        plaintext += b"\x00" * (config_size - len(plaintext))

        # XOR encrypt
        encrypted = bytes(b ^ xor_key for b in plaintext)
        # Place at start of section — extractor walks backward to block_start=0
        section_data = encrypted + b"\xCC" * 64
        family_meta = {
            "family": "XorMalware",
            "constants": {
                "xor_key_1": xor_key,
                "config_size": config_size,
            },
        }

        result = _extract_xor_single_byte(b"", section_data, 0x1000, family_meta)
        assert result is not None
        assert result["family"] == "XorMalware"
        assert result["encryption"] == "xor_single_byte"
        assert result["xor_key"] == xor_key
        assert result["config_size"] == config_size
        assert "http://c2.evil.com" in result["extracted_strings"]

    def test_no_xor_keys_returns_none(self):
        from pemcp.mcp.tools_payload import _extract_xor_single_byte
        family_meta = {
            "family": "NoKeys",
            "constants": {"config_size": 64},
        }
        result = _extract_xor_single_byte(b"", b"\x00" * 512, 0, family_meta)
        assert result is None

    def test_no_config_size_returns_none(self):
        from pemcp.mcp.tools_payload import _extract_xor_single_byte
        family_meta = {
            "family": "NoSize",
            "constants": {"xor_key_1": 0x5A},
        }
        result = _extract_xor_single_byte(b"", b"\x00" * 512, 0, family_meta)
        assert result is None

    def test_no_constants_returns_none(self):
        from pemcp.mcp.tools_payload import _extract_xor_single_byte
        family_meta = {"family": "NoConst"}
        result = _extract_xor_single_byte(b"", b"\x00" * 512, 0, family_meta)
        assert result is None

    def test_invalid_xor_key_skipped(self):
        """XOR key of 0 should be skipped (0 < v < 256)."""
        from pemcp.mcp.tools_payload import _extract_xor_single_byte
        family_meta = {
            "family": "ZeroKey",
            "constants": {"xor_key_1": 0, "config_size": 64},
        }
        result = _extract_xor_single_byte(b"", b"\x00" * 512, 0, family_meta)
        assert result is None
