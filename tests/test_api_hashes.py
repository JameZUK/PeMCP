"""Unit tests for API hash helpers and database."""
import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
#  API name database
# ---------------------------------------------------------------------------

class TestApiNameDatabase:
    """Tests for the bundled Windows API name database."""

    def test_database_file_exists(self):
        db_path = Path(__file__).resolve().parent.parent / "pemcp" / "data" / "windows_api_names.json"
        assert db_path.exists(), "windows_api_names.json missing"

    def test_database_loads_valid_json(self):
        from pemcp.mcp._helpers_api_hashes import _load_api_name_db
        db = _load_api_name_db()
        assert isinstance(db, dict)
        assert len(db) > 0

    def test_database_has_core_dlls(self):
        from pemcp.mcp._helpers_api_hashes import _load_api_name_db
        db = _load_api_name_db()
        core_dlls = ["kernel32.dll", "ntdll.dll", "advapi32.dll",
                     "user32.dll", "ws2_32.dll", "wininet.dll"]
        for dll in core_dlls:
            assert dll in db, f"Missing core DLL: {dll}"

    def test_database_has_reasonable_count(self):
        from pemcp.mcp._helpers_api_hashes import get_all_api_names
        names = get_all_api_names()
        assert len(names) >= 500, f"Only {len(names)} APIs — expected 500+"
        assert len(names) <= 2000, f"Too many APIs ({len(names)}) for curated DB"

    def test_database_has_key_apis(self):
        from pemcp.mcp._helpers_api_hashes import get_all_api_names
        names = set(get_all_api_names())
        key_apis = [
            "LoadLibraryA", "GetProcAddress", "VirtualAlloc",
            "CreateThread", "WriteProcessMemory", "WSAStartup",
            "InternetOpenA", "RegOpenKeyExA", "NtAllocateVirtualMemory",
        ]
        for api in key_apis:
            assert api in names, f"Missing key API: {api}"

    def test_get_api_names_with_dll(self):
        from pemcp.mcp._helpers_api_hashes import get_api_names_with_dll
        pairs = get_api_names_with_dll()
        assert len(pairs) > 500
        # Check format
        api, dll = pairs[0]
        assert isinstance(api, str)
        assert isinstance(dll, str)
        assert dll.endswith(".dll") or dll.endswith(".exe")

    def test_extended_db_loads(self):
        from pemcp.mcp._helpers_api_hashes import get_all_api_names
        names = get_all_api_names(include_extended=True)
        # Should be significantly larger than curated
        curated = get_all_api_names(include_extended=False)
        assert len(names) > len(curated)


# ---------------------------------------------------------------------------
#  Hash algorithm implementations
# ---------------------------------------------------------------------------

class TestHashAlgorithms:
    """Tests for hash functions with configurable seeds."""

    def test_djb2_default_seed(self):
        from pemcp.mcp._helpers_api_hashes import djb2_hash
        # Standard djb2 with seed 5381
        h = djb2_hash("LoadLibraryA")
        assert isinstance(h, int)
        assert 0 <= h <= 0xFFFFFFFF

    def test_djb2_custom_seed(self):
        from pemcp.mcp._helpers_api_hashes import djb2_hash
        # AdaptixC2 uses seed 1572
        h_default = djb2_hash("LoadLibraryA", seed=5381)
        h_custom = djb2_hash("LoadLibraryA", seed=1572)
        assert h_default != h_custom, "Different seeds should produce different hashes"

    def test_djb2_adaptixc2_known_hashes(self):
        """Verify against known AdaptixC2 hash values from the KB."""
        from pemcp.mcp._helpers_api_hashes import compute_hash
        # From malware_signatures.yaml: AdaptixC2 uses djb2 seed=1572, case_sensitive=false
        known = {
            "NtFlushInstructionCache": 2443273630,
            "VirtualAlloc": 1674470262,
            "GetProcAddress": 407841502,
            "LoadLibraryA": 291098874,
        }
        for api_name, expected_hash in known.items():
            h = compute_hash(api_name, "djb2", seed=1572, case_handling="lower")
            assert h == expected_hash, (
                f"{api_name}: expected {expected_hash}, got {h}"
            )

    def test_ror13_default(self):
        from pemcp.mcp._helpers_api_hashes import ror13_hash
        h = ror13_hash("LoadLibraryA")
        assert isinstance(h, int)
        assert 0 <= h <= 0xFFFFFFFF

    def test_ror13_custom_seed(self):
        from pemcp.mcp._helpers_api_hashes import ror13_hash
        h0 = ror13_hash("LoadLibraryA", seed=0)
        h1 = ror13_hash("LoadLibraryA", seed=0x12345678)
        assert h0 != h1

    def test_crc32(self):
        from pemcp.mcp._helpers_api_hashes import crc32_hash
        import binascii
        h = crc32_hash("LoadLibraryA")
        expected = binascii.crc32(b"LoadLibraryA") & 0xFFFFFFFF
        assert h == expected

    def test_fnv1a_default(self):
        from pemcp.mcp._helpers_api_hashes import fnv1a_hash
        h = fnv1a_hash("LoadLibraryA")
        assert isinstance(h, int)
        assert 0 <= h <= 0xFFFFFFFF

    def test_fnv1a_custom_seed(self):
        from pemcp.mcp._helpers_api_hashes import fnv1a_hash
        h_default = fnv1a_hash("test")
        h_custom = fnv1a_hash("test", seed=0)
        assert h_default != h_custom

    def test_case_handling_lower(self):
        from pemcp.mcp._helpers_api_hashes import compute_hash
        h_normal = compute_hash("LoadLibraryA", "djb2")
        h_lower = compute_hash("LoadLibraryA", "djb2", case_handling="lower")
        h_same = compute_hash("loadlibrarya", "djb2")
        assert h_normal != h_lower
        assert h_lower == h_same

    def test_case_handling_upper(self):
        from pemcp.mcp._helpers_api_hashes import compute_hash
        h_upper = compute_hash("LoadLibraryA", "djb2", case_handling="upper")
        h_same = compute_hash("LOADLIBRARYA", "djb2")
        assert h_upper == h_same

    def test_unknown_algorithm_raises(self):
        from pemcp.mcp._helpers_api_hashes import compute_hash
        with pytest.raises(ValueError, match="Unknown hash algorithm"):
            compute_hash("test", "nonexistent")


class TestBuildHashLookup:
    """Tests for build_hash_lookup utility."""

    def test_basic_lookup(self):
        from pemcp.mcp._helpers_api_hashes import build_hash_lookup
        names = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]
        lookup = build_hash_lookup(names, "djb2")
        assert len(lookup) == 3
        for h, name in lookup.items():
            assert isinstance(h, int)
            assert name in names

    def test_lookup_with_custom_seed(self):
        from pemcp.mcp._helpers_api_hashes import build_hash_lookup
        names = ["LoadLibraryA"]
        lookup_default = build_hash_lookup(names, "djb2")
        lookup_custom = build_hash_lookup(names, "djb2", seed=1572)
        # Different seeds → different hash values in keys
        assert set(lookup_default.keys()) != set(lookup_custom.keys())
