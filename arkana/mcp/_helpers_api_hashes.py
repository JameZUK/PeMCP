"""Shared helpers for API hash scanning tools.

Provides a bundled Windows API name database and hash computation functions
with configurable seeds, used by both scan_for_api_hashes and
qiling_resolve_api_hashes.
"""
import binascii
import json
import logging
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("Arkana")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_API_DB_PATH = _DATA_DIR / "windows_api_names.json"
_EXTENDED_DB_PATH = _DATA_DIR / "windows_api_exports_oalabs.json"

_api_db_cache: Optional[Dict[str, List[str]]] = None
_extended_names_cache: Optional[List[str]] = None


def _load_api_name_db() -> Dict[str, List[str]]:
    """Load and cache the bundled Windows API name database.

    Returns dict mapping DLL names to lists of exported function names.
    """
    global _api_db_cache
    if _api_db_cache is not None:
        return _api_db_cache
    if not _API_DB_PATH.exists():
        logger.warning("Windows API name database not found at %s", _API_DB_PATH)
        return {}
    with open(_API_DB_PATH, "r") as f:
        _api_db_cache = json.load(f)
    return _api_db_cache


def _load_extended_api_names() -> List[str]:
    """Load the extended OALabs API export list (~10K names).

    This is a flat list without DLL grouping, used as a secondary
    source when the curated DB doesn't resolve a hash.
    """
    global _extended_names_cache
    if _extended_names_cache is not None:
        return _extended_names_cache
    if not _EXTENDED_DB_PATH.exists():
        return []
    try:
        with open(_EXTENDED_DB_PATH, "r") as f:
            _extended_names_cache = json.load(f)
        return _extended_names_cache
    except Exception:
        logger.debug("Failed to load extended API name database", exc_info=True)
        return []


def get_all_api_names(include_extended: bool = False) -> List[str]:
    """Return a flat list of all API names from the database.

    Args:
        include_extended: If True, also include the ~10K OALabs export list.
    """
    db = _load_api_name_db()
    names = []
    for dll_names in db.values():
        names.extend(dll_names)
    if include_extended:
        extended = _load_extended_api_names()
        existing = set(names)
        names.extend(n for n in extended if n not in existing)
    return names


def get_api_names_with_dll() -> List[Tuple[str, str]]:
    """Return list of (api_name, dll_name) tuples from the curated DB."""
    db = _load_api_name_db()
    results = []
    for dll, names in db.items():
        for name in names:
            results.append((name, dll))
    return results


# ---------------------------------------------------------------------------
#  Hash algorithm implementations with configurable seeds
# ---------------------------------------------------------------------------

def ror13_hash(name: str, seed: int = 0) -> int:
    """ROR13 hash (commonly used by shellcode). Seed is the initial hash value."""
    h = seed & 0xFFFFFFFF
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def djb2_hash(name: str, seed: int = 5381) -> int:
    """DJB2 hash (Daniel J. Bernstein). Default seed is 5381."""
    h = seed & 0xFFFFFFFF
    for c in name:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def crc32_hash(name: str, seed: int = 0) -> int:
    """CRC32 hash. Seed is ignored (CRC32 initial value is fixed)."""
    return binascii.crc32(name.encode("ascii")) & 0xFFFFFFFF


def fnv1a_hash(name: str, seed: int = 0x811C9DC5) -> int:
    """FNV-1a hash (32-bit). Default seed (offset basis) is 0x811C9DC5."""
    h = seed & 0xFFFFFFFF
    for c in name:
        h = (h ^ ord(c)) & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


HASH_ALGORITHMS: Dict[str, Callable] = {
    "ror13": ror13_hash,
    "djb2": djb2_hash,
    "crc32": crc32_hash,
    "fnv1a": fnv1a_hash,
}

# Default seeds per algorithm
DEFAULT_SEEDS: Dict[str, int] = {
    "ror13": 0,
    "djb2": 5381,
    "crc32": 0,
    "fnv1a": 0x811C9DC5,
}


def compute_hash(name: str, algorithm: str, seed: Optional[int] = None,
                 case_handling: Optional[str] = None) -> int:
    """Compute an API hash with optional seed and case handling.

    Args:
        name: API function name to hash.
        algorithm: Hash algorithm name (ror13, djb2, crc32, fnv1a).
        seed: Custom seed/initial value. None uses the algorithm default.
        case_handling: 'lower', 'upper', or None (no transformation).

    Returns:
        32-bit hash value.
    """
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(
            f"Unknown hash algorithm '{algorithm}'. "
            f"Supported: {', '.join(sorted(HASH_ALGORITHMS))}"
        )

    if case_handling == "lower":
        name = name.lower()
    elif case_handling == "upper":
        name = name.upper()

    func = HASH_ALGORITHMS[algorithm]
    if seed is not None:
        return func(name, seed=seed)
    return func(name)


def build_hash_lookup(
    api_names: List[str],
    algorithm: str,
    seed: Optional[int] = None,
    case_handling: Optional[str] = None,
) -> Dict[int, str]:
    """Build a hash→API name lookup table.

    Args:
        api_names: List of API function names.
        algorithm: Hash algorithm name.
        seed: Custom seed (None for algorithm default).
        case_handling: 'lower', 'upper', or None.

    Returns:
        Dict mapping hash values to API names.
    """
    lookup = {}
    for name in api_names:
        h = compute_hash(name, algorithm, seed=seed, case_handling=case_handling)
        lookup[h] = name
    return lookup
