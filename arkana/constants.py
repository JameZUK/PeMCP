"""
Pure constants — no optional-library imports, no side effects.

Safe to import from anywhere without triggering heavyweight library loads.
"""
from pathlib import Path

# --- MCP Response Size Limit ---
MAX_MCP_RESPONSE_SIZE_KB = 64
MAX_MCP_RESPONSE_SIZE_BYTES = MAX_MCP_RESPONSE_SIZE_KB * 1024

# --- Timeout Constants (seconds) ---
ANGR_ANALYSIS_TIMEOUT = 300    # angr symbolic execution / analysis operations
ANGR_SHORT_TIMEOUT = 120       # shorter angr operations (e.g. anti-debug scan)
HTTP_DOWNLOAD_TIMEOUT = 60     # downloading resources (YARA rules, capa rules)
HTTP_API_TIMEOUT = 20          # external API calls (e.g. VirusTotal)
HTTP_QUICK_TIMEOUT = 15        # quick HTTP requests (e.g. PEiD DB download)

# --- VirusTotal ---
VT_API_URL_FILE_REPORT = "https://www.virustotal.com/api/v3/files/"

# --- PEiD ---
PEID_USERDB_URL = "https://raw.githubusercontent.com/JameZUK/Arkana/refs/heads/main/userdb.txt"

# --- Capa ---
CAPA_RULES_ZIP_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.3.0.zip"
CAPA_RULES_DEFAULT_DIR_NAME = "capa_rules_store"
CAPA_RULES_SUBDIR_NAME = "rules"

# --- YARA Rules Store ---
YARA_RULES_STORE_DIR_NAME = "yara_rules_store"
YARA_REVERSINGLABS_ZIP_URL = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip"
YARA_REVERSINGLABS_SUBDIR = "reversinglabs"
YARA_COMMUNITY_ZIP_URL = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
YARA_COMMUNITY_SUBDIR = "community"

# --- Artifact Limits ---
MAX_ARTIFACT_FILE_SIZE = 100 * 1024 * 1024        # 100 MB per artifact
MAX_TOTAL_ARTIFACT_EXPORT_SIZE = 50 * 1024 * 1024  # 50 MB total in exports

# --- FLOSS Fallback Constants ---
MIN_STR_LEN_FALLBACK_FLOSS = 4

# --- Dependencies manifest (for diagnostics / status reporting) ---
DEPENDENCIES = [
    ("cryptography", "cryptography", "Cryptography (for digital signatures)", False),
    ("requests", "requests", "Requests (for PEiD DB download & capa/FLOSS support)", False),
    ("signify.authenticode", "signify", "Signify (for Authenticode validation)", False),
    ("yara", "yara-python", "Yara (for YARA scanning)", False),
    ("capa.main", "flare-capa", "Capa (for capability detection)", False),
    ("floss.main", "flare-floss", "FLOSS (for advanced string extraction)", False),
    ("stringsifter", "stringsifter", "StringSifter (for ranking string relevance)", False),
    ("rapidfuzz", "rapidfuzz", "RapidFuzz (for fuzzy string matching)", False),
    ("viv_utils", "vivisect", "Vivisect & Viv-Utils (for FLOSS analysis backend)", False),
    ("mcp.server", "mcp[cli]", "MCP SDK (for MCP server mode)", True),
    ("angr", "angr", "Angr (for binary decompilation & solving)", False),
    ("refinery", "binary-refinery", "Binary Refinery (for data transforms, crypto, deobfuscation)", False),
]
