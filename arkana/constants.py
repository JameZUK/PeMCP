"""
Pure constants — no optional-library imports, no side effects.

Safe to import from anywhere without triggering heavyweight library loads.
"""
from pathlib import Path

__all__ = [
    "MAX_MCP_RESPONSE_SIZE_KB", "MAX_MCP_RESPONSE_SIZE_BYTES",
    "MCP_SOFT_RESPONSE_LIMIT_CHARS",
    "ANGR_ANALYSIS_TIMEOUT", "ANGR_SHORT_TIMEOUT", "ANGR_CFG_TIMEOUT",
    "BACKGROUND_TASK_TIMEOUT",
    "CAPA_ANALYSIS_TIMEOUT", "FLOSS_ANALYSIS_TIMEOUT",
    "HTTP_DOWNLOAD_TIMEOUT", "HTTP_API_TIMEOUT", "HTTP_QUICK_TIMEOUT",
    "VT_API_URL_FILE_REPORT",
    "PEID_USERDB_URL",
    "CAPA_RULES_ZIP_URL", "CAPA_RULES_DEFAULT_DIR_NAME", "CAPA_RULES_SUBDIR_NAME",
    "YARA_RULES_STORE_DIR_NAME",
    "YARA_REVERSINGLABS_ZIP_URL", "YARA_REVERSINGLABS_SUBDIR",
    "YARA_COMMUNITY_ZIP_URL", "YARA_COMMUNITY_SUBDIR",
    "BSIM_DB_DIR", "BSIM_DEFAULT_THRESHOLD", "BSIM_BACKGROUND_TIMEOUT",
    "MAX_ARTIFACT_FILE_SIZE", "MAX_TOTAL_ARTIFACT_EXPORT_SIZE",
    "MAX_BATCH_RENAMES",
    "MAX_STRUCT_FIELDS", "MAX_ENUM_VALUES",
    "MAX_BATCH_DECOMPILE", "BATCH_DECOMPILE_PER_FUNCTION_TIMEOUT",
    "MAX_HEX_PATTERN_TOKENS", "MAX_HEX_PATTERN_MATCHES",
    "DEFAULT_SEARCH_CONTEXT_LINES", "MAX_SEARCH_CONTEXT_LINES", "MAX_SEARCH_MATCHES",
    "ENRICHMENT_MAX_DECOMPILE", "ENRICHMENT_TIMEOUT",
    "MIN_STR_LEN_FALLBACK_FLOSS", "MAX_FLOSS_ENRICHMENT_STRINGS",
    "MAX_FLOSS_REFS_PER_STRING",
    "VIVISECT_BYTES_PER_SECOND_ESTIMATE", "VIVISECT_POLL_INTERVAL",
    "MAX_LIST_SAMPLES_LIMIT", "MAX_TOOL_LIMIT",
    "INTEGRITY_NULL_RATIO_SUSPICIOUS", "INTEGRITY_NULL_RATIO_CORRUPT",
    "INTEGRITY_MIN_FILE_SIZE", "INTEGRITY_PE_MIN_SIZE",
    "INTEGRITY_ELF_MIN_SIZE", "INTEGRITY_MACHO_MIN_SIZE",
    "INTEGRITY_ENTROPY_PACKED", "INTEGRITY_ENTROPY_NEAR_ZERO",
    "INTEGRITY_MAX_SECTIONS_PE", "INTEGRITY_FLAGGED_TIMEOUT_FACTOR",
    "INTEGRITY_SAMPLE_SIZE", "INTEGRITY_MAX_ISSUES",
    "MAX_ANALYSIS_WARNINGS",
    "DEFAULT_MAX_FILE_SIZE_MB",
    # Context aggregation
    "MAX_CONTEXT_DECOMPILE_LINES", "MAX_CONTEXT_STRINGS", "MAX_CONTEXT_XREFS",
    # Frida generation
    "MAX_FRIDA_HOOK_TARGETS", "MAX_FRIDA_TRACE_APIS",
    # Vulnerability scanning
    "MAX_VULN_SCAN_FUNCTIONS", "MAX_VULN_FINDINGS",
    # Symbolic execution extensions
    "MAX_SYMBOLIC_STEPS", "MAX_SYMBOLIC_ACTIVE_STATES", "MAX_SYMBOLIC_FIND_ADDRESSES",
    # .NET deobfuscation
    "DOTNET_DEOBFUSCATE_TIMEOUT", "DOTNET_DECOMPILE_TIMEOUT",
    "DOTNET_DECOMPILE_MAX_OUTPUT_LINES",
    # Data flow analysis
    "MAX_DATA_FLOW_FUNCTIONS", "MAX_DATA_FLOW_FINDINGS",
    "DATA_FLOW_PER_FUNC_TIMEOUT", "DATA_FLOW_AGGREGATE_TIMEOUT",
    # Obfuscation detection
    "CFF_MIN_BLOCKS", "CFF_DISPATCHER_IN_DEGREE_THRESHOLD",
    "CFF_BACK_EDGE_RATIO_THRESHOLD",
    "OPAQUE_PREDICATE_SOLVER_TIMEOUT", "MAX_OPAQUE_PREDICATE_BLOCKS",
    "OBFUSCATION_DETECTION_TIMEOUT",
    "MAX_CFF_SCAN_FUNCTIONS", "MAX_OPAQUE_SCAN_FUNCTIONS",
    # Debug session
    "MAX_DEBUG_SESSIONS", "DEBUG_SESSION_TTL", "DEBUG_COMMAND_TIMEOUT",
    "MAX_DEBUG_SNAPSHOTS", "MAX_DEBUG_INSTRUCTIONS", "MAX_DEBUG_MEMORY_READ",
    "DEBUG_DISASM_PREVIEW", "MAX_DEBUG_WATCHPOINT_SIZE",
    "MAX_DEBUG_BREAKPOINTS", "MAX_DEBUG_WATCHPOINTS",
    "MAX_DEBUG_USER_STUBS", "MAX_DEBUG_STUB_WRITE_SIZE", "MAX_DEBUG_STUB_WRITES",
    "DEPENDENCIES",
]

# --- MCP Response Size Limit ---
MAX_MCP_RESPONSE_SIZE_KB = 64
MAX_MCP_RESPONSE_SIZE_BYTES = MAX_MCP_RESPONSE_SIZE_KB * 1024

# Soft character limit for Claude Code CLI compatibility.
# Claude Code truncates MCP tool responses at character thresholds:
#   <10K chars: no truncation, 10-30K: truncated to 8K, 30-50K: truncated to 4K.
# Default 8000 gives safe margin under the 10K threshold.
# Override with ARKANA_MCP_RESPONSE_LIMIT_CHARS env var (e.g. 65536 to restore
# old 64KB-only behaviour for non-Claude-Code clients).
MCP_SOFT_RESPONSE_LIMIT_CHARS = 8000

# --- Timeout Constants (seconds) ---
ANGR_ANALYSIS_TIMEOUT = 300    # angr symbolic execution / analysis operations
ANGR_SHORT_TIMEOUT = 120       # shorter angr operations (e.g. anti-debug scan)
ANGR_CFG_TIMEOUT = 1800        # background CFGFast timeout (env: ARKANA_ANGR_CFG_TIMEOUT)
BACKGROUND_TASK_TIMEOUT = 1800 # background task timeout (env: ARKANA_BACKGROUND_TASK_TIMEOUT)
CAPA_ANALYSIS_TIMEOUT = 300    # capa analysis during open_file (env: ARKANA_CAPA_ANALYSIS_TIMEOUT)
FLOSS_ANALYSIS_TIMEOUT = 300   # FLOSS analysis during open_file (env: ARKANA_FLOSS_ANALYSIS_TIMEOUT)
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

# --- BSim Function Similarity ---
BSIM_DB_DIR = Path.home() / ".arkana" / "bsim"
BSIM_DEFAULT_THRESHOLD = 0.5
BSIM_BACKGROUND_TIMEOUT = 1800  # seconds — 30 min (env: ARKANA_BSIM_BACKGROUND_TIMEOUT). Note: CLAUDE.md historically said 600s; actual value is 1800s.

# --- Artifact Limits ---
MAX_ARTIFACT_FILE_SIZE = 100 * 1024 * 1024        # 100 MB per artifact
MAX_TOTAL_ARTIFACT_EXPORT_SIZE = 50 * 1024 * 1024  # 50 MB total in exports

# --- Rename / Annotation Limits ---
MAX_BATCH_RENAMES = 50

# --- Custom Type Limits ---
MAX_STRUCT_FIELDS = 100
MAX_ENUM_VALUES = 500

# --- Batch Decompile Limits ---
MAX_BATCH_DECOMPILE = 20
BATCH_DECOMPILE_PER_FUNCTION_TIMEOUT = 60  # seconds per function

# --- Hex Pattern Search Limits ---
MAX_HEX_PATTERN_TOKENS = 200
MAX_HEX_PATTERN_MATCHES = 5000

# --- Search/Grep Limits ---
DEFAULT_SEARCH_CONTEXT_LINES = 2
MAX_SEARCH_CONTEXT_LINES = 20
MAX_SEARCH_MATCHES = 500

# --- Auto-Enrichment ---
ENRICHMENT_MAX_DECOMPILE = 100       # max functions to decompile in background sweep
ENRICHMENT_TIMEOUT = 1800            # overall enrichment timeout (seconds)

# --- FLOSS Fallback Constants ---
MIN_STR_LEN_FALLBACK_FLOSS = 4
MAX_FLOSS_ENRICHMENT_STRINGS = 500  # cap xref enrichment of static strings
MAX_FLOSS_REFS_PER_STRING = 20  # Cap cross-references per string to prevent OOM

# --- FLOSS Vivisect Progress Estimation ---
VIVISECT_BYTES_PER_SECOND_ESTIMATE = 50_000  # ~50 KB/s for time-based progress curve
VIVISECT_POLL_INTERVAL = 3  # seconds between function count polls during analysis

# --- File Integrity Check ---
INTEGRITY_NULL_RATIO_SUSPICIOUS = 0.95   # ratio above this → medium issue
INTEGRITY_NULL_RATIO_CORRUPT = 0.99      # ratio above this → high issue
INTEGRITY_MIN_FILE_SIZE = 64             # below this → medium issue
INTEGRITY_PE_MIN_SIZE = 97               # minimum valid PE (DOS+PE sig+COFF)
INTEGRITY_ELF_MIN_SIZE = 52              # minimum valid ELF header (32-bit)
INTEGRITY_MACHO_MIN_SIZE = 28            # minimum valid Mach-O header
INTEGRITY_ENTROPY_PACKED = 7.0           # entropy above this → likely packed
INTEGRITY_ENTROPY_NEAR_ZERO = 0.5        # entropy below this → suspicious
INTEGRITY_MAX_SECTIONS_PE = 96           # PE with more sections → suspicious
INTEGRITY_FLAGGED_TIMEOUT_FACTOR = 0.5   # multiply timeout for flagged files
INTEGRITY_SAMPLE_SIZE = 65536            # bytes to sample for entropy/null ratio
INTEGRITY_MAX_ISSUES = 50                # cap issues list

# --- list_samples Pagination ---
MAX_LIST_SAMPLES_LIMIT = 500  # maximum files per page in list_samples

# Upper bound on generic 'limit' parameters to prevent excessive memory allocation
MAX_TOOL_LIMIT = 100_000

# --- Analysis Warning Capture ---
MAX_ANALYSIS_WARNINGS = 500  # max unique warnings retained per session

# --- File Size Limit ---
DEFAULT_MAX_FILE_SIZE_MB = 256  # default max file size for open_file / import

# --- Context Aggregation ---
MAX_CONTEXT_DECOMPILE_LINES = 80  # max decompiled lines in context response
MAX_CONTEXT_STRINGS = 50  # max strings returned per function context
MAX_CONTEXT_XREFS = 30  # max callers/callees in context response

# --- Frida Generation ---
MAX_FRIDA_HOOK_TARGETS = 50  # max API targets per hook script
MAX_FRIDA_TRACE_APIS = 100  # max APIs per trace script

# --- Vulnerability Scanning ---
MAX_VULN_SCAN_FUNCTIONS = 500  # max functions to scan at once
MAX_VULN_FINDINGS = 200  # max findings per scan

# --- Symbolic Execution Extensions ---
MAX_SYMBOLIC_STEPS = 100_000  # upper bound for max_steps parameter
MAX_SYMBOLIC_ACTIVE_STATES = 100  # upper bound for max_active parameter
MAX_SYMBOLIC_FIND_ADDRESSES = 20  # max find addresses for explore

# --- .NET Deobfuscation ---
DOTNET_DEOBFUSCATE_TIMEOUT = 120   # seconds for de4dot / NETReactorSlayer subprocess
DOTNET_DECOMPILE_TIMEOUT = 120     # seconds for ilspycmd subprocess
DOTNET_DECOMPILE_MAX_OUTPUT_LINES = 5000  # cap decompiled C# output lines

# --- Data Flow Analysis ---
MAX_DATA_FLOW_FUNCTIONS = 50       # max functions to analyse for source→sink flows
MAX_DATA_FLOW_FINDINGS = 100       # max flow findings to return
DATA_FLOW_PER_FUNC_TIMEOUT = 30    # per-function RDA timeout (seconds)
DATA_FLOW_AGGREGATE_TIMEOUT = 120  # overall tool timeout (seconds)

# --- Obfuscation Detection ---
CFF_MIN_BLOCKS = 6                              # skip functions with fewer blocks
CFF_DISPATCHER_IN_DEGREE_THRESHOLD = 4           # min in-degree for dispatcher candidate
CFF_BACK_EDGE_RATIO_THRESHOLD = 0.6              # ratio of blocks with edge to dispatcher
OPAQUE_PREDICATE_SOLVER_TIMEOUT = 15             # Z3 solver timeout per block (seconds)
MAX_OPAQUE_PREDICATE_BLOCKS = 500                # max blocks to analyse across all functions
OBFUSCATION_DETECTION_TIMEOUT = 180              # overall tool timeout (seconds)
MAX_CFF_SCAN_FUNCTIONS = 200                     # max functions to scan for CFF
MAX_OPAQUE_SCAN_FUNCTIONS = 100                  # max functions to scan for opaque predicates

# --- Debug Session Constants ---
MAX_DEBUG_SESSIONS = 3               # Max concurrent debug sessions per state (env: ARKANA_MAX_DEBUG_SESSIONS)
DEBUG_SESSION_TTL = 1800             # 30-minute idle timeout (env: ARKANA_DEBUG_SESSION_TTL)
DEBUG_COMMAND_TIMEOUT = 300          # 5-minute timeout per debug command (env: ARKANA_DEBUG_COMMAND_TIMEOUT)
MAX_DEBUG_SNAPSHOTS = 10             # Max snapshots per session (env: ARKANA_MAX_DEBUG_SNAPSHOTS)
MAX_DEBUG_INSTRUCTIONS = 10_000_000  # Max instructions per continue/run_until
MAX_DEBUG_MEMORY_READ = 1_048_576    # 1MB max memory read per call
DEBUG_DISASM_PREVIEW = 5             # Instructions to preview in read_state
MAX_DEBUG_WATCHPOINT_SIZE = 1_048_576  # 1MB max watchpoint region
MAX_DEBUG_BREAKPOINTS = 100          # Max breakpoints per session
MAX_DEBUG_WATCHPOINTS = 50           # Max watchpoints per session
MAX_DEBUG_CAPTURED_OUTPUT = 10_000   # Max captured I/O output entries
MAX_DEBUG_PENDING_INPUT = 1_000      # Max pending input entries for stubbed stdin
MAX_DEBUG_API_TRACE = 10_000         # Max API trace entries per session
MAX_DEBUG_SEARCH_MATCHES = 100       # Max memory search matches returned
DEBUG_SEARCH_CONTEXT_BYTES = 32      # Context bytes around memory search matches
MAX_DEBUG_USER_STUBS = 200           # Max user-defined API stubs per session
MAX_DEBUG_STUB_WRITE_SIZE = 1024     # Max bytes per stub write operation
MAX_DEBUG_STUB_WRITES = 8            # Max write operations per stub

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
