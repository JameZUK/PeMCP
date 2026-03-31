"""Tool registration manager for MCP tool loading.

Manages the module groups that make up Arkana's tool catalog and provides
``register_all_tools()`` which is called once at startup from ``main.py``.
"""
import importlib
import logging
import threading
from typing import Set

logger = logging.getLogger("Arkana")

# Track which modules have been registered to avoid double-imports
_registered_modules: Set[str] = set()
_registry_lock = threading.Lock()

# ---------------------------------------------------------------------------
#  Module groups
# ---------------------------------------------------------------------------

# Core tools — format-independent, needed before any file is opened.
# tools_pe is included because it contains open_file/close_file.
CORE_MODULES = [
    "arkana.mcp.tools_pe",
    "arkana.mcp.tools_config",
    "arkana.mcp.tools_samples",
    "arkana.mcp.tools_session",
    "arkana.mcp.tools_notes",
    "arkana.mcp.tools_history",
    "arkana.mcp.tools_cache",
    "arkana.mcp.tools_warnings",
    "arkana.mcp.tools_learning",
    "arkana.mcp.tools_macro",
    "arkana.mcp.tools_sandbox",
]

# Common analysis tools — registered for ANY binary format.
COMMON_ANALYSIS_MODULES = [
    "arkana.mcp.tools_strings",
    "arkana.mcp.tools_triage",
    "arkana.mcp.tools_classification",
    "arkana.mcp.tools_deobfuscation",
    "arkana.mcp.tools_crypto",
    "arkana.mcp.tools_ioc",
    "arkana.mcp.tools_format_detect",
    "arkana.mcp.tools_batch",
    "arkana.mcp.tools_struct",
    "arkana.mcp.tools_rename",
    "arkana.mcp.tools_types",
    "arkana.mcp.tools_diff",
    "arkana.mcp.tools_export",
    "arkana.mcp.tools_workflow",
    "arkana.mcp.tools_context",
    "arkana.mcp.tools_dashboard_exposed",
    "arkana.mcp.tools_malware_identify",
    "arkana.mcp.tools_malware_detect",
    "arkana.mcp.tools_threat_intel",
    "arkana.mcp.tools_payload",
    "arkana.mcp.tools_bsim",
    "arkana.mcp.tools_virustotal",
    "arkana.mcp.tools_frida",
]

# angr-based tools
ANGR_MODULES = [
    "arkana.mcp.tools_angr",
    "arkana.mcp.tools_angr_disasm",
    "arkana.mcp.tools_angr_dataflow",
    "arkana.mcp.tools_angr_hooks",
    "arkana.mcp.tools_angr_forensic",
    "arkana.mcp.tools_vuln",
    "arkana.mcp.tools_taint",
    "arkana.mcp.tools_new_libs",
]

# PE-specific tools (tools_pe is in CORE because it contains open_file/close_file)
PE_MODULES = [
    "arkana.mcp.tools_pe_extended",
    "arkana.mcp.tools_pe_structure",
    "arkana.mcp.tools_pe_forensic",
    "arkana.mcp.tools_unpack",
    "arkana.mcp.tools_autoit",
]

# ELF-specific tools
ELF_MODULES = [
    "arkana.mcp.tools_elf",
]

# Mach-O-specific tools
MACHO_MODULES = [
    "arkana.mcp.tools_macho",
]

# .NET tools
DOTNET_MODULES = [
    "arkana.mcp.tools_dotnet",
    "arkana.mcp.tools_dotnet_deobfuscate",
]

# Go tools
GO_MODULES = [
    "arkana.mcp.tools_go",
]

# Rust tools
RUST_MODULES = [
    "arkana.mcp.tools_rust",
]

# VB6 tools
VB6_MODULES = [
    "arkana.mcp.tools_vb6",
]

# Emulation / debugging tools (heavy, optional)
EMULATION_MODULES = [
    "arkana.mcp.tools_qiling",
    "arkana.mcp.tools_debug",
    "arkana.mcp.tools_emulate_inspect",
]

# Refinery tools — only when binary-refinery is installed
REFINERY_MODULES = [
    "arkana.mcp.tools_refinery",
    "arkana.mcp.tools_refinery_extract",
    "arkana.mcp.tools_refinery_forensic",
    "arkana.mcp.tools_refinery_dotnet",
    "arkana.mcp.tools_refinery_executable",
    "arkana.mcp.tools_refinery_advanced",
]

# All non-refinery modules
ALL_MODULES = (
    CORE_MODULES
    + PE_MODULES
    + COMMON_ANALYSIS_MODULES
    + ANGR_MODULES
    + ELF_MODULES
    + MACHO_MODULES
    + DOTNET_MODULES
    + GO_MODULES
    + RUST_MODULES
    + VB6_MODULES
    + EMULATION_MODULES
    # Refinery handled separately via REFINERY_AVAILABLE check
)


# ---------------------------------------------------------------------------
#  Registration API
# ---------------------------------------------------------------------------

def register_modules(modules: list, *, refinery_available: bool = False) -> int:
    """Import tool modules to register their tools with FastMCP.

    Skips modules that have already been registered.  Thread-safe.

    Returns the number of newly registered modules.
    """
    added = 0
    with _registry_lock:
        for mod_name in modules:
            if mod_name in _registered_modules:
                continue
            # Skip refinery modules if binary-refinery not installed
            if mod_name in REFINERY_MODULES and not refinery_available:
                continue
            try:
                importlib.import_module(mod_name)
                _registered_modules.add(mod_name)
                added += 1
            except Exception:
                logger.warning("Failed to register tool module %s", mod_name, exc_info=True)
    return added


def register_all_tools(*, refinery_available: bool = False) -> int:
    """Register all tools at startup."""
    added = register_modules(ALL_MODULES)
    if refinery_available:
        added += register_modules(REFINERY_MODULES, refinery_available=True)
    return added


def get_registered_module_count() -> int:
    """Return the number of currently registered tool modules."""
    return len(_registered_modules)
