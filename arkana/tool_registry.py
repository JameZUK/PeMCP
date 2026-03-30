"""Lazy tool registration manager for context-aware MCP tool loading.

Controls which tool modules are registered with the MCP server based on
the ``--tool-profile`` CLI argument or ``ARKANA_TOOL_PROFILE`` env var.

Profiles:
  full    — All tools at startup (default, backward compatible).
  lazy    — Core tools only at startup; analysis tools registered
            dynamically after ``open_file`` detects the binary format.
  minimal — Core tools only; no automatic expansion on file open.
"""
import importlib
import logging
import threading
from typing import Optional, Set

logger = logging.getLogger("Arkana")

# Current profile — set by main.py at startup
_tool_profile: str = "full"

# Track which modules have been registered to avoid double-imports
_registered_modules: Set[str] = set()
_registry_lock = threading.Lock()

# ---------------------------------------------------------------------------
#  Module groups
# ---------------------------------------------------------------------------

# Core tools — always registered regardless of profile.
# These are format-independent and needed before any file is opened.
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

# Common analysis tools — registered for ANY binary format after open_file.
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

# angr-based tools — registered when angr is available.
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

# All modules (for "full" profile) — order matches original main.py
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

def set_profile(profile: str) -> None:
    """Set the active tool profile. Called once at startup from main.py."""
    global _tool_profile
    _tool_profile = profile


def get_profile() -> str:
    """Return the active tool profile."""
    return _tool_profile


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


def register_core_tools() -> int:
    """Register the core tool set (always available)."""
    return register_modules(CORE_MODULES)


def register_all_tools(*, refinery_available: bool = False) -> int:
    """Register all tools (for 'full' profile)."""
    added = register_modules(ALL_MODULES)
    if refinery_available:
        added += register_modules(REFINERY_MODULES, refinery_available=True)
    return added


async def register_tools_for_format(
    fmt: str,
    ctx: Optional[object] = None,
    *,
    pe_data: Optional[dict] = None,
    refinery_available: bool = False,
) -> int:
    """Register tools appropriate for the detected binary format.

    Called from ``open_file`` after format detection.  In ``lazy`` profile,
    this adds the analysis tools that weren't loaded at startup.  In ``full``
    or ``minimal`` profiles this is a no-op (all tools already loaded, or
    auto-expansion disabled).

    Sends ``notifications/tools/list_changed`` to the MCP client if new
    tools were registered.

    Returns the number of newly registered modules.
    """
    if _tool_profile == "minimal":
        return 0  # User explicitly chose no auto-expansion

    if _tool_profile == "full":
        return 0  # All tools already registered at startup

    # --- "lazy" profile: register format-appropriate tools ---
    added = 0

    # Common analysis tools for any binary
    added += register_modules(COMMON_ANALYSIS_MODULES)
    added += register_modules(ANGR_MODULES)
    added += register_modules(EMULATION_MODULES)

    if refinery_available:
        added += register_modules(REFINERY_MODULES, refinery_available=True)

    # Format-specific modules
    if fmt == "pe":
        added += register_modules(PE_MODULES)
        # Check for .NET/Go/Rust/VB6 if PE data available
        if pe_data:
            imports = pe_data.get("imports", {})
            import_names = set()
            if isinstance(imports, dict):
                import_names = {k.lower() for k in imports}
            elif isinstance(imports, list):
                import_names = {
                    (e.get("dll", "") if isinstance(e, dict) else "").lower()
                    for e in imports
                }

            if "mscoree.dll" in import_names:
                added += register_modules(DOTNET_MODULES)
            if any("go" in n for n in import_names):
                added += register_modules(GO_MODULES)
            if any("vcruntime" in n or "rust" in n for n in import_names):
                added += register_modules(RUST_MODULES)
            if "msvbvm60.dll" in import_names:
                added += register_modules(VB6_MODULES)

            # If we couldn't narrow down, register all language modules
            if not import_names:
                added += register_modules(DOTNET_MODULES)
                added += register_modules(GO_MODULES)
                added += register_modules(RUST_MODULES)
                added += register_modules(VB6_MODULES)

    elif fmt == "elf":
        added += register_modules(ELF_MODULES)
        added += register_modules(GO_MODULES)
        added += register_modules(RUST_MODULES)

    elif fmt == "macho":
        added += register_modules(MACHO_MODULES)
        added += register_modules(GO_MODULES)
        added += register_modules(RUST_MODULES)

    elif fmt == "shellcode":
        # Shellcode doesn't need PE/ELF/Mach-O tools but may need angr
        pass

    # Notify client that tool list changed
    if added > 0 and ctx is not None:
        try:
            session = ctx.request_context.session
            await session.send_tool_list_changed()
            logger.info(
                "Lazy tool registration: %d modules added for format=%s, "
                "client notified via list_changed",
                added, fmt,
            )
        except Exception:
            logger.debug(
                "Could not send tool_list_changed notification",
                exc_info=True,
            )

    return added


def get_registered_module_count() -> int:
    """Return the number of currently registered tool modules."""
    return len(_registered_modules)
