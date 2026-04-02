"""Helpers for detecting Go binaries and annotating Go ABI calling conventions.

Provides Go binary detection, ABI version identification (register vs stack),
and call-site annotation with parameter/return register mappings for annotated
disassembly output.
"""
import re
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Go ABI register assignment tables (from Go internal/abi specification)
# ---------------------------------------------------------------------------

# Go 1.17+ register ABI for AMD64 (9 integer + 15 float registers)
_AMD64_INT_REGS = ("rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11")
_AMD64_FLOAT_REGS = tuple(f"x{i}" for i in range(15))
_AMD64_RESULT_INT = ("rax", "rbx")
_AMD64_RESULT_FLOAT = ("x0",)

# Go 1.18+ register ABI for ARM64 (16 integer + 16 float registers)
_ARM64_INT_REGS = tuple(f"r{i}" for i in range(16))
_ARM64_FLOAT_REGS = tuple(f"f{i}" for i in range(16))
_ARM64_RESULT_INT = tuple(f"r{i}" for i in range(16))
_ARM64_RESULT_FLOAT = tuple(f"f{i}" for i in range(16))

# Minimum Go version that uses register-based ABI per architecture
_REGABI_MIN_VERSION = {
    "amd64": (1, 17),
    "arm64": (1, 18),
}

# ---------------------------------------------------------------------------
# Go function name patterns
# ---------------------------------------------------------------------------

# Go function naming: package.Function, package.(*Type).Method, etc.
# Handles: main.main, crypto/tls.(*Conn).Read, github.com/user/repo/pkg.Func,
#   main.main.func1 (closures), type:.eq.main.Config, go:linkname_target
_GO_FUNC_PATTERN = re.compile(
    r'^(?:'
    r'[a-zA-Z0-9_/.]+\.[a-zA-Z_*().\d]+'  # pkg.Func, closures (func1), deep paths (.com)
    r'|type:\.[a-zA-Z0-9_/.]+'             # type descriptor methods
    r'|go:[a-zA-Z_.]+'                      # go:linkname targets
    r')$'
)

# CGO bridge functions use C ABI, not Go ABI
_CGO_PREFIXES = ("_cgo_", "_Cgo_", "x_cgo_", "_cgoexp_")

# Runtime functions that use internal conventions (not standard Go ABI)
_RUNTIME_INTERNAL = frozenset({
    "runtime.morestack", "runtime.morestack_noctxt",
    "runtime.rt0_go", "runtime.gogo", "runtime.mcall",
    "runtime.systemstack", "runtime.asmcgocall",
})

# Go closure pattern (e.g., main.main.func1, main.init.func2)
_CLOSURE_PATTERN = re.compile(r'^[a-zA-Z0-9_/]+\.[a-zA-Z_]+\.func\d+')

# Maximum function names to scan for Go binary detection
_DETECTION_SAMPLE_SIZE = 50

# Minimum Go function ratio to classify as Go binary
_DETECTION_THRESHOLD = 0.3


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

def _parse_go_version(version_hint: str) -> Optional[Tuple[int, int]]:
    """Extract (major, minor) from a Go version string.

    Handles formats like 'go1.21.5', '1.17', 'go1.18rc1', 'go1.20beta1'.
    Returns None if the version cannot be parsed.
    """
    if not version_hint:
        return None
    m = re.search(r'(?:go)?(\d+)\.(\d+)', str(version_hint))
    if not m:
        return None
    try:
        return (int(m.group(1)), int(m.group(2)))
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def is_go_function(name: str) -> bool:
    """Check if a function name follows Go naming conventions.

    Returns True for names like ``main.main``, ``crypto/tls.(*Conn).Read``,
    ``runtime.mallocgc``.  Returns False for C/CGO bridge functions and
    non-Go names.
    """
    if not name or not isinstance(name, str):
        return False
    # CGO bridge functions follow C ABI
    for prefix in _CGO_PREFIXES:
        if name.startswith(prefix):
            return False
    return bool(_GO_FUNC_PATTERN.match(name))


def is_cgo_function(name: str) -> bool:
    """Check if a function is a CGO bridge (uses platform ABI, not Go ABI)."""
    if not name or not isinstance(name, str):
        return False
    for prefix in _CGO_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def is_go_binary(function_names: List[str]) -> bool:
    """Heuristic detection of Go binaries from function name sample.

    Scans up to ``_DETECTION_SAMPLE_SIZE`` function names and returns True
    if at least ``_DETECTION_THRESHOLD`` fraction match Go naming patterns.
    """
    if not function_names:
        return False
    sample = function_names[:_DETECTION_SAMPLE_SIZE]
    go_count = sum(1 for name in sample if is_go_function(name))
    return go_count >= max(1, int(len(sample) * _DETECTION_THRESHOLD))


# ---------------------------------------------------------------------------
# ABI detection
# ---------------------------------------------------------------------------

def detect_go_abi(
    go_version_hint: str,
    arch: str,
) -> str:
    """Determine whether a Go binary uses register or stack ABI.

    Args:
        go_version_hint: Go version string (e.g. 'go1.21.5').
        arch: Architecture string — 'amd64', 'arm64', 'x86', etc.

    Returns:
        ``'register'``, ``'stack'``, or ``'unknown'`` if the version or
        architecture cannot be determined.
    """
    arch_lower = str(arch).lower().strip()

    # Normalise common angr/capstone arch names to Go arch names
    arch_map = {
        "x86_64": "amd64", "x64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "x86": "x86", "i386": "x86", "i686": "x86",
        "arm": "arm", "mips": "mips",
    }
    go_arch = arch_map.get(arch_lower, arch_lower)

    # x86 (32-bit) always uses stack ABI in Go
    if go_arch in ("x86", "arm", "mips"):
        return "stack"

    min_ver = _REGABI_MIN_VERSION.get(go_arch)
    if min_ver is None:
        return "unknown"

    parsed = _parse_go_version(go_version_hint)
    if parsed is None:
        return "unknown"

    if parsed >= min_ver:
        return "register"
    return "stack"


# ---------------------------------------------------------------------------
# Call-site annotation
# ---------------------------------------------------------------------------

def _get_register_table(
    arch: str,
) -> Optional[Dict[str, Any]]:
    """Return register assignment tables for the given architecture.

    Returns None for unsupported architectures.
    """
    arch_lower = str(arch).lower().strip()
    arch_map = {
        "x86_64": "amd64", "x64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
    }
    go_arch = arch_map.get(arch_lower, arch_lower)

    if go_arch == "amd64":
        return {
            "int_params": _AMD64_INT_REGS,
            "float_params": _AMD64_FLOAT_REGS,
            "int_results": _AMD64_RESULT_INT,
            "float_results": _AMD64_RESULT_FLOAT,
        }
    elif go_arch == "arm64":
        return {
            "int_params": _ARM64_INT_REGS,
            "float_params": _ARM64_FLOAT_REGS,
            "int_results": _ARM64_RESULT_INT,
            "float_results": _ARM64_RESULT_FLOAT,
        }
    return None


def annotate_go_call(
    target_name: str,
    abi_type: str,
    arch: str,
    *,
    go_version_hint: str = "",
    type_info: Optional[Dict[str, Any]] = None,
    max_params: int = 6,
) -> Optional[Dict[str, Any]]:
    """Build a Go ABI annotation dict for a call instruction.

    Args:
        target_name: The resolved function name at the call target.
        abi_type: ``'register'`` or ``'stack'`` (from ``detect_go_abi``).
        arch: Architecture string (e.g. ``'amd64'``).
        go_version_hint: Go version string for display purposes.
        type_info: Optional type information dict from Go type descriptor
            parsing.  If provided and the target function has known parameter
            types, those are included in the annotation.
        max_params: Maximum number of parameter slots to annotate (default 6).

    Returns:
        Annotation dict with ``convention``, ``params``, ``returns``, and
        ``note`` fields.  Returns None if the function is not a Go function,
        is a CGO bridge, or uses internal runtime conventions.
    """
    if not target_name or not isinstance(target_name, str):
        return None

    # Skip non-Go functions
    if not is_go_function(target_name):
        return None

    # Skip CGO bridge functions (use platform ABI)
    if is_cgo_function(target_name):
        return None

    # Skip runtime internals with non-standard conventions
    if target_name in _RUNTIME_INTERNAL:
        return None

    max_params = max(1, min(max_params, 20))

    # Resolve type information for this function if available
    param_types = _resolve_param_types(target_name, type_info)

    if abi_type == "register":
        return _annotate_register_abi(
            target_name, arch, go_version_hint, param_types, max_params,
        )
    elif abi_type == "stack":
        return _annotate_stack_abi(
            target_name, arch, go_version_hint, param_types, max_params,
        )
    return None


def _resolve_param_types(
    func_name: str,
    type_info: Optional[Dict[str, Any]],
) -> Optional[List[Dict[str, str]]]:
    """Look up known parameter types from Go type descriptor data.

    Returns a list of ``{"name": ..., "type": ...}`` dicts, or None if
    type information is unavailable for this function.
    """
    if not type_info or not isinstance(type_info, dict):
        return None

    # Method receivers: check if function is a method on a known struct
    # e.g. main.(*Config).SetHost → look up Config struct
    methods = type_info.get("methods", {})
    if func_name in methods:
        return methods[func_name].get("params")

    return None


def _annotate_register_abi(
    target_name: str,
    arch: str,
    go_version_hint: str,
    param_types: Optional[List[Dict[str, str]]],
    max_params: int,
) -> Dict[str, Any]:
    """Build annotation for Go register-based ABI (Go 1.17+ AMD64, 1.18+ ARM64)."""
    regs = _get_register_table(arch)
    if regs is None:
        return {
            "convention": "register",
            "note": f"Go register ABI — unsupported architecture '{arch}' for detailed mapping",
        }

    int_regs = regs["int_params"]
    result_regs = regs["int_results"]
    n_params = min(max_params, len(int_regs))

    params = []
    for i in range(n_params):
        p = {"register": int_regs[i], "index": i}
        if param_types and i < len(param_types):
            pt = param_types[i]
            if isinstance(pt, dict):
                if pt.get("name"):
                    p["name"] = pt["name"]
                if pt.get("type"):
                    p["type"] = pt["type"]
            else:
                p["type"] = str(pt)
        params.append(p)

    returns = [{"register": r} for r in result_regs]

    # Closures have context pointer in DX (AMD64)
    is_closure = bool(_CLOSURE_PATTERN.match(target_name))
    note_parts = []
    ver_str = go_version_hint or "1.17+"
    arch_upper = arch.upper() if arch else "?"
    note_parts.append(f"Go {ver_str} register ABI ({arch_upper})")
    note_parts.append(f"args in {', '.join(r.upper() for r in int_regs[:n_params])}")
    if is_closure:
        note_parts.append("closure — context pointer in RDX (AMD64)")

    result = {
        "convention": "register",
        "params": params,
        "returns": returns,
        "note": "; ".join(note_parts),
    }
    if is_closure:
        result["closure"] = True
    return result


def _annotate_stack_abi(
    target_name: str,
    arch: str,
    go_version_hint: str,
    param_types: Optional[List[Dict[str, str]]],
    max_params: int,
) -> Dict[str, Any]:
    """Build annotation for Go stack-based ABI (pre-1.17 or 32-bit)."""
    # Determine pointer size for stack slot calculation
    arch_lower = str(arch).lower().strip()
    if arch_lower in ("x86", "i386", "i686", "arm"):
        ptr_size = 4
    else:
        ptr_size = 8

    params = []
    for i in range(max_params):
        # First slot after return address: RSP+ptr_size, then +ptr_size each
        offset = (i + 1) * ptr_size
        p = {"stack_offset": f"[RSP+{hex(offset)}]", "index": i}
        if param_types and i < len(param_types):
            pt = param_types[i]
            if isinstance(pt, dict):
                if pt.get("name"):
                    p["name"] = pt["name"]
                if pt.get("type"):
                    p["type"] = pt["type"]
            else:
                p["type"] = str(pt)
        params.append(p)

    returns = [{"stack_offset": f"[RSP+{hex((max_params + 1) * ptr_size)}]"}]

    ver_str = go_version_hint or "pre-1.17"
    result = {
        "convention": "stack",
        "params": params,
        "returns": returns,
        "note": (
            f"Go {ver_str} stack ABI — all args on stack at [RSP+{hex(ptr_size)}], "
            f"[RSP+{hex(2 * ptr_size)}], ... (slot size {ptr_size}B)"
        ),
    }
    return result
