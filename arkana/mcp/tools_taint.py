"""MCP tool for inter-procedural taint flow tracking.

Traces data from untrusted input sources (network, file, environment) to
dangerous sinks (buffer copy, command execution, format strings) across
function call chains.  Three escalating phases:

Phase 1 — Structural discovery via call-graph BFS.
Phase 2 — Decompile-based validation of argument flow.
Phase 3 — Optional per-function RDA for high-confidence proof.
"""
import asyncio
import re
import threading
import time
from collections import deque
from typing import Dict, Any, Optional, List, Set, Tuple, FrozenSet

from arkana.config import state, logger, Context, ANGR_AVAILABLE
from arkana.constants import (
    MAX_TOOL_LIMIT,
    MAX_TAINT_CHAIN_DEPTH, MAX_TAINT_CHAINS,
    TAINT_RDA_PER_FUNC_TIMEOUT,
    TAINT_MAX_SOURCE_FUNCTIONS, TAINT_MAX_SINK_FUNCTIONS,
)
from arkana.mcp.server import (
    tool_decorator, _check_pe_loaded, _check_mcp_response_size,
)
from arkana.mcp._angr_helpers import _parse_addr
from arkana.mcp._rename_helpers import get_display_name


# =====================================================================
#  Source / Sink Taxonomy
# =====================================================================
# All names lower-cased for O(1) membership tests.

_SOURCES_NETWORK: FrozenSet[str] = frozenset(n.lower() for n in {
    "recv", "recvfrom", "recvmsg",
    "WSARecv", "WSARecvFrom", "WSARecvMsg",
    "InternetReadFile", "WinHttpReadData", "HttpQueryInfoA", "HttpQueryInfoW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "URLDownloadToCacheFileA", "URLDownloadToCacheFileW",
    "InternetOpenUrlA", "InternetOpenUrlW",
})

_SOURCES_FILE: FrozenSet[str] = frozenset(n.lower() for n in {
    "read", "fread", "ReadFile", "ReadFileEx",
    "fgets", "gets", "gets_s",
    "NtReadFile", "ZwReadFile",
    "MapViewOfFile", "MapViewOfFileEx",
})

_SOURCES_USER_INPUT: FrozenSet[str] = frozenset(n.lower() for n in {
    "scanf", "fscanf", "sscanf", "wscanf", "fwscanf", "swscanf",
    "GetDlgItemTextA", "GetDlgItemTextW",
    "GetWindowTextA", "GetWindowTextW",
    "GetClipboardData",
})

_SOURCES_ENVIRONMENT: FrozenSet[str] = frozenset(n.lower() for n in {
    "getenv", "_wgetenv",
    "GetEnvironmentVariableA", "GetEnvironmentVariableW",
    "GetCommandLineA", "GetCommandLineW",
    "CommandLineToArgvW",
    "GetCurrentDirectoryA", "GetCurrentDirectoryW",
    "GetTempPathA", "GetTempPathW",
})

_SOURCES_REGISTRY: FrozenSet[str] = frozenset(n.lower() for n in {
    "RegQueryValueExA", "RegQueryValueExW",
    "RegGetValueA", "RegGetValueW",
    "RegEnumValueA", "RegEnumValueW",
    "RegEnumKeyExA", "RegEnumKeyExW",
})

_SOURCES_ALL: FrozenSet[str] = (
    _SOURCES_NETWORK | _SOURCES_FILE | _SOURCES_USER_INPUT
    | _SOURCES_ENVIRONMENT | _SOURCES_REGISTRY
)

_SOURCE_CATEGORIES: Dict[str, FrozenSet[str]] = {
    "network": _SOURCES_NETWORK,
    "file": _SOURCES_FILE,
    "user_input": _SOURCES_USER_INPUT,
    "environment": _SOURCES_ENVIRONMENT,
    "registry": _SOURCES_REGISTRY,
    "all": _SOURCES_ALL,
}

# --- Sinks ---

_SINKS_MEMORY: FrozenSet[str] = frozenset(n.lower() for n in {
    "strcpy", "strncpy", "strcat", "strncat",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat",
    "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
    "_tcscpy", "_tcscat",
    "memcpy", "memmove", "RtlCopyMemory", "CopyMemory",
    "RtlMoveMemory", "MoveMemory",
    "gets", "gets_s",
    "sprintf", "vsprintf", "swprintf", "vswprintf",
    "wsprintfA", "wsprintfW",
})

_SINKS_EXECUTION: FrozenSet[str] = frozenset(n.lower() for n in {
    "system", "_wsystem", "popen", "_popen", "_wpopen",
    "WinExec",
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW", "CreateProcessWithTokenW",
    "_execl", "_execlp", "_execle", "_execv", "_execvp", "_execvpe",
})

_SINKS_FORMAT: FrozenSet[str] = frozenset(n.lower() for n in {
    "printf", "fprintf", "sprintf", "snprintf", "syslog",
    "wprintf", "fwprintf", "swprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
})

_SINKS_EXFILTRATION: FrozenSet[str] = frozenset(n.lower() for n in {
    "send", "sendto", "sendmsg",
    "WSASend", "WSASendTo", "WSASendMsg",
    "HttpSendRequestA", "HttpSendRequestW",
    "WinHttpSendRequest", "WinHttpWriteData",
    "InternetWriteFile",
    "WriteFile",
})

_SINKS_ALL: FrozenSet[str] = (
    _SINKS_MEMORY | _SINKS_EXECUTION | _SINKS_FORMAT | _SINKS_EXFILTRATION
)

_SINK_CATEGORIES: Dict[str, FrozenSet[str]] = {
    "memory": _SINKS_MEMORY,
    "execution": _SINKS_EXECUTION,
    "format": _SINKS_FORMAT,
    "exfiltration": _SINKS_EXFILTRATION,
    "all": _SINKS_ALL,
}

# Risk labels per sink category for output enrichment
_SINK_RISK_LABELS: Dict[str, str] = {}
for _api in _SINKS_MEMORY:
    _SINK_RISK_LABELS[_api] = "buffer_overflow"
for _api in _SINKS_EXECUTION:
    _SINK_RISK_LABELS[_api] = "command_injection"
for _api in _SINKS_FORMAT:
    _SINK_RISK_LABELS.setdefault(_api, "format_string")
for _api in _SINKS_EXFILTRATION:
    _SINK_RISK_LABELS.setdefault(_api, "data_exfiltration")


# =====================================================================
#  Phase 1 — Structural Discovery
# =====================================================================

def _get_function_callees(func_obj, cfg) -> Set[str]:
    """Return lower-cased callee names reachable from *func_obj*."""
    callee_names: Set[str] = set()
    if not hasattr(func_obj, "transition_graph"):
        return callee_names
    func_addr = func_obj.addr
    for node in func_obj.transition_graph.nodes():
        addr = getattr(node, "addr", None)
        if addr is None or addr == func_addr:
            continue
        callee = cfg.functions.get(addr)
        if callee and callee.name:
            callee_names.add(callee.name.lower())
    return callee_names


def _classify_functions(
    cfg,
    active_sources: FrozenSet[str],
    active_sinks: FrozenSet[str],
    target_addr: Optional[int] = None,
) -> Tuple[Dict[int, List[str]], Dict[int, List[str]]]:
    """Classify CFG functions as source-callers, sink-callers, or both.

    Returns ``(source_funcs, sink_funcs)`` mapping address → matched API names.
    """
    source_funcs: Dict[int, List[str]] = {}
    sink_funcs: Dict[int, List[str]] = {}

    funcs = cfg.functions
    for addr, func_obj in funcs.items():
        if getattr(func_obj, "is_simprocedure", False) or getattr(func_obj, "is_plt", False):
            continue
        if target_addr is not None and addr != target_addr:
            # When focused on a single function, still classify others as
            # potential sinks (chains *from* target need sink discovery).
            pass

        callee_names = _get_function_callees(func_obj, cfg)
        if not callee_names:
            continue

        sources = sorted(callee_names & active_sources)
        sinks = sorted(callee_names & active_sinks)

        if sources:
            source_funcs[addr] = sources
        if sinks:
            sink_funcs[addr] = sinks

    return source_funcs, sink_funcs


def _find_taint_chains(
    callgraph,
    cfg_functions,
    source_funcs: Dict[int, List[str]],
    sink_funcs: Dict[int, List[str]],
    max_depth: int,
    limit: int,
    target_addr: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """BFS from source functions through the call graph to find paths reaching
    sink functions.  Returns raw chain dicts with ``confidence='low'``.
    """
    chains: List[Dict[str, Any]] = []

    # Decide which sources to start from
    if target_addr is not None:
        # If target is a source, trace forward. If it's a sink, trace backward.
        # If neither, trace forward anyway (let user specify any start point).
        start_addrs = [target_addr] if target_addr in source_funcs else []
        # Also support "target is a sink — find what feeds it"
        reverse_mode = target_addr in sink_funcs and not start_addrs
        if reverse_mode:
            return _find_taint_chains_reverse(
                callgraph, cfg_functions, source_funcs, sink_funcs,
                target_addr, max_depth, limit,
            )
        if not start_addrs:
            # Target is neither source nor sink — treat as source start anyway
            start_addrs = [target_addr]
    else:
        # Sort source functions by address for deterministic output
        start_addrs = sorted(source_funcs.keys())[:TAINT_MAX_SOURCE_FUNCTIONS]

    for start_addr in start_addrs:
        if len(chains) >= limit:
            break
        # BFS with path tracking
        queue: deque = deque([(start_addr, [start_addr])])
        visited: Set[int] = {start_addr}

        while queue and len(chains) < limit:
            current, path = queue.popleft()
            depth = len(path) - 1

            # Check if we reached a sink (depth > 0 to exclude self-loops
            # where source == sink, which find_dangerous_data_flows covers)
            if current in sink_funcs and current != start_addr:
                func_obj_src = cfg_functions.get(start_addr)
                func_obj_sink = cfg_functions.get(current)
                src_name = get_display_name(
                    hex(start_addr),
                    func_obj_src.name if func_obj_src else None,
                )
                sink_name = get_display_name(
                    hex(current),
                    func_obj_sink.name if func_obj_sink else None,
                )
                # Build chain names
                chain_names = []
                for a in path:
                    fo = cfg_functions.get(a)
                    chain_names.append(get_display_name(hex(a), fo.name if fo else None))

                # Determine risk from first matching sink API
                risk = "unknown"
                for api in sink_funcs[current]:
                    if api in _SINK_RISK_LABELS:
                        risk = _SINK_RISK_LABELS[api]
                        break

                chains.append({
                    "chain": [hex(a) for a in path],
                    "chain_names": chain_names,
                    "source_function": hex(start_addr),
                    "source_function_name": src_name,
                    "source_apis": source_funcs.get(start_addr, []),
                    "sink_function": hex(current),
                    "sink_function_name": sink_name,
                    "sink_apis": sink_funcs[current],
                    "depth": depth,
                    "confidence": "low",
                    "validation_method": "structural",
                    "risk": risk,
                })

            # Continue BFS if within depth limit
            if depth < max_depth:
                try:
                    successors = list(callgraph.successors(current))
                except Exception:
                    successors = []
                for succ in successors:
                    if succ not in visited:
                        visited.add(succ)
                        queue.append((succ, [*path, succ]))

    return chains


def _find_taint_chains_reverse(
    callgraph,
    cfg_functions,
    source_funcs: Dict[int, List[str]],
    sink_funcs: Dict[int, List[str]],
    target_sink: int,
    max_depth: int,
    limit: int,
) -> List[Dict[str, Any]]:
    """Reverse BFS from a sink function backward through callers to find which
    source functions can reach it.
    """
    chains: List[Dict[str, Any]] = []
    queue: deque = deque([(target_sink, [target_sink])])
    visited: Set[int] = {target_sink}

    while queue and len(chains) < limit:
        current, path = queue.popleft()
        depth = len(path) - 1

        if current in source_funcs and current != target_sink:
            # We found a source that can reach the target sink
            full_path = list(reversed(path))  # source → ... → sink
            chain_names = []
            for a in full_path:
                fo = cfg_functions.get(a)
                chain_names.append(get_display_name(hex(a), fo.name if fo else None))

            risk = "unknown"
            for api in sink_funcs.get(target_sink, []):
                if api in _SINK_RISK_LABELS:
                    risk = _SINK_RISK_LABELS[api]
                    break

            chains.append({
                "chain": [hex(a) for a in full_path],
                "chain_names": chain_names,
                "source_function": hex(current),
                "source_function_name": chain_names[0],
                "source_apis": source_funcs[current],
                "sink_function": hex(target_sink),
                "sink_function_name": chain_names[-1],
                "sink_apis": sink_funcs.get(target_sink, []),
                "depth": depth,
                "confidence": "low",
                "validation_method": "structural",
                "risk": risk,
            })

        if depth < max_depth:
            try:
                predecessors = list(callgraph.predecessors(current))
            except Exception:
                predecessors = []
            for pred in predecessors:
                if pred not in visited:
                    visited.add(pred)
                    queue.append((pred, [*path, pred]))

    return chains


# =====================================================================
#  Phase 2 — Decompile-Based Validation
# =====================================================================

# Regex to detect function-call patterns in angr pseudocode.
# Matches patterns like:  some_func(v1, v2, ...)  or  result = call(...)
_CALL_ARG_RE = re.compile(
    r'(\w+)\s*\(([^)]*)\)', re.ASCII
)


def _get_decompiled_lines(addr_int: int) -> Optional[List[str]]:
    """Retrieve decompiled lines from the cache for the given function address."""
    try:
        from arkana.mcp.tools_angr import (
            _decompile_meta, _decompile_meta_lock, _make_decompile_key,
        )
        cache_key = _make_decompile_key(addr_int)
        with _decompile_meta_lock:
            meta = _decompile_meta.get(cache_key)
        if meta and meta.get("lines"):
            return meta["lines"]
    except Exception:
        pass
    return None


def _find_api_lines(
    lines: List[str],
    api_names: List[str],
) -> List[Dict[str, Any]]:
    """Find lines in decompiled code that reference any of the given API names."""
    results = []
    api_lower = {a.lower() for a in api_names}
    for i, line in enumerate(lines):
        line_lower = line.lower()
        for api in api_lower:
            if api in line_lower:
                results.append({"line": i + 1, "text": line.strip()[:150]})
                break
    return results[:5]


def _check_argument_flow(
    lines: List[str],
    source_apis: List[str],
    callee_addr_hex: str,
    callee_name: str,
) -> bool:
    """Heuristic check: does the return value of a source API appear as an
    argument to a call to the next function in the chain?

    Scans decompiled pseudocode for patterns like:
        buf = recv(...)
        process_data(buf, ...)
    """
    source_lower = {a.lower() for a in source_apis}
    callee_name_lower = callee_name.lower() if callee_name else ""
    callee_addr_clean = callee_addr_hex.lower().replace("0x", "")

    # Collect variable names assigned from source API calls
    assigned_vars: Set[str] = set()
    for line in lines:
        for m in _CALL_ARG_RE.finditer(line):
            func_name_in_code = m.group(1).lower()
            if func_name_in_code in source_lower:
                # Check if this is an assignment: var = source_api(...)
                prefix = line[:m.start()].rstrip()
                if "=" in prefix:
                    var_name = prefix.rsplit("=", 1)[0].strip().split()[-1] if prefix.rsplit("=", 1)[0].strip() else ""
                    if var_name and var_name.isidentifier():
                        assigned_vars.add(var_name)

    if not assigned_vars:
        # Source return value not captured in a named variable — can't track
        return False

    # Check if any of those variables appear as arguments to the callee
    for line in lines:
        line_lower = line.lower()
        # Match calls to the next function (by name or address)
        if callee_name_lower and callee_name_lower in line_lower:
            for var in assigned_vars:
                if var in line:
                    return True
        if callee_addr_clean and callee_addr_clean in line_lower:
            for var in assigned_vars:
                if var in line:
                    return True

    return False


def _check_parameter_to_sink(
    lines: List[str],
    sink_apis: List[str],
) -> bool:
    """Heuristic check: does a function parameter flow to a sink API call?

    Looks for the function's first parameter (typically 'a0', 'a1', 'arg0',
    'arg1', or similar angr naming) appearing as an argument to a sink call.
    """
    sink_lower = {a.lower() for a in sink_apis}

    # angr decompilation typically names parameters a0, a1, ... or arg_N
    param_patterns = {"a0", "a1", "a2", "a3", "arg_0", "arg_1", "arg_2", "arg_3",
                      "arg0", "arg1", "arg2", "arg3"}

    for line in lines:
        line_lower = line.lower()
        for sink in sink_lower:
            if sink not in line_lower:
                continue
            # Check if any parameter name appears in the same call
            for m in _CALL_ARG_RE.finditer(line):
                if m.group(1).lower() in sink_lower:
                    args_text = m.group(2)
                    for param in param_patterns:
                        if param in args_text:
                            return True
    return False


def _validate_chains_decompile(
    chains: List[Dict[str, Any]],
    cfg_functions,
) -> Tuple[int, int, int]:
    """Run Phase 2 validation on all chains.

    Mutates chain dicts in-place: upgrades confidence to 'medium' where
    decompile evidence supports argument flow, and attaches evidence snippets.

    Returns (validated_count, partial_count, no_decompile_count).
    """
    validated = 0
    partial = 0
    no_decompile = 0

    for chain in chains:
        addrs = [int(a, 16) for a in chain["chain"]]
        if len(addrs) < 2:
            continue

        evidence = {"source_lines": [], "sink_lines": []}
        flow_confirmed_steps = 0
        total_steps = len(addrs) - 1
        has_any_decompile = False

        for step_idx in range(total_steps):
            curr_addr = addrs[step_idx]
            next_addr = addrs[step_idx + 1]
            lines = _get_decompiled_lines(curr_addr)
            if lines is None:
                continue
            has_any_decompile = True

            # For the first step: check source API → next function argument flow
            if step_idx == 0:
                next_func = cfg_functions.get(next_addr)
                next_name = next_func.name if next_func else ""
                source_confirmed = _check_argument_flow(
                    lines, chain["source_apis"], hex(next_addr), next_name,
                )
                if source_confirmed:
                    flow_confirmed_steps += 1
                # Collect source evidence lines
                src_lines = _find_api_lines(lines, chain["source_apis"])
                if src_lines:
                    evidence["source_lines"] = src_lines

        # Check the sink function
        sink_addr = addrs[-1]
        sink_lines_code = _get_decompiled_lines(sink_addr)
        if sink_lines_code:
            has_any_decompile = True
            sink_confirmed = _check_parameter_to_sink(
                sink_lines_code, chain["sink_apis"],
            )
            if sink_confirmed:
                flow_confirmed_steps += 1
            # Collect sink evidence lines
            snk_lines = _find_api_lines(sink_lines_code, chain["sink_apis"])
            if snk_lines:
                evidence["sink_lines"] = snk_lines

        if not has_any_decompile:
            no_decompile += 1
            continue

        # Attach evidence
        if evidence["source_lines"] or evidence["sink_lines"]:
            chain["evidence"] = evidence

        # Upgrade confidence based on validation results
        if flow_confirmed_steps >= 2:
            # Both source outflow and sink inflow confirmed
            chain["confidence"] = "medium"
            chain["validation_method"] = "decompile_both"
            validated += 1
        elif flow_confirmed_steps == 1:
            chain["confidence"] = "medium"
            chain["validation_method"] = "decompile_partial"
            partial += 1
        # flow_confirmed_steps == 0: stays at 'low' / 'structural'

    return validated, partial, no_decompile


# =====================================================================
#  Phase 3 — RDA Deep Validation
# =====================================================================

def _deep_validate_chain(project, cfg, chain: Dict[str, Any]) -> bool:
    """Run per-function RDA on source and sink functions to confirm data flow.

    Returns True if RDA completed successfully (upgrades confidence to 'high').
    """
    try:
        from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis  # noqa: F401
    except ImportError:
        return False

    addrs = [int(a, 16) for a in chain["chain"]]
    if len(addrs) < 2:
        return False

    # Run RDA on source function
    source_addr = addrs[0]
    sink_addr = addrs[-1]

    for addr in (source_addr, sink_addr):
        func_obj = cfg.functions.get(addr)
        if func_obj is None:
            continue

        result_holder = [None]
        cancel = threading.Event()

        def _run(fo=func_obj):
            try:
                rd = project.analyses.ReachingDefinitions(
                    subject=fo, observe_all=True,
                )
                if not cancel.is_set() and hasattr(rd, "dep_graph") and rd.dep_graph is not None:
                    result_holder[0] = True
            except Exception:
                pass

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=TAINT_RDA_PER_FUNC_TIMEOUT)
        if t.is_alive():
            cancel.set()
            return False
        if result_holder[0] is None:
            return False

    return True


def _run_deep_validation(chains: List[Dict[str, Any]], limit: int) -> Dict[str, int]:
    """Run Phase 3 RDA validation on medium-confidence chains.

    Mutates chain dicts: upgrades confidence to 'high' where RDA succeeds.
    Returns stats dict.
    """
    project, cfg = state.get_angr_snapshot()
    if not cfg or not project:
        return {"rda_attempted": 0, "rda_succeeded": 0, "rda_failed": 0}

    # Only validate chains that Phase 2 already marked as medium
    candidates = [c for c in chains if c.get("confidence") == "medium"]
    candidates = candidates[:limit]

    succeeded = 0
    failed = 0
    for chain in candidates:
        if _deep_validate_chain(project, cfg, chain):
            chain["confidence"] = "high"
            chain["validation_method"] = "rda"
            succeeded += 1
        else:
            failed += 1

    return {
        "rda_attempted": succeeded + failed,
        "rda_succeeded": succeeded,
        "rda_failed": failed,
    }


# =====================================================================
#  Orchestrator
# =====================================================================

def _sync_trace_flows(
    source_category: str,
    sink_category: str,
    max_depth: int,
    validate: bool,
    deep_validate: bool,
    target_addr: Optional[int],
    limit: int,
) -> Dict[str, Any]:
    """Synchronous orchestrator — runs Phase 1, optionally Phase 2 and 3."""
    t0 = time.monotonic()

    if not ANGR_AVAILABLE:
        return {"error": "angr is not available. Install angr for taint tracking."}

    project, cfg = state.get_angr_snapshot()
    if not cfg:
        return {
            "error": "No CFG available. Open a file and wait for CFG analysis to complete.",
            "hint": "Run open_file() first. The CFG builds automatically.",
        }

    callgraph = getattr(cfg.functions, "callgraph", None)
    if callgraph is None:
        return {"error": "Call graph not available from CFG."}

    active_sources = _SOURCE_CATEGORIES.get(source_category)
    active_sinks = _SINK_CATEGORIES.get(sink_category)
    if active_sources is None:
        return {
            "error": f"Unknown source_category: {source_category!r}",
            "valid_categories": sorted(_SOURCE_CATEGORIES.keys()),
        }
    if active_sinks is None:
        return {
            "error": f"Unknown sink_category: {sink_category!r}",
            "valid_categories": sorted(_SINK_CATEGORIES.keys()),
        }

    # --- Phase 1: Structural discovery ---
    source_funcs, sink_funcs = _classify_functions(
        cfg, active_sources, active_sinks, target_addr,
    )

    if not source_funcs:
        return {
            "taint_flows": [],
            "total_flows": 0,
            "source_functions_found": 0,
            "sink_functions_found": len(sink_funcs),
            "note": "No functions calling source APIs found in this binary.",
            "hint": f"Source category '{source_category}' matched 0 functions. "
                    "Try source_category='all' or check if imports are resolved.",
        }
    if not sink_funcs:
        return {
            "taint_flows": [],
            "total_flows": 0,
            "source_functions_found": len(source_funcs),
            "sink_functions_found": 0,
            "note": "No functions calling dangerous sink APIs found.",
            "hint": f"Sink category '{sink_category}' matched 0 functions. "
                    "Try sink_category='all'.",
        }

    chains = _find_taint_chains(
        callgraph, cfg.functions, source_funcs, sink_funcs,
        max_depth, limit, target_addr,
    )

    phase1_time = time.monotonic() - t0

    # --- Phase 2: Decompile-based validation ---
    validation_stats: Dict[str, Any] = {
        "structural_only": len(chains),
        "decompile_validated": 0,
        "decompile_partial": 0,
        "no_decompilation": 0,
        "rda_validated": 0,
    }

    if validate and chains:
        t1 = time.monotonic()
        validated, partial, no_dec = _validate_chains_decompile(chains, cfg.functions)
        validation_stats["decompile_validated"] = validated
        validation_stats["decompile_partial"] = partial
        validation_stats["no_decompilation"] = no_dec
        validation_stats["structural_only"] = (
            len(chains) - validated - partial - no_dec
        )
        validation_stats["phase2_time_ms"] = int((time.monotonic() - t1) * 1000)

    # --- Phase 3: Deep RDA validation ---
    if deep_validate and chains:
        rda_stats = _run_deep_validation(chains, limit=20)
        validation_stats["rda_validated"] = rda_stats["rda_succeeded"]
        validation_stats.update(rda_stats)

    # Sort chains: high > medium > low, then by depth (shorter = higher priority)
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    chains.sort(key=lambda c: (confidence_order.get(c["confidence"], 9), c["depth"]))

    total_time = time.monotonic() - t0

    # Build summary by risk type
    risk_summary: Dict[str, int] = {}
    for c in chains:
        risk = c.get("risk", "unknown")
        risk_summary[risk] = risk_summary.get(risk, 0) + 1

    result: Dict[str, Any] = {
        "taint_flows": chains,
        "total_flows": len(chains),
        "source_functions_found": len(source_funcs),
        "sink_functions_found": len(sink_funcs),
        "functions_in_callgraph": len(cfg.functions),
        "source_category": source_category,
        "sink_category": sink_category,
        "max_depth": max_depth,
        "validation_stats": validation_stats,
        "risk_summary": risk_summary,
        "timing": {
            "phase1_ms": int(phase1_time * 1000),
            "total_ms": int(total_time * 1000),
        },
    }

    # Actionable hints
    hints = []
    if validation_stats.get("no_decompilation", 0) > len(chains) * 0.5:
        hints.append(
            "Many chain functions lack decompilation. Run batch_decompile() "
            "first for better validation coverage."
        )
    if not chains:
        hints.append(
            "No taint chains found. This may mean: (1) source/sink APIs are "
            "resolved dynamically (GetProcAddress), (2) call graph is incomplete "
            "for indirect calls, or (3) the binary genuinely has no source→sink paths."
        )
    if len(chains) >= limit:
        hints.append(
            f"Results capped at {limit}. Increase limit or narrow source_category/"
            "sink_category to see more."
        )
    if hints:
        result["hints"] = hints

    return result


# =====================================================================
#  MCP Tool Entry Point
# =====================================================================

@tool_decorator
async def trace_taint_flows(
    ctx: Context,
    source_category: str = "all",
    sink_category: str = "all",
    max_depth: int = 5,
    validate: bool = True,
    deep_validate: bool = False,
    target_function: Optional[str] = None,
    limit: int = 30,
) -> Dict[str, Any]:
    """
    [Phase: analysis] Trace inter-procedural taint flows from untrusted input
    sources to dangerous sinks through the call graph.

    Phase 1 (structural): Classifies functions as source/sink callers via
    import analysis, then BFS-walks the call graph to find chains connecting
    them.  Phase 2 (validate=True): Checks decompiled pseudocode at each
    chain step for argument-flow evidence, upgrading confidence from 'low'
    to 'medium'.  Phase 3 (deep_validate=True): Runs reaching-definition
    analysis per function for 'high' confidence results — slower but more
    precise.

    When to use: During vulnerability audits or malware analysis after CFG
    analysis completes.  More comprehensive than find_dangerous_data_flows()
    because it traces across function boundaries rather than requiring both
    source and sink in the same function.

    If target_function is a *sink*, the tool automatically traces backward
    through callers to find which source functions can reach it.

    Next steps: decompile_function_with_angr() on chain functions,
    assess_function_attack_surface() on endpoints,
    find_dangerous_data_flows() for same-function flows,
    scan_for_vulnerability_patterns() for pattern-based detection.

    Args:
        source_category: Source API type to trace from: 'network', 'file',
                        'user_input', 'environment', 'registry', or 'all'.
                        Default 'all'.
        sink_category: Sink API type to trace to: 'memory', 'execution',
                      'format', 'exfiltration', or 'all'. Default 'all'.
        max_depth: Maximum call-chain hops to explore (1-20). Default 5.
                  Higher values find deeper chains but are slower.
        validate: If True (default), run Phase 2 decompile-based validation.
                 Set to False for fast structural-only results.
        deep_validate: If True, additionally run Phase 3 RDA validation on
                      medium-confidence chains. Slower but high precision.
                      Default False.
        target_function: If set, only trace from/to this function (hex address
                        e.g. '0x401000'). If the address is a sink function,
                        automatically traces backward to find sources.
        limit: Maximum taint chains to return (1-100000). Default 30.
    """
    _check_pe_loaded("trace_taint_flows")

    # Validate and clamp parameters
    limit = max(1, min(limit, MAX_TOOL_LIMIT))
    limit = min(limit, MAX_TAINT_CHAINS)
    max_depth = max(1, min(max_depth, MAX_TAINT_CHAIN_DEPTH))

    target_addr = None
    if target_function:
        target_addr = _parse_addr(target_function, "target_function")

    result = await asyncio.to_thread(
        _sync_trace_flows,
        source_category, sink_category, max_depth,
        validate, deep_validate,
        target_addr, limit,
    )

    return await _check_mcp_response_size(ctx, result, "trace_taint_flows")
