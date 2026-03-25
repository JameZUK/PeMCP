#!/usr/bin/env python
"""Standalone speakeasy runner -- invoked via subprocess from Arkana.

Reads a JSON command from stdin, runs the requested speakeasy emulation,
and writes a JSON result to stdout.

This script is executed inside the speakeasy venv (/app/speakeasy-venv)
which has unicorn 1.x, keeping the main env free to use unicorn 2.x
for angr's native unicorn bridge.
"""
import json
import sys

import speakeasy
import speakeasy.winenv.arch as _arch


def _validate_file_path(filepath):
    """Validate that a file path exists and is a regular file.

    Defense-in-depth: the parent MCP tool layer enforces path sandboxing,
    but direct invocation of this runner (e.g. during development) would
    bypass those checks.
    """
    import os
    if not filepath:
        raise ValueError("No file path provided")
    # Resolve symlinks to prevent path traversal via symlink chains
    filepath = os.path.realpath(filepath)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a regular file: {filepath}")


def _safe_slice(value, n):
    """Safely slice a value to at most *n* items."""
    if isinstance(value, (list, tuple)):
        return value[:n]
    if isinstance(value, dict):
        keys = list(value.keys())[:n]
        return {k: value[k] for k in keys}
    if isinstance(value, str):
        return value[:n]
    return value


def _collect_api_calls(report, limit):
    """Extract and truncate API call entries from a speakeasy report."""
    api_calls = []
    for event in report.get("api_calls", []):
        args = event.get("args", [])
        if isinstance(args, (list, tuple)):
            args = args[:5]
        else:
            args = str(args)
        entry = {
            "api": event.get("api_name", ""),
            "args": args,
            "ret_val": event.get("ret_val"),
        }
        if "caller" in event:
            entry["caller"] = hex(event["caller"]) if event.get("caller") else None
        api_calls.append(entry)
        if len(api_calls) >= limit:
            break
    return api_calls


def _parse_int(val):
    """Parse a Speakeasy argument value to int."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 0) if val.startswith(("0x", "0X")) else int(val)
        except (ValueError, TypeError):
            return 0
    return 0


# Windows memory protection constants
_PROTECT_FLAGS = {
    0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE", 0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
}


def _analyze_allocation_activity(report, limit):
    """Analyze memory allocation patterns from Speakeasy API call log.

    Tracks VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualFree,
    HeapAlloc, and HeapCreate calls. Flags suspicious patterns like
    RWX allocations and allocation-then-execute sequences.
    """
    allocations = []
    anomalies = []
    max_ops = limit * 2  # Safety cap

    for event in report.get("api_calls", []):
        api_name = event.get("api_name") or ""
        api_lower = api_name.lower()
        args = event.get("args", [])
        ret = event.get("ret_val")

        if "virtualalloc" in api_lower and "free" not in api_lower:
            is_ex = "ex" in api_lower
            size_idx = 2 if is_ex else 1
            prot_idx = 4 if is_ex else 3
            size = _parse_int(args[size_idx]) if len(args) > size_idx else 0
            protect = _parse_int(args[prot_idx]) if len(args) > prot_idx else 0
            prot_name = _PROTECT_FLAGS.get(protect & 0xFF, hex(protect))

            allocations.append({
                "api": api_name, "type": "alloc",
                "address": hex(ret) if isinstance(ret, int) else str(ret),
                "size": size, "protection": prot_name,
            })

            if protect & 0x40:  # PAGE_EXECUTE_READWRITE
                anomalies.append({
                    "type": "RWX_ALLOCATION", "severity": "high",
                    "api": api_name, "size": size,
                    "detail": f"Allocated {size} bytes with RWX — common in unpacking and shellcode injection",
                })
            if size > 1048576:
                anomalies.append({
                    "type": "LARGE_ALLOCATION", "severity": "medium",
                    "api": api_name, "size": size,
                    "detail": f"Large allocation ({size} bytes) — may indicate process hollowing or payload staging",
                })

        elif "virtualprotect" in api_lower:
            prot_idx = 2
            new_protect = _parse_int(args[prot_idx]) if len(args) > prot_idx else 0
            prot_name = _PROTECT_FLAGS.get(new_protect & 0xFF, hex(new_protect))
            allocations.append({
                "api": api_name, "type": "protect",
                "address": str(args[0]) if args else "?",
                "size": _parse_int(args[1]) if len(args) > 1 else 0,
                "new_protection": prot_name,
            })
            if new_protect & 0x40:
                anomalies.append({
                    "type": "RWX_PROTECTION_CHANGE", "severity": "high",
                    "api": api_name,
                    "detail": "Protection changed to RWX — often precedes shellcode execution",
                })

        elif "virtualfree" in api_lower:
            allocations.append({
                "api": api_name, "type": "free",
                "address": str(args[0]) if args else "?",
            })

        elif "heapalloc" in api_lower or "heapcreate" in api_lower:
            size = _parse_int(args[-1]) if args else 0
            allocations.append({"api": api_name, "type": "heap", "size": size})

        if len(allocations) >= max_ops:
            break

    # Detect allocation-then-execute pattern
    has_allocs = any(e.get("type") == "alloc" for e in allocations)
    has_protect = any(e.get("type") == "protect" for e in allocations)
    if has_allocs and has_protect:
        anomalies.append({
            "type": "ALLOC_THEN_PROTECT_SEQUENCE", "severity": "high",
            "detail": "VirtualAlloc followed by VirtualProtect — classic unpacking/injection pattern",
        })

    return {
        "memory_operations": allocations[:limit],
        "anomalies": anomalies[:limit],
        "summary": {
            "total_operations": len(allocations),
            "total_anomalies": len(anomalies),
            "anomaly_types": sorted(set(a["type"] for a in anomalies)),
        },
    }


def emulate_pe(cmd):
    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    timeout_seconds = cmd.get("timeout_seconds", 60)
    limit = cmd.get("limit", 200)
    track_allocations = cmd.get("track_allocations", False)

    se = speakeasy.Speakeasy()
    try:
        module = se.load_module(filepath)
    except Exception as e:
        return {"error": f"Failed to load module: {e}"}

    try:
        se.run_module(module, timeout=timeout_seconds)
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as e:
        # Emulation may raise on exit or unhandled API -- expected.
        # Log to stderr for debugging without breaking the JSON result.
        print(f"[speakeasy] Emulation exception (non-fatal): {type(e).__name__}: {e}", file=sys.stderr)

    report = se.get_report()
    result = {
        "status": "completed",
        "total_api_calls": len(report.get("api_calls", [])),
        "api_calls": _collect_api_calls(report, limit),
        "strings_found": _safe_slice(report.get("strings", []), 100),
        "network_activity": _safe_slice(report.get("network", []), 50),
        "file_activity": _safe_slice(report.get("file_access", []), 50),
        "registry_activity": _safe_slice(report.get("registry", []), 50),
    }

    if track_allocations:
        result["allocation_activity"] = _analyze_allocation_activity(report, limit)

    return result


def emulate_shellcode(cmd):
    shellcode_hex = cmd.get("shellcode_hex")
    filepath = cmd.get("filepath")
    architecture = cmd.get("architecture", "x86")
    timeout_seconds = cmd.get("timeout_seconds", 30)
    limit = cmd.get("limit", 200)

    se = speakeasy.Speakeasy()

    if shellcode_hex:
        sc_data = bytes.fromhex(shellcode_hex)
    elif filepath:
        _validate_file_path(filepath)
        with open(filepath, "rb") as f:
            sc_data = f.read()
    else:
        return {"error": "No shellcode provided and no file loaded."}

    try:
        arch_val = _arch.ARCH_X86 if architecture == "x86" else _arch.ARCH_AMD64
    except AttributeError:
        arch_val = architecture

    try:
        addr = se.load_shellcode(
            filepath if not shellcode_hex else None,
            arch_val,
            data=sc_data,
        )
    except Exception as e:
        return {"error": f"Failed to load shellcode: {e}"}

    try:
        se.run_shellcode(addr, timeout=timeout_seconds)
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as e:
        # Emulation may raise on exit or unhandled API -- expected.
        print(f"[speakeasy] Shellcode emulation exception (non-fatal): {type(e).__name__}: {e}", file=sys.stderr)

    report = se.get_report()
    return {
        "status": "completed",
        "architecture": architecture,
        "total_api_calls": len(report.get("api_calls", [])),
        "api_calls": _collect_api_calls(report, limit),
        "strings_found": _safe_slice(report.get("strings", []), 100),
        "network_activity": _safe_slice(report.get("network", []), 50),
    }


def main():
    cmd = json.loads(sys.stdin.read())
    action = cmd.get("action")

    try:
        if action == "emulate_pe":
            result = emulate_pe(cmd)
        elif action == "emulate_shellcode":
            result = emulate_shellcode(cmd)
        else:
            result = {"error": f"Unknown action: {action}"}
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}"}

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
