#!/usr/bin/env python
"""Standalone speakeasy runner -- invoked via subprocess from PeMCP.

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


def emulate_pe(cmd):
    filepath = cmd["filepath"]
    timeout_seconds = cmd.get("timeout_seconds", 60)
    limit = cmd.get("limit", 200)

    se = speakeasy.Speakeasy()
    try:
        module = se.load_module(filepath)
    except Exception as e:
        return {"error": f"Failed to load module: {e}"}

    try:
        se.run_module(module, timeout=timeout_seconds)
    except Exception:
        # Emulation may raise on exit or unhandled API -- expected
        pass

    report = se.get_report()
    return {
        "status": "completed",
        "total_api_calls": len(report.get("api_calls", [])),
        "api_calls": _collect_api_calls(report, limit),
        "strings_found": _safe_slice(report.get("strings", []), 100),
        "network_activity": _safe_slice(report.get("network", []), 50),
        "file_activity": _safe_slice(report.get("file_access", []), 50),
        "registry_activity": _safe_slice(report.get("registry", []), 50),
    }


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
        se.run_shellcode(addr, timeout=timeout_seconds)
    except Exception:
        # Emulation may raise on exit or unhandled API -- expected
        pass

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
