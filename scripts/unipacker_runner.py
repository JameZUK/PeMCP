#!/usr/bin/env python
"""Standalone unipacker runner -- invoked via subprocess from PeMCP.

Reads a JSON command from stdin, runs the requested unpacking operation,
and writes a JSON result to stdout.

This script is executed inside the unipacker venv (/app/unipacker-venv)
which has unicorn 1.x (via unicorn-unipacker), keeping the main env free
to use unicorn 2.x for angr's native unicorn bridge.
"""
import json
import os
import sys
import threading


def _validate_file_path(filepath):
    """Validate that a file path exists and is a regular file.

    Defense-in-depth: the parent MCP tool layer enforces path sandboxing,
    but direct invocation of this runner (e.g. during development) would
    bypass those checks.
    """
    if not filepath:
        raise ValueError("No file path provided")
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a regular file: {filepath}")


def unpack_pe(cmd):
    filepath = cmd["filepath"]
    _validate_file_path(filepath)
    output_path = cmd["output_path"]
    timeout_seconds = cmd.get("timeout_seconds", 300)

    from unipacker.core import UnpackerClient

    try:
        from unipacker.core import UnpackerEngine, SimpleClient
        from unipacker.core import Sample as _UnipackerSample
    except ImportError:
        UnpackerEngine = None
        SimpleClient = None
        _UnipackerSample = None

    try:
        # Modern API (>=1.0.8): UnpackerEngine + SimpleClient + threading.Event
        if UnpackerEngine is not None and SimpleClient is not None:
            done_event = threading.Event()
            client = SimpleClient(done_event)
            # unipacker >=1.0.8 expects a Sample object, not a raw path
            _sample = _UnipackerSample(filepath) if _UnipackerSample is not None else filepath
            engine = UnpackerEngine(_sample, output_path)
            engine.register_client(client)
            engine.emu()
            # Wait for completion (with timeout to avoid hanging)
            if not done_event.wait(timeout=timeout_seconds):
                return {
                    "status": "timeout",
                    "input_file": filepath,
                    "output_file": output_path,
                    "output_size": os.path.getsize(output_path) if os.path.exists(output_path) else 0,
                    "warning": f"Unpacking timed out after {timeout_seconds}s. Output may be incomplete.",
                }
        else:
            # Fallback: try calling UnpackerClient directly in case
            # an older unipacker version has a simpler API.
            try:
                client = UnpackerClient(filepath)
                if hasattr(client, 'unpack'):
                    client.unpack(output_path)
                elif hasattr(client, 'run'):
                    client.run()
            except TypeError:
                client = UnpackerClient()
                if hasattr(client, 'unpack'):
                    client.unpack(filepath, output_path)

        return {
            "status": "success",
            "input_file": filepath,
            "output_file": output_path,
            "output_size": os.path.getsize(output_path) if os.path.exists(output_path) else 0,
        }
    except Exception as e:
        return {"error": f"Unpacking failed: {e}"}


def main():
    cmd = json.loads(sys.stdin.read())
    action = cmd.get("action")

    # Redirect stdout → stderr while unipacker runs.
    # The unipacker library (engine.emu()) prints log messages directly to
    # stdout (e.g. "Section hopping detected", "Fixing Imports...") which
    # would corrupt the JSON result that the parent process expects on
    # stdout.  Sending those logs to stderr keeps the JSON channel clean.
    real_stdout = sys.stdout
    sys.stdout = sys.stderr

    try:
        if action == "unpack_pe":
            result = unpack_pe(cmd)
        else:
            result = {"error": f"Unknown action: {action}"}
    except Exception as e:
        result = {"error": f"{type(e).__name__}: {e}"}
    finally:
        sys.stdout = real_stdout

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
