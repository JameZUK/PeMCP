"""Centralized state management for analyzed files.

Supports per-session state isolation via ``StateProxy`` and ``contextvars``.
In stdio mode (single client) the default state is used transparently.
In HTTP mode each MCP session gets its own ``AnalyzerState`` instance so
concurrent clients cannot interfere with each other.
"""
import contextvars
import datetime
import logging
import time
import threading
from collections import deque
from typing import Dict, Any, Optional, List

logger = logging.getLogger("Arkana")

# Maximum number of completed/failed background tasks to retain per session.
MAX_COMPLETED_TASKS = 50

# Maximum number of tool history entries to retain per session.
MAX_TOOL_HISTORY = 500

# Stale session TTL in seconds (1 hour).
SESSION_TTL_SECONDS = 3600

# Task status constants — use these instead of raw strings to prevent typo bugs.
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_FAILED = "failed"


class AnalyzerState:
    """Per-session state for a single analyzed file."""
    def __init__(self):
        self.filepath: Optional[str] = None
        self.pe_data: Optional[Dict[str, Any]] = None
        self.pe_object: Optional[Any] = None  # pefile.PE or MockPE
        self._inherited_pe_object: bool = False  # True if pe_object was inherited from _default_state
        self.pefile_version: Optional[str] = None
        self.loaded_from_cache: bool = False

        # Path sandboxing for network-exposed MCP servers
        self.allowed_paths: Optional[List[str]] = None  # None = no restriction

        # Samples directory path (configured via --samples-path or ARKANA_SAMPLES env var)
        self.samples_path: Optional[str] = None

        # API key for HTTP bearer token authentication (None = no auth required)
        self.api_key: Optional[str] = None

        # Dashboard token (set by dashboard app on startup)
        self.dashboard_token: Optional[str] = None

        # PE close guard
        self._pe_lock = threading.Lock()

        # Angr State
        self._angr_lock = threading.Lock()
        self.angr_project = None
        self.angr_cfg = None
        self.angr_loop_cache = None
        self.angr_loop_cache_config = None
        self.angr_hooks: Dict[str, Dict[str, Any]] = {}  # addr_hex -> hook info

        # Background Tasks
        self._task_lock = threading.Lock()
        self.background_tasks: Dict[str, Dict[str, Any]] = {}
        self.monitor_thread_started = False

        # Notes (persisted per-binary via cache)
        self._notes_lock = threading.Lock()
        self._notes_counter: int = 0
        self.notes: List[Dict[str, Any]] = []

        # Tool History (per-session, saved to cache on close)
        self._history_lock = threading.Lock()
        self.tool_history: List[Dict[str, Any]] = []

        # Artifacts (extracted files, persisted per-binary via cache)
        self._artifacts_lock = threading.Lock()
        self._artifacts_counter: int = 0
        self.artifacts: List[Dict[str, Any]] = []

        # Renames (persisted per-binary via cache)
        self._renames_lock = threading.Lock()
        self.renames: Dict[str, Any] = {
            "functions": {},   # addr_hex -> new_name
            "variables": {},   # func_addr_hex -> {old_name: new_name}
            "labels": {},      # addr_hex -> {"name": str, "category": str}
        }

        # Triage status (persisted per-binary via cache)
        self._triage_lock = threading.Lock()
        self.triage_status: Dict[str, str] = {}  # addr_hex -> "unreviewed"|"suspicious"|"clean"|"flagged"

        # Custom types (persisted per-binary via cache)
        self._types_lock = threading.Lock()
        self.custom_types: Dict[str, Any] = {
            "structs": {},   # name -> {"fields": [...], "size": int, "created_at": str}
            "enums": {},     # name -> {"values": {name: int}, "size": int, "created_at": str}
        }

        # Previous session context (populated from cache on open_file)
        self.previous_session_history: List[Dict[str, Any]] = []

        # Cached analysis results for progressive disclosure tools
        self._cached_triage: Optional[Dict[str, Any]] = None
        self._cached_function_scores: Optional[List[Dict[str, Any]]] = None
        self.last_digest_timestamp: float = 0.0

        # Enrichment cached results (populated by background auto-enrichment)
        self._cached_classification: Optional[Dict[str, Any]] = None
        self._cached_similarity_hashes: Optional[Dict[str, Any]] = None
        self._cached_mitre_mapping: Optional[Dict[str, Any]] = None
        self._cached_iocs: Optional[Dict[str, Any]] = None

        # Decompilation priority control (background vs on-demand)
        self._decompile_lock = threading.Lock()
        self._decompile_on_demand_waiting: bool = False

        # Enrichment cancellation
        self._enrichment_cancel = threading.Event()

        # Newly-decompiled notification queue (SSE push to dashboard)
        self._newly_decompiled: deque = deque(maxlen=200)

        # Active tool tracking (for dashboard live status)
        self._active_tool_lock = threading.Lock()
        self.active_tool: Optional[str] = None
        self.active_tool_progress: int = 0
        self.active_tool_total: int = 100

        # Paginated result cache (LRU per-tool, 5 slots each)
        from arkana.mcp._input_helpers import _ToolResultCache
        self.result_cache = _ToolResultCache()

        # Timestamp of last activity (for session TTL cleanup)
        self.last_active: float = time.time()

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Thread-safe read of a background task."""
        with self._task_lock:
            task = self.background_tasks.get(task_id)
            return dict(task) if task else None

    def set_task(self, task_id: str, task_data: Dict[str, Any]):
        """Thread-safe creation/replacement of a background task."""
        with self._task_lock:
            self.background_tasks[task_id] = task_data
            self._evict_old_tasks()

    def update_task(self, task_id: str, **kwargs):
        """Thread-safe partial update of a background task's fields."""
        with self._task_lock:
            if task_id in self.background_tasks:
                self.background_tasks[task_id].update(kwargs)

    def get_all_task_ids(self) -> List[str]:
        """Thread-safe snapshot of current task IDs."""
        with self._task_lock:
            return list(self.background_tasks.keys())

    def check_path_allowed(self, file_path: str) -> None:
        """Raise RuntimeError if the path is outside all allowed directories."""
        import os
        from pathlib import Path
        if self.allowed_paths is None:
            return  # No restriction configured
        resolved = Path(os.path.realpath(file_path))
        for allowed in self.allowed_paths:
            allowed_resolved = Path(os.path.realpath(allowed))
            # Allow if the file is exactly the allowed path or inside it
            if resolved == allowed_resolved or resolved.is_relative_to(allowed_resolved):
                return
        raise RuntimeError(
            f"Access denied: '{file_path}' is outside the allowed paths. "
            f"Allowed: {self.allowed_paths}. "
            "Configure with --allowed-paths at server startup."
        )

    def touch(self):
        """Update the last-active timestamp (called by the tool decorator)."""
        self.last_active = time.time()

    def _evict_old_tasks(self):
        """Remove oldest completed/failed tasks when the count exceeds the limit.

        Must be called while ``_task_lock`` is held.
        """
        finished = [
            (tid, t) for tid, t in self.background_tasks.items()
            if t.get("status") in (TASK_COMPLETED, TASK_FAILED)
        ]
        if len(finished) <= MAX_COMPLETED_TASKS:
            return
        # Sort by numeric epoch (oldest first) and remove excess
        finished.sort(key=lambda item: item[1].get("created_at_epoch", 0))
        to_remove = len(finished) - MAX_COMPLETED_TASKS
        for tid, _ in finished[:to_remove]:
            del self.background_tasks[tid]

    # ------------------------------------------------------------------
    #  Notes accessors
    # ------------------------------------------------------------------

    def add_note(self, content: str, category: str = "general",
                 address: Optional[str] = None, tool_name: Optional[str] = None) -> Dict[str, Any]:
        """Thread-safe note creation. Returns the new note dict."""
        now = datetime.datetime.now(datetime.timezone.utc)
        with self._notes_lock:
            self._notes_counter += 1
            note: Dict[str, Any] = {
                "id": f"n_{int(now.timestamp())}_{self._notes_counter}",
                "category": category,
                "address": address,
                "tool_name": tool_name,
                "content": content,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
            }
            self.notes.append(note)
            return dict(note)

    def get_notes(self, category: Optional[str] = None,
                  address: Optional[str] = None) -> List[Dict[str, Any]]:
        """Thread-safe filtered read of notes. Returns copies."""
        with self._notes_lock:
            result = list(self.notes)
        if category:
            result = [n for n in result if n.get("category") == category]
        if address:
            result = [n for n in result if n.get("address") == address]
        return result

    def update_note(self, note_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Thread-safe partial update. Returns updated note or None."""
        with self._notes_lock:
            for note in self.notes:
                if note["id"] == note_id:
                    for k, v in kwargs.items():
                        if k in ("content", "category", "address", "tool_name") and v is not None:
                            note[k] = v
                    note["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    return dict(note)
        return None

    def delete_note(self, note_id: str) -> bool:
        """Thread-safe note removal. Returns True if found and deleted."""
        with self._notes_lock:
            for i, note in enumerate(self.notes):
                if note["id"] == note_id:
                    self.notes.pop(i)
                    return True
        return False

    def clear_notes(self) -> int:
        """Thread-safe clear of all notes. Returns count of notes removed."""
        with self._notes_lock:
            count = len(self.notes)
            self.notes = []
            self._notes_counter = 0
            return count

    def get_all_notes_snapshot(self) -> List[Dict[str, Any]]:
        """Thread-safe snapshot of all notes for cache persistence."""
        with self._notes_lock:
            return [dict(n) for n in self.notes]

    # ------------------------------------------------------------------
    #  Tool history accessors
    # ------------------------------------------------------------------

    def record_tool_call(self, tool_name: str, parameters: Dict[str, Any],
                         result_summary: str, duration_ms: int) -> None:
        """Thread-safe recording of a tool invocation."""
        entry: Dict[str, Any] = {
            "tool_name": tool_name,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "timestamp_epoch": time.time(),
            "parameters": parameters,
            "result_summary": result_summary,
            "duration_ms": duration_ms,
            "sha256": (self.pe_data or {}).get("file_hashes", {}).get("sha256"),
        }
        with self._history_lock:
            self.tool_history.append(entry)
            if len(self.tool_history) > MAX_TOOL_HISTORY:
                self.tool_history = self.tool_history[-MAX_TOOL_HISTORY:]

    def get_tool_history(self, tool_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Thread-safe filtered read of tool history."""
        with self._history_lock:
            result = list(self.tool_history)
        if tool_name:
            result = [h for h in result if h.get("tool_name") == tool_name]
        return result

    def clear_tool_history(self) -> int:
        """Thread-safe clear. Returns count of entries removed."""
        with self._history_lock:
            count = len(self.tool_history)
            self.tool_history = []
            return count

    def get_tool_history_snapshot(self) -> List[Dict[str, Any]]:
        """Thread-safe snapshot of history for cache persistence."""
        with self._history_lock:
            return list(self.tool_history)

    # ------------------------------------------------------------------
    #  Artifact accessors
    # ------------------------------------------------------------------

    def register_artifact(self, path: str, sha256: str, md5: str,
                          size: int, source_tool: str, description: str,
                          detected_type: Optional[str] = None) -> Dict[str, Any]:
        """Thread-safe artifact registration. Returns the new artifact dict."""
        now = datetime.datetime.now(datetime.timezone.utc)
        with self._artifacts_lock:
            self._artifacts_counter += 1
            artifact: Dict[str, Any] = {
                "id": f"art_{int(now.timestamp())}_{self._artifacts_counter}",
                "path": path,
                "sha256": sha256,
                "md5": md5,
                "size": size,
                "source_tool": source_tool,
                "description": description,
                "detected_type": detected_type,
                "created_at": now.isoformat(),
            }
            self.artifacts.append(artifact)
            return dict(artifact)

    def get_artifacts(self, source_tool: Optional[str] = None) -> List[Dict[str, Any]]:
        """Thread-safe filtered read of artifacts. Returns copies."""
        with self._artifacts_lock:
            result = [dict(a) for a in self.artifacts]
        if source_tool:
            result = [a for a in result if a.get("source_tool") == source_tool]
        return result

    def get_all_artifacts_snapshot(self) -> List[Dict[str, Any]]:
        """Thread-safe snapshot of all artifacts for cache persistence."""
        with self._artifacts_lock:
            return [dict(a) for a in self.artifacts]

    def clear_artifacts(self) -> int:
        """Thread-safe clear of all artifacts. Returns count removed."""
        with self._artifacts_lock:
            count = len(self.artifacts)
            self.artifacts = []
            self._artifacts_counter = 0
            return count

    # ------------------------------------------------------------------
    #  Rename accessors
    # ------------------------------------------------------------------

    def rename_function(self, address: str, new_name: str) -> Dict[str, Any]:
        """Thread-safe function rename. Returns the rename entry."""
        addr = address.lower()
        with self._renames_lock:
            self.renames["functions"][addr] = new_name
            return {"address": addr, "new_name": new_name, "type": "function"}

    def rename_variable(self, func_addr: str, old_name: str, new_name: str) -> Dict[str, Any]:
        """Thread-safe variable rename within function scope."""
        faddr = func_addr.lower()
        with self._renames_lock:
            if faddr not in self.renames["variables"]:
                self.renames["variables"][faddr] = {}
            self.renames["variables"][faddr][old_name] = new_name
            return {"function_address": faddr, "old_name": old_name, "new_name": new_name, "type": "variable"}

    def add_label(self, address: str, name: str, category: str = "general") -> Dict[str, Any]:
        """Thread-safe label creation at an address."""
        addr = address.lower()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._renames_lock:
            self.renames["labels"][addr] = {"name": name, "category": category, "created_at": now}
            return {"address": addr, "name": name, "category": category, "type": "label"}

    def get_renames(self, rename_type: Optional[str] = None) -> Dict[str, Any]:
        """Thread-safe read of renames, optionally filtered by type."""
        with self._renames_lock:
            if rename_type and rename_type in self.renames:
                return {rename_type: dict(self.renames[rename_type])}
            return {k: dict(v) if isinstance(v, dict) else v for k, v in self.renames.items()}

    def delete_rename(self, address: str, rename_type: str) -> bool:
        """Thread-safe removal of a rename/label. Returns True if found."""
        addr = address.lower()
        with self._renames_lock:
            if rename_type == "function":
                return self.renames["functions"].pop(addr, None) is not None
            elif rename_type == "variable":
                return self.renames["variables"].pop(addr, None) is not None
            elif rename_type == "label":
                return self.renames["labels"].pop(addr, None) is not None
            return False

    def get_all_renames_snapshot(self) -> Dict[str, Any]:
        """Thread-safe snapshot for cache persistence."""
        with self._renames_lock:
            return {
                "functions": dict(self.renames["functions"]),
                "variables": {k: dict(v) for k, v in self.renames["variables"].items()},
                "labels": {k: dict(v) for k, v in self.renames["labels"].items()},
            }

    def clear_renames(self) -> int:
        """Thread-safe clear. Returns total count removed."""
        with self._renames_lock:
            count = (len(self.renames["functions"])
                     + len(self.renames["variables"])
                     + len(self.renames["labels"]))
            self.renames = {"functions": {}, "variables": {}, "labels": {}}
            return count

    def get_function_display_name(self, address: str) -> Optional[str]:
        """Return user-assigned name for a function address, or None."""
        addr = address.lower()
        with self._renames_lock:
            return self.renames["functions"].get(addr)

    # ------------------------------------------------------------------
    #  Custom type accessors
    # ------------------------------------------------------------------

    def create_struct(self, name: str, fields: list, size: int) -> Dict[str, Any]:
        """Thread-safe struct creation. Returns the struct definition."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._types_lock:
            self.custom_types["structs"][name] = {
                "fields": list(fields),
                "size": size,
                "created_at": now,
            }
            return {"name": name, "fields": fields, "size": size, "type": "struct", "created_at": now}

    def create_enum(self, name: str, values: dict, size: int = 4) -> Dict[str, Any]:
        """Thread-safe enum creation. Returns the enum definition."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._types_lock:
            self.custom_types["enums"][name] = {
                "values": dict(values),
                "size": size,
                "created_at": now,
            }
            return {"name": name, "values": values, "size": size, "type": "enum", "created_at": now}

    def get_custom_type(self, name: str) -> Optional[Dict[str, Any]]:
        """Thread-safe lookup of a custom type by name."""
        with self._types_lock:
            if name in self.custom_types["structs"]:
                result = dict(self.custom_types["structs"][name])
                result["type"] = "struct"
                result["name"] = name
                return result
            if name in self.custom_types["enums"]:
                result = dict(self.custom_types["enums"][name])
                result["type"] = "enum"
                result["name"] = name
                return result
        return None

    def get_all_custom_types(self) -> Dict[str, Any]:
        """Thread-safe read of all custom types."""
        with self._types_lock:
            return {
                "structs": {k: dict(v) for k, v in self.custom_types["structs"].items()},
                "enums": {k: dict(v) for k, v in self.custom_types["enums"].items()},
            }

    def delete_custom_type(self, name: str) -> bool:
        """Thread-safe removal. Returns True if found."""
        with self._types_lock:
            if name in self.custom_types["structs"]:
                del self.custom_types["structs"][name]
                return True
            if name in self.custom_types["enums"]:
                del self.custom_types["enums"][name]
                return True
        return False

    def get_all_types_snapshot(self) -> Dict[str, Any]:
        """Thread-safe snapshot for cache persistence."""
        with self._types_lock:
            return {
                "structs": {k: dict(v) for k, v in self.custom_types["structs"].items()},
                "enums": {k: dict(v) for k, v in self.custom_types["enums"].items()},
            }

    def clear_custom_types(self) -> int:
        """Thread-safe clear. Returns total count removed."""
        with self._types_lock:
            count = len(self.custom_types["structs"]) + len(self.custom_types["enums"])
            self.custom_types = {"structs": {}, "enums": {}}
            return count

    # ------------------------------------------------------------------
    #  Triage status accessors
    # ------------------------------------------------------------------

    def set_triage_status(self, address: str, status: str) -> Dict[str, str]:
        """Thread-safe triage status update. Returns the entry."""
        addr = address.lower()
        if status not in ("unreviewed", "suspicious", "clean", "flagged"):
            raise ValueError(f"Invalid triage status: {status}")
        with self._triage_lock:
            self.triage_status[addr] = status
            return {"address": addr, "status": status}

    def get_triage_status(self, address: Optional[str] = None) -> Any:
        """Thread-safe read of triage status."""
        with self._triage_lock:
            if address:
                return self.triage_status.get(address.lower(), "unreviewed")
            return dict(self.triage_status)

    def get_all_triage_snapshot(self) -> Dict[str, str]:
        """Thread-safe snapshot for cache persistence."""
        with self._triage_lock:
            return dict(self.triage_status)

    def clear_triage(self) -> int:
        """Thread-safe clear. Returns count removed."""
        with self._triage_lock:
            count = len(self.triage_status)
            self.triage_status = {}
            return count

    # ------------------------------------------------------------------
    #  Angr state
    # ------------------------------------------------------------------

    def set_angr_results(self, project, cfg, loop_cache, loop_cache_config):
        """Atomically set all angr analysis results."""
        with self._angr_lock:
            self.angr_project = project
            self.angr_cfg = cfg
            self.angr_loop_cache = loop_cache
            self.angr_loop_cache_config = loop_cache_config

    def get_angr_snapshot(self):
        """Return a consistent snapshot of (project, cfg)."""
        with self._angr_lock:
            return self.angr_project, self.angr_cfg

    def reset_angr(self):
        with self._angr_lock:
            self.angr_project = None
            self.angr_cfg = None
            self.angr_loop_cache = None
            self.angr_loop_cache_config = None
            self.angr_hooks = {}
        # Also clear background tasks (angr startup task) so a stalled
        # "startup-angr" task doesn't persist across file reloads and
        # block angr-dependent tools with "still in progress" errors.
        with self._task_lock:
            self.background_tasks.clear()

    def close_pe(self):
        with self._pe_lock:
            if self.pe_object:
                # Close the PE object only if we own it.  Sessions that
                # inherited the reference at creation time must NOT close
                # it — doing so would invalidate the object for all other
                # sessions and the default state.
                # We use the ``_inherited_pe_object`` flag rather than
                # comparing ``is _default_state.pe_object`` because the
                # default state's reference can change if another session
                # calls ``open_file``.
                if self is _default_state or not self._inherited_pe_object:
                    try:
                        self.pe_object.close()
                    except (OSError, AttributeError) as e:
                        logger.debug("Failed to close PE object: %s", e)
                self.pe_object = None
                self._inherited_pe_object = False


# ---------------------------------------------------------------------------
# Session-scoped state (HTTP mode isolation)
# ---------------------------------------------------------------------------

# ContextVar holds the active AnalyzerState for the current async/thread context.
_current_state_var: contextvars.ContextVar[Optional[AnalyzerState]] = contextvars.ContextVar(
    '_current_state', default=None,
)

# Registry: session_key -> AnalyzerState
_session_registry: Dict[str, AnalyzerState] = {}
_registry_lock = threading.Lock()

# Default state instance (stdio / fallback)
_default_state = AnalyzerState()


def get_current_state() -> AnalyzerState:
    """Return the ``AnalyzerState`` for the current context."""
    s = _current_state_var.get()
    return s if s is not None else _default_state


def set_current_state(state: AnalyzerState) -> None:
    """Explicitly set the ``AnalyzerState`` for the current context."""
    _current_state_var.set(state)


def get_or_create_session_state(session_key: str) -> AnalyzerState:
    """Get or lazily create an ``AnalyzerState`` for *session_key*.

    For stdio mode (``"default"``), returns the global ``_default_state``
    directly so that files pre-loaded at startup via ``--input-file`` are
    immediately available to tool calls.

    For HTTP sessions, a new ``AnalyzerState`` is created and inherits the
    server-level configuration **and** any pre-loaded file data from the
    default state.  Each session can subsequently call ``open_file`` to
    load a different file without affecting other sessions.
    """
    # In stdio mode there is only one client — use the default state
    # directly so startup pre-loading works transparently.
    if session_key == "default":
        return _default_state

    stale_to_cleanup = []
    with _registry_lock:
        # Collect stale sessions — mark them as closing inside the lock
        # to prevent TOCTOU races with session key reuse.
        now = time.time()
        stale_keys = [
            key for key, st in _session_registry.items()
            if (now - st.last_active) > SESSION_TTL_SECONDS
        ]
        for key in stale_keys:
            stale_session = _session_registry.pop(key)
            # Mark as closing so it cannot be reactivated if the id()
            # is reused by Python's memory allocator.
            stale_session.last_active = 0
            stale_to_cleanup.append(stale_session)

        if session_key not in _session_registry:
            new_state = AnalyzerState()
            # Inherit server-level config from the default state
            new_state.allowed_paths = _default_state.allowed_paths
            new_state.samples_path = _default_state.samples_path
            # Inherit any pre-loaded file data so HTTP clients can
            # immediately access files loaded at startup via --input-file.
            # Each session gets a shared reference; calling open_file
            # replaces the reference on the session only.
            if _default_state.filepath is not None:
                new_state.filepath = _default_state.filepath
                new_state.pe_data = _default_state.pe_data
                new_state.pe_object = _default_state.pe_object
                new_state._inherited_pe_object = True
                new_state.pefile_version = _default_state.pefile_version
                new_state.loaded_from_cache = _default_state.loaded_from_cache
                new_state.angr_project = _default_state.angr_project
                new_state.angr_cfg = _default_state.angr_cfg
            _session_registry[session_key] = new_state
        result = _session_registry[session_key]

    # Clean up stale sessions outside the lock.
    # Sessions with inherited PE objects must not close them (close_pe
    # now checks _inherited_pe_object flag).
    for stale in stale_to_cleanup:
        if stale.pe_object is not None:
            stale.close_pe()
        if stale.angr_project is not None and stale.angr_project is not _default_state.angr_project:
            stale.reset_angr()

    return result


def get_all_session_states() -> list:
    """Return a snapshot of all active session states (for heartbeat monitoring)."""
    with _registry_lock:
        return [*list(_session_registry.values()), _default_state]


def activate_session_state(session_key: str) -> AnalyzerState:
    """Activate the per-session state for the current context and return it."""
    s = get_or_create_session_state(session_key)
    _current_state_var.set(s)
    return s


def get_session_key_from_context(ctx) -> str:
    """Extract a unique session key from an MCP ``Context`` object.

    Falls back to ``"default"`` when no session can be identified (e.g.
    stdio mode), which transparently collapses to the singleton model.
    """
    try:
        # FastMCP Context wraps a RequestContext
        if hasattr(ctx, '_request_context'):
            session = getattr(ctx._request_context, 'session', None)
            if session is not None:
                return str(id(session))
        if hasattr(ctx, 'session'):
            return str(id(ctx.session))
    except Exception:
        logger.debug("Could not extract session key from context, using default", exc_info=True)
    return "default"


class StateProxy:
    """Transparent proxy that delegates attribute access to the active session
    ``AnalyzerState`` (via *contextvars*).

    In stdio mode the default state is used.  In HTTP mode the per-session
    state set by the tool decorator is used.  All existing code that does
    ``state.pe_data``, ``state.filepath = ...``, etc. works unchanged.

    Note: ``__setattr__`` delegates ALL attribute sets to the underlying
    ``AnalyzerState``.  If you need to store private attributes on the proxy
    itself, use ``object.__setattr__(self, name, value)`` explicitly.
    """

    def __getattr__(self, name: str):
        return getattr(get_current_state(), name)

    def __setattr__(self, name: str, value):
        # Allow StateProxy's own private attributes (prefixed with _proxy_)
        # to be stored on the proxy instance itself rather than delegating.
        if name.startswith("_proxy_"):
            object.__setattr__(self, name, value)
        else:
            setattr(get_current_state(), name, value)

    def __repr__(self):
        current = get_current_state()
        return f"<StateProxy -> {current!r}>"
