"""Centralized state management for analyzed files."""
import threading
from typing import Dict, Any, Optional, List


class AnalyzerState:
    """Centralized state management for analyzed files."""
    def __init__(self):
        self.filepath: Optional[str] = None
        self.pe_data: Optional[Dict[str, Any]] = None
        self.pe_object: Optional[Any] = None  # pefile.PE or MockPE
        self.pefile_version: Optional[str] = None
        self.loaded_from_cache: bool = False

        # Path sandboxing for network-exposed MCP servers
        self.allowed_paths: Optional[List[str]] = None  # None = no restriction

        # Angr State
        self.angr_project = None
        self.angr_cfg = None
        self.angr_loop_cache = None
        self.angr_loop_cache_config = None
        self.angr_hooks: Dict[str, Dict[str, Any]] = {}  # addr_hex -> hook info

        # Background Tasks
        self._task_lock = threading.Lock()
        self.background_tasks: Dict[str, Dict[str, Any]] = {}
        self.monitor_thread_started = False

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Thread-safe read of a background task."""
        with self._task_lock:
            task = self.background_tasks.get(task_id)
            return dict(task) if task else None

    def set_task(self, task_id: str, task_data: Dict[str, Any]):
        """Thread-safe creation/replacement of a background task."""
        with self._task_lock:
            self.background_tasks[task_id] = task_data

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
        if self.allowed_paths is None:
            return  # No restriction configured
        resolved = os.path.realpath(file_path)
        for allowed in self.allowed_paths:
            allowed_resolved = os.path.realpath(allowed)
            # Allow if the file is exactly the allowed path or inside it
            if resolved == allowed_resolved or resolved.startswith(allowed_resolved + os.sep):
                return
        raise RuntimeError(
            f"Access denied: '{file_path}' is outside the allowed paths. "
            f"Allowed: {self.allowed_paths}. "
            "Configure with --allowed-paths at server startup."
        )

    def reset_angr(self):
        self.angr_project = None
        self.angr_cfg = None
        self.angr_loop_cache = None
        self.angr_loop_cache_config = None
        self.angr_hooks = {}

    def close_pe(self):
        if self.pe_object:
            try:
                self.pe_object.close()
            except Exception:
                pass
            self.pe_object = None
