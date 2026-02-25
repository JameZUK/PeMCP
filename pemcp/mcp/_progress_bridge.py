"""Thread-safe bridge for sending MCP progress notifications from worker threads.

Heavy analysis (PE parsing, angr CFG, FLOSS, etc.) runs in worker threads via
``asyncio.to_thread()``.  The MCP Context methods (``report_progress``,
``info``) are async coroutines that must execute on the event loop.  This module
provides :class:`ProgressBridge` which safely posts those coroutines from any
thread using :func:`asyncio.run_coroutine_threadsafe`.
"""

import asyncio
import time
from typing import Callable, Optional

from pemcp.config import logger


class ProgressBridge:
    """Bridges synchronous thread code to async MCP Context progress reporting.

    Create on the async side (where ``ctx`` and the event loop are available),
    then pass into worker threads.  All public methods are safe to call from
    any thread.

    Example::

        bridge = ProgressBridge(ctx, loop=asyncio.get_running_loop())

        def blocking_work():
            bridge.report_progress(10, 100)
            bridge.info("Computing hashes...")
            # ... heavy work ...
            bridge.report_progress(90, 100)

        await asyncio.to_thread(blocking_work)

    Parameters
    ----------
    ctx : Context
        MCP Context with ``report_progress`` and ``info`` coroutine methods.
    loop : asyncio.AbstractEventLoop, optional
        The running event loop.  If *None*, progress calls are silently
        dropped (useful for non-MCP / testing contexts).
    throttle_seconds : float
        Minimum interval between dispatched notifications.  Prevents
        flooding the client when milestones fire in quick succession.
    delivery_timeout : float
        Maximum seconds to wait for a notification to be delivered to the
        event loop before giving up.
    """

    def __init__(
        self,
        ctx,
        *,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        throttle_seconds: float = 1.0,
        delivery_timeout: float = 5.0,
    ):
        self._ctx = ctx
        self._loop = loop
        self._throttle = throttle_seconds
        self._delivery_timeout = delivery_timeout
        self._last_progress_time: float = 0.0
        self._last_info_time: float = 0.0

    # ------------------------------------------------------------------
    # Public API (thread-safe)
    # ------------------------------------------------------------------

    def report_progress(self, current: int, total: int, *, force: bool = False) -> None:
        """Send a progress notification to the MCP client.

        Throttled by default; pass ``force=True`` for critical milestones
        (start / complete).
        """
        now = time.monotonic()
        if not force and (now - self._last_progress_time) < self._throttle:
            return
        self._last_progress_time = now
        self._dispatch(self._ctx.report_progress(current, total))

    def info(self, message: str, *, force: bool = False) -> None:
        """Send a log-level info message to the MCP client."""
        now = time.monotonic()
        if not force and (now - self._last_info_time) < self._throttle:
            return
        self._last_info_time = now
        self._dispatch(self._ctx.info(message))

    def make_callback(
        self, base_pct: int = 0, range_pct: int = 100
    ) -> Callable[[int, int, str], None]:
        """Return a ``progress_callback`` compatible with :func:`_parse_pe_to_dict`.

        Maps the ``(step, total, message)`` signature to MCP progress
        notifications.  The parser's 0–100 range is linearly mapped to
        ``[base_pct, base_pct + range_pct]`` of overall progress.

        Example::

            cb = bridge.make_callback(base_pct=5, range_pct=85)
            # Parser step 0/100 → MCP 5/100
            # Parser step 50/100 → MCP 47/100
            # Parser step 100/100 → MCP 90/100
        """

        def _cb(step: int, total: int, message: str) -> None:
            mapped = base_pct + int(step * range_pct / max(total, 1))
            self.report_progress(mapped, 100)
            self.info(message)

        return _cb

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dispatch(self, coro) -> None:
        """Post *coro* to the event loop from the current (worker) thread."""
        if self._loop is None or self._loop.is_closed():
            return
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self._loop)
            future.result(timeout=self._delivery_timeout)
        except Exception:
            # Never let progress reporting break an analysis.
            logger.debug("ProgressBridge: notification delivery failed", exc_info=True)
