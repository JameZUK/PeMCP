"""Starlette ASGI app for the Arkana dashboard."""
import asyncio
import contextvars
import functools
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tarfile
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import (
    FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response,
)
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware
from starlette.types import ASGIApp, Receive, Scope, Send

from jinja2 import Environment, FileSystemLoader

from arkana.dashboard.state_api import (
    get_overview_data,
    get_functions_data,
    get_callgraph_data,
    get_sections_data,
    get_imports_data,
    get_timeline_data,
    get_notes_data,
    get_decompiled_code,
    trigger_decompile,
    get_strings_data,
    global_search,
    get_function_xrefs_data,
    get_function_strings_data,
    get_function_analysis_data,
    get_floss_summary,
    get_hex_dump_data,
    get_mitre_data,
    get_capa_data,
    get_function_cfg_data,
    get_disassembly_data,
    get_function_variables_data,
    get_entropy_data,
    get_resources_data,
    get_triage_report_data,
    get_packing_data,
    get_similarity_data,
    get_custom_types_data,
    get_function_similarity_data,
    get_export_report_data,
    search_decompiled_code,
    get_diff_data,
    get_list_files_data,
    get_digest_data,
    generate_report_text,
    get_ioc_summary_data,
    get_capabilities_summary_data,
    get_bsim_db_stats,
    get_bsim_indexed_binaries,
    get_bsim_triage_data,
    get_bsim_triage_function_matches,
    get_bsim_db_health,
    delete_bsim_binary,
    clear_bsim_db,
    index_current_binary,
    _BSIM_HEX64_RE,
    get_settings_data,
    get_project_comparison_data,
)
from arkana.dashboard.projects_api import (
    get_projects_list_data,
    get_project_detail_data,
    create_project_data,
    rename_project_data,
    tag_project_data,
    delete_project_data,
    set_primary_binary_data,
    list_importable_archives,
    import_archive_data,
    save_dashboard_state,
)
from arkana.dashboard.artifacts_api import (
    get_artifacts_list_data,
    get_artifact_detail,
    update_artifact_metadata_data,
    delete_artifact_data,
    bulk_delete_artifacts,
    bulk_tag_artifacts,
    get_artifact_file_for_download,
)
from arkana.projects import project_manager
from arkana.mcp.tools_pe import open_file as _open_file_tool

from arkana.constants import DASHBOARD_THREAD_POOL_SIZE
from arkana.utils import _safe_env_int

logger = logging.getLogger("Arkana.dashboard")

class DashboardShutdownError(RuntimeError):
    """Raised when the dashboard executor has been shut down (process is
    exiting). Routes should return a 503 instead of a 500 traceback."""


# --- Dedicated dashboard thread pool ---
# Prevents dashboard requests from being starved when MCP tools or background
# tasks saturate the default executor (which has only min(32, cpu+4) threads).
#
# NOTE: We deliberately do NOT register an atexit handler to shut this down.
# The dashboard runs in a daemon thread that may still be processing htmx
# polls when the main MCP thread exits and atexit fires. If we shut the
# executor down at that point, every in-flight and subsequent request blows
# up with ``RuntimeError: cannot schedule new futures after shutdown`` until
# Python finally kills the daemon thread — and that window can be many
# seconds long when the interpreter is hung waiting on uvicorn's event loop.
# By leaving the executor alone, the OS reclaims it when the process truly
# exits and we never serve a half-shutdown error.
_dashboard_executor = ThreadPoolExecutor(
    max_workers=_safe_env_int("ARKANA_DASHBOARD_THREADS", DASHBOARD_THREAD_POOL_SIZE, min_val=1, max_val=32),
    thread_name_prefix="arkana-dash",
)


async def _dash_to_thread(func, /, *args, **kwargs):
    """Like asyncio.to_thread() but uses the dashboard's dedicated thread pool.

    Resilient to a shut-down executor: raises ``DashboardShutdownError``
    instead of letting ``RuntimeError`` from the bottom of
    ``ThreadPoolExecutor.submit`` propagate up to the route handlers as an
    unhandled 500. Routes catch this in their existing ``except Exception``
    blocks and return a clean 503 via ``_api_error_response``.
    """
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    func_call = functools.partial(ctx.run, func, *args, **kwargs)
    try:
        return await loop.run_in_executor(_dashboard_executor, func_call)
    except RuntimeError as exc:
        # ``cannot schedule new futures after shutdown`` is the only
        # RuntimeError ThreadPoolExecutor.submit() raises. Re-raise as a
        # domain-specific error the routes can detect.
        if "shutdown" in str(exc):
            raise DashboardShutdownError("dashboard executor is shut down") from exc
        raise


_LOCATE_MAX_HASH = 8         # never hash more than this many candidates per call
_LOCATE_MAX_WALK = 20000     # cap directory walks (defends against pathological trees)
_LOCATE_HASH_CHUNK = 1 << 20  # 1 MiB streaming hash chunk
_LOCATE_MAX_FILE_BYTES = 512 * 1024 * 1024  # don't hash candidates above this size

# Result cache for ``_locate_binary_for_stub`` — short-circuits the 20K-entry
# rglob walk for sha256s we recently resolved. Not strictly required for
# correctness (the helper is bounded), but a successful resolve costs ~500ms
# of disk I/O on a populated samples dir, and the dashboard hits the helper
# repeatedly when expanding the projects grid or opening many migrated stubs
# in a row. Cache lifetime is short so a deleted/moved file becomes stale
# fast and the helper falls back to the cold path.
_LOCATE_CACHE_TTL_S = 300.0  # 5 minutes
_LOCATE_CACHE_MAX_ENTRIES = 256
_locate_cache: Dict[str, Tuple[float, str]] = {}  # sha256 → (expiry_epoch, path)
_locate_cache_lock = threading.Lock()


def _locate_cache_get(sha256: str) -> Optional[str]:
    now = time.time()
    with _locate_cache_lock:
        entry = _locate_cache.get(sha256)
        if entry is None:
            return None
        expiry, path = entry
        if now >= expiry:
            del _locate_cache[sha256]
            return None
    # Verify the cached path still exists — a stale entry should fall
    # through to the cold path so the user doesn't get stuck on a
    # deleted file.
    if not os.path.isfile(path):
        with _locate_cache_lock:
            _locate_cache.pop(sha256, None)
        return None
    return path


def _locate_cache_put(sha256: str, path: str) -> None:
    if not sha256 or not path:
        return
    with _locate_cache_lock:
        # Bounded LRU-ish: drop the oldest entry when full. Cache is small
        # enough that linear scan for min is cheaper than ordered structures.
        if len(_locate_cache) >= _LOCATE_CACHE_MAX_ENTRIES:
            try:
                oldest_sha = min(_locate_cache, key=lambda k: _locate_cache[k][0])
                _locate_cache.pop(oldest_sha, None)
            except (KeyError, ValueError):
                pass
        _locate_cache[sha256] = (time.time() + _LOCATE_CACHE_TTL_S, path)

# Bulk-action caps for /api/artifacts/bulk — defend against authenticated
# CPU DoS where a huge id/tag list multiplies into N×N work under lock.
_MAX_BULK_ARTIFACT_IDS = 500
_MAX_BULK_ARTIFACT_TAGS = 50

# /api/projects/dashboard-state value caps. Per-key type and size budget so
# repeated calls cannot grow the manifest unbounded.
_DASHBOARD_STATE_VALUE_BUDGET = {
    "last_tab": (str, 80),
    "hex_offset": (int, None),
    "last_function_address": (str, 64),
    "functions_scroll": (int, None),
    "callgraph_layout": (dict, 4096),
}


def _build_directory_tarball(src_path: str, arcname: str) -> str:
    """Build a tar.gz of *src_path* into a NamedTemporaryFile and return its path.

    Streams via tarfile rather than buffering bytes in memory. Caller is
    responsible for unlinking the result (use ``_unlink_quiet`` as a
    BackgroundTask). Symlinks are NOT followed (``dereference=False``).

    Pre-validates *src_path* against TOCTOU swaps:
      - Refuses if the path is a symlink (a directory artifact registered
        as a real dir could be replaced with a symlink to ``/etc`` between
        registration and download).
      - Refuses if it isn't a directory.
      - Resolves the path before walking so a parent-symlink swap also
        gets caught.
    """
    src = Path(src_path)
    try:
        if src.is_symlink():
            raise RuntimeError(
                f"Refusing to tarball symlinked directory: {src_path}"
            )
        resolved_src = src.resolve(strict=True)
        if not resolved_src.is_dir():
            raise RuntimeError(
                f"Directory artifact path is not a directory: {src_path}"
            )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Directory artifact path no longer exists: {src_path}"
        ) from exc

    fd = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tmp_path = fd.name
    fd.close()
    try:
        with tarfile.open(tmp_path, mode="w:gz", dereference=False) as tf:
            tf.add(str(resolved_src), arcname=arcname, recursive=True)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return tmp_path


def _unlink_quiet(path: str) -> None:
    """Best-effort unlink — used as a BackgroundTask after FileResponse."""
    try:
        os.unlink(path)
    except OSError:
        pass


class _NoopCtx:
    """Stand-in for FastMCP's Context when calling MCP tools from the dashboard.

    ``open_file`` only invokes ``ctx.info`` / ``ctx.warning`` / ``ctx.error`` /
    ``ctx.report_progress`` — noop async methods satisfy the interface.
    """
    async def info(self, *args, **kwargs): pass
    async def warning(self, *args, **kwargs): pass
    async def error(self, *args, **kwargs): pass
    async def report_progress(self, *args, **kwargs): pass


def _resolve_project_member(project, chosen_sha: str) -> Dict[str, Any]:
    """Resolve a project member + presence check under one lock acquisition.

    Returns a dict with:
      - ``member``: the ProjectMember dataclass (or None on lookup failure)
      - ``binary_path``: absolute path on disk (or "")
      - ``present``: bool — whether the file exists on disk right now
      - ``error``: str — present only if sha256 validation failed

    Used by ``api_projects_open`` to avoid doing the stat() + lock dance on
    the async event loop.
    """
    try:
        member = project.get_member(chosen_sha) if hasattr(project, "get_member") else None
    except ValueError as exc:
        return {"error": str(exc), "member": None, "binary_path": "", "present": False}
    if member is None:
        return {"member": None, "binary_path": "", "present": False}
    path = member.copy_path or ""
    return {
        "member": member,
        "binary_path": path,
        "present": bool(path) and os.path.isfile(path),
    }


def _locate_binary_for_stub(state, sha256: str, original_filename: str) -> str:
    """Search known sample directories for a file matching *sha256*.

    Returns the absolute path of the first match, or "" if nothing is found.
    Used by ``api_projects_open`` to materialise stub members from migrated
    projects (where the binary copy was never copied into the project's
    binaries/ dir).

    Search strategy (in order):
      1. Try ``samples_path / original_filename`` directly.
      2. Walk ``state.allowed_paths`` (if configured) and ``state.samples_path``
         (the most common case for stdio mode), looking for filename matches
         first, then any other files within the walk cap.
      3. Hash up to ``_LOCATE_MAX_HASH`` candidates (filename matches first)
         and return the first sha256 match.

    Bounds: ``_LOCATE_MAX_WALK`` directory entries scanned per call,
    ``_LOCATE_MAX_HASH`` files hashed, ``_LOCATE_MAX_FILE_BYTES`` per file.

    Path safety: env-var roots (``ARKANA_EXPORT_DIR`` and friends) MUST be
    inside ``state.allowed_paths`` when an allowlist is configured, and
    are always rejected if their resolved path has fewer than two
    components (e.g. ``/`` or ``/home``) — otherwise a misconfigured env
    var would let an authenticated user trigger a 20K-entry walk over the
    whole filesystem on every stub-open call.
    """
    if not sha256 or not original_filename:
        return ""
    sha256 = sha256.lower()
    # Fast path: short-circuit on the recent-resolution cache.
    cached = _locate_cache_get(sha256)
    if cached:
        return cached
    target_basename = os.path.basename(original_filename)
    if not target_basename:
        return ""
    target_lower = target_basename.lower()

    allowed_paths_list = list(getattr(state, "allowed_paths", None) or [])
    allowed_paths_resolved = set()
    for ap in allowed_paths_list:
        try:
            allowed_paths_resolved.add(str(Path(str(ap)).resolve()))
        except (OSError, ValueError):
            pass

    def _is_under_allowlist(rp: Path) -> bool:
        """True if *rp* is inside any configured allowed_paths root.

        When no allowlist is configured (stdio mode), this returns True so
        the helper still works in development. When an allowlist IS set,
        env-var roots must be contained by it.
        """
        if not allowed_paths_resolved:
            return True
        for ap in allowed_paths_resolved:
            try:
                if rp == Path(ap) or rp.is_relative_to(Path(ap)):
                    return True
            except (OSError, ValueError):
                continue
        return False

    # Build search roots from state — both allowed_paths (path sandbox) and
    # samples_path (the explicit "where my samples live" hint).
    roots: List[Path] = []
    seen_roots: set = set()

    def _add_root(p: object, *, trusted: bool = False) -> None:
        """Add *p* to the walk roots after resolution + safety checks.

        ``trusted=True`` skips the depth and allowlist gate — used for
        ``state.allowed_paths`` itself (which is the source of truth) and
        ``state.samples_path`` (operator-configured at startup).
        Untrusted roots (env-var fallbacks) must (a) sit under the
        allowlist when one is configured and (b) have at least two path
        components so a misconfigured ``ARKANA_OUTPUT=/`` doesn't let the
        helper walk the whole filesystem on every stub-open call.
        """
        if not p:
            return
        try:
            rp = Path(str(p)).resolve()
        except (OSError, ValueError):
            return
        key = str(rp)
        if key in seen_roots:
            return
        if not rp.is_dir():
            return
        if not trusted:
            # Reject too-shallow roots ("/", "/home", "/var", etc.) — even
            # an allowlisted shallow root is a footgun for a recursive walk.
            if len(rp.parts) < 3:
                logger.debug("locate_binary: skipping shallow env root %s", rp)
                return
            if not _is_under_allowlist(rp):
                logger.debug("locate_binary: env root %s outside allowlist", rp)
                return
        seen_roots.add(key)
        roots.append(rp)

    for p in allowed_paths_list:
        _add_root(p, trusted=True)
    _add_root(getattr(state, "samples_path", None), trusted=True)
    # Also probe well-known export/output dirs — extracted artifacts (e.g.
    # decrypted payloads) often live here, and migrated projects sometimes
    # reference them as their primary binary. NOT trusted: rejected if not
    # under the allowlist or if too shallow.
    for env_var in ("ARKANA_EXPORT_DIR", "ARKANA_HOST_EXPORT", "ARKANA_OUTPUT"):
        _add_root(os.environ.get(env_var))

    if not roots:
        return ""

    def _hash(path: Path) -> str:
        try:
            st = path.stat()
            if st.st_size > _LOCATE_MAX_FILE_BYTES:
                return ""
        except OSError:
            return ""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(_LOCATE_HASH_CHUNK)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    # Fast path: direct filename hit at the root of any search dir
    for root in roots:
        direct = root / target_basename
        try:
            if direct.is_file() and _hash(direct) == sha256:
                resolved = str(direct.resolve())
                _locate_cache_put(sha256, resolved)
                return resolved
        except OSError:
            pass

    # Walked search: prioritise filename matches, then collect other files
    # up to the cap so a sha256 hit can still find a renamed binary.
    name_hits: List[Path] = []
    others: List[Path] = []
    walked = 0
    for root in roots:
        if walked >= _LOCATE_MAX_WALK:
            break
        try:
            for entry in root.rglob("*"):
                walked += 1
                if walked >= _LOCATE_MAX_WALK:
                    break
                try:
                    if not entry.is_file():
                        continue
                except OSError:
                    continue
                if entry.name.lower() == target_lower:
                    name_hits.append(entry)
                elif len(others) < _LOCATE_MAX_HASH:
                    # Only keep enough non-matching candidates that we could
                    # hash if no name hits were found.
                    others.append(entry)
        except OSError:
            continue

    # Hash filename matches first, then fall back to a few non-matching
    # files (handles renames). Bounded by _LOCATE_MAX_HASH total hashes.
    candidates = name_hits[:_LOCATE_MAX_HASH]
    if len(candidates) < _LOCATE_MAX_HASH:
        candidates.extend(others[: _LOCATE_MAX_HASH - len(candidates)])
    for cand in candidates:
        if _hash(cand) == sha256:
            resolved = str(cand.resolve())
            _locate_cache_put(sha256, resolved)
            return resolved
    return ""


# --- Paths ---
_DASHBOARD_DIR = Path(__file__).parent
_TEMPLATES_DIR = _DASHBOARD_DIR / "templates"
_STATIC_DIR = _DASHBOARD_DIR / "static"
_TOKEN_FILE = Path.home() / ".arkana" / "dashboard_token"

# --- Jinja2 ---
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=True,
)


def _markdown_to_html(text: str) -> str:
    """Convert a subset of markdown to HTML for dashboard display.

    Supports: headings (##/###), bold (**), inline code (`), bullet lists,
    markdown tables, and paragraph breaks. No external dependencies.
    """
    from markupsafe import Markup, escape

    text = str(escape(text))
    lines = text.split("\n")
    out: list = []
    in_ul = False
    in_table = False
    table_has_header = False

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # --- Table rows (| col | col |) ---
        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_has_header = False
                if in_ul:
                    out.append("</ul>")
                    in_ul = False
                out.append('<table class="md-table">')
            # Skip separator rows (|---|---|)
            if re.match(r"^\|[\s\-:|]+\|$", stripped):
                table_has_header = True
                i += 1
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            tag = "th" if not table_has_header and (
                i + 1 < len(lines) and re.match(
                    r"^\|[\s\-:|]+\|$", lines[i + 1].strip()
                )
            ) else "td"
            row = "".join(f"<{tag}>{_md_inline(c)}</{tag}>" for c in cells)
            out.append(f"<tr>{row}</tr>")
            i += 1
            continue

        if in_table:
            out.append("</table>")
            in_table = False
            table_has_header = False

        # --- Headings ---
        m = re.match(r"^(#{2,4})\s+(.+)$", stripped)
        if m:
            if in_ul:
                out.append("</ul>")
                in_ul = False
            level = min(len(m.group(1)) + 1, 6)  # ## -> h3, ### -> h4
            out.append(f"<h{level}>{_md_inline(m.group(2))}</h{level}>")
            i += 1
            continue

        # --- Bullet lists ---
        m = re.match(r"^[-*]\s+(.+)$", stripped)
        if m:
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{_md_inline(m.group(1))}</li>")
            i += 1
            continue

        if in_ul:
            out.append("</ul>")
            in_ul = False

        # --- Empty line = paragraph break ---
        if not stripped:
            out.append("<br>")
            i += 1
            continue

        # --- Regular text ---
        out.append(f"<p>{_md_inline(stripped)}</p>")
        i += 1

    if in_ul:
        out.append("</ul>")
    if in_table:
        out.append("</table>")

    return Markup("\n".join(out))


def _md_inline(text: str) -> str:
    """Apply inline markdown formatting (bold, code).

    SECURITY: _md_inline() MUST only be called AFTER escape() — it injects raw HTML
    tags (<code>, <strong>) and returns unescaped strings that are wrapped in Markup().
    Moving this before escape() would allow XSS via user-controlled note content.
    """
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


_jinja_env.filters["md"] = _markdown_to_html

# Cookie name for dashboard auth
_COOKIE_NAME = "arkana_dash"
# Cookie max age: 30 days
_COOKIE_MAX_AGE = 30 * 24 * 3600

# SSE connection limit
_MAX_SSE_CONNECTIONS = 10
_sse_connection_count = 0
# H13: threading.Lock is acceptable here — held for nanoseconds (counter
# increment only), so event loop blocking is negligible.
_sse_lock = threading.Lock()

# --- CSRF: per-session token derived via HMAC (bound to auth cookie) ---
_csrf_secret: bytes = b""  # Random key, generated once per app instance
_csrf_dashboard_token: str = ""  # Cached dashboard token for CSRF derivation


def _compute_csrf_token(cookie_value: str) -> str:
    """Derive a CSRF token from the auth cookie value using HMAC.

    Binds the token to both the per-instance secret and the session credential
    so that (a) tokens rotate on restart and (b) each auth credential yields
    a different CSRF token.
    """
    if not _csrf_secret or not cookie_value:
        return ""
    return hmac.new(_csrf_secret, cookie_value.encode(), "sha256").hexdigest()[:32]

# --- Login rate limiting ---
_login_attempts: dict[str, list[float]] = {}
_login_lock = asyncio.Lock()
_MAX_LOGIN_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 60
_MAX_LOGIN_IPS = 1000  # Hard cap to prevent unbounded memory growth

# M7: Concurrency limiters for expensive endpoints
_diff_semaphore = asyncio.Semaphore(2)
_decompile_semaphore = asyncio.Semaphore(2)
_report_semaphore = asyncio.Semaphore(2)
_bsim_semaphore = asyncio.Semaphore(1)  # BSim index/triage are heavy

# --- Content-Security-Policy value (single source of truth) ---
_CSP_VALUE = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self';"


def _api_error_response(endpoint: str, exc: Exception, status_code: int = 500) -> JSONResponse:
    """Return a sanitized JSON error response — logs full details, returns generic message.

    Promotes ``DashboardShutdownError`` to a 503 with a brief message
    instead of logging the full traceback every poll. The dashboard hits
    this state when the parent MCP process is in the middle of exiting.
    """
    if isinstance(exc, DashboardShutdownError):
        logger.debug("%s: dashboard shutting down", endpoint)
        return JSONResponse(
            {"error": "Dashboard is shutting down"},
            status_code=503,
        )
    logger.error("%s error: %s", endpoint, exc, exc_info=True)
    return JSONResponse({"error": f"Internal server error in {endpoint}"}, status_code=status_code)


# ---------------------------------------------------------------------------
#  Security headers middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware:
    """ASGI middleware that injects security HTTP headers on every response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check if this is a static file request
        path = scope.get("path", "")
        is_static = path.startswith("/dashboard/static/") or path.startswith("/static/")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                security_headers = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
                    (b"content-security-policy", _CSP_VALUE.encode()),
                ]
                if is_static:
                    security_headers.append(
                        (b"cache-control", b"public, max-age=3600")
                    )
                else:
                    security_headers.append(
                        (b"cache-control", b"no-store")
                    )
                headers.extend(security_headers)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---------------------------------------------------------------------------
#  Token management
# ---------------------------------------------------------------------------

def _ensure_token() -> str:
    """Load or generate the dashboard token. Persisted to ~/.arkana/dashboard_token."""
    _TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)  # M1-v10
    if _TOKEN_FILE.exists():
        token = _TOKEN_FILE.read_text().strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    # M2-v10: Atomic secure file creation — never world-readable
    fd = os.open(str(_TOKEN_FILE), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode())
    finally:
        os.close(fd)
    return token


def _get_valid_tokens(dashboard_token: str) -> list:
    """Return list of tokens that should be accepted (dashboard + optional API key)."""
    from arkana.state import _default_state
    tokens = [dashboard_token]
    api_key = getattr(_default_state, "api_key", None)
    if api_key:
        tokens.append(api_key)
    return tokens


def _check_token(provided: str, dashboard_token: str) -> bool:
    """Check if provided token matches any valid token.

    Accumulates results to avoid early-return timing leak that could
    reveal how many valid tokens exist.
    """
    result = False
    for valid in _get_valid_tokens(dashboard_token):
        result = result | hmac.compare_digest(provided, valid)
    return result


# ---------------------------------------------------------------------------
#  Auth helpers
# ---------------------------------------------------------------------------

def _is_authenticated(request: Request, dashboard_token: str) -> bool:
    """Check if request is authenticated via cookie, query param, or Bearer header."""
    # Cookie
    cookie = request.cookies.get(_COOKIE_NAME)
    if cookie and _check_token(cookie, dashboard_token):
        return True
    # Query param
    token_param = request.query_params.get("token")
    if token_param and _check_token(token_param, dashboard_token):
        return True
    # Bearer header (for API endpoints)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        bearer = auth_header[7:]
        if _check_token(bearer, dashboard_token):
            return True
    return False


def _make_auth_response(request: Request, dashboard_token: str, response: Response) -> Response:
    """If authenticated via query param, set cookie and redirect to strip token from URL.

    Always stores the canonical dashboard_token in the cookie, not the
    user-supplied value, so the cookie is consistent.
    """
    token_param = request.query_params.get("token")
    if token_param and _check_token(token_param, dashboard_token):
        # Build clean URL without the token parameter
        other_params = {k: v for k, v in request.query_params.items() if k != "token"}
        clean_url = request.url.path
        if other_params:
            clean_url += "?" + urlencode(other_params)
        redirect = RedirectResponse(clean_url, status_code=302)
        redirect.set_cookie(
            _COOKIE_NAME, dashboard_token,
            max_age=_COOKIE_MAX_AGE,
            httponly=True,
            samesite="strict",
            secure=_is_https(request),
            path="/dashboard",
        )
        return redirect
    return response


# ---------------------------------------------------------------------------
#  CSRF validation
# ---------------------------------------------------------------------------

def _validate_csrf(request: Request, form_token: str = "") -> bool:
    """Check CSRF token from X-CSRF-Token header or form field.

    Recomputes the expected HMAC-based token from the request's auth cookie
    (or the dashboard token itself as fallback) so that CSRF tokens are
    cryptographically bound to the session credential.
    """
    if not _csrf_secret:
        logger.warning("CSRF validation called before secret initialised — denying")
        return False  # Fail-closed: deny until CSRF is ready

    # Determine the auth credential to derive the expected CSRF token.
    # Prefer the cookie value; fall back to the cached dashboard token.
    cookie = request.cookies.get(_COOKIE_NAME, "")
    expected = _compute_csrf_token(cookie) if cookie else _compute_csrf_token(_csrf_dashboard_token)
    if not expected:
        logger.warning("CSRF expected token could not be computed — denying")
        return False  # Fail-closed: deny if token computation fails

    # Check header first (JSON API calls)
    header_token = request.headers.get("x-csrf-token", "")
    if header_token and hmac.compare_digest(header_token, expected):
        return True
    # Check form field (login form)
    if form_token and hmac.compare_digest(form_token, expected):
        return True
    return False


def _is_https(request: Request) -> bool:
    """Detect HTTPS from scheme or X-Forwarded-Proto header.

    Note: trusts X-Forwarded-Proto unconditionally.  This is acceptable
    because the dashboard is a local-only tool (127.0.0.1:8082) and the
    header only affects whether the auth cookie gets the ``Secure`` flag.
    """
    if request.url.scheme == "https":
        return True
    return request.headers.get("x-forwarded-proto", "") == "https"


_VALID_NOTE_CATEGORIES = {"general", "function", "tool_result", "ioc", "hypothesis", "conclusion", "manual"}

_HEX_ADDR_RE = re.compile(r'0x[0-9a-fA-F]+$')


def _validate_address(address: str):
    """Return an error JSONResponse if address is invalid, else None."""
    if not address:
        return JSONResponse({"error": "missing address"}, status_code=400)
    if len(address) > 40:
        return JSONResponse({"error": "address too long"}, status_code=400)
    if not _HEX_ADDR_RE.match(address):
        return JSONResponse({"error": "invalid address (expected 0x hex)"}, status_code=400)
    return None


# ---------------------------------------------------------------------------
#  Route handlers
# ---------------------------------------------------------------------------

def _create_routes(dashboard_token: str) -> list:
    """Build the list of Starlette routes."""

    def _render(template_name: str, context: dict = None) -> str:
        ctx = context or {}
        ctx.setdefault("nav_active", "")
        # Inject dashboard theme into every template for base.html
        if "dashboard_theme" not in ctx:
            from arkana.user_config import get_dashboard_theme
            ctx["dashboard_theme"] = get_dashboard_theme()
        return _jinja_env.get_template(template_name).render(**ctx)

    # --- Login ---
    async def login_page(request: Request) -> Response:
        if _is_authenticated(request, dashboard_token):
            return RedirectResponse("/dashboard/", status_code=302)
        _KNOWN_ERRORS = {"invalid": "Invalid token.", "rate_limited": "Too many attempts. Try again later."}
        error_key = request.query_params.get("error", "")
        error = _KNOWN_ERRORS.get(error_key, "")
        html = _render("login.html", {"error": error})
        return HTMLResponse(html)

    async def login_post(request: Request) -> Response:
        # Reject oversized bodies before reading (login form should be tiny)
        content_length = request.headers.get("content-length")
        try:
            cl_int = int(content_length) if content_length else 0
        except (ValueError, TypeError):
            cl_int = 0
        if cl_int > 65536:
            return HTMLResponse("Request too large", status_code=413)
        form = await request.form()
        # CSRF check
        csrf_field = form.get("csrf_token", "")
        if not _validate_csrf(request, form_token=csrf_field):
            return HTMLResponse("CSRF validation failed", status_code=403)
        # Rate limiting (async-safe with bounded memory)
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        async with _login_lock:
            # Hard cap: evict oldest IPs when dict exceeds limit
            if len(_login_attempts) > _MAX_LOGIN_IPS:
                stale_ips = [ip for ip, ts in _login_attempts.items()
                             if not ts or now - ts[-1] > _LOGIN_WINDOW_SECONDS]
                for ip in stale_ips:
                    del _login_attempts[ip]
                # If still over limit, evict oldest entries
                if len(_login_attempts) > _MAX_LOGIN_IPS:
                    sorted_ips = sorted(_login_attempts.items(),
                                        key=lambda x: x[1][-1] if x[1] else 0)
                    for ip, _ in sorted_ips[:len(_login_attempts) - _MAX_LOGIN_IPS]:
                        del _login_attempts[ip]
            attempts = _login_attempts.get(client_ip, [])
            # Prune stale entries for this IP
            attempts = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
            _login_attempts[client_ip] = attempts
            if len(attempts) >= _MAX_LOGIN_ATTEMPTS:
                return HTMLResponse("Too many login attempts. Try again later.", status_code=429)
            # Validate token inside the lock to prevent TOCTOU race
            token = form.get("token", "").strip()
            if _check_token(token, dashboard_token):
                _login_attempts.pop(client_ip, None)
                resp = RedirectResponse("/dashboard/", status_code=302)
                resp.set_cookie(
                    _COOKIE_NAME, dashboard_token,
                    max_age=_COOKIE_MAX_AGE,
                    httponly=True,
                    samesite="strict",
                    secure=_is_https(request),
                    path="/dashboard",
                )
                return resp
            # Record failed attempt while still holding the lock
            attempts.append(now)
            _login_attempts[client_ip] = attempts
        return RedirectResponse("/dashboard/login?error=invalid", status_code=302)

    # --- JSON POST body helper ---
    async def _parse_json_body(request: Request) -> tuple:
        """Parse and validate a JSON POST body.

        Returns (body_dict, None) on success, or (None, error_response) on failure.
        """
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return None, JSONResponse({"error": "Content-Type must be application/json"}, status_code=415)
        content_length = request.headers.get("content-length")
        try:
            cl_int = int(content_length) if content_length else 0
        except (ValueError, TypeError):
            cl_int = 0
        if cl_int > _MAX_POST_BODY_SIZE:
            return None, JSONResponse({"error": "Request body too large"}, status_code=413)
        try:
            raw_body = await request.body()
        except Exception:
            return None, JSONResponse({"error": "Failed to read request body"}, status_code=400)
        if len(raw_body) > _MAX_POST_BODY_SIZE:
            return None, JSONResponse({"error": "Request body too large"}, status_code=413)
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return None, JSONResponse({"error": "invalid JSON"}, status_code=400)
        return body, None

    # --- Auth-required page wrapper ---
    def _auth_page(template: str, nav: str, data_fn=None):
        async def handler(request: Request) -> Response:
            if not _is_authenticated(request, dashboard_token):
                return RedirectResponse("/dashboard/login", status_code=302)
            ctx = {"nav_active": nav}
            if data_fn:
                try:
                    ctx["data"] = await _dash_to_thread(data_fn)
                except Exception:
                    logger.debug("Page data function failed for %s", template, exc_info=True)
                    ctx["data"] = {} if template != "functions.html" else []
            resp = HTMLResponse(_render(template, ctx))
            return _make_auth_response(request, dashboard_token, resp)
        return handler

    # --- Helpers ---
    def _get_active_state():
        """Return the active AnalyzerState (session or default)."""
        from arkana.dashboard.state_api import _get_state
        return _get_state()

    # --- API endpoints ---
    async def api_state(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_overview_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_state", exc)

    async def api_debug(request: Request) -> Response:
        """Diagnostic endpoint — shows minimal state isolation info."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        from arkana.state import _default_state as ds, _session_registry, _registry_lock
        from arkana.dashboard.state_api import _get_state
        resolved = _get_state()
        with _registry_lock:
            session_count = len(_session_registry)
        return JSONResponse({
            "default_has_file": ds.filepath is not None,
            "resolved_has_file": resolved.filepath is not None,
            "resolved_is_default": resolved is ds,
            "session_count": session_count,
        })

    async def api_functions(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        sort_by = request.query_params.get("sort", "address")
        if sort_by not in ("address", "name", "size", "complexity", "score", "triage"):
            sort_by = "address"
        filter_triage = request.query_params.get("triage", "all")
        if filter_triage not in ("all", "unreviewed", "suspicious", "clean", "flagged"):
            filter_triage = "all"
        search = request.query_params.get("search", "")[:500]
        sort_asc = request.query_params.get("asc", "1") == "1"
        try:
            data = await _dash_to_thread(
                get_functions_data, sort_by=sort_by, filter_triage=filter_triage,
                search=search, sort_asc=sort_asc,
            )
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_functions", exc)

    async def api_callgraph(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_callgraph_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_callgraph", exc)

    _MAX_POST_BODY_SIZE = 1024 * 1024  # 1 MB

    async def api_triage(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        address = body.get("address", "").strip().lower()
        status = body.get("status", "").strip()
        if len(address) > 40:
            return JSONResponse({"error": "address too long"}, status_code=400)
        if not address or not re.fullmatch(r'0x[0-9a-f]+', address):
            return JSONResponse({"error": "invalid address (expected 0x hex)"}, status_code=400)
        if status not in ("unreviewed", "suspicious", "clean", "flagged"):
            return JSONResponse({"error": "invalid status"}, status_code=400)
        st = _get_active_state()
        st.set_triage_status(address, status)
        # User state lives in the project overlay (flushed by close_file /
        # the background flush thread); no cache wrapper write needed.
        return JSONResponse({"ok": True, "address": address, "status": status})

    async def api_decompile_get(request: Request) -> Response:
        """Return cached decompilation for an address."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            result = await _dash_to_thread(get_decompiled_code, address)
            return JSONResponse(result)
        except Exception as exc:
            return _api_error_response("api_decompile_get", exc)

    async def api_decompile_post(request: Request) -> Response:
        """Trigger a new decompilation for an address."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        address = body.get("address", "").strip().lower()
        if len(address) > 40:
            return JSONResponse({"error": "address too long"}, status_code=400)
        if not address or not re.fullmatch(r'0x[0-9a-f]+', address):
            return JSONResponse({"error": "invalid address (expected 0x hex)"}, status_code=400)
        async with _decompile_semaphore:
            try:
                result = await asyncio.wait_for(
                    _dash_to_thread(trigger_decompile, address),
                    timeout=300,
                )
            except asyncio.TimeoutError:
                return JSONResponse(
                    {"cached": False, "error": "Decompilation timed out (300s)"},
                    status_code=504,
                )
            except Exception as e:
                logger.debug("Decompile endpoint error: %s", e, exc_info=True)
                return JSONResponse(
                    {"cached": False, "error": "Decompilation failed"},
                    status_code=500,
                )
        return JSONResponse(result)

    async def api_strings(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        search = request.query_params.get("search", "")[:500]
        string_type = request.query_params.get("type", "all")
        if string_type not in ("all", "ascii", "static", "stack", "decoded", "tight"):
            string_type = "all"
        cat = request.query_params.get("category", "")[:100]
        try:
            min_score = float(request.query_params.get("min_score", "0"))
            min_score = max(0.0, min(min_score, 1000.0))
        except (ValueError, TypeError):
            min_score = 0.0
        sort = request.query_params.get("sort", "score")
        if sort not in ("score", "length", "type", "address"):
            sort = "score"
        asc = request.query_params.get("asc", "0") == "1"
        try:
            off = int(request.query_params.get("offset", "0"))
            off = max(0, min(off, 100000))
        except (ValueError, TypeError):
            off = 0
        try:
            lim = int(request.query_params.get("limit", "100"))
            lim = max(1, min(lim, 500))
        except (ValueError, TypeError):
            lim = 100
        try:
            data = await _dash_to_thread(
                get_strings_data, search=search, string_type=string_type,
                category=cat, min_score=min_score, sort_by=sort,
                sort_asc=asc, offset=off, limit=lim,
            )
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_strings", exc)

    async def api_search(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        q = request.query_params.get("q", "").strip()
        if len(q) < 2:
            return JSONResponse({"error": "query too short (min 2 chars)"}, status_code=400)
        q = q[:500]
        try:
            data = await _dash_to_thread(global_search, q)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_search", exc)

    async def api_function_xrefs(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            data = await _dash_to_thread(get_function_xrefs_data, address)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_function_xrefs error for %s", address, exc_info=True)
            return JSONResponse({"callers": [], "callees": [], "_error": True})

    async def api_function_analysis(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            data = await _dash_to_thread(get_function_analysis_data, address)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_function_analysis error for %s", address, exc_info=True)
            return JSONResponse({"address": address, "callers": [], "callees": [], "suspicious_apis": [], "strings": [], "_error": True})

    async def api_function_strings(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            data = await _dash_to_thread(get_function_strings_data, address)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_function_strings error for %s", address, exc_info=True)
            return JSONResponse({"strings": [], "_error": True})

    async def api_timeline(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            limit = int(request.query_params.get("limit", "100"))
            limit = max(1, min(limit, 5000))
        except (ValueError, TypeError):
            limit = 100
        try:
            data = await _dash_to_thread(get_timeline_data, limit=limit)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_timeline", exc)

    async def api_events(request: Request) -> Response:
        """SSE endpoint — streams state changes every 2 seconds."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        global _sse_connection_count
        with _sse_lock:
            if _sse_connection_count >= _MAX_SSE_CONNECTIONS:
                return JSONResponse(
                    {"error": "too many SSE connections"},
                    status_code=429,
                )

        # C3: Capture auth token at connection time for re-validation
        # Check cookie, then Bearer header, then query param as fallback sources
        connection_token = request.cookies.get(_COOKIE_NAME, "")
        if not connection_token:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                connection_token = auth_header[7:]
        if not connection_token:
            connection_token = request.query_params.get("token", "")

        async def event_generator():
            global _sse_connection_count
            # Reserve SSE slot inside the generator to prevent leaks if the
            # generator never starts (e.g. framework error between reservation
            # and first iteration).
            with _sse_lock:
                if _sse_connection_count >= _MAX_SSE_CONNECTIONS:
                    return
                _sse_connection_count += 1
            try:
                # Seed with current state so the first tick isn't a false "file-changed"
                try:
                    # M-E4: Use to_thread to avoid blocking the event loop
                    seed = await _dash_to_thread(get_overview_data)
                except Exception:
                    seed = {}
                last_tool_count = seed.get("tool_calls", 0)
                last_notes_count = seed.get("notes_count", 0)
                last_active_tool = seed.get("active_tool")
                last_progress = seed.get("active_tool_progress", 0)
                seed_tasks = seed.get("background_tasks", [])
                last_task_count = len(seed_tasks)
                last_task_running = sum(
                    1 for t in seed_tasks if t.get("status") == "running"
                )
                last_file_sha256 = seed.get("sha256")
                last_triage_counts = seed.get("triage_counts", {})
                last_artifacts_count = seed.get("artifacts_count", 0)
                last_explored_funcs = seed.get("explored_functions", 0)
                last_decompiled_addrs: set = set()
                # Send initial state so browsers confirm the connection immediately
                try:
                    init_data = json.dumps(seed)
                except Exception:
                    init_data = "{}"
                yield f"retry: 5000\nevent: state-update\ndata: {init_data}\n\n"
                while True:
                    await asyncio.sleep(2)
                    # C3: Re-validate auth each iteration; break if token revoked
                    if not connection_token or not _check_token(connection_token, dashboard_token):
                        logger.debug("SSE: connection token invalidated, closing")
                        return
                    try:
                        overview = await _dash_to_thread(get_overview_data)
                        current_tools = overview["tool_calls"]
                        current_notes = overview["notes_count"]
                        current_active = overview.get("active_tool")
                        current_progress = overview.get("active_tool_progress", 0)
                        current_tasks = overview.get("background_tasks", [])
                        current_task_count = len(current_tasks)
                        current_task_running = sum(
                            1 for t in current_tasks if t.get("status") == "running"
                        )
                        current_sha256 = overview.get("sha256")
                        current_triage = overview.get("triage_counts", {})
                        current_artifacts = overview.get("artifacts_count", 0)
                        current_explored = overview.get("explored_functions", 0)
                        changed = (
                            current_tools != last_tool_count
                            or current_notes != last_notes_count
                            or current_active != last_active_tool
                            or current_progress != last_progress
                            or current_task_count != last_task_count
                            or current_task_running != last_task_running
                            or current_triage != last_triage_counts
                            or current_artifacts != last_artifacts_count
                            or current_sha256 != last_file_sha256
                            or current_explored != last_explored_funcs
                        )
                        if changed:
                            file_changed = (
                                current_sha256 != last_file_sha256
                                and current_sha256 is not None
                            )
                            last_tool_count = current_tools
                            last_notes_count = current_notes
                            last_active_tool = current_active
                            last_progress = current_progress
                            last_task_count = current_task_count
                            last_task_running = current_task_running
                            last_file_sha256 = current_sha256
                            last_triage_counts = current_triage
                            last_artifacts_count = current_artifacts
                            last_explored_funcs = current_explored
                            data = json.dumps(overview)
                            if file_changed:
                                yield f"event: file-changed\ndata: {data}\n\n"
                            else:
                                yield f"event: state-update\ndata: {data}\n\n"

                        # Check for newly-decompiled functions (per-connection tracking)
                        try:
                            from arkana.dashboard.state_api import _get_decompiled_addresses
                            current_decompiled = _get_decompiled_addresses()
                            new_addrs = current_decompiled - last_decompiled_addrs
                            if new_addrs:
                                last_decompiled_addrs = current_decompiled
                                logger.debug("SSE: emitting decompile-update for %d addrs", len(new_addrs))
                                yield f"event: decompile-update\ndata: {json.dumps({'addresses': sorted(new_addrs)})}\n\n"
                        except Exception:
                            logger.debug("SSE: decompile check error", exc_info=True)
                    except asyncio.CancelledError:
                        return
                    except Exception:
                        logger.debug("SSE event generation error", exc_info=True)
            finally:
                with _sse_lock:
                    _sse_connection_count = max(0, _sse_connection_count - 1)

        from starlette.responses import StreamingResponse
        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # --- Partial templates for htmx ---
    async def page_notes(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return RedirectResponse("/dashboard/login", status_code=302)
        category = request.query_params.get("category", "").strip() or None
        if category and category not in _VALID_NOTE_CATEGORIES:
            category = None
        data = await _dash_to_thread(get_notes_data, category=category)
        ctx = {"nav_active": "notes", "data": data, "active_category": category or "all"}
        resp = HTMLResponse(_render("notes.html", ctx))
        return _make_auth_response(request, dashboard_token, resp)

    async def partial_overview_stats(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return HTMLResponse("", status_code=401)
        try:
            data = await _dash_to_thread(get_overview_data)
            html = _render("partials/_overview_stats.html", {"data": data})
            return HTMLResponse(html)
        except Exception:
            logger.debug("partial_overview_stats error", exc_info=True)
            return HTMLResponse("")

    async def partial_task_list(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return HTMLResponse("", status_code=401)
        try:
            data = await _dash_to_thread(get_overview_data)
            html = _render("partials/_task_list.html", {"data": data})
            return HTMLResponse(html)
        except Exception:
            logger.debug("partial_task_list error", exc_info=True)
            return HTMLResponse("")

    async def partial_timeline_entry(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return HTMLResponse("", status_code=401)
        try:
            entries = await _dash_to_thread(get_timeline_data, limit=20)
            html = _render("partials/_timeline_entry.html", {"entries": entries})
            return HTMLResponse(html)
        except Exception:
            logger.debug("partial_timeline_entry error", exc_info=True)
            return HTMLResponse("")

    async def partial_global_status(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return HTMLResponse("", status_code=401)
        try:
            data = await _dash_to_thread(get_overview_data)
            html = _render("partials/_global_status.html", {"data": data})
            return HTMLResponse(html)
        except Exception:
            logger.debug("partial_global_status error", exc_info=True)
            return HTMLResponse("")

    async def api_floss_summary(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_floss_summary)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_floss_summary", exc)

    # --- New API endpoints (Batch 1-3) ---

    async def api_hex(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            offset = int(request.query_params.get("offset", "0"))
            offset = max(0, min(offset, 0x7FFFFFFF))
        except (ValueError, TypeError):
            offset = 0
        try:
            length = int(request.query_params.get("length", "256"))
            length = max(1, min(length, 4096))
        except (ValueError, TypeError):
            length = 256
        try:
            data = await _dash_to_thread(get_hex_dump_data, offset, length)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_hex", exc)

    async def api_mitre(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_mitre_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_mitre", exc)

    async def api_capabilities(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_capa_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_capabilities", exc)

    async def api_function_cfg(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            data = await _dash_to_thread(get_function_cfg_data, address)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_function_cfg error for %s", address, exc_info=True)
            return JSONResponse({"nodes": [], "edges": [], "error": "analysis error"})

    async def api_disassembly(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            count = int(request.query_params.get("count", "200"))
            count = max(1, min(count, 2000))
        except (ValueError, TypeError):
            count = 200
        try:
            data = await _dash_to_thread(get_disassembly_data, address, count)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_disassembly error for %s", address, exc_info=True)
            return JSONResponse({"instructions": [], "error": "disassembly error"})

    async def api_function_variables(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            data = await _dash_to_thread(get_function_variables_data, address)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_function_variables error for %s", address, exc_info=True)
            return JSONResponse({"parameters": [], "locals": [], "error": "analysis error"})

    async def api_entropy(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_entropy_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_entropy", exc)

    async def api_resources(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_resources_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_resources", exc)

    async def api_triage_report(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_triage_report_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_triage_report", exc)

    async def api_packing(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_packing_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_packing", exc)

    async def api_similarity(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_similarity_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_similarity", exc)

    async def api_types(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_custom_types_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_types", exc)

    async def api_types_struct_post(request: Request) -> Response:
        """Create or update a struct type."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        name = body.get("name", "").strip()
        if not name or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', name):
            return JSONResponse({"error": "invalid name"}, status_code=400)
        if len(name) > 128:
            return JSONResponse({"error": "name too long"}, status_code=400)
        fields = body.get("fields", [])
        if not isinstance(fields, list):
            return JSONResponse({"error": "fields must be a list"}, status_code=400)
        st = _get_active_state()
        try:
            st.create_struct(name, fields, body.get("size", 0))
        except (ValueError, TypeError) as e:
            return JSONResponse({"error": str(e)[:200]}, status_code=400)
        except Exception:
            logger.debug("Struct creation error", exc_info=True)
            return JSONResponse({"error": "struct creation failed"}, status_code=400)
        return JSONResponse({"ok": True, "name": name})

    async def api_types_enum_post(request: Request) -> Response:
        """Create or update an enum type."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        name = body.get("name", "").strip()
        if not name or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', name):
            return JSONResponse({"error": "invalid name"}, status_code=400)
        if len(name) > 128:
            return JSONResponse({"error": "name too long"}, status_code=400)
        values = body.get("values", {})
        if not isinstance(values, dict):
            return JSONResponse({"error": "values must be a dict"}, status_code=400)
        st = _get_active_state()
        try:
            st.create_enum(name, values, body.get("size", 4))
        except (ValueError, TypeError) as e:
            return JSONResponse({"error": str(e)[:200]}, status_code=400)
        except Exception:
            logger.debug("Enum creation error", exc_info=True)
            return JSONResponse({"error": "enum creation failed"}, status_code=400)
        return JSONResponse({"ok": True, "name": name})

    async def api_types_delete(request: Request) -> Response:
        """Delete a custom type."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        name = request.query_params.get("name", "").strip()
        if not name or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', name) or len(name) > 128:
            return JSONResponse({"error": "invalid name"}, status_code=400)
        st = _get_active_state()
        if st.delete_custom_type(name):
            return JSONResponse({"ok": True})
        return JSONResponse({"error": "type not found"}, status_code=404)

    async def api_function_similarity(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        address = request.query_params.get("address", "").strip()
        err = _validate_address(address)
        if err:
            return err
        try:
            data = await _dash_to_thread(get_function_similarity_data, address)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_function_similarity error for %s", address, exc_info=True)
            return JSONResponse({"matches": [], "available": False})

    async def api_export_report(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        try:
            report = await _dash_to_thread(get_export_report_data)
            report_json = json.dumps(report, indent=2, default=str)
            filename = "arkana_report.json"
            file_info = report.get("file_info", {})
            if file_info.get("filename"):
                base = os.path.splitext(file_info["filename"])[0]
                safe_base = re.sub(r'[^a-zA-Z0-9_\-.]', '_', base)[:100]
                filename = f"arkana_report_{safe_base}.json"
            return Response(
                content=report_json,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=\"{filename}\""},
            )
        except Exception:
            logger.debug("api_export_report error", exc_info=True)
            return JSONResponse({"error": "report generation failed"}, status_code=500)

    # --- IOC Summary ---
    async def api_ioc_summary(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_ioc_summary_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_ioc_summary", exc)

    # --- Capabilities Summary ---
    async def api_capabilities_summary(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_capabilities_summary_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_capabilities_summary", exc)

    # --- Analysis Digest ---
    async def api_digest(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_digest_data)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_digest error", exc_info=True)
            return JSONResponse({"available": False}, status_code=500)

    # --- Generate Markdown Report ---
    async def api_generate_report(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        async with _report_semaphore:
            try:
                data = await asyncio.wait_for(
                    _dash_to_thread(generate_report_text), timeout=60
                )
                return JSONResponse(data)
            except asyncio.TimeoutError:
                return JSONResponse({"error": "report generation timed out"}, status_code=504)
            except Exception:
                logger.debug("api_generate_report error", exc_info=True)
                return JSONResponse({"error": "report generation failed"}, status_code=500)

    # --- Batch 4: Full-text decompiled search ---
    async def api_search_code(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        q = request.query_params.get("q", "").strip()
        if not q:
            return JSONResponse({"error": "query is required"}, status_code=400)
        if len(q) > 200:
            return JSONResponse({"error": "query too long (max 200)"}, status_code=400)
        limit_str = request.query_params.get("limit", "100")
        try:
            limit = max(1, min(int(limit_str), 200))
        except (ValueError, TypeError):
            limit = 100
        try:
            data = await _dash_to_thread(search_decompiled_code, q, max_results=limit)
            return JSONResponse(data)
        except Exception:
            logger.debug("api_search_code error", exc_info=True)
            return JSONResponse({"error": "search failed"}, status_code=500)

    # --- Batch 4: Binary diff ---
    async def api_diff(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        file_path_b = body.get("file_path_b", "")
        if not isinstance(file_path_b, str) or not file_path_b.strip():
            return JSONResponse({"error": "file_path_b is required"}, status_code=400)
        file_path_b = file_path_b.strip()
        if len(file_path_b) > 512:
            return JSONResponse({"error": "file_path_b too long"}, status_code=400)
        if "\x00" in file_path_b:
            return JSONResponse({"error": "invalid path"}, status_code=400)
        # If it's a relative path (from file browser), reconstruct full path
        st = _get_active_state()
        if not os.path.isabs(file_path_b):
            samples_path = getattr(st, "samples_path", None) or getattr(
                __import__('arkana.state', fromlist=['_default_state'])._default_state,
                "samples_path", None)
            if not samples_path:
                return JSONResponse({"error": "no samples directory configured"}, status_code=400)
            file_path_b = os.path.join(samples_path, file_path_b)
            # Ensure relative paths stay within the samples directory
            resolved = os.path.realpath(file_path_b)
            resolved_samples = os.path.realpath(samples_path)
            if not resolved.startswith(resolved_samples + os.sep) and resolved != resolved_samples:
                return JSONResponse({"error": "path is outside samples directory"}, status_code=403)
        # Resolve symlinks and validate path is within allowed directories
        try:
            resolved = os.path.realpath(file_path_b)
            # When no allowed_paths configured, restrict absolute paths to samples directory
            if st.allowed_paths is None:
                samples_path_abs = getattr(st, "samples_path", None) or getattr(
                    __import__('arkana.state', fromlist=['_default_state'])._default_state,
                    "samples_path", None)
                if samples_path_abs:
                    if not resolved.startswith(os.path.realpath(str(samples_path_abs)) + os.sep):
                        return JSONResponse({"error": "Absolute paths must be within the samples directory"}, status_code=403)
                else:
                    return JSONResponse({"error": "Absolute paths not allowed without --allowed-paths"}, status_code=403)
            st.check_path_allowed(resolved)
        except RuntimeError:
            return JSONResponse({"error": "path is outside allowed directories"}, status_code=403)

        def _run_diff():
            if not os.path.isfile(resolved):
                return {"error": "file not found or not accessible"}
            return get_diff_data(resolved)

        async with _diff_semaphore:
            try:
                data = await _dash_to_thread(_run_diff)
                if data.get("error") == "file not found or not accessible":
                    return JSONResponse(data, status_code=400)
                return JSONResponse(data)
            except Exception:
                logger.debug("api_diff error", exc_info=True)
                return JSONResponse({"error": "diff failed"}, status_code=500)

    # --- File listing for diff browser ---
    async def api_list_files(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        search = request.query_params.get("search", "").strip()
        if len(search) > 200:
            search = search[:200]
        sort_by = request.query_params.get("sort", "name")
        if sort_by not in ("name", "size", "format"):
            sort_by = "name"
        try:
            data = await _dash_to_thread(get_list_files_data, search, sort_by)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_list_files", exc)

    # --- BSim signature database endpoints ---

    async def api_bsim_stats(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_bsim_db_stats)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_bsim_stats", exc)

    async def api_bsim_binaries(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_bsim_indexed_binaries)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_bsim_binaries", exc)

    async def api_bsim_triage(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        cache_only = bool(body.get("cache_only", False))
        async with _bsim_semaphore:
            try:
                data = await _dash_to_thread(get_bsim_triage_data, cache_only)
                return JSONResponse(data)
            except Exception as exc:
                return _api_error_response("api_bsim_triage", exc)

    async def api_bsim_matches(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        sha256 = body.get("binary_sha256", "")
        if not isinstance(sha256, str) or not _BSIM_HEX64_RE.match(sha256):
            return JSONResponse({"error": "Invalid SHA256"}, status_code=400)
        try:
            data = await _dash_to_thread(get_bsim_triage_function_matches, sha256)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_bsim_matches", exc)

    async def api_bsim_index(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        async with _bsim_semaphore:
            try:
                data = await _dash_to_thread(index_current_binary)
                return JSONResponse(data)
            except Exception as exc:
                return _api_error_response("api_bsim_index", exc)

    async def api_bsim_validate(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        async with _bsim_semaphore:
            try:
                data = await _dash_to_thread(get_bsim_db_health)
                return JSONResponse(data)
            except Exception as exc:
                return _api_error_response("api_bsim_validate", exc)

    async def api_bsim_delete(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        sha256 = body.get("sha256", "")
        if not isinstance(sha256, str) or not _BSIM_HEX64_RE.match(sha256):
            return JSONResponse({"error": "Invalid SHA256"}, status_code=400)
        if not body.get("confirm"):
            return JSONResponse({"error": "Confirmation required"}, status_code=400)
        try:
            data = await _dash_to_thread(delete_bsim_binary, sha256)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_bsim_delete", exc)

    async def api_bsim_clear(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        if not body.get("confirm"):
            return JSONResponse({"error": "Confirmation required"}, status_code=400)
        try:
            data = await _dash_to_thread(clear_bsim_db)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_bsim_clear", exc)

    async def api_bsim_compare_projects(request: Request) -> Response:
        """Compare every member of project_a against every member of project_b
        function-by-function via the BSim DB. Used by the new PROJECTS sub-tab
        on the Similarity page."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        pa = (request.query_params.get("project_a") or "").strip()[:64]
        pb = (request.query_params.get("project_b") or "").strip()[:64]
        if not pa or not pb:
            return JSONResponse(
                {"error": "project_a and project_b are required"},
                status_code=400,
            )
        # Pass the raw threshold string through — ``get_project_comparison_data``
        # does the float coercion + NaN/inf guard + [0,1] clamp itself, so we
        # don't need a duplicate parser here that would silently turn ``nan``
        # into 0.0 via ``max(0.0, min(nan, 1.0))``.
        threshold = request.query_params.get("threshold", "0.7")
        try:
            data = await _dash_to_thread(
                get_project_comparison_data, pa, pb, threshold,
            )
            if not data.get("available") and data.get("error"):
                return JSONResponse(data, status_code=400)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_bsim_compare_projects", exc)

    # --- Settings page ---
    async def page_settings(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return RedirectResponse("/dashboard/login", status_code=302)
        data = await _dash_to_thread(get_settings_data)
        ctx = {"nav_active": "settings", **data}
        resp = HTMLResponse(_render("settings.html", ctx))
        return _make_auth_response(request, dashboard_token, resp)

    async def api_settings_get(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(get_settings_data)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_settings_get", exc)

    async def api_settings_post(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        from arkana.user_config import save_settings, SETTINGS_REGISTRY
        try:
            errors = await _dash_to_thread(save_settings, body)
            # Check if any saved setting has restart=True
            restart_keys = {s["key"] for s in SETTINGS_REGISTRY if s.get("restart")}
            saved_keys = set(body.keys()) - set(errors.keys())
            restart_required = bool(saved_keys & restart_keys)
            return JSONResponse({
                "status": "ok",
                "saved": len(saved_keys),
                "errors": errors,
                "restart_required": restart_required,
            })
        except Exception as exc:
            return _api_error_response("api_settings_post", exc)

    async def api_settings_reset(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        from arkana.user_config import reset_all_settings
        try:
            count = await _dash_to_thread(reset_all_settings)
            return JSONResponse({"status": "ok", "reset": count})
        except Exception as exc:
            return _api_error_response("api_settings_reset", exc)

    # ----------------------------------------------------------------------
    #  Projects (Phase 2 — PROJECTS tab)
    # ----------------------------------------------------------------------

    async def page_projects(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return RedirectResponse("/dashboard/login", status_code=302)
        try:
            data = await _dash_to_thread(get_projects_list_data)
        except Exception:
            logger.debug("page_projects: data load failed", exc_info=True)
            data = {"projects": [], "total_count": 0, "active_project_id": None}
        ctx = {"nav_active": "projects", "data": data}
        resp = HTMLResponse(_render("projects.html", ctx))
        return _make_auth_response(request, dashboard_token, resp)

    async def api_projects_list(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        filter_q = request.query_params.get("filter", "")[:200]
        tag = request.query_params.get("tag", "")[:80]
        sort_by = request.query_params.get("sort_by", "last_opened")
        if sort_by not in ("last_opened", "name", "created_at"):
            sort_by = "last_opened"
        try:
            data = await _dash_to_thread(
                get_projects_list_data, filter=filter_q, tag=tag, sort_by=sort_by,
            )
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_list", exc)

    async def api_projects_detail(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        pid = request.query_params.get("project_id", "")[:64].strip()
        if not pid:
            return JSONResponse({"error": "project_id is required"}, status_code=400)
        try:
            data = await _dash_to_thread(get_project_detail_data, pid)
            if data is None:
                return JSONResponse({"error": f"Project {pid} not found"}, status_code=404)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_detail", exc)

    async def api_projects_create(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        name = (body.get("name") or "").strip()
        if not name:
            return JSONResponse({"error": "name is required"}, status_code=400)
        tags = body.get("tags") or []
        if not isinstance(tags, list):
            return JSONResponse({"error": "tags must be a list"}, status_code=400)
        try:
            data = await _dash_to_thread(create_project_data, name, tags)
            return JSONResponse(data)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        except Exception as exc:
            return _api_error_response("api_projects_create", exc)

    async def api_projects_rename(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        pid = (body.get("project_id") or "").strip()
        new_name = (body.get("new_name") or "").strip()
        if not pid or not new_name:
            return JSONResponse({"error": "project_id and new_name are required"}, status_code=400)
        try:
            data = await _dash_to_thread(rename_project_data, pid, new_name)
            if "error" in data:
                return JSONResponse(data, status_code=400)
            return JSONResponse(data)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        except Exception as exc:
            return _api_error_response("api_projects_rename", exc)

    async def api_projects_tag(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        pid = (body.get("project_id") or "").strip()
        if not pid:
            return JSONResponse({"error": "project_id is required"}, status_code=400)
        add = body.get("add") or []
        remove = body.get("remove") or []
        replace = bool(body.get("replace", False))
        if not isinstance(add, list) or not isinstance(remove, list):
            return JSONResponse({"error": "add/remove must be lists"}, status_code=400)
        try:
            data = await _dash_to_thread(tag_project_data, pid, add, remove, replace)
            if "error" in data:
                return JSONResponse(data, status_code=400)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_tag", exc)

    async def api_projects_delete(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        pid = (body.get("project_id") or "").strip()
        confirm = bool(body.get("confirm", False))
        if not pid:
            return JSONResponse({"error": "project_id is required"}, status_code=400)
        if not confirm:
            return JSONResponse({"error": "confirm=true required"}, status_code=400)
        try:
            data = await _dash_to_thread(delete_project_data, pid)
            if "error" in data:
                return JSONResponse(data, status_code=404)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_delete", exc)

    async def api_projects_open(request: Request) -> Response:
        """Switch the active project to *project_id* and load *binary_sha256*
        (or last-active / primary)."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        pid = (body.get("project_id") or "").strip()
        binary_sha = (body.get("binary_sha256") or "").strip().lower()
        if not pid:
            return JSONResponse({"error": "project_id is required"}, status_code=400)

        proj = await _dash_to_thread(project_manager.get, pid)
        if proj is None:
            return JSONResponse({"error": f"Project {pid} not found"}, status_code=404)
        chosen = binary_sha or proj.manifest.last_active_sha256 or proj.manifest.primary_sha256
        if not chosen:
            return JSONResponse({"error": "Project has no binaries"}, status_code=400)

        # Member resolution + stat happen in the worker pool to keep the
        # event loop free. Handles ValueError from sha256 validation cleanly.
        resolved = await _dash_to_thread(_resolve_project_member, proj, chosen)
        if resolved.get("error"):
            return JSONResponse({"error": resolved["error"]}, status_code=400)
        member = resolved["member"]
        if member is None:
            return JSONResponse({"error": f"Member {chosen[:12]} not in project"}, status_code=400)
        binary_path = resolved["binary_path"]

        if not resolved["present"]:
            # Stub member (migrated project or deleted copy) — try to locate
            # the original binary in allowed sample directories by sha256 +
            # filename, then adopt it into the stub.
            active_state = _get_active_state()
            located = await _dash_to_thread(
                _locate_binary_for_stub, active_state, chosen, member.original_filename
            )
            if located:
                try:
                    await _dash_to_thread(proj.adopt_binary_into_stub, chosen, located)
                    binary_path = member.copy_path
                except Exception as exc:
                    return JSONResponse(
                        {"error": f"Failed to adopt located binary: {exc}"},
                        status_code=500,
                    )
            if not binary_path or not await _dash_to_thread(os.path.isfile, binary_path):
                return JSONResponse(
                    {
                        "error": (
                            f"Binary '{member.original_filename}' ({chosen[:12]}) "
                            f"is not available on disk. This project was migrated "
                            f"from the old cache or the file was moved. Use the "
                            f"MCP tool add_binary_to_project(project_id, file_path) "
                            f"to point it at the binary, or re-open the original "
                            f"file via open_file() to auto-adopt."
                        ),
                        "sha256": chosen,
                        "original_filename": member.original_filename,
                    },
                    status_code=409,
                )

        # Bind the project on the active state, then call open_file via the
        # MCP tool helper. The module-level _NoopCtx satisfies the tool's
        # ctx.info/warning/error/report_progress interface.
        active_state = _get_active_state()
        active_state.bind_project(proj)

        try:
            result = await _open_file_tool(_NoopCtx(), binary_path, force_switch=True)
            return JSONResponse({"status": "success", "open_result": result})
        except Exception as exc:
            return _api_error_response("api_projects_open", exc)

    async def api_projects_set_primary(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        pid = (body.get("project_id") or "").strip()
        sha = (body.get("sha256") or "").strip().lower()
        if not pid or not sha:
            return JSONResponse({"error": "project_id and sha256 required"}, status_code=400)
        try:
            data = await _dash_to_thread(set_primary_binary_data, pid, sha)
            if "error" in data:
                return JSONResponse(data, status_code=400)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_set_primary", exc)

    async def api_projects_importable_archives(request: Request) -> Response:
        """List .arkana_project.tar.gz files in known output directories."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            data = await _dash_to_thread(list_importable_archives)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_importable_archives", exc)

    async def api_projects_import_archive(request: Request) -> Response:
        """Import a single archive into a new project."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        path = (body.get("path") or "").strip()
        if not path:
            return JSONResponse({"error": "path is required"}, status_code=400)
        try:
            data = await _dash_to_thread(import_archive_data, path)
            if "error" in data:
                return JSONResponse(data, status_code=400)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_import_archive", exc)

    async def api_projects_dashboard_state(request: Request) -> Response:
        """Persist a small piece of dashboard state into the project manifest.

        Per-key type and size validation defends against repeated calls
        growing the manifest unbounded (every value lands in JSON on disk).
        """
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        pid = (body.get("project_id") or "").strip()
        key = (body.get("key") or "").strip()
        value = body.get("value")
        if not pid or not key:
            return JSONResponse({"error": "project_id and key required"}, status_code=400)
        budget = _DASHBOARD_STATE_VALUE_BUDGET.get(key)
        if budget is None:
            return JSONResponse({"error": f"unknown dashboard_state key: {key}"},
                                status_code=400)
        expected_type, max_size = budget
        if not isinstance(value, expected_type):
            return JSONResponse(
                {"error": f"value for '{key}' must be {expected_type.__name__}"},
                status_code=400,
            )
        if expected_type is str and max_size and len(value) > max_size:
            return JSONResponse(
                {"error": f"value for '{key}' exceeds {max_size} chars"},
                status_code=400,
            )
        if expected_type is dict and max_size:
            try:
                serialised = json.dumps(value)
            except (TypeError, ValueError):
                return JSONResponse(
                    {"error": f"value for '{key}' is not JSON-serialisable"},
                    status_code=400,
                )
            if len(serialised) > max_size:
                return JSONResponse(
                    {"error": f"value for '{key}' exceeds {max_size} bytes"},
                    status_code=400,
                )
        try:
            data = await _dash_to_thread(save_dashboard_state, pid, key, value)
            if "error" in data:
                return JSONResponse(data, status_code=400)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_projects_dashboard_state", exc)

    # ----------------------------------------------------------------------
    #  Artifacts (Phase 2 — ARTIFACTS tab)
    # ----------------------------------------------------------------------

    async def page_artifacts(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return RedirectResponse("/dashboard/login", status_code=302)
        try:
            data = await _dash_to_thread(get_artifacts_list_data)
        except Exception:
            logger.debug("page_artifacts: data load failed", exc_info=True)
            data = {"artifacts": [], "total_count": 0, "facets": {"kinds": [], "tools": [], "tags": []}}
        ctx = {"nav_active": "artifacts", "data": data}
        resp = HTMLResponse(_render("artifacts.html", ctx))
        return _make_auth_response(request, dashboard_token, resp)

    async def api_artifacts_list(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        qs = request.query_params
        try:
            data = await _dash_to_thread(
                get_artifacts_list_data,
                filter=qs.get("filter", "")[:200],
                kind=qs.get("kind", ""),
                source_tool=qs.get("tool", "")[:80],
                tag=qs.get("tag", "")[:80],
                sort_by=qs.get("sort", "created_at"),
                limit=int(qs.get("limit", "500") or "500"),
            )
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_artifacts_list", exc)

    async def api_artifacts_detail(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        aid = request.query_params.get("id", "")
        if not aid:
            return JSONResponse({"error": "id required"}, status_code=400)
        try:
            data = await _dash_to_thread(get_artifact_detail, aid)
            if data is None:
                return JSONResponse({"error": "artifact not found"}, status_code=404)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_artifacts_detail", exc)

    async def api_artifacts_update(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        aid = (body.get("id") or "").strip()
        if not aid:
            return JSONResponse({"error": "id required"}, status_code=400)
        try:
            data = await _dash_to_thread(
                update_artifact_metadata_data,
                aid,
                description=body.get("description"),
                tags=body.get("tags"),
                notes=body.get("notes"),
                replace_tags=bool(body.get("replace_tags", False)),
            )
            if "error" in data:
                return JSONResponse(data, status_code=404)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_artifacts_update", exc)

    async def api_artifacts_delete(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        aid = (body.get("id") or "").strip()
        if not aid:
            return JSONResponse({"error": "id required"}, status_code=400)
        try:
            data = await _dash_to_thread(delete_artifact_data, aid)
            if "error" in data:
                return JSONResponse(data, status_code=404)
            return JSONResponse(data)
        except Exception as exc:
            return _api_error_response("api_artifacts_delete", exc)

    async def api_artifacts_bulk(request: Request) -> Response:
        """Bulk operations: tag or delete a list of artifacts."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        if not _validate_csrf(request):
            return JSONResponse({"error": "CSRF validation failed"}, status_code=403)
        body, err = await _parse_json_body(request)
        if err:
            return err
        op = (body.get("op") or "").strip()
        ids = body.get("ids") or []
        if not isinstance(ids, list) or not ids:
            return JSONResponse({"error": "ids must be a non-empty list"}, status_code=400)
        # Defend against authenticated CPU DoS — each id triggers an O(n)
        # snapshot copy of the artifact list under lock.
        if len(ids) > _MAX_BULK_ARTIFACT_IDS:
            return JSONResponse(
                {"error": f"too many ids (max {_MAX_BULK_ARTIFACT_IDS})"},
                status_code=400,
            )
        if op == "delete":
            try:
                data = await _dash_to_thread(bulk_delete_artifacts, ids)
                return JSONResponse(data)
            except Exception as exc:
                return _api_error_response("api_artifacts_bulk_delete", exc)
        elif op == "tag":
            tags = body.get("tags") or []
            replace = bool(body.get("replace_tags", False))
            if not isinstance(tags, list) or not tags:
                return JSONResponse({"error": "tags must be a non-empty list"}, status_code=400)
            if len(tags) > _MAX_BULK_ARTIFACT_TAGS:
                return JSONResponse(
                    {"error": f"too many tags (max {_MAX_BULK_ARTIFACT_TAGS})"},
                    status_code=400,
                )
            try:
                data = await _dash_to_thread(bulk_tag_artifacts, ids, tags, replace)
                return JSONResponse(data)
            except Exception as exc:
                return _api_error_response("api_artifacts_bulk_tag", exc)
        else:
            return JSONResponse({"error": f"Unknown op: {op}"}, status_code=400)

    async def api_artifacts_download(request: Request) -> Response:
        """Stream a single artifact file to the client.

        Directory artifacts are tarballed in a worker thread to avoid blocking
        the event loop while gzip-compressing large bundles. The tarball is
        written to a NamedTemporaryFile and cleaned up via a BackgroundTask
        after the response finishes.
        """
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        aid = request.query_params.get("id", "")
        if not aid:
            return JSONResponse({"error": "id required"}, status_code=400)
        try:
            meta = await _dash_to_thread(get_artifact_file_for_download, aid)
            if meta is None:
                return JSONResponse({"error": "artifact not found"}, status_code=404)
            if "error" in meta:
                return JSONResponse(meta, status_code=404)
            if meta.get("kind") == "directory":
                tmp_path = await _dash_to_thread(_build_directory_tarball,
                                                 meta["path"], meta["filename"])
                return FileResponse(
                    tmp_path,
                    filename=f'{meta["filename"]}.tar.gz',
                    media_type="application/gzip",
                    headers={"Cache-Control": "no-store"},
                    background=BackgroundTask(_unlink_quiet, tmp_path),
                )
            return FileResponse(
                meta["path"],
                filename=meta["filename"],
                media_type="application/octet-stream",
                headers={"Cache-Control": "no-store"},
            )
        except Exception as exc:
            return _api_error_response("api_artifacts_download", exc)

    return [
        Route("/login", endpoint=login_page, methods=["GET"]),
        Route("/login", endpoint=login_post, methods=["POST"]),
        Route("/", endpoint=_auth_page("overview.html", "overview", get_overview_data), methods=["GET"]),
        Route("/functions", endpoint=_auth_page("functions.html", "functions", get_functions_data), methods=["GET"]),
        Route("/callgraph", endpoint=_auth_page("callgraph.html", "callgraph"), methods=["GET"]),
        Route("/sections", endpoint=_auth_page("sections.html", "sections", get_sections_data), methods=["GET"]),
        Route("/imports", endpoint=_auth_page("imports.html", "imports", get_imports_data), methods=["GET"]),
        Route("/strings", endpoint=_auth_page("strings.html", "strings", get_strings_data), methods=["GET"]),
        Route("/timeline", endpoint=_auth_page("timeline.html", "timeline", lambda: get_timeline_data(100)), methods=["GET"]),
        Route("/notes", endpoint=page_notes, methods=["GET"]),
        # New pages (Batch 2)
        Route("/hexview", endpoint=_auth_page("hexview.html", "hexview"), methods=["GET"]),
        Route("/mitre", endpoint=_auth_page("mitre.html", "mitre", get_mitre_data), methods=["GET"]),
        Route("/capabilities", endpoint=_auth_page("capabilities.html", "capabilities", get_capa_data), methods=["GET"]),
        Route("/types", endpoint=_auth_page("types.html", "types", get_custom_types_data), methods=["GET"]),
        # New pages (Batch 4)
        Route("/similarity", endpoint=_auth_page("similarity.html", "similarity"), methods=["GET"]),
        Route("/settings", endpoint=page_settings, methods=["GET"]),
        # API
        Route("/api/state", endpoint=api_state, methods=["GET"]),
        Route("/api/functions", endpoint=api_functions, methods=["GET"]),
        Route("/api/callgraph", endpoint=api_callgraph, methods=["GET"]),
        Route("/api/triage", endpoint=api_triage, methods=["POST"]),
        Route("/api/timeline", endpoint=api_timeline, methods=["GET"]),
        Route("/api/decompile", endpoint=api_decompile_get, methods=["GET"]),
        Route("/api/decompile", endpoint=api_decompile_post, methods=["POST"]),
        Route("/api/strings", endpoint=api_strings, methods=["GET"]),
        Route("/api/search", endpoint=api_search, methods=["GET"]),
        Route("/api/function-xrefs", endpoint=api_function_xrefs, methods=["GET"]),
        Route("/api/function-strings", endpoint=api_function_strings, methods=["GET"]),
        Route("/api/function-analysis", endpoint=api_function_analysis, methods=["GET"]),
        *([Route("/api/debug", endpoint=api_debug, methods=["GET"])] if os.environ.get("ARKANA_DEBUG") == "1" else []),
        Route("/api/events", endpoint=api_events, methods=["GET"]),
        Route("/api/floss-summary", endpoint=api_floss_summary, methods=["GET"]),
        # New API endpoints (Batch 1-3)
        Route("/api/hex", endpoint=api_hex, methods=["GET"]),
        Route("/api/mitre", endpoint=api_mitre, methods=["GET"]),
        Route("/api/capabilities", endpoint=api_capabilities, methods=["GET"]),
        Route("/api/function-cfg", endpoint=api_function_cfg, methods=["GET"]),
        Route("/api/disassembly", endpoint=api_disassembly, methods=["GET"]),
        Route("/api/function-variables", endpoint=api_function_variables, methods=["GET"]),
        Route("/api/entropy", endpoint=api_entropy, methods=["GET"]),
        Route("/api/resources", endpoint=api_resources, methods=["GET"]),
        Route("/api/triage-report", endpoint=api_triage_report, methods=["GET"]),
        Route("/api/packing", endpoint=api_packing, methods=["GET"]),
        Route("/api/similarity", endpoint=api_similarity, methods=["GET"]),
        Route("/api/types", endpoint=api_types, methods=["GET"]),
        Route("/api/types/struct", endpoint=api_types_struct_post, methods=["POST"]),
        Route("/api/types/enum", endpoint=api_types_enum_post, methods=["POST"]),
        Route("/api/types/delete", endpoint=api_types_delete, methods=["POST"]),
        Route("/api/function-similarity", endpoint=api_function_similarity, methods=["GET"]),
        Route("/api/export-report", endpoint=api_export_report, methods=["POST"]),
        Route("/api/digest", endpoint=api_digest, methods=["GET"]),
        Route("/api/generate-report", endpoint=api_generate_report, methods=["POST"]),
        Route("/api/ioc-summary", endpoint=api_ioc_summary, methods=["GET"]),
        Route("/api/capabilities-summary", endpoint=api_capabilities_summary, methods=["GET"]),
        # New API endpoints (Batch 4)
        Route("/api/search-code", endpoint=api_search_code, methods=["GET"]),
        Route("/api/diff", endpoint=api_diff, methods=["POST"]),
        Route("/api/list-files", endpoint=api_list_files, methods=["GET"]),
        # BSim API endpoints
        Route("/api/bsim/stats", endpoint=api_bsim_stats, methods=["GET"]),
        Route("/api/bsim/binaries", endpoint=api_bsim_binaries, methods=["GET"]),
        Route("/api/bsim/triage", endpoint=api_bsim_triage, methods=["POST"]),
        Route("/api/bsim/matches", endpoint=api_bsim_matches, methods=["POST"]),
        Route("/api/bsim/index", endpoint=api_bsim_index, methods=["POST"]),
        Route("/api/bsim/validate", endpoint=api_bsim_validate, methods=["POST"]),
        Route("/api/bsim/delete", endpoint=api_bsim_delete, methods=["POST"]),
        Route("/api/bsim/clear", endpoint=api_bsim_clear, methods=["POST"]),
        Route("/api/bsim/compare-projects", endpoint=api_bsim_compare_projects, methods=["GET"]),
        # Settings API
        Route("/api/settings", endpoint=api_settings_get, methods=["GET"]),
        Route("/api/settings", endpoint=api_settings_post, methods=["POST"]),
        Route("/api/settings/reset", endpoint=api_settings_reset, methods=["POST"]),
        # Projects (Phase 2)
        Route("/projects", endpoint=page_projects, methods=["GET"]),
        Route("/api/projects", endpoint=api_projects_list, methods=["GET"]),
        Route("/api/projects", endpoint=api_projects_create, methods=["POST"]),
        Route("/api/projects/detail", endpoint=api_projects_detail, methods=["GET"]),
        Route("/api/projects/rename", endpoint=api_projects_rename, methods=["POST"]),
        Route("/api/projects/tag", endpoint=api_projects_tag, methods=["POST"]),
        Route("/api/projects/delete", endpoint=api_projects_delete, methods=["POST"]),
        Route("/api/projects/open", endpoint=api_projects_open, methods=["POST"]),
        Route("/api/projects/set-primary", endpoint=api_projects_set_primary, methods=["POST"]),
        Route("/api/projects/dashboard-state", endpoint=api_projects_dashboard_state, methods=["POST"]),
        Route("/api/projects/importable-archives", endpoint=api_projects_importable_archives, methods=["GET"]),
        Route("/api/projects/import-archive", endpoint=api_projects_import_archive, methods=["POST"]),
        # Artifacts (Phase 2)
        Route("/artifacts", endpoint=page_artifacts, methods=["GET"]),
        Route("/api/artifacts", endpoint=api_artifacts_list, methods=["GET"]),
        Route("/api/artifacts/detail", endpoint=api_artifacts_detail, methods=["GET"]),
        Route("/api/artifacts/update", endpoint=api_artifacts_update, methods=["POST"]),
        Route("/api/artifacts/delete", endpoint=api_artifacts_delete, methods=["POST"]),
        Route("/api/artifacts/bulk", endpoint=api_artifacts_bulk, methods=["POST"]),
        Route("/api/artifacts/download", endpoint=api_artifacts_download, methods=["GET"]),
        # Partials
        Route("/partials/overview-stats", endpoint=partial_overview_stats, methods=["GET"]),
        Route("/partials/task-list", endpoint=partial_task_list, methods=["GET"]),
        Route("/partials/timeline", endpoint=partial_timeline_entry, methods=["GET"]),
        Route("/partials/global-status", endpoint=partial_global_status, methods=["GET"]),
        # Static files
        Mount("/static", app=StaticFiles(directory=str(_STATIC_DIR)), name="dashboard_static"),
    ]


# ---------------------------------------------------------------------------
#  App factory
# ---------------------------------------------------------------------------

def create_dashboard_app(token: Optional[str] = None, standalone: bool = False) -> Starlette:
    """Create and return the dashboard Starlette ASGI app.

    If *token* is not provided, loads/generates from ~/.arkana/dashboard_token.
    Stores the token on the default AnalyzerState for MCP tool access.

    When *standalone* is True (stdio mode), routes are mounted under ``/dashboard/``
    so URLs are consistent regardless of mode.  When False (HTTP mode), the caller
    mounts the app under ``/dashboard`` via Starlette ``Mount``.
    """
    global _csrf_secret, _csrf_dashboard_token
    dashboard_token = token or _ensure_token()

    # Generate per-instance CSRF secret and derive token bound to dashboard credential
    _csrf_secret = secrets.token_bytes(32)
    _csrf_dashboard_token = dashboard_token
    _jinja_env.globals["csrf_token"] = _compute_csrf_token(dashboard_token)

    # Store on default state for get_config() access
    from arkana.state import _default_state
    _default_state.dashboard_token = dashboard_token

    routes = _create_routes(dashboard_token)
    middleware = [Middleware(SecurityHeadersMiddleware)]
    if standalone:
        app = Starlette(
            routes=[Mount("/dashboard", routes=routes)],
            middleware=middleware,
        )
    else:
        app = Starlette(routes=routes, middleware=middleware)
    return app


# ---------------------------------------------------------------------------
#  Stdio-mode background server
# ---------------------------------------------------------------------------

def start_dashboard_thread(host: str = "127.0.0.1", port: int = 8082) -> threading.Thread:
    """Start the dashboard in a background daemon thread (for stdio mode)."""
    dashboard_token = _ensure_token()
    app = create_dashboard_app(token=dashboard_token, standalone=True)

    def _run():
        try:
            import uvicorn
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            config = uvicorn.Config(
                app, host=host, port=port,
                log_level="warning",
                access_log=False,
            )
            server = uvicorn.Server(config)
            loop.run_until_complete(server.serve())
        except Exception:
            logger.exception("Dashboard server thread crashed")

    t = threading.Thread(target=_run, daemon=True, name="arkana-dashboard")
    t.start()
    logger.info(
        "Dashboard: http://%s:%d/dashboard/?token=<see %s>",
        host, port, _TOKEN_FILE,
    )
    return t
