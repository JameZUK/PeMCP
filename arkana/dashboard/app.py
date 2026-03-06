"""Starlette ASGI app for the Arkana dashboard."""
import asyncio
import hmac
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.middleware import Middleware

from jinja2 import Environment, FileSystemLoader

from arkana.dashboard.state_api import (
    get_overview_data,
    get_functions_data,
    get_callgraph_data,
    get_sections_data,
    get_imports_data,
    get_timeline_data,
    get_notes_data,
)

logger = logging.getLogger("Arkana.dashboard")

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

# Cookie name for dashboard auth
_COOKIE_NAME = "arkana_dash"
# Cookie max age: 30 days
_COOKIE_MAX_AGE = 30 * 24 * 3600

# SSE connection limit
_MAX_SSE_CONNECTIONS = 10
_sse_connection_count = 0
_sse_lock = threading.Lock()


# ---------------------------------------------------------------------------
#  Token management
# ---------------------------------------------------------------------------

def _ensure_token() -> str:
    """Load or generate the dashboard token. Persisted to ~/.arkana/dashboard_token."""
    _TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _TOKEN_FILE.exists():
        token = _TOKEN_FILE.read_text().strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    _TOKEN_FILE.write_text(token)
    try:
        os.chmod(str(_TOKEN_FILE), 0o600)
    except OSError:
        pass
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
    """Check if provided token matches any valid token."""
    for valid in _get_valid_tokens(dashboard_token):
        if hmac.compare_digest(provided, valid):
            return True
    return False


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
    """If authenticated via query param, set cookie on the response."""
    token_param = request.query_params.get("token")
    if token_param and _check_token(token_param, dashboard_token):
        response.set_cookie(
            _COOKIE_NAME, token_param,
            max_age=_COOKIE_MAX_AGE,
            httponly=True,
            samesite="strict",
        )
    return response


# ---------------------------------------------------------------------------
#  Route handlers
# ---------------------------------------------------------------------------

def _create_routes(dashboard_token: str) -> list:
    """Build the list of Starlette routes."""

    def _render(template_name: str, context: dict = None) -> str:
        ctx = context or {}
        ctx.setdefault("nav_active", "")
        return _jinja_env.get_template(template_name).render(**ctx)

    # --- Login ---
    async def login_page(request: Request) -> Response:
        if _is_authenticated(request, dashboard_token):
            return RedirectResponse("/dashboard/", status_code=302)
        error = request.query_params.get("error", "")
        html = _render("login.html", {"error": error})
        return HTMLResponse(html)

    async def login_post(request: Request) -> Response:
        form = await request.form()
        token = form.get("token", "").strip()
        if _check_token(token, dashboard_token):
            resp = RedirectResponse("/dashboard/", status_code=302)
            resp.set_cookie(
                _COOKIE_NAME, token,
                max_age=_COOKIE_MAX_AGE,
                httponly=True,
                samesite="strict",
            )
            return resp
        return RedirectResponse("/dashboard/login?error=invalid", status_code=302)

    # --- Auth-required page wrapper ---
    def _auth_page(template: str, nav: str, data_fn=None):
        async def handler(request: Request) -> Response:
            if not _is_authenticated(request, dashboard_token):
                return RedirectResponse("/dashboard/login", status_code=302)
            ctx = {"nav_active": nav}
            if data_fn:
                ctx["data"] = data_fn()
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
        return JSONResponse(get_overview_data())

    async def api_debug(request: Request) -> Response:
        """Diagnostic endpoint — shows state isolation info (sanitized)."""
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        from arkana.state import _default_state as ds, _session_registry, _registry_lock
        from arkana.dashboard.state_api import _get_state
        resolved = _get_state()
        sessions = []
        with _registry_lock:
            for key, st in _session_registry.items():
                sessions.append({
                    "key": key[:8] + "...",
                    "has_file": st.filepath is not None,
                    "notes": len(st.get_notes()),
                })
        return JSONResponse({
            "default_has_file": ds.filepath is not None,
            "resolved_has_file": resolved.filepath is not None,
            "resolved_is_default": resolved is ds,
            "session_count": len(sessions),
            "sessions": sessions,
        })

    async def api_functions(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        sort_by = request.query_params.get("sort", "address")
        if sort_by not in ("address", "name", "size", "complexity", "triage"):
            sort_by = "address"
        filter_triage = request.query_params.get("triage", "all")
        if filter_triage not in ("all", "unreviewed", "suspicious", "clean", "flagged"):
            filter_triage = "all"
        search = request.query_params.get("search", "")[:500]
        sort_asc = request.query_params.get("asc", "1") == "1"
        data = get_functions_data(sort_by=sort_by, filter_triage=filter_triage, search=search, sort_asc=sort_asc)
        return JSONResponse(data)

    async def api_callgraph(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse(get_callgraph_data())

    async def api_triage(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        address = body.get("address", "").strip().lower()
        status = body.get("status", "").strip()
        if not address or status not in ("unreviewed", "suspicious", "clean", "flagged"):
            return JSONResponse({"error": "invalid address or status"}, status_code=400)
        st = _get_active_state()
        st.set_triage_status(address, status)
        # Persist to cache
        sha = (st.pe_data or {}).get("file_hashes", {}).get("sha256")
        if sha:
            try:
                from arkana.config import analysis_cache
                analysis_cache.update_session_data(sha, triage_status=st.get_all_triage_snapshot())
            except (OSError, IOError, KeyError):
                pass
        return JSONResponse({"ok": True, "address": address, "status": status})

    async def api_timeline(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            limit = int(request.query_params.get("limit", "100"))
            limit = max(1, min(limit, 5000))
        except (ValueError, TypeError):
            limit = 100
        return JSONResponse(get_timeline_data(limit=limit))

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
            _sse_connection_count += 1

        async def event_generator():
            global _sse_connection_count
            try:
                last_tool_count = 0
                last_notes_count = 0
                last_active_tool = None
                last_progress = 0
                last_task_count = 0
                last_task_running = 0
                last_file_sha256 = None
                last_triage_counts = {}
                last_artifacts_count = 0
                while True:
                    await asyncio.sleep(2)
                    try:
                        overview = get_overview_data()
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
                        )
                        if changed:
                            file_changed = (
                                current_sha256 != last_file_sha256
                                and last_file_sha256 is not None
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
                            data = json.dumps(overview)
                            if file_changed:
                                yield f"event: file-changed\ndata: {data}\n\n"
                            else:
                                yield f"event: state-update\ndata: {data}\n\n"
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
        data = get_notes_data(category=category)
        ctx = {"nav_active": "notes", "data": data, "active_category": category or "all"}
        resp = HTMLResponse(_render("notes.html", ctx))
        return _make_auth_response(request, dashboard_token, resp)

    async def partial_overview_stats(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return HTMLResponse("", status_code=401)
        data = get_overview_data()
        html = _render("partials/_overview_stats.html", {"data": data})
        return HTMLResponse(html)

    async def partial_task_list(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return HTMLResponse("", status_code=401)
        data = get_overview_data()
        html = _render("partials/_task_list.html", {"data": data})
        return HTMLResponse(html)

    async def partial_timeline_entry(request: Request) -> Response:
        if not _is_authenticated(request, dashboard_token):
            return HTMLResponse("", status_code=401)
        entries = get_timeline_data(limit=20)
        html = _render("partials/_timeline_entry.html", {"entries": entries})
        return HTMLResponse(html)

    return [
        Route("/login", endpoint=login_page, methods=["GET"]),
        Route("/login", endpoint=login_post, methods=["POST"]),
        Route("/", endpoint=_auth_page("overview.html", "overview", get_overview_data), methods=["GET"]),
        Route("/functions", endpoint=_auth_page("functions.html", "functions", get_functions_data), methods=["GET"]),
        Route("/callgraph", endpoint=_auth_page("callgraph.html", "callgraph"), methods=["GET"]),
        Route("/sections", endpoint=_auth_page("sections.html", "sections", get_sections_data), methods=["GET"]),
        Route("/imports", endpoint=_auth_page("imports.html", "imports", get_imports_data), methods=["GET"]),
        Route("/timeline", endpoint=_auth_page("timeline.html", "timeline", lambda: get_timeline_data(100)), methods=["GET"]),
        Route("/notes", endpoint=page_notes, methods=["GET"]),
        # API
        Route("/api/state", endpoint=api_state, methods=["GET"]),
        Route("/api/functions", endpoint=api_functions, methods=["GET"]),
        Route("/api/callgraph", endpoint=api_callgraph, methods=["GET"]),
        Route("/api/triage", endpoint=api_triage, methods=["POST"]),
        Route("/api/timeline", endpoint=api_timeline, methods=["GET"]),
        Route("/api/debug", endpoint=api_debug, methods=["GET"]),
        Route("/api/events", endpoint=api_events, methods=["GET"]),
        # Partials
        Route("/partials/overview-stats", endpoint=partial_overview_stats, methods=["GET"]),
        Route("/partials/task-list", endpoint=partial_task_list, methods=["GET"]),
        Route("/partials/timeline", endpoint=partial_timeline_entry, methods=["GET"]),
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
    dashboard_token = token or _ensure_token()

    # Store on default state for get_config() access
    from arkana.state import _default_state
    _default_state.dashboard_token = dashboard_token

    routes = _create_routes(dashboard_token)
    if standalone:
        app = Starlette(routes=[Mount("/dashboard", routes=routes)])
    else:
        app = Starlette(routes=routes)
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
        "Dashboard: http://%s:%d/dashboard/ (token: %s...)",
        host, port, dashboard_token[:8],
    )
    return t
