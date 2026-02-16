"""Unit tests for pemcp/auth.py — BearerAuthMiddleware."""
import asyncio
import pytest
from pemcp.auth import BearerAuthMiddleware


# ---------------------------------------------------------------------------
# Helpers to simulate ASGI request/response
# ---------------------------------------------------------------------------

async def _make_request(app, headers=None, scope_type="http"):
    """Simulate an ASGI request and return (status, response_body)."""
    scope = {
        "type": scope_type,
        "method": "POST",
        "path": "/mcp",
        "headers": headers or [],
    }
    response_started = {}
    response_body = b""

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        nonlocal response_body
        if message["type"] == "http.response.start":
            response_started["status"] = message["status"]
            response_started["headers"] = message.get("headers", [])
        elif message["type"] == "http.response.body":
            response_body = message.get("body", b"")

    await app(scope, receive, send)
    return response_started.get("status"), response_body


async def _passthrough_app(scope, receive, send):
    """Dummy ASGI app that returns 200 OK."""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"OK"})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBearerAuthMiddleware:
    def test_valid_token_passes_through(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.get_event_loop().run_until_complete(
            _make_request(app, headers=[(b"authorization", b"Bearer secret-token-123")])
        )
        assert status == 200
        assert body == b"OK"

    def test_missing_auth_header_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.get_event_loop().run_until_complete(
            _make_request(app, headers=[])
        )
        assert status == 401
        assert b"Unauthorized" in body

    def test_wrong_token_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.get_event_loop().run_until_complete(
            _make_request(app, headers=[(b"authorization", b"Bearer wrong-token")])
        )
        assert status == 401

    def test_missing_bearer_prefix_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.get_event_loop().run_until_complete(
            _make_request(app, headers=[(b"authorization", b"secret-token-123")])
        )
        assert status == 401

    def test_non_http_scope_passes_through(self):
        """Non-HTTP ASGI events (lifespan, websocket) should pass through."""
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        # lifespan scope should bypass auth entirely
        scope = {"type": "lifespan"}
        received = []

        async def _run():
            async def receive():
                return {"type": "lifespan.startup"}
            async def send(msg):
                received.append(msg)
            # The passthrough app doesn't handle lifespan, but middleware should
            # still pass it through without returning 401
            try:
                await app(scope, receive, send)
            except (KeyError, TypeError):
                pass  # passthrough_app doesn't handle lifespan, that's fine

        asyncio.get_event_loop().run_until_complete(_run())
        # If auth had blocked this, we'd see a 401 response. The fact that we
        # reach the inner app (which might error on lifespan) means auth passed.
        assert all(r.get("status") != 401 for r in received)

    def test_empty_bearer_value_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.get_event_loop().run_until_complete(
            _make_request(app, headers=[(b"authorization", b"Bearer ")])
        )
        assert status == 401

    def test_uses_constant_time_comparison(self):
        """Verify that hmac.compare_digest is used (import check)."""
        import inspect
        source = inspect.getsource(BearerAuthMiddleware.__call__)
        assert "hmac.compare_digest" in source or "compare_digest" in source
