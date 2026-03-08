"""Unit tests for arkana/auth.py — BearerAuthMiddleware."""
import asyncio
import pytest
from arkana.auth import BearerAuthMiddleware


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
        status, body = asyncio.run(
            _make_request(app, headers=[(b"authorization", b"Bearer secret-token-123")])
        )
        assert status == 200
        assert body == b"OK"

    def test_missing_auth_header_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.run(
            _make_request(app, headers=[])
        )
        assert status == 401
        assert b"Unauthorized" in body

    def test_wrong_token_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.run(
            _make_request(app, headers=[(b"authorization", b"Bearer wrong-token")])
        )
        assert status == 401

    def test_missing_bearer_prefix_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.run(
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

        asyncio.run(_run())
        # If auth had blocked this, we'd see a 401 response. The fact that we
        # reach the inner app (which might error on lifespan) means auth passed.
        assert all(r.get("status") != 401 for r in received)

    def test_empty_bearer_value_returns_401(self):
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.run(
            _make_request(app, headers=[(b"authorization", b"Bearer ")])
        )
        assert status == 401

    def test_uses_constant_time_comparison(self):
        """Verify that hmac.compare_digest is used (import check)."""
        import inspect
        source = inspect.getsource(BearerAuthMiddleware.__call__)
        assert "hmac.compare_digest" in source or "compare_digest" in source

    def test_duplicate_authorization_headers_returns_400(self):
        """Multiple Authorization headers should be rejected (header smuggling)."""
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        status, body = asyncio.run(
            _make_request(app, headers=[
                (b"authorization", b"Bearer secret-token-123"),
                (b"authorization", b"Bearer other-token"),
            ])
        )
        assert status == 400
        assert b"Ambiguous" in body

    def test_websocket_rejected_without_auth(self):
        """WebSocket connections without auth should get close code."""
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        scope = {
            "type": "websocket",
            "path": "/ws",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        messages = []

        async def _run():
            async def receive():
                return {"type": "websocket.connect"}
            async def send(msg):
                messages.append(msg)
            await app(scope, receive, send)

        asyncio.run(_run())
        assert any(m.get("type") == "websocket.close" for m in messages)

    def test_websocket_duplicate_auth_rejected(self):
        """WebSocket with duplicate auth headers should be rejected."""
        app = BearerAuthMiddleware(_passthrough_app, api_key="secret-token-123")
        scope = {
            "type": "websocket",
            "path": "/ws",
            "headers": [
                (b"authorization", b"Bearer secret-token-123"),
                (b"authorization", b"Bearer other"),
            ],
            "client": ("127.0.0.1", 12345),
        }
        messages = []

        async def _run():
            async def receive():
                return {"type": "websocket.connect"}
            async def send(msg):
                messages.append(msg)
            await app(scope, receive, send)

        asyncio.run(_run())
        assert any(m.get("type") == "websocket.close" for m in messages)
