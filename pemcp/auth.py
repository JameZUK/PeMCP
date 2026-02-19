"""ASGI middleware for bearer token authentication in HTTP transport mode."""
import hmac
import logging

logger = logging.getLogger("PeMCP")


class BearerAuthMiddleware:
    """ASGI middleware that requires a valid Bearer token on every HTTP request.

    Wraps the FastMCP ASGI app to enforce authentication before any MCP
    processing occurs.  Both HTTP and WebSocket connections are validated.
    Only lifespan events pass through without authentication.

    Uses ``hmac.compare_digest()`` for constant-time comparison to prevent
    timing side-channel attacks on the API key.

    Usage::

        app = mcp_server.streamable_http_app()
        secured_app = BearerAuthMiddleware(app, api_key="secret-token")
        uvicorn.run(secured_app, host="0.0.0.0", port=8082)
    """

    def __init__(self, app, api_key: str):
        self.app = app
        self.api_key = api_key

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("utf-8", "ignore")
            expected = f"Bearer {self.api_key}"
            # Constant-time comparison to prevent timing side-channel attacks
            if not hmac.compare_digest(auth_header, expected):
                logger.warning("Rejected unauthenticated %s request", scope["type"])
                if scope["type"] == "websocket":
                    # Reject WebSocket upgrade with a close code
                    await send({"type": "websocket.close", "code": 4003})
                    return
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"www-authenticate", b"Bearer"],
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"error": "Unauthorized. Provide a valid Bearer token via the Authorization header."}',
                })
                return
        # Lifespan scopes or authenticated requests pass through
        await self.app(scope, receive, send)
