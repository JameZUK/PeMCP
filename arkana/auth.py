"""ASGI middleware for bearer token authentication in HTTP transport mode."""
import hmac
import logging

logger = logging.getLogger("Arkana")


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
            # Collect all Authorization headers — reject if ambiguous (header smuggling)
            auth_values = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
            if len(auth_values) > 1:
                path = scope.get("path", "unknown")
                client = scope.get("client", ("unknown", 0))
                logger.warning(
                    "Rejected %s request with %d Authorization headers from %s:%s to %s",
                    scope["type"], len(auth_values), client[0], client[1], path,
                )
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 4003})
                    return
                await send({
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [[b"content-type", b"application/json"]],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"error": "Ambiguous Authorization: multiple headers provided."}',
                })
                return
            auth_header = auth_values[0].decode("utf-8", "ignore") if auth_values else ""
            expected = f"Bearer {self.api_key}"
            # Constant-time comparison to prevent timing side-channel attacks
            if not hmac.compare_digest(auth_header, expected):
                path = scope.get("path", "unknown")
                client = scope.get("client", ("unknown", 0))
                logger.warning(
                    "Rejected unauthenticated %s request from %s:%s to %s",
                    scope["type"], client[0], client[1], path,
                )
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
