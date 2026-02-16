"""ASGI middleware for bearer token authentication in HTTP transport mode."""
import logging

logger = logging.getLogger("PeMCP")


class BearerAuthMiddleware:
    """ASGI middleware that requires a valid Bearer token on every HTTP request.

    Wraps the FastMCP ASGI app to enforce authentication before any MCP
    processing occurs.  Non-HTTP ASGI events (lifespan, websocket) are
    passed through unchanged.

    Usage::

        app = mcp_server.streamable_http_app()
        secured_app = BearerAuthMiddleware(app, api_key="secret-token")
        uvicorn.run(secured_app, host="0.0.0.0", port=8082)
    """

    def __init__(self, app, api_key: str):
        self.app = app
        self.api_key = api_key

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("utf-8", "ignore")
            expected = f"Bearer {self.api_key}"
            if auth_header != expected:
                logger.warning("Rejected unauthenticated HTTP request")
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
        # Non-HTTP scopes (lifespan, websocket) or authenticated requests pass through
        await self.app(scope, receive, send)
