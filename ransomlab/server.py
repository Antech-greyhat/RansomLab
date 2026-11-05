"""A bounded loopback ASGI wrapper around the read-only Flask views."""
from __future__ import annotations

import asyncio
import secrets

from .core.errors import DependencyError, ValidationError


class BoundedRequest:
    """Bound the body before the WSGI adapter can buffer an untrusted request."""

    def __init__(self, app, max_bytes=1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return

        async def reject(status):
            await send({"type": "http.response.start", "status": status,
                        "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store"), (b"connection", b"close")]})
            await send({"type": "http.response.body", "body": b'{"error":"request_rejected"}'})

        headers = scope.get("headers", [])
        if len(headers) > 64 or sum(len(key) + len(value) for key, value in headers) > 8192:
            return await reject(431)
        chunks, size = [], 0
        try:
            async with asyncio.timeout(5):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body = message.get("body", b"")
                    size += len(body)
                    if size > self.max_bytes:
                        return await reject(413)
                    chunks.append(body)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await reject(408)
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)


def serve(port=8765, service=None):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValidationError("Dashboard port must be between 1024 and 65535")
    try:
        import uvicorn
        from uvicorn.middleware.wsgi import WSGIMiddleware
        from .dashboard import create_app
    except ImportError as exc:
        raise DependencyError("The reviewed Flask and Uvicorn environment is required for the dashboard") from exc
    token = secrets.token_urlsafe(32)
    app = BoundedRequest(WSGIMiddleware(create_app(service, access_token=token), workers=4))
    print(f"RansomLab dashboard: http://127.0.0.1:{port}/#token={token}", flush=True)
    print("Keep this local access URL private. Press Ctrl+C to stop.", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, proxy_headers=False, access_log=False,
                log_level="warning", loop="asyncio", http="h11", ws="none", lifespan="off",
                limit_concurrency=16, limit_max_requests=10000, timeout_keep_alive=5,
                timeout_graceful_shutdown=5, backlog=16, h11_max_incomplete_event_size=8192,
                server_header=False)
