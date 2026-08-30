from __future__ import annotations

import hmac
import importlib.util
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp

_SERVER_PATH = Path(__file__).with_name("server.py")
_SERVER_SPEC = importlib.util.spec_from_file_location("resource_studio_mcp_server", _SERVER_PATH)
if _SERVER_SPEC is None or _SERVER_SPEC.loader is None:
    raise RuntimeError(f"cannot load local MCP server: {_SERVER_PATH}")
_SERVER_MODULE = importlib.util.module_from_spec(_SERVER_SPEC)
sys.modules[_SERVER_SPEC.name] = _SERVER_MODULE
_SERVER_SPEC.loader.exec_module(_SERVER_MODULE)
server = _SERVER_MODULE.server


DEFAULT_ALLOWED_HOSTS = "127.0.0.1,localhost"
DEFAULT_ALLOWED_ORIGINS = "http://127.0.0.1,http://localhost"


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _bearer_token(header: str | None) -> str | None:
    if not header or not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    return token or None


class MCPHTTPAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        token: str,
        allowed_origins: Iterable[str],
        require_tls: bool,
    ) -> None:
        super().__init__(app)
        self.token = token
        self.allowed_origins = frozenset(allowed_origins)
        self.require_tls = require_tls

    async def dispatch(self, request: Request, call_next) -> Response:
        origin = request.headers.get("origin")
        if origin and origin not in self.allowed_origins:
            return JSONResponse({"error": "origin_not_allowed"}, status_code=403)
        if self.require_tls:
            forwarded = request.headers.get("x-forwarded-proto", request.url.scheme)
            if forwarded.lower() != "https":
                return JSONResponse({"error": "https_required"}, status_code=400)
        supplied = _bearer_token(request.headers.get("authorization"))
        if supplied is None or not hmac.compare_digest(supplied, self.token):
            return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)


def create_app(
    *,
    token: str | None = None,
    allowed_hosts: Iterable[str] | None = None,
    allowed_origins: Iterable[str] | None = None,
    require_tls: bool | None = None,
):
    """Build the authenticated Streamable HTTP ASGI app; no socket is opened here."""
    allow_remote = _is_true(os.environ.get("RESOURCE_STUDIO_MCP_ALLOW_REMOTE"))
    token = token or os.environ.get("RESOURCE_STUDIO_MCP_TOKEN", "")
    if not token:
        raise RuntimeError("RESOURCE_STUDIO_MCP_TOKEN is required for Streamable HTTP")
    if allow_remote and len(token) < 32:
        raise RuntimeError("remote MCP token must contain at least 32 characters")
    hosts = tuple(allowed_hosts or _csv(os.environ.get("RESOURCE_STUDIO_MCP_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS)))
    origins = tuple(allowed_origins or _csv(os.environ.get("RESOURCE_STUDIO_MCP_ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS)))
    require_tls = allow_remote if require_tls is None else require_tls
    app = server.streamable_http_app(
        streamable_http_path=os.environ.get("RESOURCE_STUDIO_MCP_PATH", "/mcp"),
        stateless_http=False,
        json_response=True,
        host=os.environ.get("RESOURCE_STUDIO_MCP_HOST", "127.0.0.1"),
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(hosts))
    app.add_middleware(MCPHTTPAuthMiddleware, token=token, allowed_origins=origins, require_tls=require_tls)

    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("resource-studio-mcp: ready\n")

    app.add_route("/healthz", healthz, methods=["GET"])
    return app


def run() -> None:
    import uvicorn

    host = os.environ.get("RESOURCE_STUDIO_MCP_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"} and not _is_true(os.environ.get("RESOURCE_STUDIO_MCP_ALLOW_REMOTE")):
        raise RuntimeError("remote bind requires RESOURCE_STUDIO_MCP_ALLOW_REMOTE=true")
    uvicorn.run(
        create_app(),
        host=host,
        port=int(os.environ.get("RESOURCE_STUDIO_MCP_PORT", "8765")),
        log_level=os.environ.get("RESOURCE_STUDIO_MCP_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    run()
