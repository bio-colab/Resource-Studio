from __future__ import annotations

import anyio
import httpx
import importlib.util
from pathlib import Path

HTTP_SERVER = Path(__file__).resolve().parents[1] / "mcp" / "http_server.py"
_spec = importlib.util.spec_from_file_location("resource_studio_mcp_http", HTTP_SERVER)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"cannot load {HTTP_SERVER}")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
create_app = _module.create_app


async def main() -> None:
    app = create_app(token="t" * 40, require_tls=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.get("/healthz")
        assert response.status_code == 401

        response = await client.get("/healthz", headers={"Authorization": "Bearer " + "t" * 40})
        assert response.status_code == 200
        assert response.text == "resource-studio-mcp: ready\n"

        response = await client.get(
            "/healthz",
            headers={
                "Authorization": "Bearer " + "t" * 40,
                "Origin": "https://evil.example",
            },
        )
        assert response.status_code == 403

        response = await client.get(
            "/healthz",
            headers={
                "Authorization": "Bearer " + "t" * 40,
                "Host": "evil.example",
            },
        )
        assert response.status_code == 400

    remote_app = create_app(token="t" * 40, allowed_hosts=("mcp.example",), allowed_origins=("https://mcp.example",), require_tls=True)
    remote_transport = httpx.ASGITransport(app=remote_app)
    async with httpx.AsyncClient(transport=remote_transport, base_url="https://mcp.example") as client:
        response = await client.get(
            "/healthz",
            headers={
                "Authorization": "Bearer " + "t" * 40,
                "Origin": "https://mcp.example",
                "Host": "mcp.example",
                "X-Forwarded-Proto": "https",
            },
        )
        assert response.status_code == 200


if __name__ == "__main__":
    anyio.run(main)
    print("mcp-http-tests: passed")
