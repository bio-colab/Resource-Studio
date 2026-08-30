from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from core.external_integrations import IntegrationError, IntegrationGateway, IntegrationRegistry


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit: int) -> bytes:
        return b'{"ok":true}'


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-integrations-") as directory:
        config = Path(directory) / "integrations.json"
        config.write_text(
            json.dumps(
                {
                    "integrations": [
                        {
                            "id": "example.api",
                            "name": "Example API",
                            "baseUrl": "https://api.example.test",
                            "authEnv": "EXAMPLE_TOKEN",
                            "operations": {"health": {"method": "GET", "path": "/health"}},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with patch("core.external_integrations.socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
            registry = IntegrationRegistry(config)
            assert len(registry.list()) == 1
            gateway = IntegrationGateway(registry)
            with patch.dict(os.environ, {"EXAMPLE_TOKEN": "secret"}):
                with patch("core.external_integrations.urllib.request.build_opener") as build:
                    build.return_value.open.return_value = FakeResponse()
                    result = gateway.request_json("example.api", "health")
                    assert result["data"] == {"ok": True}
                    request = build.return_value.open.call_args.args[0]
                    assert request.full_url == "https://api.example.test/health"
                    assert request.get_header("Authorization") == "Bearer secret"
            try:
                gateway.request_json("example.api", "missing")
            except IntegrationError:
                pass
            else:
                raise AssertionError("non-allowlisted operation was accepted")

        bad = Path(directory) / "bad.json"
        bad.write_text(json.dumps({"integrations": [{"id": "bad", "baseUrl": "http://127.0.0.1", "operations": {"x": {"path": "/"}}}]}), encoding="utf-8")
        with patch("core.external_integrations.socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 80))]):
            rejected = IntegrationRegistry(bad)
            assert rejected.list() == []
            assert rejected.errors()
    print("external-integration-tests: passed")


if __name__ == "__main__":
    main()
