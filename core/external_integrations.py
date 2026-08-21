from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


MAX_REQUEST_BYTES = 1 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
ALLOWED_METHODS = frozenset({"GET", "POST"})


class IntegrationError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not allowed", headers, fp)


@dataclass(frozen=True)
class IntegrationOperation:
    name: str
    method: str
    path: str
    description: str = ""

    @classmethod
    def from_dict(cls, name: str, value: dict[str, Any]) -> "IntegrationOperation":
        method = str(value.get("method", "GET")).upper()
        path = str(value.get("path", ""))
        if method not in ALLOWED_METHODS:
            raise ValueError(f"unsupported integration method: {method}")
        if not path.startswith("/") or ".." in path or "?" in path or "#" in path:
            raise ValueError("integration operation path must be an absolute fixed path without query or traversal")
        return cls(name=name, method=method, path=path, description=str(value.get("description", "")))


@dataclass(frozen=True)
class IntegrationSpec:
    integration_id: str
    name: str
    base_url: str
    auth_env: str | None
    operations: tuple[IntegrationOperation, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IntegrationSpec":
        integration_id = str(value.get("id", ""))
        if not integration_id or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for char in integration_id):
            raise ValueError("integration id must be lowercase and stable")
        base_url = str(value.get("baseUrl", ""))
        _validate_public_https_url(base_url)
        raw_operations = value.get("operations")
        if not isinstance(raw_operations, dict) or not raw_operations:
            raise ValueError("integration must declare at least one fixed operation")
        operations = tuple(IntegrationOperation.from_dict(name, item) for name, item in sorted(raw_operations.items()) if isinstance(item, dict))
        if not operations:
            raise ValueError("integration operations are invalid")
        auth_env = value.get("authEnv")
        if auth_env is not None:
            auth_env = str(auth_env)
            if not auth_env.isidentifier() or not auth_env.isupper():
                raise ValueError("authEnv must be an uppercase environment variable name")
        return cls(
            integration_id=integration_id,
            name=str(value.get("name", integration_id)),
            base_url=base_url.rstrip("/"),
            auth_env=auth_env,
            operations=operations,
        )

    def operation(self, name: str) -> IntegrationOperation:
        for operation in self.operations:
            if operation.name == name:
                return operation
        raise IntegrationError(f"operation is not allowlisted: {name}")

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.integration_id,
            "name": self.name,
            "baseUrl": self.base_url,
            "authEnv": self.auth_env,
            "operations": [
                {"name": item.name, "method": item.method, "path": item.path, "description": item.description}
                for item in self.operations
            ],
            "secretsIncluded": False,
            "arbitraryUrlsAllowed": False,
        }


class IntegrationRegistry:
    def __init__(self, config_path: Path) -> None:
        self.config_path = Path(config_path).expanduser().resolve()
        self._specs: dict[str, IntegrationSpec] = {}
        self._errors: list[dict[str, str]] = []
        self.config_sha256 = ""
        self.reload()

    def reload(self) -> None:
        self._specs.clear()
        self._errors.clear()
        self.config_sha256 = ""
        if not self.config_path.is_file():
            return
        try:
            raw = self.config_path.read_bytes()
            self.config_sha256 = hashlib.sha256(raw).hexdigest()
            payload = json.loads(raw.decode("utf-8"))
            values = payload.get("integrations", []) if isinstance(payload, dict) else []
            if not isinstance(values, list):
                raise ValueError("integrations config must contain a list")
            for item in values:
                try:
                    spec = IntegrationSpec.from_dict(item)
                    if spec.integration_id in self._specs:
                        raise ValueError("duplicate integration id")
                    self._specs[spec.integration_id] = spec
                except (TypeError, ValueError) as exc:
                    self._errors.append({"status": "rejected", "reason": str(exc)})
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            self._errors.append({"status": "rejected", "reason": str(exc)})

    def list(self) -> list[dict[str, Any]]:
        return [self._specs[key].public_dict() for key in sorted(self._specs)]

    def errors(self) -> list[dict[str, str]]:
        return list(self._errors)

    def get(self, integration_id: str) -> IntegrationSpec:
        try:
            return self._specs[integration_id]
        except KeyError as exc:
            raise IntegrationError(f"unknown integration: {integration_id}") from exc


class IntegrationGateway:
    def __init__(self, registry: IntegrationRegistry) -> None:
        self.registry = registry

    def request_json(
        self,
        integration_id: str,
        operation_name: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        if timeout_seconds <= 0 or timeout_seconds > DEFAULT_TIMEOUT_SECONDS:
            raise IntegrationError("timeout_seconds must be between 0 and 10")
        spec = self.registry.get(integration_id)
        operation = spec.operation(operation_name)
        url = spec.base_url + operation.path
        _validate_public_https_url(url)
        body = None
        if operation.method == "POST":
            body = json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(body) > MAX_REQUEST_BYTES:
                raise IntegrationError("integration request exceeds the configured size limit")
        headers = {"Accept": "application/json", "User-Agent": "Resource-Studio-Integration/1"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if spec.auth_env:
            secret = os.environ.get(spec.auth_env)
            if not secret:
                raise IntegrationError(f"required credential environment variable is missing: {spec.auth_env}")
            headers["Authorization"] = f"Bearer {secret}"
        request = urllib.request.Request(url, data=body, headers=headers, method=operation.method)
        try:
            with urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout_seconds) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = int(response.status)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise IntegrationError(f"integration request failed: {type(exc).__name__}") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise IntegrationError("integration response exceeds the configured size limit")
        if status < 200 or status >= 300:
            raise IntegrationError(f"integration returned HTTP {status}")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrationError("integration response is not JSON") from exc
        if not isinstance(value, dict):
            raise IntegrationError("integration response must be a JSON object")
        return {"integrationId": integration_id, "operation": operation_name, "status": status, "data": value}


def _validate_public_https_url(value: str) -> None:
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.port not in {None, 443}:
        raise ValueError("integration endpoints must use HTTPS on the default port")
    hostname = parts.hostname.lower().rstrip(".")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise ValueError("local integration endpoints are rejected")
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ValueError("integration hostname could not be resolved") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("integration endpoint resolves to a non-public address")
