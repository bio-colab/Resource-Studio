from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import lief

from .access import path_access_status
from .deep_invariants import inspect_deep
from .project import _entries_from_lief
from .resource_index import ResourceIndex


@dataclass(frozen=True)
class HealthReport:
    path: str
    sha256: str
    size: int
    is_pe: bool
    machine: str | None
    sections: int
    resource_count: int
    signed: bool
    signature_count: int
    warnings: tuple[str, ...]
    resource_index: tuple[dict[str, Any], ...] = ()
    status: str = "VALID_PE"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["warnings"] = list(self.warnings)
        payload.pop("resource_index", None)
        payload["resourceIndex"] = [dict(item) for item in self.resource_index]
        return payload


class PEHealth:
    @staticmethod
    def inspect(path: Path) -> HealthReport:
        path = Path(path).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"file not found: {path}")
        access_status = path_access_status(path)
        if access_status in {"LOCKED", "ACCESS_DENIED", "ACCESS_ERROR"}:
            return HealthReport(
                path=str(path), sha256="", size=0, is_pe=False, machine=None,
                sections=0, resource_count=0, signed=False, signature_count=0,
                warnings=(f"file access status: {access_status}",), status=access_status,
            )
        data = path.read_bytes()
        try:
            binary = lief.parse(str(path))
        except Exception as exc:
            return HealthReport(
                path=str(path), sha256=_sha256(data), size=len(data), is_pe=False, machine=None,
                sections=0, resource_count=0, signed=False, signature_count=0,
                warnings=(f"PE parser failed: {exc}",), status="MALFORMED_PE",
            )
        if binary is None or not isinstance(binary, lief.PE.Binary):
            return HealthReport(
                path=str(path), sha256=_sha256(data), size=len(data), is_pe=False, machine=None,
                sections=0, resource_count=0, signed=False, signature_count=0,
                warnings=("file is not a supported PE",), status="NOT_PE",
            )
        entries = _entries_from_lief(binary) if binary.has_resources else []
        resource_index = tuple(ResourceIndex.from_entries(entries).to_dicts())
        signed = bool(getattr(binary, "has_signatures", False))
        signature_count = len(list(binary.signatures)) if signed else 0
        warnings: list[str] = []
        for item in resource_index:
            offset = item.get("offset")
            size = item.get("size")
            if isinstance(offset, int) and isinstance(size, int) and (offset < 0 or offset + size > len(data)):
                warnings.append(f"resource offset/size outside file bounds: {item.get('type')}:{item.get('name')}:{item.get('language')}")
        if signed:
            warnings.append("writing a new binary changes its hash; re-verify or re-sign with the owner's certificate")
        if not binary.has_resources:
            warnings.append("PE has no resource directory")
        deep = inspect_deep(path, binary=binary)
        if not deep.valid:
            warnings.extend(f"deep invariant: {issue}" for issue in deep.issues[:8])
        status = "VALID_PE" if deep.valid and not any("outside file bounds" in warning for warning in warnings) else "MALFORMED_PE"
        return HealthReport(
            path=str(path), sha256=_sha256(data), size=len(data), is_pe=True,
            machine=str(getattr(getattr(binary, "header", None), "machine", "unknown")),
            sections=len(getattr(binary, "sections", [])), resource_count=len(entries), signed=signed,
            signature_count=signature_count, warnings=tuple(warnings), resource_index=resource_index, status=status,
        )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
