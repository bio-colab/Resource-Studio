from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping


_SCHEMA = "resource_studio.evidence_summary.v1"


def build_evidence_summary(
    path: Path,
    *,
    inspector: Mapping[str, Any] | None = None,
    signature: Mapping[str, Any] | None = None,
    integrity: Mapping[str, Any] | None = None,
    resource_graph: Mapping[str, Any] | None = None,
    raw_resource: Mapping[str, Any] | None = None,
    raw_comparison: Mapping[str, Any] | None = None,
    verification: Mapping[str, Any] | None = None,
    external_scans: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Normalize existing PE reports into attributable observations and findings."""

    source = Path(path).expanduser().resolve()
    data = source.read_bytes()
    inspector = dict(inspector or {})
    signature = dict(signature or {})
    integrity = dict(integrity or {})
    resource_graph = dict(resource_graph or {})
    raw_resource = dict(raw_resource or {})
    raw_comparison = dict(raw_comparison or {})
    verification = dict(verification or {})
    external_scan_records = [dict(item) for item in (external_scans or ()) if isinstance(item, Mapping)]
    observations: list[dict[str, Any]] = []

    def observe(
        subject: str,
        property_name: str,
        value: Any,
        source_name: str,
        parser: str,
        *,
        confidence: str = "HIGH",
        raw_range: Mapping[str, Any] | None = None,
    ) -> str:
        observation_id = f"O-{len(observations) + 1:04d}"
        item = {
            "id": observation_id,
            "subject": subject,
            "property": property_name,
            "value": value,
            "source": source_name,
            "parser": parser,
            "confidence": confidence,
        }
        if raw_range is not None:
            item["rawRange"] = dict(raw_range)
        observations.append(item)
        return observation_id

    observe("file", "sha256", hashlib.sha256(data).hexdigest(), "file-bytes", "sha256")
    observe("file", "size", len(data), "file-bytes", "filesystem")
    for key in ("machine", "entrypoint", "imagebase", "checksum", "computedChecksum", "checksumValid"):
        if key in inspector:
            observe("pe", key, inspector[key], "LIEF", "PEInspector")

    leaves = list(resource_graph.get("leaves", []))
    raw_leaves = {tuple([item.get("type"), str(item.get("name")), item.get("language")]): item for item in raw_resource.get("leaves", [])}
    for leaf in leaves:
        key = (leaf.get("type"), str(leaf.get("name")), leaf.get("language"))
        subject = f"resource:{key[0]}/{key[1]}/{key[2]}"
        raw_range = {"offset": leaf.get("offset", 0), "length": leaf.get("size", 0)}
        for property_name in ("size", "sha256", "codePage", "semanticFingerprint"):
            if property_name in leaf:
                observe(subject, property_name, leaf[property_name], "LIEF", "ResourceGraph", raw_range=raw_range)
        raw_leaf = raw_leaves.get(key)
        if raw_leaf is not None:
            observe(subject, "sha256", raw_leaf.get("sha256"), "raw-pe", "IMAGE_RESOURCE_DIRECTORY", raw_range={"offset": raw_leaf.get("offset", 0), "length": raw_leaf.get("size", 0)})

    for section in inspector.get("sections", []):
        subject = f"section:{section.get('name', '')}"
        for property_name in ("rawOffset", "rawSize", "virtualAddress", "virtualSize", "entropy"):
            if property_name in section:
                observe(subject, property_name, section[property_name], "LIEF", "PEInspector", confidence="MEDIUM" if property_name == "entropy" else "HIGH")

    if signature:
        for key in ("present", "signatureCount", "verification", "certificateTable"):
            if key in signature:
                observe("authenticode", key, signature[key], "LIEF", "SignatureInspector", confidence="LIMITED" if key == "verification" else "HIGH")
    if integrity:
        for key in ("storedChecksum", "liefChecksum", "windowsChecksum", "checksumValidLief", "checksumValidWindows", "warnings"):
            if key in integrity:
                observe("integrity", key, integrity[key], "PEIntegrity", "inspect_integrity", confidence="LIMITED" if key == "checksumValidWindows" and integrity[key] is None else "HIGH")

    graph_issues = list(resource_graph.get("issues", []))
    raw_issues = list(raw_resource.get("issues", []))
    findings: list[dict[str, Any]] = []

    def finding(
        severity: str,
        confidence: str,
        title: str,
        detail: str,
        *,
        observation_ids: list[str] | None = None,
        limitations: list[str] | None = None,
    ) -> None:
        findings.append({
            "id": f"F-{len(findings) + 1:03d}",
            "severity": severity,
            "confidence": confidence,
            "title": title,
            "detail": detail,
            "observationIds": list(observation_ids or []),
            "limitations": list(limitations or []),
        })

    if graph_issues:
        finding("HIGH", "HIGH", "Resource graph reports structural issues", "; ".join(graph_issues), limitations=["Canonical graph validation does not replace the Windows loader oracle."])
    if raw_issues or raw_comparison.get("matches") is False:
        detail = "; ".join(raw_issues) or "Raw resource leaves disagree with the canonical graph"
        finding("HIGH", "HIGH", "Raw resource corroboration has a discrepancy", detail, limitations=["Raw parser coverage is intentionally bounded to the PE resource directory model."])
    for warning in integrity.get("warnings", []):
        severity = "HIGH" if "checksum" in str(warning).lower() and "does not match" in str(warning).lower() else "INFO"
        finding(severity, "HIGH", "PE integrity observation", str(warning), limitations=["Checksum state is not a cryptographic authenticity verdict."])
    if signature.get("present"):
        finding("INFO", "LIMITED", "Authenticode state requires platform verification", "A certificate table is present; trust must be checked with WinVerifyTrust on Windows.", limitations=["Static certificate presence is not equivalent to trusted signature validation."])
    for warning in inspector.get("warnings", []):
        finding("MEDIUM", "MEDIUM", "PE inspector warning", str(warning))
    if verification:
        for error in verification.get("errors", []):
            finding("HIGH", "HIGH", "Verification error", str(error))

    resource_types = sorted({str(item.get("type")) for item in leaves})
    languages = sorted({int(item.get("language")) for item in leaves if item.get("language") is not None})
    largest = max((int(item.get("size", 0)) for item in leaves), default=0)
    corroborated = bool(raw_comparison.get("matches")) if raw_comparison else None
    return {
        "schema": _SCHEMA,
        "capturedAtUtc": datetime.now(UTC).isoformat(),
        "artifact": {"path": str(source), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
        "provenance": {"sources": ["file-bytes", "LIEF", "PEIntegrity", "ResourceGraph", "raw-pe"], "normalization": _SCHEMA},
        "observations": observations,
        "corroboration": {"resourceGraphVsRaw": "CORROBORATED" if corroborated is True else "DISCREPANCY" if corroborated is False else "NOT_RUN"},
        "statistics": {"resources": len(leaves), "uniqueTypes": len(resource_types), "types": resource_types, "languages": languages, "largestResource": largest, "sections": len(inspector.get("sections", [])), "imports": sum(len(item.get("entries", [])) for item in inspector.get("imports", [])), "exports": len(inspector.get("exports", []))},
        "findings": findings,
        "externalScans": external_scan_records,
    }


def evidence_summary_hash(summary: Mapping[str, Any]) -> str:
    """Hash a summary without its capture timestamp for stable comparisons."""
    payload = dict(summary)
    payload.pop("capturedAtUtc", None)
    artifact = dict(payload.get("artifact", {}))
    artifact.pop("path", None)
    payload["artifact"] = artifact
    import json

    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


__all__ = ["build_evidence_summary", "evidence_summary_hash"]


# ponytail: keep normalization as a function until a second evidence schema needs independent behavior.
