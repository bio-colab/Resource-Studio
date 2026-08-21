from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence_model import build_evidence_summary
from .invariants import snapshot
from .pe_inspector import PEInspector
from .pe_integrity import inspect_integrity
from .raw_resource_parser import compare_with_graph, parse_raw_resources
from .signature import inspect_signature
from .verification import ResourceGraph


def build_post_write_diagnostics(before_path: Path, after_path: Path) -> dict[str, Any]:
    """Explain before/after PE changes without mutating either file."""

    before_path = Path(before_path).expanduser().resolve()
    after_path = Path(after_path).expanduser().resolve()
    before_inspector = PEInspector.inspect(before_path).to_dict()
    after_inspector = PEInspector.inspect(after_path).to_dict()
    before_state = snapshot(before_path)
    after_state = snapshot(after_path)
    before_graph = ResourceGraph.from_path(before_path).to_dict()
    after_graph = ResourceGraph.from_path(after_path).to_dict()
    before_integrity = inspect_integrity(before_path).to_dict()
    after_integrity = inspect_integrity(after_path).to_dict()
    before_signature = inspect_signature(before_path).to_dict()
    after_signature = inspect_signature(after_path).to_dict()

    try:
        raw_after = parse_raw_resources(after_path)
        raw_resource = raw_after.to_dict()
        raw_comparison = compare_with_graph(raw_after, after_graph).to_dict()
    except Exception as exc:
        raw_resource = {"path": str(after_path), "leafCount": 0, "leaves": [], "issues": [], "parserError": str(exc)}
        raw_comparison = {}

    protected = {
        "sections": _section_records(before_state.sections, resource=False) == _section_records(after_state.sections, resource=False),
        "directories": before_state.directories == after_state.directories,
        "imports": before_state.imports == after_state.imports,
        "exports": before_state.exports == after_state.exports,
        "tls": before_state.tls == after_state.tls,
        "loadConfig": before_state.load_config == after_state.load_config,
        "debug": before_state.debug == after_state.debug,
        "overlay": before_state.overlay == after_state.overlay,
    }
    resource_diff = _resource_diff(before_graph, after_graph)
    findings: list[dict[str, Any]] = []

    def add(severity: str, title: str, detail: str, limitation: str | None = None) -> None:
        item = {"id": f"D-{len(findings) + 1:03d}", "severity": severity, "title": title, "detail": detail}
        if limitation:
            item["limitation"] = limitation
        findings.append(item)

    failed = [name for name, preserved in protected.items() if not preserved]
    if failed:
        add("HIGH", "Protected PE structures changed", ", ".join(failed), "Review the before/after evidence before distributing the output.")
    if before_state.overlay != after_state.overlay:
        add("HIGH", "Overlay changed", "The bytes after the last PE section differ.")
    if after_graph.get("issues"):
        add("HIGH", "Resource graph has issues", "; ".join(after_graph["issues"]))
    if raw_comparison.get("matches") is False:
        add("HIGH", "Raw resource corroboration failed", "The independent raw resource directory does not match the canonical graph.")
    if after_integrity.get("warnings"):
        add("MEDIUM", "Integrity warnings present", "; ".join(after_integrity["warnings"]), "Checksum state is not a cryptographic authenticity verdict.")
    if before_signature != after_signature:
        add("INFO", "Authenticode state changed", "The certificate/signature report differs; re-verify trust on Windows before release.")
    if not findings:
        add("INFO", "No protected structure differences detected", "The compared output differs only within the resource graph or not at all.")

    evidence = build_evidence_summary(
        after_path,
        inspector=after_inspector,
        signature=after_signature,
        integrity=after_integrity,
        resource_graph=after_graph,
        raw_resource=raw_resource,
        raw_comparison=raw_comparison,
    )
    return {
        "schema": "resource_studio.post_write_diagnostics.v1",
        "before": {"path": str(before_path), "sha256": _sha256(before_path), "size": before_path.stat().st_size},
        "after": {"path": str(after_path), "sha256": _sha256(after_path), "size": after_path.stat().st_size},
        "sizeDelta": after_path.stat().st_size - before_path.stat().st_size,
        "protected": protected,
        "sections": {"before": list(before_inspector.get("sections", [])), "after": list(after_inspector.get("sections", [])), "nonResourcePreserved": protected["sections"]},
        "directories": {"before": [dict(item) for item in before_state.directories], "after": [dict(item) for item in after_state.directories], "preserved": protected["directories"]},
        "checksum": {"before": before_integrity, "after": after_integrity},
        "signature": {"before": before_signature, "after": after_signature, "changed": before_signature != after_signature},
        "overlay": {"before": dict(before_state.overlay), "after": dict(after_state.overlay), "preserved": protected["overlay"]},
        "resources": resource_diff,
        "rawResource": raw_resource,
        "rawResourceComparison": raw_comparison,
        "findings": findings,
        "evidence": evidence,
    }


def _resource_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    left = {_key(item): item for item in before.get("leaves", [])}
    right = {_key(item): item for item in after.get("leaves", [])}
    added = sorted(set(right) - set(left))
    removed = sorted(set(left) - set(right))
    changed = sorted(key for key in set(left) & set(right) if _stable(left[key]) != _stable(right[key]))
    return {
        "beforeFingerprint": before.get("fingerprint"),
        "afterFingerprint": after.get("fingerprint"),
        "added": [list(item) for item in added],
        "removed": [list(item) for item in removed],
        "changed": [list(item) for item in changed],
        "changedCount": len(added) + len(removed) + len(changed),
    }


def _section_records(sections: Any, *, resource: bool) -> tuple[dict[str, Any], ...]:
    return tuple(dict(item) for item in sections if bool(item.get("isResource")) is resource)


def _key(item: dict[str, Any]) -> tuple[str, str, int]:
    return str(item.get("type")), str(item.get("name")), int(item.get("language", 0))


def _stable(item: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(item.get(key) for key in ("type", "name", "language", "semanticFingerprint", "size", "sha256", "codePage"))


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = ["build_post_write_diagnostics"]
