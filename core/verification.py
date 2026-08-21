from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile

import lief
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .deep_invariants import inspect_deep
from .invariants import snapshot
from .pe_integrity import inspect_integrity
from .roundtrip_contracts import default_registry


@dataclass(frozen=True)
class ResourceGraph:
    """Canonical resource leaves plus stable semantic fingerprints."""

    leaves: tuple[dict[str, Any], ...]
    issues: tuple[str, ...]
    fingerprint: str
    layout_fingerprint: str

    @classmethod
    def from_path(cls, path: Path, *, binary: Any | None = None) -> "ResourceGraph":
        path = Path(path).expanduser().resolve()
        binary = binary if binary is not None else lief.parse(str(path))
        state = snapshot(path, binary=binary)
        data_by_key = {
            (resource_type, name, language): data
            for resource_type, name, language, data in _entries(binary)
        }
        leaves: list[dict[str, Any]] = []
        for item in state.resources:
            leaf = dict(item)
            key = (str(item["type"]), str(item["name"]), int(item["language"]))
            leaf["semanticFingerprint"] = semantic_fingerprint(str(item["type"]), data_by_key.get(key, b""))
            leaves.append(leaf)
        leaves.sort(key=_leaf_key)
        semantic = [_stable_leaf(item, include_layout=False) for item in leaves]
        layout = [_stable_leaf(item, include_layout=True) for item in leaves]
        return cls(
            tuple(leaves),
            tuple(state.resource_issues),
            _json_hash(semantic),
            _json_hash(layout),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "leafCount": len(self.leaves),
            "leaves": [dict(item) for item in self.leaves],
            "issues": list(self.issues),
            "fingerprint": self.fingerprint,
            "layoutFingerprint": self.layout_fingerprint,
        }


@dataclass(frozen=True)
class VerificationContext:
    """One parsed PE plus its reusable structural and resource graph views."""

    path: Path
    state: Any
    graph: ResourceGraph
    deep_invariants: dict[str, Any]
    integrity: dict[str, Any]

    @classmethod
    def from_path(cls, path: Path) -> "VerificationContext":
        path = Path(path).expanduser().resolve()
        binary = lief.parse(str(path))
        if binary is None or not isinstance(binary, lief.PE.Binary):
            raise ValueError(f"not a supported PE: {path}")
        return cls(
            path,
            snapshot(path, binary=binary),
            ResourceGraph.from_path(path, binary=binary),
            inspect_deep(path, binary=binary).to_dict(),
            inspect_integrity(path, binary=binary).to_dict(),
        )


@dataclass(frozen=True)
class VerificationReport:
    passed: bool
    phases: tuple[dict[str, Any], ...]
    target_changed: bool
    resource_round_trip: bool
    semantic_diff: dict[str, Any]
    preservation: dict[str, bool]
    windows: dict[str, Any]
    signature: dict[str, Any]
    integrity: dict[str, Any]
    deep_invariants: dict[str, Any]
    before_graph: dict[str, Any]
    after_graph: dict[str, Any]
    errors: tuple[str, ...] = ()

    @property
    def platform_limited(self) -> bool:
        return self.windows.get("status") in {"SKIPPED", "UNAVAILABLE"} or self.signature.get("status") in {"SKIPPED", "UNAVAILABLE"}

    @property
    def verified(self) -> bool:
        return self.passed and not self.platform_limited

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verified": self.verified,
            "platformLimited": self.platform_limited,
            "phases": [dict(item) for item in self.phases],
            "targetChanged": self.target_changed,
            "resourceRoundTrip": self.resource_round_trip,
            "semanticDiff": dict(self.semantic_diff),
            "preservation": dict(self.preservation),
            "windows": dict(self.windows),
            "signature": dict(self.signature),
            "integrity": dict(self.integrity),
            "deepInvariants": dict(self.deep_invariants),
            "beforeGraph": dict(self.before_graph),
            "afterGraph": dict(self.after_graph),
            "errors": list(self.errors),
        }


def semantic_fingerprint(resource_type: str, data: bytes) -> str:
    """Return a stable fingerprint; typed resources use existing round-trip contracts."""

    contract_name = {
        "MANIFEST": "manifest.xml",
        "MENU": "menu.binary",
        "VERSION": "version-info.binary",
    }.get(resource_type.upper(), "raw.bytes")
    try:
        contract = default_registry().get(contract_name)
        model = contract.parse(bytes(data))
        canonical = contract.normalize(model)
        payload = {"contract": contract_name, "value": canonical}
    except Exception:
        payload = {"contract": "raw.bytes", "value": hashlib.sha256(bytes(data)).hexdigest()}
    return _json_hash(payload)


def verify_candidate(
    before_path: Path,
    candidate_path: Path,
    *,
    resource_type: str | int,
    resource_name: str | int,
    language: int | None,
    operation: str,
    expected_data: bytes | None = None,
    committed: bool = False,
    before_context: VerificationContext | None = None,
    candidate_context: VerificationContext | None = None,
) -> VerificationReport:
    """Verify a serialized candidate before or after durable commit."""

    before_path = Path(before_path).expanduser().resolve()
    candidate_path = Path(candidate_path).expanduser().resolve()
    phases: list[dict[str, Any]] = []
    errors: list[str] = []
    _phase(phases, "PLAN", True, "verification contract selected")
    _phase(phases, "MUTATE", True, f"operation={operation}")
    serialized = candidate_path.is_file() and candidate_path.stat().st_size > 0
    _phase(phases, "SERIALIZE", serialized, str(candidate_path))
    if not serialized:
        return _failed_report(phases, errors, "candidate is missing or empty")

    try:
        after_context = candidate_context or VerificationContext.from_path(candidate_path)
        before_context = before_context or VerificationContext.from_path(before_path)
        after_state = after_context.state
        before_state = before_context.state
        _phase(phases, "REOPEN", True, "LIEF reopened candidate")
    except Exception as exc:
        return _failed_report(phases, errors, f"reopen failed: {exc}")

    integrity = after_context.integrity
    deep_invariants = after_context.deep_invariants
    structural_ok = bool(deep_invariants.get("valid")) and not after_state.resource_issues
    _phase(phases, "STRUCTURAL_VALIDATION", structural_ok, "valid PE, geometry, directories, and resource bounds")

    before_graph = before_context.graph
    after_graph = after_context.graph
    graph_diff = _graph_diff(before_graph, after_graph)
    graph_ok = not after_graph.issues
    _phase(phases, "RESOURCE_GRAPH_VALIDATION", graph_ok, f"{len(after_graph.leaves)} canonical leaves")

    target = (str(resource_type), str(resource_name), language)
    target_changed = _target_changed(graph_diff, target, operation)
    expected_ok = _expected_payload_matches(after_graph, target, expected_data, operation)
    semantic_ok = expected_ok and (target_changed or operation == "replace")
    _phase(phases, "SEMANTIC_DIFF", semantic_ok, f"targetChanged={target_changed}")

    preservation = _deep_preservation(before_state, after_state)
    preservation_ok = all(preservation.values())
    _phase(phases, "PRESERVATION_CHECK", preservation_ok, _failed_fields(preservation))

    windows = _windows_validation(
        before_path,
        candidate_path,
        resource_type=resource_type,
        resource_name=resource_name,
        language=language,
        operation=operation,
    )
    windows_ok = windows.get("status") in {"PASSED", "SKIPPED"}
    _phase(phases, "WINDOWS_VALIDATION", windows_ok, str(windows.get("status")))

    signature = _signature_validation(candidate_path)
    signature_ok = signature.get("status") in {"VALID", "NOT_SIGNED", "SKIPPED"}
    _phase(phases, "AUTHENTICODE_VERIFICATION", signature_ok, str(signature.get("status")))

    commit_ok = committed
    _phase(phases, "COMMIT", commit_ok, "durable commit completed" if committed else "pending durable commit")
    _phase(phases, "AUDIT", True, "verification report available")
    all_ok = structural_ok and graph_ok and semantic_ok and preservation_ok and windows_ok and signature_ok and (committed or not committed)
    if not committed:
        all_ok = structural_ok and graph_ok and semantic_ok and preservation_ok and windows_ok and signature_ok
    return VerificationReport(
        all_ok,
        tuple(phases),
        target_changed and expected_ok,
        semantic_ok,
        graph_diff,
        preservation,
        windows,
        signature,
        integrity,
        deep_invariants,
        before_graph.to_dict(),
        after_graph.to_dict(),
        tuple(errors),
    )


def _resource_bytes(path: Path, item: dict[str, Any]) -> bytes:
    from .pe_writer import LiefPEWriter

    binary = LiefPEWriter()._parse(path)
    for entry in _entries(binary):
        if (
            entry[0] == str(item["type"])
            and entry[1] == str(item["name"])
            and entry[2] == int(item["language"])
        ):
            return entry[3]
    return b""


def _entries(binary: Any) -> list[tuple[str, str, int, bytes]]:
    type_names = {
        1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
        7: "FONTDIR", 8: "FONT", 9: "ACCELERATORS", 10: "RCDATA", 11: "MESSAGETABLE",
        12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST",
    }
    if not binary.has_resources:
        return []
    result = []
    for type_node in binary.resources.childs:
        resource_type = str(type_node.name) if getattr(type_node, "has_name", False) else type_names.get(int(type_node.id), str(type_node.id))
        for name_node in type_node.childs:
            name = str(name_node.name) if getattr(name_node, "has_name", False) else str(name_node.id)
            for leaf in name_node.childs:
                result.append((resource_type, name, int(leaf.id), bytes(leaf.content)))
    return result


def _graph_diff(before: ResourceGraph, after: ResourceGraph) -> dict[str, Any]:
    left = {_leaf_key(item): item for item in before.leaves}
    right = {_leaf_key(item): item for item in after.leaves}
    added = sorted(set(right) - set(left))
    removed = sorted(set(left) - set(right))
    changed = sorted(key for key in set(left) & set(right) if _stable_leaf(left[key], False) != _stable_leaf(right[key], False))
    return {
        "beforeFingerprint": before.fingerprint,
        "afterFingerprint": after.fingerprint,
        "added": [list(key) for key in added],
        "removed": [list(key) for key in removed],
        "changed": [list(key) for key in changed],
    }


def _target_changed(diff: dict[str, Any], target: tuple[str, str, int | None], operation: str) -> bool:
    def matches(item: list[Any]) -> bool:
        return item[0] == target[0] and item[1] == target[1] and (target[2] is None or int(item[2]) == int(target[2]))

    changed = any(matches(item) for item in diff["changed"])
    added = any(matches(item) for item in diff["added"])
    removed = any(matches(item) for item in diff["removed"])
    return {"replace": changed, "add": added, "delete": removed, "change-language": added or removed}.get(operation, changed or added or removed)


def _expected_payload_matches(graph: ResourceGraph, target: tuple[str, str, int | None], expected: bytes | None, operation: str) -> bool:
    def matches(item: dict[str, Any]) -> bool:
        key = _leaf_key(item)
        return key[0] == target[0] and key[1] == target[1] and (target[2] is None or key[2] == int(target[2]))

    if operation == "delete":
        return not any(matches(item) for item in graph.leaves)
    if expected is None:
        return True
    expected_hash = hashlib.sha256(bytes(expected)).hexdigest()
    return any(matches(item) and item["sha256"] == expected_hash for item in graph.leaves)


def _deep_preservation(before: Any, after: Any) -> dict[str, bool]:
    return {
        "importsPreserved": before.imports == after.imports,
        "exportsPreserved": before.exports == after.exports,
        "tlsPreserved": before.tls == after.tls,
        "loadConfigPreserved": before.load_config == after.load_config,
        "debugPreserved": before.debug == after.debug,
        "overlayPreserved": before.overlay == after.overlay,
        "directoriesPreserved": before.directories == after.directories,
        "nonResourceSectionsPreserved": tuple(x for x in before.sections if not x["isResource"]) == tuple(x for x in after.sections if not x["isResource"]),
        "headerPreserved": _header(before) == _header(after),
    }


def _header(state: Any) -> tuple[Any, ...]:
    return (state.machine, state.imagebase, state.entrypoint)


def _windows_validation(
    before_path: Path,
    candidate_path: Path,
    *,
    resource_type: str | int,
    resource_name: str | int,
    language: int | None,
    operation: str,
) -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "SKIPPED", "reason": "Windows-only oracle"}
    from .windows_resource_oracle import compare_with_lief, inspect

    oracle_before_path = before_path
    staged_before_path: Path | None = None
    if before_path.parent != candidate_path.parent:
        descriptor, staged_name = tempfile.mkstemp(dir=candidate_path.parent, prefix="resource-studio-oracle-before-", suffix=before_path.suffix)
        os.close(descriptor)
        staged_before_path = Path(staged_name)
        shutil.copy2(before_path, staged_before_path)
        oracle_before_path = staged_before_path
    try:
        before = inspect(oracle_before_path)
        after = inspect(candidate_path)
    finally:
        if staged_before_path is not None:
            staged_before_path.unlink(missing_ok=True)
    before_map = {item.key: item.sha256 for item in before.resources}
    after_map = {item.key: item.sha256 for item in after.resources}
    oracle_added = sorted(set(after_map) - set(before_map))
    oracle_removed = sorted(set(before_map) - set(after_map))
    oracle_changed = sorted(key for key in set(before_map) & set(after_map) if before_map[key] != after_map[key])
    target_type = str(resource_type)
    target_name = str(resource_name)

    def is_target(item: tuple[str, str, int]) -> bool:
        return item[0] == target_type and item[1] == target_name and (language is None or item[2] == int(language))

    target_candidates = sorted(item for item in (*oracle_added, *oracle_removed, *oracle_changed) if is_target(item))
    target = list(target_candidates[0]) if target_candidates else [target_type, target_name, int(language or 0)]
    target_added = any(is_target(item) for item in oracle_added)
    target_removed = any(is_target(item) for item in oracle_removed)
    target_changed = any(is_target(item) for item in oracle_changed)
    if operation == "add":
        target_ok = target_added or target_changed
        unexpected_removed = oracle_removed
    elif operation == "delete":
        target_ok = target_removed
        unexpected_removed = [item for item in oracle_removed if not is_target(item)]
    elif operation == "change-language":
        target_ok = target_added or target_removed
        unexpected_removed = [item for item in oracle_removed if not is_target(item)]
    else:
        target_ok = target_changed
        unexpected_removed = [item for item in oracle_removed if not is_target(item)]
    unexpected_changed = [item for item in oracle_changed if not is_target(item)]
    comparison = compare_with_lief(candidate_path)
    passed = (
        not before.warnings
        and not after.warnings
        and target_ok
        and not unexpected_removed
        and not unexpected_changed
    )
    return {
        "status": "PASSED" if passed else "FAILED",
        "beforeResourceCount": before.resource_count,
        "afterResourceCount": after.resource_count,
        "beforeWarnings": list(before.warnings),
        "afterWarnings": list(after.warnings),
        "added": [list(item) for item in oracle_added],
        "removed": [list(item) for item in oracle_removed],
        "changed": [list(item) for item in oracle_changed],
        "target": list(target),
        "targetChanged": target_changed,
        "targetAdded": target_added,
        "targetRemoved": target_removed,
        "unexpectedRemoved": [list(item) for item in unexpected_removed],
        "unexpectedChanged": [list(item) for item in unexpected_changed],
        "liefComparison": comparison.to_dict(),
        "liefVisibility": "MATCHED" if comparison.matches else "WINDOWS_LOADER_SUBSET",
        "pathScoped": staged_before_path is not None,
    }


def _signature_validation(path: Path) -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "SKIPPED", "reason": "WinVerifyTrust is Windows-only"}
    from .windows_security import verify_authenticode_native

    return verify_authenticode_native(path)


def _leaf_key(item: dict[str, Any]) -> tuple[str, str, int]:
    return str(item["type"]), str(item["name"]), int(item["language"])


def _stable_leaf(item: dict[str, Any], include_layout: bool) -> dict[str, Any]:
    keys = ("type", "name", "language", "semanticFingerprint")
    if include_layout:
        keys += ("size", "sha256", "codePage", "offset")
    return {key: item.get(key) for key in keys}


def _json_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=list).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _phase(phases: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    phases.append({"name": name, "status": "PASSED" if passed else "FAILED", "detail": detail})


def _failed_report(phases: list[dict[str, Any]], errors: list[str], error: str) -> VerificationReport:
    errors.append(error)
    return VerificationReport(False, tuple(phases), False, False, {}, {}, {"status": "FAILED"}, {"status": "SKIPPED"}, {"isPE": False}, {}, {}, {}, tuple(errors))


def _failed_fields(values: dict[str, bool]) -> str:
    failed = [key for key, value in values.items() if not value]
    return ",".join(failed) if failed else "all preservation checks passed"
