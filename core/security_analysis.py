from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .deep_invariants import inspect_deep
from .evidence_model import build_evidence_summary, evidence_summary_hash
from .health import PEHealth
from .invariants import snapshot
from .pe_inspector import PEInspector
from .pe_integrity import inspect_integrity
from .raw_resource_parser import compare_with_graph, parse_raw_resources
from .security_providers import ExternalScanResult
from .signature import inspect_signature
from .verification import ResourceGraph

_SCHEMA = "resource_studio.security_report.v1"
_INJECTION_IMPORTS = {
    "virtualallocex",
    "virtualprotectex",
    "writeprocessmemory",
    "ntwritevirtualmemory",
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "setthreadcontext",
    "mapviewoffile",
}
_CRYPTO_IMPORTS = {"cryptacquirecontexta", "cryptacquirecontextw", "bcryptencrypt", "bcryptdecrypt", "cryptencrypt", "cryptdecrypt", "wincrypt", "certopenstore", "schannela"}
_NETWORK_IMPORTS = {"internetopenurla", "internetconnecta", "winhttpopen", "winhttpconnect", "wsastartup", "connect", "send", "recv", "httpsendrequesta"}
_PERSISTENCE_IMPORTS = {"createservicewa", "createservicew", "regsetvalueexa", "regopenkeyexa", "shellexecutea", "shellexecutew"}
_STRING_MARKERS = {
    "ransom-note-marker": ("ransom", "decrypt", "your files", "bitcoin"),
    "remote-control-marker": ("remote desktop", "reverse shell", "command and control"),
    "network-endpoint-marker": ("http://", "https://", ".onion"),
    "persistence-marker": ("\\\\run", "\\\\startup", "createservice", "scheduled task"),
}


def analyze_security(path: Path, external_results: tuple[ExternalScanResult, ...] = ()) -> dict[str, Any]:
    """Produce a static-only security report; never executes or mutates the target."""

    source = Path(path).expanduser().resolve()
    access = _access_probe(source)
    base: dict[str, Any] = {
        "schema": _SCHEMA,
        "target": {"path": str(source), "sha256": None, "size": None},
        "access": access,
        "parse": {"status": "NOT_RUN", "errors": []},
        "signature": None,
        "integrity": None,
        "deepInvariants": None,
        "staticIndicators": [],
        "externalScans": [result.to_dict() for result in external_results],
        "runtime": {"status": "RUNTIME_NOT_ASSESSED", "executed": False},
        "findings": [],
        "limitations": [
            "Static PE analysis cannot prove that a file is malware or that process injection occurred.",
            "No target execution, unpacking, emulation, decryption, network access, or memory inspection was performed.",
            "External scanners are not run by this report and therefore remain NOT_SCANNED.",
        ],
    }
    if not access["exists"] or not access["readable"]:
        base["parse"] = {"status": "NOT_READ", "errors": [access["error"] or "file is not readable"]}
        base["findings"].append(_finding("HIGH", "HIGH", "ACCESS", "File could not be read", access["error"] or "unknown read failure"))
        return base

    try:
        data = source.read_bytes()
        target_sha256 = hashlib.sha256(data).hexdigest()
        base["target"].update({"sha256": target_sha256, "size": len(data)})
        for result in external_results:
            if result.target_sha256 and result.target_sha256 != target_sha256:
                base["findings"].append(_finding("HIGH", "HIGH", "EXTERNAL_SCAN", "External result targets a different file", f"{result.provider}: {result.target_sha256} != {target_sha256}"))
    except OSError as exc:
        base["access"].update({"readable": False, "error": str(exc)})
        base["parse"] = {"status": "NOT_READ", "errors": [str(exc)]}
        base["findings"].append(_finding("HIGH", "HIGH", "ACCESS", "File read failed", str(exc)))
        return base

    try:
        health = PEHealth.inspect(source).to_dict()
        inspector = PEInspector.inspect(source).to_dict()
        deep = inspect_deep(source).to_dict()
        invariant = snapshot(source).to_dict()
        signature = inspect_signature(source).to_dict()
        integrity = inspect_integrity(source).to_dict()
        graph = ResourceGraph.from_path(source).to_dict()
        raw_parser = parse_raw_resources(source)
        raw = raw_parser.to_dict()
        raw_comparison = compare_with_graph(raw_parser, graph).to_dict()
        base["parse"] = {"status": "VALID_PE", "errors": [], "health": health}
        base["signature"] = signature
        base["integrity"] = integrity
        base["deepInvariants"] = deep
        base["invariants"] = invariant
        base["resourceGraph"] = graph
        base["rawResource"] = raw
        base["rawResourceComparison"] = raw_comparison
        base["staticIndicators"] = _static_indicators(inspector, deep, invariant, data)
        base["findings"].extend(_structural_findings(health, deep, raw_comparison, signature, inspector, integrity))
        for result in external_results:
            if result.status == "DETECTED":
                base["findings"].append(_finding("HIGH", "EXTERNAL", "EXTERNAL_SCAN", f"External provider detected a match: {result.provider}", "; ".join(str(item) for item in result.matches) or "provider reported DETECTED"))
            elif result.status == "ERROR":
                base["findings"].append(_finding("MEDIUM", "EXTERNAL", "EXTERNAL_SCAN", f"External provider returned an error: {result.provider}", "; ".join(result.limitations) or "provider error"))
        if raw_comparison.get("matches") is False:
            base["findings"].append(_finding("HIGH", "HIGH", "CORRUPTION", "Canonical ResourceGraph disagrees with the independent raw resource parser", "Resource corroboration failed"))
        evidence = build_evidence_summary(
            source,
            inspector=inspector,
            signature=signature,
            integrity=integrity,
            resource_graph=graph,
            raw_resource=raw,
            raw_comparison=raw_comparison,
            external_scans=[result.to_dict() for result in external_results],
        )
        base["evidence"] = evidence
        base["evidenceHash"] = evidence_summary_hash(evidence)
    except Exception as exc:
        base["parse"] = {"status": "CORRUPT_OR_UNSUPPORTED", "errors": [str(exc)]}
        base["findings"].append(_finding("HIGH", "HIGH", "CORRUPTION", "PE parsing failed", str(exc)))
        base["limitations"].append("A parse failure is not proof of malware; the file may be unsupported, truncated, encrypted, or malformed.")
    return base


def _access_probe(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "readable": False, "lockStatus": "MISSING", "error": f"file not found: {path}"}
    if not path.is_file():
        return {"exists": True, "readable": False, "lockStatus": "NOT_REGULAR_FILE", "error": "target is not a regular file"}
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except PermissionError as exc:
        return {"exists": True, "readable": False, "lockStatus": "ACCESS_DENIED", "error": str(exc)}
    except OSError as exc:
        return {"exists": True, "readable": False, "lockStatus": "READ_ERROR", "error": str(exc)}
    result = {"exists": True, "readable": True, "lockStatus": "UNKNOWN", "error": None}
    if os.name == "nt":
        result["lockStatus"] = _windows_sharing_probe(path)
    else:
        result["lockStatus"] = "UNSUPPORTED_PLATFORM"
    return result


def _windows_sharing_probe(path: Path) -> str:
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
        invalid = ctypes.c_void_p(-1).value
        if handle in (-1, invalid):
            error = ctypes.get_last_error()
            if error in (32, 33):
                return "SHARING_VIOLATION"
            if error == 5:
                return "ACCESS_DENIED"
            return f"WIN32_ERROR_{error}"
        kernel32.CloseHandle(wintypes.HANDLE(handle))
        return "UNLOCKED"
    except Exception:
        return "UNKNOWN"


def _static_indicators(inspector: dict[str, Any], deep: dict[str, Any], invariant: dict[str, Any], data: bytes) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    overlay = invariant.get("overlay", {})
    if int(overlay.get("size", 0)) > 0:
        indicators.append({"id": f"TAMPER-{len(indicators) + 1:03d}", "category": "TAMPER", "kind": "OVERLAY_DATA", "offset": overlay.get("offset"), "size": overlay.get("size"), "sha256": overlay.get("sha256"), "confidence": "HIGH", "limitation": "Overlay data can be legitimate installer or publisher data; it is not proof of implantation."})
    entrypoint = int(invariant.get("entrypoint", 0))
    executable_ranges = [(int(item.get("virtualAddress", 0)), int(item.get("virtualAddress", 0)) + max(int(item.get("virtualSize", 0)), int(item.get("rawSize", 0)))) for item in inspector.get("sections", []) if int(item.get("characteristics", 0)) & 0x20000000]
    if entrypoint and not any(start <= entrypoint < end for start, end in executable_ranges):
        indicators.append({"id": f"TAMPER-{len(indicators) + 1:03d}", "category": "TAMPER", "kind": "ENTRYPOINT_OUTSIDE_EXECUTABLE_SECTION", "value": entrypoint, "confidence": "HIGH", "limitation": "Malformed or unusual PE layout can cause this observation; it does not identify an actor."})
    for section in inspector.get("sections", []):
        entropy = float(section.get("entropy", 0.0))
        name = str(section.get("name", ""))
        if entropy >= 7.2:
            indicators.append({"id": f"OBF-{len(indicators) + 1:03d}", "category": "OBFUSCATION", "kind": "HIGH_ENTROPY_SECTION", "section": name, "value": entropy, "confidence": "LIMITED", "limitation": "High entropy may be caused by compression, encryption, media, or legitimate generated data."})
        characteristics = int(section.get("characteristics", 0))
        if characteristics & 0x20000000 and characteristics & 0x80000000:
            indicators.append({"id": f"INJ-{len(indicators) + 1:03d}", "category": "INJECTION", "kind": "EXECUTABLE_WRITABLE_SECTION", "section": name, "confidence": "LIMITED", "limitation": "This is a static indicator only and does not prove process injection or malicious code."})
    imports = {str(entry.get("name", "")).lower() for library in inspector.get("imports", []) for entry in library.get("entries", [])}
    for category, kind, names, limitation in (("CRYPTO", "CRYPTO_RELATED_IMPORTS", _CRYPTO_IMPORTS, "Crypto APIs are common in TLS, installers, DRM, and document protection."), ("NETWORK", "NETWORK_RELATED_IMPORTS", _NETWORK_IMPORTS, "Network APIs are common in legitimate applications and do not prove C2."), ("PERSISTENCE", "PERSISTENCE_RELATED_IMPORTS", _PERSISTENCE_IMPORTS, "Persistence APIs are common in installers and services.")):
        matched = sorted(name for name in imports if name in names)
        if matched:
            indicators.append({"id": f"{category}-{len(indicators) + 1:03d}", "category": category, "kind": kind, "imports": matched, "confidence": "LIMITED", "limitation": limitation})
    matched = sorted(name for name in imports if name in _INJECTION_IMPORTS)
    if matched:
        indicators.append({"id": f"INJ-{len(indicators) + 1:03d}", "category": "INJECTION", "kind": "INJECTION_RELATED_IMPORTS", "imports": matched, "confidence": "LIMITED", "limitation": "Imports can be used by legitimate debuggers, installers, accessibility tools, and security software; runtime telemetry is required for attribution."})
    text = data.decode("latin-1", errors="ignore").lower()
    for marker, needles in _STRING_MARKERS.items():
        matched_needles = [needle for needle in needles if needle in text]
        if matched_needles:
            indicators.append({"id": f"STRING-{len(indicators) + 1:03d}", "category": "STRING_MARKER", "kind": marker, "matches": matched_needles, "confidence": "LIMITED", "limitation": "Strings can be decoys, documentation, test data, or legitimate application content."})
    for issue in deep.get("issues", []):
        indicators.append({"id": f"COR-{len(indicators) + 1:03d}", "category": "CORRUPTION", "kind": "DEEP_INVARIANT_ISSUE", "value": issue, "confidence": "HIGH"})
    return indicators


def _structural_findings(health: dict[str, Any], deep: dict[str, Any], raw_comparison: dict[str, Any], signature: dict[str, Any], inspector: dict[str, Any], integrity: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not health.get("is_pe", False):
        findings.append(_finding("HIGH", "HIGH", "CORRUPTION", "Input is not a supported PE", "PEHealth rejected the input"))
    if not deep.get("valid", False):
        findings.append(_finding("HIGH", "HIGH", "CORRUPTION", "Deep PE invariants failed", "; ".join(deep.get("issues", []))))
    if raw_comparison.get("matches") is False:
        findings.append(_finding("HIGH", "HIGH", "CORRUPTION", "Raw resource corroboration failed", "ResourceGraph and raw parser disagree"))
    if signature.get("present") and signature.get("verification") not in {"VALID", "valid", None}:
        findings.append(_finding("MEDIUM", "LIMITED", "SIGNATURE", "Authenticode state is not confirmed as trusted", str(signature.get("verification"))))
    for warning in integrity.get("warnings", []):
        findings.append(_finding("MEDIUM" if "checksum" not in str(warning).lower() else "INFO", "LIMITED", "INTEGRITY", "PE integrity warning", str(warning)))
    return findings


def _finding(severity: str, confidence: str, category: str, title: str, detail: str) -> dict[str, Any]:
    stable = hashlib.sha256(f"{category}|{title}|{detail}".encode("utf-8")).hexdigest()[:10].upper()
    return {"id": f"SEC-{category}-{stable}", "severity": severity, "confidence": confidence, "category": category, "title": title, "detail": detail, "evidenceRefs": [], "limitations": []}


__all__ = ["analyze_security"]
