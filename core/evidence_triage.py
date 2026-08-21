from __future__ import annotations

from typing import Any, Mapping


_SCHEMA = "resource_studio.evidence_triage.v1"
_LEVELS = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}
_COLORS = {"NONE": "#6B7280", "INFO": "#2563EB", "LOW": "#A855F7", "MEDIUM": "#D97706", "HIGH": "#DC2626"}


def build_triage_map(report: Mapping[str, Any]) -> dict[str, Any]:
    """Map existing security/evidence signals to visual triage only.

    This contract never changes a verdict. It provides stable colors and reasons
    so WPF can render a resource tree without parsing free-form report text.
    """

    resources: dict[str, dict[str, Any]] = {}

    def mark(key: str, level: str, reason: str, source: str) -> None:
        normalized = level.upper() if level.upper() in _LEVELS else "MEDIUM"
        current = resources.get(key)
        if current is None or _LEVELS[normalized] > _LEVELS[current["level"]]:
            resources[key] = {"level": normalized, "color": _COLORS[normalized], "reasons": [reason], "sources": [source]}
        elif reason not in current["reasons"]:
            current["reasons"].append(reason)
            if source not in current["sources"]:
                current["sources"].append(source)

    global_level = "NONE"
    global_reasons: list[str] = []
    parse_status = str(report.get("parse", {}).get("status", ""))
    if parse_status == "CORRUPT_OR_UNSUPPORTED":
        global_level = "HIGH"
        global_reasons.append("CORRUPT_OR_UNSUPPORTED")
    evidence = report.get("evidence", {})
    resource_subjects = [
        str(item.get("subject"))
        for item in evidence.get("observations", [])
        if isinstance(item, Mapping) and str(item.get("subject", "")).startswith("resource:")
    ]
    for observation in evidence.get("observations", []):
        if not isinstance(observation, Mapping):
            continue
        subject = str(observation.get("subject", ""))
        confidence = str(observation.get("confidence", "")).upper()
        if subject.startswith("resource:") and confidence in {"LOW", "LIMITED"}:
            mark(subject, "LOW" if confidence == "LOW" else "INFO", f"evidence confidence {confidence}", "evidence")

    for finding in report.get("findings", []):
        if not isinstance(finding, Mapping):
            continue
        confidence = str(finding.get("confidence", "")).upper()
        category = str(finding.get("category", "")).upper()
        severity = str(finding.get("severity", "INFO")).upper()
        level = "HIGH" if category in {"CORRUPTION", "ACCESS"} or confidence == "LOW" else "MEDIUM" if severity in {"HIGH", "MEDIUM"} else "INFO"
        if _LEVELS[level] > _LEVELS[global_level]:
            global_level = level
        reason = str(finding.get("title", category or "finding"))
        global_reasons.append(reason)
        if level == "HIGH" and resource_subjects:
            for subject in resource_subjects:
                mark(subject, level, reason, "finding")
        for reference in finding.get("resourceRefs", []):
            if isinstance(reference, str):
                mark(reference, level, reason, "finding")
    for indicator in list(report.get("staticIndicators", [])) + list(report.get("unpackingIndicators", [])):
        if not isinstance(indicator, Mapping):
            continue
        category = str(indicator.get("category", "")).upper()
        kind = str(indicator.get("kind", "")).upper()
        if "OBFUSCATION" in category or "OBFUSCATION" in kind or "PACK" in kind or "ENTROPY" in kind:
            level = "MEDIUM"
            reason = str(indicator.get("kind", "OBFUSCATION_INDICATOR"))
            if _LEVELS[level] > _LEVELS[global_level]:
                global_level = level
            global_reasons.append(reason)
            resource_key = indicator.get("resourceKey")
            if isinstance(resource_key, str):
                mark(resource_key, level, reason, "staticIndicator")
    return {
        "schema": _SCHEMA,
        "global": {"level": global_level, "color": _COLORS[global_level], "reasons": _unique(global_reasons)},
        "resources": resources,
        "legend": [{"level": level, "color": _COLORS[level]} for level in ("HIGH", "MEDIUM", "LOW", "INFO", "NONE")],
        "limitations": ["Colors are visual triage cues, not malware verdicts or trust decisions."],
    }


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


__all__ = ["build_triage_map"]
