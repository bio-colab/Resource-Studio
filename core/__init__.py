"""Package facade with lazy re-exports (PEP 562).

Importing any ``core`` submodule no longer executes the whole package.
Every public name below is imported on first attribute access, so
``from core.project import Project`` pays only for ``core.project`` and
its own dependencies. Previously this file eagerly imported every module,
which dragged ``core.batch -> core.pe_writer -> lief`` (~250 ms) into
every consumer: each CLI spawn from the WPF shell, every MCP handler
import, and even ``--help``.

Compatibility notes:
- ``from core import Project`` works via ``__getattr__`` (mapped name).
- ``from core import verification`` works (submodule branch below).
- ``dir(core)`` and ``core.__all__`` keep the same 152 names as before.
"""
from __future__ import annotations

import importlib
from pathlib import Path

_EXPORTS = {
    # audit
    "AuditLog": "core.audit",
    # batch
    "BatchError": "core.batch",
    "BatchJob": "core.batch",
    "BatchWorkspace": "core.batch",
    # diff
    "DiffNode": "core.diff",
    "diff_image_payloads": "core.diff",
    "diff_resources": "core.diff",
    "diff_texts": "core.diff",
    "merge_selected_resources": "core.diff",
    # durable_commit
    "CommitResult": "core.durable_commit",
    "DurableCommitError": "core.durable_commit",
    "commit_temporary": "core.durable_commit",
    # evidence_ledger
    "EvidenceLedger": "core.evidence_ledger",
    "EvidenceLedgerError": "core.evidence_ledger",
    "LedgerVerification": "core.evidence_ledger",
    "generate_ed25519_keypair": "core.evidence_ledger",
    # evidence_model
    "build_evidence_summary": "core.evidence_model",
    "evidence_summary_hash": "core.evidence_model",
    # dialog_resources
    "DialogControl": "core.dialog_resources",
    "DialogResource": "core.dialog_resources",
    "DialogResourceError": "core.dialog_resources",
    # compatibility
    "PECompatibilityReport": "core.compatibility",
    "inspect_compatibility": "core.compatibility",
    # commands
    "AddResourceCommand": "core.commands",
    "ChangeIdCommand": "core.commands",
    "ChangeLanguageCommand": "core.commands",
    "CommandGroup": "core.commands",
    "CommandHistory": "core.commands",
    "DeleteResourceCommand": "core.commands",
    "ReplaceResourceCommand": "core.commands",
    # health
    "HealthReport": "core.health",
    "PEHealth": "core.health",
    # fuzz_harness
    "FuzzOutcome": "core.fuzz_harness",
    "assert_no_unexpected_failures": "core.fuzz_harness",
    "run_parser_cases": "core.fuzz_harness",
    "run_structure_aware_cases": "core.fuzz_harness",
    "structure_aware_cases": "core.fuzz_harness",
    # image_resources
    "BitmapResource": "core.image_resources",
    "IconCursorEntry": "core.image_resources",
    "IconCursorGroup": "core.image_resources",
    "ImageResourceError": "core.image_resources",
    "icon_cursor_bmp_to_payload": "core.image_resources",
    "icon_cursor_payload_to_bmp": "core.image_resources",
    # hex_templates
    "HexField": "core.hex_templates",
    "build_hex_template": "core.hex_templates",
    # hex_view
    "HexSlice": "core.hex_view",
    "HexViewer": "core.hex_view",
    # invariants
    "PEInvariantSnapshot": "core.invariants",
    "PESurgicalChangeReport": "core.invariants",
    "compare_surgical_change": "core.invariants",
    "snapshot": "core.invariants",
    # deep_invariants
    "DeepPEInvariantReport": "core.deep_invariants",
    "inspect_deep": "core.deep_invariants",
    # diagnostics
    "build_post_write_diagnostics": "core.diagnostics",
    # evidence_triage
    "build_triage_map": "core.evidence_triage",
    # security_analysis
    "analyze_security": "core.security_analysis",
    # security_providers
    "ExternalScanResult": "core.security_providers",
    "external_scan_hash": "core.security_providers",
    "load_external_scan": "core.security_providers",
    # security_workspace
    "StagedArtifact": "core.security_workspace",
    "stage_readonly_copy": "core.security_workspace",
    # runtime_evidence
    "load_runtime_evidence": "core.runtime_evidence",
    # live_analysis
    "LiveAnalysisAdapter": "core.live_analysis",
    "LiveAnalysisSession": "core.live_analysis",
    # static_code_analysis
    "analyze_static_code": "core.static_code_analysis",
    # evidence_graph
    "EvidenceEdge": "core.evidence_graph",
    "EvidenceGraph": "core.evidence_graph",
    "EvidenceNode": "core.evidence_graph",
    # evidence_query
    "EvidenceQueryError": "core.evidence_query",
    "parse_query": "core.evidence_query",
    "query_summary": "core.evidence_query",
    "records_from_summary": "core.evidence_query",
    # case_lifecycle
    "CaseFile": "core.case_lifecycle",
    "CaseLifecycleError": "core.case_lifecycle",
    "analyze_into_case": "core.case_lifecycle",
    # localization
    "LocalizationCatalog": "core.localization",
    "LocalizedString": "core.localization",
    # menu_resources
    "MenuItem": "core.menu_resources",
    "MenuResource": "core.menu_resources",
    "MenuResourceError": "core.menu_resources",
    # manifest
    "ManifestDocument": "core.manifest",
    # pe_inspector
    "PEInspector": "core.pe_inspector",
    "PEInspectorReport": "core.pe_inspector",
    # pe_integrity
    "PEIntegrityReport": "core.pe_integrity",
    "inspect_integrity": "core.pe_integrity",
    # pe_metadata
    "PEMetadataInspector": "core.pe_metadata",
    "PEMetadataReport": "core.pe_metadata",
    # pe_writer
    "LiefPEWriter": "core.pe_writer",
    "PEWriterError": "core.pe_writer",
    "WriteResult": "core.pe_writer",
    # preservation
    "ByteChange": "core.preservation",
    "PreservationMap": "core.preservation",
    "build_preservation_map": "core.preservation",
    # raw_resource_parser
    "RawResourceComparison": "core.raw_resource_parser",
    "RawResourceLeaf": "core.raw_resource_parser",
    "RawResourceParserError": "core.raw_resource_parser",
    "RawResourceReport": "core.raw_resource_parser",
    "compare_with_graph": "core.raw_resource_parser",
    "parse_raw_resources": "core.raw_resource_parser",
    # plugin_host
    "PluginHost": "core.plugin_host",
    "PluginHostError": "core.plugin_host",
    "PluginLimits": "core.plugin_host",
    "PluginResult": "core.plugin_host",
    # plugins
    "PluginContext": "core.plugins",
    "PluginManifest": "core.plugins",
    "PluginRegistry": "core.plugins",
    "ResourceTypeDefinition": "core.plugins",
    # preview
    "PreviewEngine": "core.preview",
    "PreviewResult": "core.preview",
    # project
    "Project": "core.project",
    "ResourceEntry": "core.project",
    # provenance
    "build_provenance": "core.provenance",
    "write_provenance": "core.provenance",
    # reports
    "render_report": "core.reports",
    # roundtrip_contracts
    "RoundTripContract": "core.roundtrip_contracts",
    "RoundTripContractRegistry": "core.roundtrip_contracts",
    "RoundTripResult": "core.roundtrip_contracts",
    "default_registry": "core.roundtrip_contracts",
    # rc_format
    "RC_DEFAULT_LANGUAGE": "core.rc_format",
    "RCDocument": "core.rc_format",
    "RCMenus": "core.rc_format",
    "RCStringTable": "core.rc_format",
    "compile_rc": "core.rc_format",
    "decompile_res": "core.rc_format",
    # signature
    "PESignatureReport": "core.signature",
    "SignatureOperationResult": "core.signature",
    "SignatureToolError": "core.signature",
    "create_test_certificate": "core.signature",
    "find_signtool": "core.signature",
    "inspect_signature": "core.signature",
    "resign_authenticode": "core.signature",
    "strip_authenticode": "core.signature",
    # search
    "SearchHit": "core.search",
    "search_resources": "core.search",
    # res_format
    "ResFile": "core.res_format",
    "ResRecord": "core.res_format",
    # string_table
    "StringTableBlock": "core.string_table",
    "string_table_block_id": "core.string_table",
    # version_info
    "VersionInfo": "core.version_info",
    # verification
    "ResourceGraph": "core.verification",
    "VerificationReport": "core.verification",
    "semantic_fingerprint": "core.verification",
    "verify_candidate": "core.verification",
    # forensics
    "ForensicBaseline": "core.forensics",
    "ForensicEvidence": "core.forensics",
    "verify_transformation": "core.forensics",
    # pure_loader_oracle
    "PureLoaderSelection": "core.pure_loader_oracle",
    "select_from_graph": "core.pure_loader_oracle",
    "select_language": "core.pure_loader_oracle",
    "select_resource": "core.pure_loader_oracle",
    # windows_security
    "WindowsAuthenticodeReport": "core.windows_security",
    "inspect_authenticode_windows": "core.windows_security",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    target = _EXPORTS.get(name)
    if target is not None:
        return getattr(importlib.import_module(target), name)
    # Submodule access, e.g. ``from core import verification``: resolve
    # against real files so a missing attribute keeps raising AttributeError
    # even if the submodule itself fails to import for another reason.
    here = Path(__file__).parent
    if (here / f"{name}.py").is_file() or (here / name / "__init__.py").is_file():
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))
