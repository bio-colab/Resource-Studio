from .audit import AuditLog
from .batch import BatchError, BatchJob, BatchWorkspace
from .diff import DiffNode, diff_image_payloads, diff_resources, diff_texts, merge_selected_resources
from .durable_commit import CommitResult, DurableCommitError, commit_temporary
from .evidence_ledger import EvidenceLedger, EvidenceLedgerError, LedgerVerification, generate_ed25519_keypair
from .evidence_model import build_evidence_summary, evidence_summary_hash
from .dialog_resources import DialogControl, DialogResource, DialogResourceError
from .compatibility import PECompatibilityReport, inspect_compatibility
from .commands import (
    AddResourceCommand,
    ChangeIdCommand,
    ChangeLanguageCommand,
    CommandGroup,
    CommandHistory,
    DeleteResourceCommand,
    ReplaceResourceCommand,
)
from .health import HealthReport, PEHealth
from .fuzz_harness import FuzzOutcome, assert_no_unexpected_failures, run_parser_cases, run_structure_aware_cases, structure_aware_cases
from .image_resources import BitmapResource, IconCursorEntry, IconCursorGroup, ImageResourceError, icon_cursor_bmp_to_payload, icon_cursor_payload_to_bmp
from .hex_view import HexSlice, HexViewer
from .invariants import PEInvariantSnapshot, PESurgicalChangeReport, compare_surgical_change, snapshot
from .deep_invariants import DeepPEInvariantReport, inspect_deep
from .diagnostics import build_post_write_diagnostics
from .security_analysis import analyze_security
from .security_providers import ExternalScanResult, external_scan_hash, load_external_scan
from .security_workspace import StagedArtifact, stage_readonly_copy
from .runtime_evidence import load_runtime_evidence
from .static_code_analysis import analyze_static_code
from .evidence_graph import EvidenceEdge, EvidenceGraph, EvidenceNode
from .evidence_query import EvidenceQueryError, parse_query, query_summary, records_from_summary
from .case_lifecycle import CaseFile, CaseLifecycleError, analyze_into_case
from .localization import LocalizationCatalog, LocalizedString
from .menu_resources import MenuItem, MenuResource, MenuResourceError
from .manifest import ManifestDocument
from .pe_inspector import PEInspector, PEInspectorReport
from .pe_integrity import PEIntegrityReport, inspect_integrity
from .pe_metadata import PEMetadataInspector, PEMetadataReport
from .pe_writer import LiefPEWriter, PEWriterError, WriteResult
from .preservation import ByteChange, PreservationMap, build_preservation_map
from .raw_resource_parser import RawResourceComparison, RawResourceLeaf, RawResourceParserError, RawResourceReport, compare_with_graph, parse_raw_resources
from .plugin_host import PluginHost, PluginHostError, PluginLimits, PluginResult
from .plugins import PluginContext, PluginManifest, PluginRegistry, ResourceTypeDefinition
from .preview import PreviewEngine, PreviewResult
from .project import Project, ResourceEntry
from .provenance import build_provenance, write_provenance
from .reports import render_report
from .roundtrip_contracts import RoundTripContract, RoundTripContractRegistry, RoundTripResult, default_registry
from .rc_format import RC_DEFAULT_LANGUAGE, RCDocument, RCMenus, RCStringTable, compile_rc, decompile_res
from .signature import PESignatureReport, SignatureOperationResult, SignatureToolError, create_test_certificate, find_signtool, inspect_signature, resign_authenticode, strip_authenticode
from .search import SearchHit, search_resources
from .res_format import ResFile, ResRecord
from .string_table import StringTableBlock, string_table_block_id
from .version_info import VersionInfo
from .verification import ResourceGraph, VerificationReport, semantic_fingerprint, verify_candidate
from .forensics import ForensicBaseline, ForensicEvidence, verify_transformation
from .pure_loader_oracle import PureLoaderSelection, select_from_graph, select_language, select_resource
from .windows_security import WindowsAuthenticodeReport, inspect_authenticode_windows

__all__ = [
    "BatchError",
    "BatchJob",
    "BatchWorkspace",
    "PECompatibilityReport",
    "inspect_compatibility",
    "AddResourceCommand",
    "AuditLog",
    "ChangeIdCommand",
    "ChangeLanguageCommand",
    "CommandGroup",
    "CommandHistory",
    "DeleteResourceCommand",
    "DiffNode",
    "CommitResult",
    "DurableCommitError",
    "commit_temporary",
    "EvidenceLedger",
    "build_evidence_summary",
    "evidence_summary_hash",
    "EvidenceLedgerError",
    "LedgerVerification",
    "generate_ed25519_keypair",
    "DialogControl",
    "DialogResource",
    "DialogResourceError",
    "diff_image_payloads",
    "merge_selected_resources",
    "HealthReport",
    "FuzzOutcome",
    "assert_no_unexpected_failures",
    "run_parser_cases",
    "run_structure_aware_cases",
    "structure_aware_cases",
    "BitmapResource",
    "IconCursorEntry",
    "IconCursorGroup",
    "ImageResourceError",
    "icon_cursor_payload_to_bmp",
    "icon_cursor_bmp_to_payload",
    "HexSlice",
    "HexViewer",
    "PEInvariantSnapshot",
    "PESurgicalChangeReport",
    "compare_surgical_change",
    "snapshot",
    "DeepPEInvariantReport",
    "build_post_write_diagnostics",
    "analyze_security",
    "ExternalScanResult",
    "external_scan_hash",
    "load_external_scan",
    "StagedArtifact",
    "stage_readonly_copy",
    "load_runtime_evidence",
    "analyze_static_code",
    "EvidenceEdge",
    "EvidenceGraph",
    "EvidenceNode",
    "EvidenceQueryError",
    "parse_query",
    "query_summary",
    "records_from_summary",
    "CaseFile",
    "CaseLifecycleError",
    "analyze_into_case",
    "inspect_deep",
    "LocalizationCatalog",
    "LocalizedString",
    "MenuItem",
    "MenuResource",
    "MenuResourceError",
    "LiefPEWriter",
    "ManifestDocument",
    "PEHealth",
    "PEInspector",
    "PEInspectorReport",
    "PEIntegrityReport",
    "inspect_integrity",
    "PEMetadataInspector",
    "PEMetadataReport",
    "PEWriterError",
    "PluginContext",
    "PluginHost",
    "PluginHostError",
    "PluginLimits",
    "PluginManifest",
    "PluginRegistry",
    "ResourceTypeDefinition",
    "PluginResult",
    "PreviewEngine",
    "PreviewResult",
    "Project",
    "ReplaceResourceCommand",
    "ResourceEntry",
    "build_provenance",
    "write_provenance",
    "ResFile",
    "ResRecord",
    "StringTableBlock",
    "string_table_block_id",
    "render_report",
    "RoundTripContract",
    "RoundTripContractRegistry",
    "RoundTripResult",
    "default_registry",
    "RCDocument",
    "RCMenus",
    "RCStringTable",
    "RC_DEFAULT_LANGUAGE",
    "compile_rc",
    "decompile_res",
    "PESignatureReport",
    "SignatureOperationResult",
    "SignatureToolError",
    "create_test_certificate",
    "find_signtool",
    "inspect_signature",
    "resign_authenticode",
    "strip_authenticode",
    "SearchHit",
    "search_resources",
    "VersionInfo",
    "ResourceGraph",
    "VerificationReport",
    "semantic_fingerprint",
    "verify_candidate",
    "ForensicBaseline",
    "ForensicEvidence",
    "verify_transformation",
    "PureLoaderSelection",
    "select_from_graph",
    "select_language",
    "select_resource",
    "WindowsAuthenticodeReport",
    "inspect_authenticode_windows",
    "diff_resources",
    "diff_texts",
    "WriteResult",
    "ByteChange",
    "PreservationMap",
    "build_preservation_map",
    "RawResourceComparison",
    "RawResourceLeaf",
    "RawResourceParserError",
    "RawResourceReport",
    "compare_with_graph",
    "parse_raw_resources",
]
