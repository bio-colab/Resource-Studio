from .audit import AuditLog
from .diff import DiffNode, diff_image_payloads, diff_resources, diff_texts, merge_selected_resources
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
from .image_resources import BitmapResource, IconCursorEntry, IconCursorGroup, ImageResourceError
from .hex_view import HexSlice, HexViewer
from .invariants import PEInvariantSnapshot, PESurgicalChangeReport, compare_surgical_change, snapshot
from .localization import LocalizationCatalog, LocalizedString
from .menu_resources import MenuItem, MenuResource, MenuResourceError
from .manifest import ManifestDocument
from .pe_inspector import PEInspector, PEInspectorReport
from .pe_metadata import PEMetadataInspector, PEMetadataReport
from .pe_writer import LiefPEWriter, PEWriterError, WriteResult
from .plugin_host import PluginHost, PluginHostError, PluginLimits, PluginResult
from .plugins import PluginContext, PluginManifest, PluginRegistry, ResourceTypeDefinition
from .project import Project, ResourceEntry
from .provenance import build_provenance, write_provenance
from .reports import render_report
from .rc_format import RCDocument, RCMenus, RCStringTable
from .signature import PESignatureReport, inspect_signature
from .search import SearchHit, search_resources
from .res_format import ResFile, ResRecord
from .string_table import StringTableBlock, string_table_block_id
from .version_info import VersionInfo

__all__ = [
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
    "diff_image_payloads",
    "merge_selected_resources",
    "HealthReport",
    "BitmapResource",
    "IconCursorEntry",
    "IconCursorGroup",
    "ImageResourceError",
    "HexSlice",
    "HexViewer",
    "PEInvariantSnapshot",
    "PESurgicalChangeReport",
    "compare_surgical_change",
    "snapshot",
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
    "RCDocument",
    "RCMenus",
    "RCStringTable",
    "PESignatureReport",
    "inspect_signature",
    "SearchHit",
    "search_resources",
    "VersionInfo",
    "diff_resources",
    "diff_texts",
    "WriteResult",
]
