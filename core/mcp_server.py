from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from .dialog_resources import DialogResource
from .diff import diff_resources
from .health import PEHealth
from .pe_identity import classify as classify_pe
from .pe_inspector import PEInspector
from .pe_integrity import inspect_integrity
from .recipe import apply_recipe as core_apply_recipe, create_recipe as core_create_recipe
from .resource_reader import ResourceReader


def _safe_identifier(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", str(name))
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned


def _format_byte_array(data: bytes, bytes_per_line: int = 12) -> str:
    lines: list[str] = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_items = [f"0x{b:02X}" for b in chunk]
        line = "    " + ", ".join(hex_items)
        if i + bytes_per_line < len(data):
            line += ","
        lines.append(line)
    return "\n".join(lines)


def create_mcp_server(
    name: str = "ResourceStudio",
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastMCP:
    """Creates and configures the ResourceStudio MCP Server instance."""
    server = FastMCP(
        name=name,
        instructions=(
            "Resource Studio MCP Server provides provably safe Win32 PE binary resource analysis, "
            "decompiled inspection, dialog clipping validation, binary forensics, and declarative recipe automation."
        ),
        host=host,
        port=port,
    )

    @server.tool()
    def list_pe_resources(file_path: str) -> list[dict[str, Any]]:
        """List all resources (type, name, language, size, sha256) embedded in a PE binary.

        Args:
            file_path: Absolute or relative path to the Windows PE binary (.exe, .dll, .sys).
        """
        path = Path(file_path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"PE file not found: {file_path}")
        entries = ResourceReader(path).entries
        return [
            {
                "type": entry.resource_type,
                "name": entry.name,
                "language": entry.language,
                "size": len(entry.data),
                "sha256": entry.sha256,
            }
            for entry in entries
        ]

    @server.tool()
    def inspect_pe(file_path: str) -> dict[str, Any]:
        """Inspect detailed PE binary structure including architecture, sections, imports, exports, and debug/PDB directories.

        Args:
            file_path: Path to the Windows PE binary to inspect.
        """
        path = Path(file_path).expanduser().resolve()
        report = PEInspector.inspect(path)
        return report.to_dict()

    @server.tool()
    def validate_pe(file_path: str, strict: bool = False) -> dict[str, Any]:
        """Validate PE integrity, structural invariants, checksum match, alignment, overlay bytes, and health status.

        Args:
            file_path: Path to the Windows PE binary.
            strict: If true, treat warnings as validation failures.
        """
        path = Path(file_path).expanduser().resolve()
        health = PEHealth.inspect(path).to_dict()
        integrity = inspect_integrity(path).to_dict()
        identity = classify_pe(path).to_dict()

        is_valid = health.get("status") == "VALID_PE"
        if strict and (health.get("warnings") or integrity.get("warnings")):
            is_valid = False

        return {
            "path": str(path),
            "valid": is_valid,
            "status": health.get("status"),
            "health": health,
            "integrity": integrity,
            "identity": identity,
        }

    @server.tool()
    def extract_resource(
        file_path: str,
        resource_type: str,
        resource_name: str,
        language: int | None = None,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        """Extract a specific PE resource payload by type, name, and optional language.

        Args:
            file_path: Path to the PE binary.
            resource_type: Win32 resource type name or number (e.g., 'MANIFEST', 'DIALOG', 'ICON', '10').
            resource_name: Resource identifier or name (e.g., '1', 'MAIN', '101').
            language: Optional LCID language identifier (e.g., 1033).
            output_path: Optional file path to write extracted raw payload.
        """
        path = Path(file_path).expanduser().resolve()
        entries = ResourceReader(path).entries
        matches = [
            e
            for e in entries
            if str(e.resource_type).upper() == str(resource_type).upper()
            and str(e.name).upper() == str(resource_name).upper()
            and (language is None or e.language == language)
        ]
        if not matches:
            raise ValueError(f"Resource not found: type={resource_type}, name={resource_name}, lang={language}")
        if len(matches) > 1 and language is None:
            raise ValueError(
                f"Multiple language instances found for {resource_type}/{resource_name}. Please specify language."
            )

        target = matches[0]
        data = target.data

        written_path: str | None = None
        if output_path:
            out = Path(output_path).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            written_path = str(out)

        b64_content = base64.b64encode(data).decode("ascii") if len(data) <= 5 * 1024 * 1024 else None

        return {
            "type": target.resource_type,
            "name": target.name,
            "language": target.language,
            "size": len(data),
            "sha256": target.sha256,
            "outputPath": written_path,
            "base64": b64_content,
        }

    @server.tool()
    def diff_pe_resources(left_path: str, right_path: str, typed: bool = False) -> dict[str, Any]:
        """Compare resources between two PE binaries and return structured additions, removals, and modifications.

        Args:
            left_path: Original PE binary path.
            right_path: Modified/Compared PE binary path.
            typed: Whether to perform semantic deep inspection on typed resources.
        """
        left = Path(left_path).expanduser().resolve()
        right = Path(right_path).expanduser().resolve()
        left_entries = ResourceReader(left).entries
        right_entries = ResourceReader(right).entries
        tree = diff_resources(left_entries, right_entries, typed=typed).to_dict()

        changes: list[dict[str, Any]] = []
        for node in tree.get("children", []):
            if node.get("status") == "unchanged":
                continue
            record = {"status": node.get("status")}
            if "before" in node:
                record.update(node["before"])
            if "after" in node and node.get("status") == "added":
                record.update(node["after"])
            if node.get("status") == "modified":
                record.update({"before": node.get("before"), "after": node.get("after")})
            changes.append(record)

        left_hash = hashlib.sha256(left.read_bytes()).hexdigest()
        right_hash = hashlib.sha256(right.read_bytes()).hexdigest()

        return {
            "leftPath": str(left),
            "rightPath": str(right),
            "filesIdentical": left_hash == right_hash,
            "changeCount": len(changes),
            "changes": changes,
            "tree": tree,
        }

    @server.tool()
    def analyze_dialog(file_path: str, dialog_name: str, language: int | None = None) -> dict[str, Any]:
        """Parse and analyze a Win32 DIALOG/DIALOGEX template, reporting controls, DLU dimensions, and text clipping risks.

        Args:
            file_path: Path to the PE binary containing the DIALOG resource.
            dialog_name: Resource ID or name of the DIALOG (e.g., '101' or 'IDD_MAIN').
            language: Optional resource language ID.
        """
        path = Path(file_path).expanduser().resolve()
        entries = ResourceReader(path).entries
        matches = [
            e
            for e in entries
            if e.resource_type == "DIALOG"
            and str(e.name).upper() == str(dialog_name).upper()
            and (language is None or e.language == language)
        ]
        if not matches:
            raise ValueError(f"DIALOG resource '{dialog_name}' not found in {file_path}")
        if len(matches) > 1 and language is None:
            raise ValueError(f"Multiple languages found for DIALOG '{dialog_name}'; pass language parameter.")

        dialog_entry = matches[0]
        dialog_res = DialogResource.parse(dialog_entry.data)
        validation_report = dialog_res.validate()
        controls_summary = []
        clipping_risks = []

        for ctrl in dialog_res.controls:
            ctrl_info = ctrl.to_dict()
            ctrl_info["classLabel"] = ctrl.class_label
            ctrl_info["estimatedRequiredDlu"] = ctrl.estimated_required_width_dlu
            ctrl_info["isClipped"] = ctrl.is_clipped
            controls_summary.append(ctrl_info)
            if ctrl.is_clipped:
                clipping_risks.append(
                    {
                        "controlId": ctrl.control_id,
                        "class": ctrl.class_label,
                        "title": str(ctrl.title),
                        "width": ctrl.width,
                        "requiredDlu": ctrl.estimated_required_width_dlu,
                        "overflow": ctrl.estimated_required_width_dlu - ctrl.width,
                    }
                )

        return {
            "dialogName": dialog_entry.name,
            "language": dialog_entry.language,
            "font": dialog_res.font_name,
            "fontSize": dialog_res.font_size,
            "controlCount": len(dialog_res.controls),
            "clippingRiskCount": len(clipping_risks),
            "clippingRisks": clipping_risks,
            "validationReport": validation_report,
            "controls": controls_summary,
        }

    @server.tool()
    def export_recipe(original_path: str, edited_path: str, output_dir: str) -> dict[str, Any]:
        """Create a declarative, reproducible CI/CD recipe package from the resource differences between two PE files.

        Args:
            original_path: Path to baseline PE binary.
            edited_path: Path to modified PE binary with intended resources.
            output_dir: Target directory where recipe.json and resource payloads will be generated.
        """
        orig = Path(original_path).expanduser().resolve()
        edit = Path(edited_path).expanduser().resolve()
        out = Path(output_dir).expanduser().resolve()
        return core_create_recipe(orig, edit, out)

    @server.tool()
    def apply_recipe(target_path: str, recipe_path: str, output_path: str) -> dict[str, Any]:
        """Safely apply a declarative automation recipe to a target PE with strict verification and Save-As safety.

        Args:
            target_path: Path to target PE binary to patch.
            recipe_path: Path to recipe.json manifest or recipe directory.
            output_path: Destination path for the patched new PE binary.
        """
        target = Path(target_path).expanduser().resolve()
        recipe = Path(recipe_path).expanduser().resolve()
        out = Path(output_path).expanduser().resolve()
        return core_apply_recipe(target, recipe, out)

    @server.tool()
    def generate_developer_code(
        file_path: str,
        resource_type: str,
        resource_name: str,
        language: int | None = None,
        code_kind: Literal["c_array", "csharp_span", "base64", "sha256", "resource_h"] = "c_array",
    ) -> dict[str, Any]:
        """Generate developer-ready code snippets (C/C++ array, C# ReadOnlySpan, Base64, SHA-256, or resource.h definition).

        Args:
            file_path: Path to PE binary.
            resource_type: Resource type (e.g., 'ICON', 'DIALOG', 'RCDATA').
            resource_name: Resource identifier or name (e.g., '1', '101').
            language: Optional resource language ID.
            code_kind: Format to generate: 'c_array', 'csharp_span', 'base64', 'sha256', or 'resource_h'.
        """
        path = Path(file_path).expanduser().resolve()
        entries = ResourceReader(path).entries
        matches = [
            e
            for e in entries
            if str(e.resource_type).upper() == str(resource_type).upper()
            and str(e.name).upper() == str(resource_name).upper()
            and (language is None or e.language == language)
        ]
        if not matches:
            raise ValueError(f"Resource {resource_type}/{resource_name} not found")

        target = matches[0]
        data = target.data
        ident = _safe_identifier(f"{target.resource_type}_{target.name}")
        sha = target.sha256

        snippet = ""
        if code_kind == "c_array":
            body = _format_byte_array(data)
            snippet = (
                f"// Resource: {target.resource_type} / {target.name} ({len(data)} bytes)\n"
                f"// SHA-256: {sha}\n"
                f"const unsigned char res_{ident}[] = {{\n"
                f"{body}\n"
                f"}};\n"
                f"const unsigned int res_{ident}_len = {len(data)};\n"
            )
        elif code_kind == "csharp_span":
            body = _format_byte_array(data)
            snippet = (
                f"// Resource: {target.resource_type} / {target.name} ({len(data)} bytes)\n"
                f"// SHA-256: {sha}\n"
                f"ReadOnlySpan<byte> res_{ident} = [\n"
                f"{body}\n"
                f"];\n"
            )
        elif code_kind == "base64":
            snippet = base64.b64encode(data).decode("ascii")
        elif code_kind == "sha256":
            snippet = sha
        elif code_kind == "resource_h":
            num_id = target.name if str(target.name).isdigit() else 101
            snippet = f"#define IDR_{ident.upper()} {num_id}\n"
        else:
            raise ValueError(f"Unknown code_kind: {code_kind}")

        return {
            "resource": {"type": target.resource_type, "name": target.name, "language": target.language},
            "kind": code_kind,
            "size": len(data),
            "sha256": sha,
            "snippet": snippet,
        }

    @server.tool()
    def inspect_security(file_path: str) -> dict[str, Any]:
        """Inspect PE binary security characteristics including digital signature, certificate details, and PDB leak forensics.

        Args:
            file_path: Path to the PE binary.
        """
        path = Path(file_path).expanduser().resolve()
        identity = classify_pe(path).to_dict()
        integrity = inspect_integrity(path).to_dict()

        return {
            "path": str(path),
            "signed": identity.get("signed", False),
            "pdbPath": identity.get("pdbPath"),
            "overlayBytes": identity.get("overlayBytes", 0),
            "notices": identity.get("notices", []),
            "storedChecksum": integrity.get("storedChecksum"),
            "liefChecksum": integrity.get("liefChecksum"),
            "signatureStatus": integrity.get("signatureVerification"),
            "certificateTable": integrity.get("certificateTable"),
        }

    @server.tool()
    def scan_resource_xrefs(file_path: str) -> dict[str, Any]:
        """Scan PE code sections and import table to establish code-to-resource cross references, identifying dead/orphaned resources and code call sites.

        Args:
            file_path: Path to the Windows PE binary to analyze.
        """
        path = Path(file_path).expanduser().resolve()
        from .xref_scanner import scan_pe_xrefs

        report = scan_pe_xrefs(path)
        return report.to_dict()

    @server.tool()
    def correlate_dialog_behavior(
        file_path: str,
        dialog_name: str,
        decompiled_code: str | None = None,
        language: int | None = None,
    ) -> dict[str, Any]:
        """Correlate Win32 dialog controls with decompiled DialogProc C logic (e.g. from GhidraMCP) to map button clicks to handlers.

        Args:
            file_path: Path to the PE binary containing the DIALOG template.
            dialog_name: Dialog resource identifier (e.g., '101' or '201').
            decompiled_code: Decompiled C/C++ pseudocode of DialogProc. If None, retrieves controls without code mapping.
            language: Optional language ID.
        """
        path = Path(file_path).expanduser().resolve()
        entries = ResourceReader(path).entries
        matches = [
            e
            for e in entries
            if e.resource_type == "DIALOG"
            and str(e.name).upper() == str(dialog_name).upper()
            and (language is None or e.language == language)
        ]
        if not matches:
            raise ValueError(f"DIALOG resource '{dialog_name}' not found")

        dialog_res = DialogResource.parse(matches[0].data)
        ctrl_dicts = [ctrl.to_dict() for ctrl in dialog_res.controls]

        mappings: list[dict[str, Any]] = []
        if decompiled_code:
            from .ghidra_bridge import GhidraBridge

            raw_mappings = GhidraBridge.parse_dialog_proc_branches(decompiled_code, ctrl_dicts)
            mappings = [m.to_dict() for m in raw_mappings]

        return {
            "dialogName": dialog_name,
            "controlCount": len(ctrl_dicts),
            "controls": ctrl_dicts,
            "hasCodeMapping": bool(decompiled_code),
            "mappings": mappings,
        }

    @server.prompt()
    def triage_pe_resources(file_path: str) -> str:
        """Prompt to guide an AI agent in triaging and auditing PE resources."""
        return (
            f"You are an expert Win32 Reverse Engineer auditing the PE file at '{file_path}'.\n"
            f"1. First, call list_pe_resources to enumerate all resources and identify their types.\n"
            f"2. Call validate_pe and inspect_security to check integrity, signatures, and PDB leaks.\n"
            f"3. For any DIALOG resources found, call analyze_dialog to detect UI text truncation risks.\n"
            f"4. Summarize your findings, potential anomalies, and recommended patch recipes."
        )

    @server.prompt()
    def plan_resource_patch(original_pe: str, goal_description: str) -> str:
        """Prompt to guide an AI agent in safely planning PE resource modifications."""
        return (
            f"Goal: {goal_description}\n"
            f"Target binary: {original_pe}\n"
            f"Instructions:\n"
            f"- Verify the original binary with validate_pe.\n"
            f"- Extract relevant resources with extract_resource.\n"
            f"- Prepare modifications without corrupting headers or non-target sections.\n"
            f"- Apply the modification to a new output file with Save-As semantics.\n"
            f"- Generate a verifiable automation recipe via export_recipe."
        )

    return server


def run_server(
    transport: Literal["stdio", "sse"] = "stdio",
    host: str = "127.0.0.1",
    port: int = 8000,
) -> None:
    """Entry point to execute the Resource Studio FastMCP server."""
    server = create_mcp_server(host=host, port=port)
    if transport == "stdio":
        server.run(transport="stdio")
    elif transport == "sse":
        server.run(transport="sse")
    else:
        raise ValueError(f"Unsupported transport: {transport}. Must be 'stdio' or 'sse'.")
