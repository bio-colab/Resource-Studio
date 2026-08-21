from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from core.batch import BatchWorkspace
from core.compatibility import inspect_compatibility
from core.diff import diff_image_payloads, diff_resources
from core.evidence_ledger import EvidenceLedger, generate_ed25519_keypair
from core.forensics import ForensicBaseline
from core.deep_invariants import inspect_deep
from core.dialog_resources import DialogResource
from core.health import PEHealth
from core.image_resources import BitmapResource, IconCursorGroup, icon_cursor_bmp_to_payload, icon_cursor_payload_to_bmp
from core.hex_view import HexViewer
from core.pe_inspector import PEInspector
from core.pe_integrity import inspect_integrity
from core.pe_metadata import PEMetadataInspector
from core.preview import PreviewEngine
from core.project import Project, ResourceEntry
from core.reports import FORMATS, render_report
from core.rc_format import compile_rc, decompile_res
from core.search import search_resources
from core.string_table import StringTableBlock
from core.localization import LocalizationCatalog
from core.manifest import ManifestDocument
from core.menu_resources import MenuResource
from core.signature import create_test_certificate, inspect_signature, resign_authenticode, strip_authenticode
from core.version_info import VersionInfo
from core.verification import ResourceGraph


def _entries(path: Path) -> list[ResourceEntry]:
    with tempfile.TemporaryDirectory(prefix="resource-studio-cli-") as temporary:
        project = Project.open_pe(path, Path(temporary) / "project")
        return list(project.entries.values())


def _entry_record(entry: ResourceEntry) -> dict[str, Any]:
    return {
        "type": entry.resource_type,
        "name": entry.name,
        "language": entry.language,
        "size": len(entry.data),
        "sha256": entry.sha256,
    }


def _print(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if isinstance(payload, list):
        for item in payload:
            print("\t".join(str(item.get(key, "")) for key in ("type", "name", "language", "size", "sha256")))
    elif isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def _diff_payload(left_path: Path, right_path: Path) -> dict[str, Any]:
    left_entries = _entries(left_path)
    right_entries = _entries(right_path)
    tree = diff_resources(left_entries, right_entries).to_dict()
    changes: list[dict[str, Any]] = []
    for node in tree.get("children", []):
        if node["status"] == "unchanged":
            continue
        record = {"status": node["status"]}
        if "before" in node:
            record.update(node["before"])
        if "after" in node and node["status"] == "added":
            record.update(node["after"])
        if node["status"] == "modified":
            record = {"status": "modified", "before": node.get("before"), "after": node.get("after")}
        changes.append(record)
    return {
        "left": str(left_path.expanduser().resolve()),
        "right": str(right_path.expanduser().resolve()),
        "fileChanged": _sha256(left_path) != _sha256(right_path),
        "changes": changes,
        "tree": tree,
    }


def command_list(args: argparse.Namespace) -> int:
    _print([_entry_record(entry) for entry in _entries(args.input)], args.json)
    return 0


def command_extract(args: argparse.Namespace) -> int:
    matches = [
        entry
        for entry in _entries(args.input)
        if entry.resource_type == args.type
        and entry.name == args.name
        and (args.language is None or entry.language == args.language)
    ]
    if not matches:
        raise ValueError("resource was not found")
    if len(matches) > 1:
        raise ValueError("resource has multiple languages; pass --language")
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(matches[0].data)
    _print({"output": str(output), "resource": _entry_record(matches[0])}, args.json)
    return 0


def command_plan(args: argparse.Namespace) -> int:
    from core.pe_writer import LiefPEWriter

    name: int | str = int(args.name) if args.name.isdigit() else args.name
    writer = LiefPEWriter()
    data = args.data.read_bytes()
    if args.action == "add":
        if not isinstance(name, int) or args.language is None:
            raise ValueError("plan add requires numeric name and language")
        payload = writer.plan_add_resource(args.input, args.type, name, args.language, data)
    else:
        payload = writer.plan_replace_resource(args.input, args.type, name, args.language, data)
    _print(payload, args.json)
    return 0


def command_search(args: argparse.Namespace) -> int:
    entries = _entries(args.input)
    if args.type or args.language is not None:
        entries = [entry for entry in entries if (not args.type or entry.resource_type == args.type) and (args.language is None or entry.language == args.language)]
    hits = search_resources(entries, args.query, regex=args.regex, case_sensitive=args.case_sensitive, hex_query=args.hex)
    _print([hit.to_dict() for hit in hits], args.json)
    return 0


def command_diff(args: argparse.Namespace) -> int:
    _print(_diff_payload(args.left, args.right), args.json)
    return 0


def command_export(args: argparse.Namespace) -> int:
    project = Project.load(args.project)
    output = project.export_git(args.output)
    _print({"output": str(output), "resourceCount": len(project.entries)}, args.json)
    return 0


def command_import(args: argparse.Namespace) -> int:
    project = Project.import_git(args.input, args.project)
    _print({"project": str(project.project_dir), "resourceCount": len(project.entries)}, args.json)
    return 0


def command_batch(args: argparse.Namespace) -> int:
    workspace = BatchWorkspace.load(args.manifest)
    payload = workspace.plan() if args.action == "plan" else workspace.apply(args.report)
    _print(payload, args.json)
    return 0 if payload.get("willWrite", True) else 1


def command_build(args: argparse.Namespace) -> int:
    project = Project.load(args.project)
    output = project.build(args.output)
    _print({"output": str(output), "sha256": _sha256(output)}, args.json)
    return 0


def command_evidence_ledger(args: argparse.Namespace) -> int:
    if args.action == "keygen":
        generate_ed25519_keypair(args.private_key, args.public_key)
        _print({"privateKey": str(args.private_key.resolve()), "publicKey": str(args.public_key.resolve())}, args.json)
        return 0
    ledger = EvidenceLedger(args.ledger, private_key=args.private_key, public_key=args.public_key)
    if args.action == "append":
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("evidence input must be a JSON object")
        record = ledger.append(payload)
        _print({"record": record, "verification": ledger.verify().to_dict()}, args.json)
        return 0
    verification = ledger.verify().to_dict()
    _print(verification, args.json)
    return 0 if verification["valid"] else 1


def command_forensic_baseline(args: argparse.Namespace) -> int:
    baseline = ForensicBaseline.from_path(args.input)
    artifact = baseline.save(args.output)
    payload = baseline.to_dict()
    payload["artifactPath"] = str(artifact)
    _print(payload, args.json)
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    payload = PEInspector.inspect(args.input).to_dict()
    payload["metadata"] = PEMetadataInspector.inspect(args.input).to_dict()
    payload["signature"] = inspect_signature(args.input).to_dict()
    payload["integrity"] = inspect_integrity(args.input).to_dict()
    payload["compatibility"] = inspect_compatibility(args.input).to_dict()
    payload["deepInvariants"] = inspect_deep(args.input).to_dict()
    payload["resourceGraph"] = ResourceGraph.from_path(args.input).to_dict()
    _print(payload, args.json)
    return 0


def _resource_match(input_path: Path, resource_type: str, name: str, language: int | None) -> ResourceEntry:
    resource_name = str(name)
    matches = [entry for entry in _entries(input_path) if entry.resource_type == resource_type and entry.name == resource_name and (language is None or entry.language == language)]
    if not matches:
        raise ValueError(f"{resource_type} resource was not found")
    if len(matches) > 1:
        raise ValueError(f"{resource_type} resource has multiple languages; pass --language")
    return matches[0]


def command_preview(args: argparse.Namespace) -> int:
    entry = _resource_match(args.input, args.type.upper(), args.name, args.language)
    output = args.output if args.output is not None else None
    result = PreviewEngine.preview(args.type, entry.data, resource_name=entry.name, language=entry.language, raw_length=args.length, output_path=output)
    _print(result.to_dict(), args.json)
    return 0


def command_image_payload(args: argparse.Namespace) -> int:
    kind = args.kind.upper()
    resource_type = "ICON" if kind == "ICON" else "CURSOR"
    format_name = args.format.lower()
    if args.action == "export":
        entry = _resource_match(args.input, resource_type, str(args.resource_id), args.language)
        data = icon_cursor_payload_to_bmp(entry.data, kind) if format_name == "bmp" else entry.data
        args.output.write_bytes(data)
        _print({"output": str(args.output.resolve()), "kind": kind, "resourceId": args.resource_id, "size": len(data), "format": format_name}, args.json)
        return 0
    data = args.payload.read_bytes()
    if not data or len(data) > 16 * 1024 * 1024:
        raise ValueError("image payload must be non-empty and no larger than 16 MiB")
    if format_name == "bmp" or (format_name == "auto" and data[:2] == b"BM") or (format_name == "auto" and data.startswith(b"\x89PNG\r\n\x1a\n")):
        data = icon_cursor_bmp_to_payload(data, kind)
    from core.pe_writer import LiefPEWriter
    result = LiefPEWriter().replace_resource(args.input, args.output, resource_type, args.resource_id, args.language, data)
    _print({"output": str(result.output_path), "beforeSha256": result.before_sha256, "afterSha256": result.after_sha256, "verified": result.verified, "verification": result.verification, "forensicEvidence": result.forensic_evidence, "forensicBaselinePath": result.forensic_baseline_path, "kind": kind, "resourceId": args.resource_id, "format": format_name, "size": len(data)}, args.json)
    return 0


def command_image_resource(args: argparse.Namespace) -> int:
    kind = args.kind.upper()
    resource_type = {"BITMAP": "BITMAP", "ICON": "GROUP_ICON", "CURSOR": "GROUP_CURSOR"}[kind]
    if args.action == "export":
        entry = _resource_match(args.input, resource_type, args.name, args.language)
        if kind == "BITMAP":
            payload = BitmapResource.from_dib(entry.data)
            args.output.write_bytes(payload.to_bmp())
            _print({"output": str(args.output.resolve()), "kind": kind, "width": payload.width, "height": payload.height, "bitCount": payload.bit_count}, args.json)
        else:
            group = IconCursorGroup.parse(entry.data)
            args.output.write_text(json.dumps(group.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            _print({"output": str(args.output.resolve()), "kind": group.kind, "dimensions": group.dimensions()}, args.json)
        return 0
    from core.pe_writer import LiefPEWriter
    name: int | str = int(args.name, 0) if args.name.isdigit() else args.name
    if kind == "BITMAP":
        data = BitmapResource.from_bmp(args.model.read_bytes()).to_dib()
    else:
        group = IconCursorGroup.from_dict(json.loads(args.model.read_text(encoding="utf-8")))
        if group.kind.upper() != kind:
            raise ValueError("image group kind does not match --kind")
        data = group.to_bytes()
    result = LiefPEWriter().replace_typed_resource(args.input, args.output, resource_type, name, args.language, data)
    _print({"output": str(result.output_path), "beforeSha256": result.before_sha256, "afterSha256": result.after_sha256, "verified": result.verified, "verification": result.verification, "forensicEvidence": result.forensic_evidence, "forensicBaselinePath": result.forensic_baseline_path}, args.json)
    return 0


def command_version_resource(args: argparse.Namespace) -> int:
    if args.action == "export":
        entry = _resource_match(args.input, "VERSION", args.name, args.language)
        info = VersionInfo.from_bytes(entry.data)
        args.output.write_text(info.to_json(), encoding="utf-8")
        _print({"output": str(args.output.resolve()), "type": "VERSION", "name": args.name, "language": entry.language}, args.json)
        return 0
    model = VersionInfo.from_json(args.model.read_text(encoding="utf-8"))
    from core.pe_writer import LiefPEWriter
    name: int | str = int(args.name, 0) if args.name.isdigit() else args.name
    result = LiefPEWriter().replace_typed_resource(args.input, args.output, "VERSION", name, args.language, model.to_bytes())
    _print({"output": str(result.output_path), "beforeSha256": result.before_sha256, "afterSha256": result.after_sha256, "verified": result.verified, "verification": result.verification, "forensicEvidence": result.forensic_evidence, "forensicBaselinePath": result.forensic_baseline_path}, args.json)
    return 0


def command_manifest_resource(args: argparse.Namespace) -> int:
    if args.action == "export":
        entry = _resource_match(args.input, "MANIFEST", args.name, args.language)
        document = ManifestDocument.parse(entry.data.decode("utf-8-sig"))
        args.output.write_text(json.dumps({"format": "resource_studio.manifest.v1", "xml": document.to_xml(), "validation": document.validate()}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _print({"output": str(args.output.resolve()), "type": "MANIFEST", "name": args.name, "language": entry.language}, args.json)
        return 0
    payload = json.loads(args.model.read_text(encoding="utf-8"))
    if payload.get("format") != "resource_studio.manifest.v1":
        raise ValueError("unsupported manifest model format")
    document = ManifestDocument.parse(str(payload["xml"]))
    report = document.validate()
    if report["errors"]:
        raise ValueError("cannot apply invalid manifest: " + "; ".join(report["errors"]))
    from core.pe_writer import LiefPEWriter
    result = LiefPEWriter().replace_manifest(args.input, args.output, document.to_xml())
    _print({"output": str(result.output_path), "beforeSha256": result.before_sha256, "afterSha256": result.after_sha256, "verified": result.verified, "verification": result.verification, "forensicEvidence": result.forensic_evidence, "forensicBaselinePath": result.forensic_baseline_path}, args.json)
    return 0


def command_menu_resource(args: argparse.Namespace) -> int:
    if args.action == "export":
        entry = _resource_match(args.input, "MENU", args.name, args.language)
        menu = MenuResource.parse(entry.data)
        args.output.write_text(json.dumps(menu.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _print({"output": str(args.output.resolve()), "type": "MENU", "name": args.name, "language": entry.language}, args.json)
        return 0
    menu = MenuResource.from_dict(json.loads(args.model.read_text(encoding="utf-8")))
    from core.pe_writer import LiefPEWriter
    name: int | str = int(args.name, 0) if args.name.isdigit() else args.name
    result = LiefPEWriter().replace_typed_resource(args.input, args.output, "MENU", name, args.language, menu.to_bytes())
    _print({"output": str(result.output_path), "beforeSha256": result.before_sha256, "afterSha256": result.after_sha256, "verified": result.verified, "verification": result.verification, "forensicEvidence": result.forensic_evidence, "forensicBaselinePath": result.forensic_baseline_path}, args.json)
    return 0


def command_string_table(args: argparse.Namespace) -> int:
    if args.action == "export":
        matches = [entry for entry in _entries(args.input) if entry.resource_type == "STRING" and entry.name == str(args.name) and (args.language is None or entry.language == args.language)]
        if not matches:
            raise ValueError("STRINGTABLE resource was not found")
        if len(matches) > 1:
            raise ValueError("STRINGTABLE resource has multiple languages; pass --language")
        block_id = int(str(args.name), 0)
        block = StringTableBlock.from_bytes(block_id, matches[0].data)
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"format": "resource_studio.string_table.v1", "blockId": block.block_id, "firstStringId": block.first_string_id, "strings": list(block.strings)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _print({"output": str(output), "type": "STRING", "name": args.name, "language": matches[0].language, "firstStringId": block.first_string_id}, args.json)
        return 0
    if args.model is None:
        raise ValueError("string-table apply requires --model")
    model = json.loads(args.model.read_text(encoding="utf-8"))
    if model.get("format") != "resource_studio.string_table.v1":
        raise ValueError("unsupported STRINGTABLE model format")
    block = StringTableBlock(int(model["blockId"]), tuple(str(value) for value in model["strings"]))
    from core.pe_writer import LiefPEWriter

    resource_name: int | str = int(str(args.name), 0) if str(args.name).isdigit() else args.name
    result = LiefPEWriter().replace_typed_resource(args.input, args.output, "STRING", resource_name, args.language, block.to_bytes())
    _print({"output": str(result.output_path), "beforeSha256": result.before_sha256, "afterSha256": result.after_sha256, "verified": result.verified, "verification": result.verification, "forensicEvidence": result.forensic_evidence, "forensicBaselinePath": result.forensic_baseline_path}, args.json)
    return 0


def command_localization(args: argparse.Namespace) -> int:
    catalog = LocalizationCatalog.from_json(args.input.read_text(encoding="utf-8"))
    if args.action == "compare":
        _print(catalog.mode_report(args.source_language, args.target_language), args.json)
        return 0
    pseudo = catalog.pseudo_localize(args.source_language, args.target_language)
    if args.output is None:
        raise ValueError("localization pseudo requires --output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(pseudo.to_json(), encoding="utf-8")
    _print({"output": str(args.output), "sourceLanguage": args.source_language, "targetLanguage": args.target_language}, args.json)
    return 0


def command_signature(args: argparse.Namespace) -> int:
    if args.action == "inspect":
        _print(inspect_signature(args.input).to_dict(), args.json)
        return 0
    if args.action == "strip":
        result = strip_authenticode(args.input, args.output)
        _print(result.to_dict(), args.json)
        return 0
    if args.action == "re-sign":
        result = resign_authenticode(
            args.input,
            args.output,
            args.certificate,
            password_env=args.password_env,
            timestamp_url=args.timestamp_url,
            signtool=args.signtool,
            strip_existing=args.strip_existing,
        )
        _print(result.to_dict(), args.json)
        return 0
    password = os.environ.get(args.password_env, "")
    if not password:
        raise ValueError(f"certificate password is missing from environment variable {args.password_env}")
    payload = create_test_certificate(args.output, password=password, subject=args.subject, days=args.days)
    _print(payload, args.json)
    return 0


def command_dialog(args: argparse.Namespace) -> int:
    if args.action == "export":
        matches = [entry for entry in _entries(args.input) if entry.resource_type == "DIALOG" and entry.name == args.name and (args.language is None or entry.language == args.language)]
        if not matches:
            raise ValueError("DIALOG resource was not found")
        if len(matches) > 1:
            raise ValueError("DIALOG resource has multiple languages; pass --language")
        dialog = DialogResource.parse(matches[0].data)
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(dialog.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        _print({"output": str(output), "type": "DIALOG", "name": args.name, "language": matches[0].language}, args.json)
        return 0
    if args.model is None:
        raise ValueError("dialog apply requires --model")
    model = json.loads(args.model.read_text(encoding="utf-8"))
    dialog = DialogResource.from_dict(model)
    from core.pe_writer import LiefPEWriter

    result = LiefPEWriter().replace_typed_resource(args.input, args.output, "DIALOG", args.name, args.language, dialog.to_bytes())
    _print({"output": str(result.output_path), "beforeSha256": result.before_sha256, "afterSha256": result.after_sha256, "verified": result.verified, "verification": result.verification, "forensicEvidence": result.forensic_evidence, "forensicBaselinePath": result.forensic_baseline_path}, args.json)
    return 0


def command_version_info(args: argparse.Namespace) -> int:
    text = args.input.read_text(encoding="utf-8")
    source_format = args.input_format
    if source_format == "auto":
        source_format = "json" if args.input.suffix.lower() == ".json" else "rc"
    version = VersionInfo.from_json(text) if source_format == "json" else VersionInfo.from_rc(text)
    output_format = args.output_format
    rendered = version.to_json() if output_format == "json" else version.to_rc()
    if args.output:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        payload = {"output": str(output), "format": output_format, "valid": version.validate()["valid"]}
    else:
        payload = {"format": output_format, "content": rendered}
    _print(payload, args.json)
    return 0


def command_hex(args: argparse.Namespace) -> int:
    viewer = HexViewer(args.input.read_bytes())
    if args.offset is not None:
        chunk = viewer.slice(args.offset, args.length)
        source = "file"
        resource = None
    else:
        with tempfile.TemporaryDirectory(prefix="resource-studio-cli-hex-") as temporary:
            project = Project.open_pe(args.input, Path(temporary) / "project")
            index = project.index_resources()
            item = index.find(args.type, args.name, args.language)
            if item is None:
                raise ValueError("resource was not found")
            chunk = viewer.resource_slice(index, args.type, args.name, args.language, args.length)
        source = "resource"
        resource = {"type": args.type, "name": args.name, "language": args.language}
    payload = {"source": source, "resource": resource, "offset": chunk.offset, "size": len(chunk.data), "hex": chunk.hex(), "ascii": chunk.ascii(), "base64": chunk.base64(), "cArray": chunk.as_c_array()}
    _print(payload, args.json)
    return 0


def command_rc(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.action == "compile":
        resource_file = compile_rc(args.input.read_text(encoding="utf-8"), language=args.language)
        output.write_bytes(resource_file.to_bytes())
        payload = {"output": str(output), "format": "res", "recordCount": len(resource_file.records), "size": output.stat().st_size}
    else:
        content = decompile_res(args.input.read_bytes())
        output.write_text(content, encoding="utf-8")
        payload = {"output": str(output), "format": "rc", "size": output.stat().st_size}
    _print(payload, args.json)
    return 0


def command_image_diff(args: argparse.Namespace) -> int:
    before = args.left.read_bytes()
    after = args.right.read_bytes()
    _print(diff_image_payloads(before, after, kind=args.kind).to_dict(), args.json)
    return 0


def command_validate(args: argparse.Namespace) -> int:
    report = PEHealth.inspect(args.input).to_dict()
    _print(report, args.json)
    return 0 if report["is_pe"] and (not args.strict or not report["warnings"]) else 1


def command_report(args: argparse.Namespace) -> int:
    if args.kind == "health":
        payload = PEHealth.inspect(args.input).to_dict()
    elif args.kind == "inspect":
        payload = PEInspector.inspect(args.input).to_dict()
        payload["metadata"] = PEMetadataInspector.inspect(args.input).to_dict()
        payload["signature"] = inspect_signature(args.input).to_dict()
        payload["integrity"] = inspect_integrity(args.input).to_dict()
        payload["compatibility"] = inspect_compatibility(args.input).to_dict()
    elif args.kind == "image-diff":
        payload = diff_image_payloads(args.input.read_bytes(), args.right.read_bytes(), kind=args.image_kind).to_dict()
    else:
        payload = _diff_payload(args.input, args.right)
    rendered = render_report(payload, args.format)
    if args.output:
        output = Path(args.output).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(str(output))
    else:
        sys.stdout.write(rendered)
    return 0


def _key(entry: ResourceEntry) -> tuple[str, str, int | None]:
    return entry.key


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="resource-studio", description="Resource Studio core CLI")
    subparsers = root.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list PE resources")
    list_parser.add_argument("input", type=Path)
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(handler=command_list)

    extract_parser = subparsers.add_parser("extract", help="extract one resource")
    extract_parser.add_argument("input", type=Path)
    extract_parser.add_argument("--type", required=True)
    extract_parser.add_argument("--name", required=True)
    extract_parser.add_argument("--language", type=int)
    extract_parser.add_argument("--output", required=True, type=Path)
    extract_parser.add_argument("--json", action="store_true")
    extract_parser.set_defaults(handler=command_extract)

    plan_parser = subparsers.add_parser("plan", help="preview a resource write without creating the requested output")
    plan_parser.add_argument("action", choices=("add", "replace"))
    plan_parser.add_argument("input", type=Path)
    plan_parser.add_argument("--type", required=True)
    plan_parser.add_argument("--name", required=True)
    plan_parser.add_argument("--language", type=int)
    plan_parser.add_argument("--data", required=True, type=Path)
    plan_parser.add_argument("--json", action="store_true")
    plan_parser.set_defaults(handler=command_plan)

    search_parser = subparsers.add_parser("search", help="search text, UTF-16, metadata, or bytes in PE resources")
    search_parser.add_argument("input", type=Path)
    search_parser.add_argument("query")
    search_parser.add_argument("--type")
    search_parser.add_argument("--language", type=int)
    search_parser.add_argument("--regex", action="store_true")
    search_parser.add_argument("--case-sensitive", action="store_true")
    search_parser.add_argument("--hex", action="store_true")
    search_parser.add_argument("--json", action="store_true")
    search_parser.set_defaults(handler=command_search)

    diff_parser = subparsers.add_parser("diff", help="compare resources in two PE files")
    diff_parser.add_argument("left", type=Path)
    diff_parser.add_argument("right", type=Path)
    diff_parser.add_argument("--json", action="store_true")
    diff_parser.set_defaults(handler=command_diff)

    export_parser = subparsers.add_parser("export", help="export a portable project directory")
    export_parser.add_argument("project", type=Path)
    export_parser.add_argument("--output", required=True, type=Path)
    export_parser.add_argument("--json", action="store_true")
    export_parser.set_defaults(handler=command_export)

    import_parser = subparsers.add_parser("import", help="import a portable project directory")
    import_parser.add_argument("input", type=Path)
    import_parser.add_argument("--project", required=True, type=Path)
    import_parser.add_argument("--json", action="store_true")
    import_parser.set_defaults(handler=command_import)

    batch_parser = subparsers.add_parser("batch", help="plan or apply a multi-file PE batch manifest")
    batch_parser.add_argument("action", choices=("plan", "apply"))
    batch_parser.add_argument("manifest", type=Path)
    batch_parser.add_argument("--report", type=Path)
    batch_parser.add_argument("--json", action="store_true")
    batch_parser.set_defaults(handler=command_batch)

    build_parser = subparsers.add_parser("build", help="save an isolated project workspace as a new PE")
    build_parser.add_argument("project", type=Path)
    build_parser.add_argument("--output", required=True, type=Path)
    build_parser.add_argument("--json", action="store_true")
    build_parser.set_defaults(handler=command_build)

    ledger_parser = subparsers.add_parser("evidence-ledger", help="append or verify tamper-evident evidence records")
    ledger_parser.add_argument("action", choices=("append", "verify", "keygen"))
    ledger_parser.add_argument("--ledger", required=True, type=Path)
    ledger_parser.add_argument("--input", type=Path)
    ledger_parser.add_argument("--private-key", type=Path)
    ledger_parser.add_argument("--public-key", type=Path)
    ledger_parser.add_argument("--json", action="store_true")
    ledger_parser.set_defaults(handler=command_evidence_ledger)

    baseline_parser = subparsers.add_parser("forensic-baseline", help="persist an independent PE baseline artifact")
    baseline_parser.add_argument("input", type=Path)
    baseline_parser.add_argument("--output", required=True, type=Path)
    baseline_parser.add_argument("--json", action="store_true")
    baseline_parser.set_defaults(handler=command_forensic_baseline)

    inspect_parser = subparsers.add_parser("inspect", help="inspect PE structure without writing")
    inspect_parser.add_argument("input", type=Path)
    inspect_parser.add_argument("--json", action="store_true")
    inspect_parser.set_defaults(handler=command_inspect)

    preview_parser = subparsers.add_parser("preview", help="preview a typed resource with raw fallback")
    preview_parser.add_argument("input", type=Path)
    preview_parser.add_argument("--type", required=True)
    preview_parser.add_argument("--name", required=True)
    preview_parser.add_argument("--language", type=int, required=True)
    preview_parser.add_argument("--length", type=int, default=4096)
    preview_parser.add_argument("--output", type=Path)
    preview_parser.add_argument("--json", action="store_true")
    preview_parser.set_defaults(handler=command_preview)

    image_payload_parser = subparsers.add_parser("image-payload", help="export or replace an individual ICON/CURSOR payload")
    image_payload_parser.add_argument("action", choices=("export", "apply"))
    image_payload_parser.add_argument("input", type=Path)
    image_payload_parser.add_argument("--kind", choices=("icon", "cursor"), required=True)
    image_payload_parser.add_argument("--resource-id", type=int, required=True)
    image_payload_parser.add_argument("--language", type=int, required=True)
    image_payload_parser.add_argument("--output", type=Path, required=True)
    image_payload_parser.add_argument("--payload", type=Path)
    image_payload_parser.add_argument("--format", choices=("raw", "bmp", "auto"), default="raw")
    image_payload_parser.add_argument("--json", action="store_true")
    image_payload_parser.set_defaults(handler=command_image_payload)

    image_parser = subparsers.add_parser("image-resource", help="export or apply BITMAP or GROUP_ICON/GROUP_CURSOR")
    image_parser.add_argument("action", choices=("export", "apply"))
    image_parser.add_argument("input", type=Path)
    image_parser.add_argument("--kind", choices=("bitmap", "icon", "cursor"), required=True)
    image_parser.add_argument("--name", required=True)
    image_parser.add_argument("--language", type=int, required=True)
    image_parser.add_argument("--output", type=Path, required=True)
    image_parser.add_argument("--model", type=Path)
    image_parser.add_argument("--json", action="store_true")
    image_parser.set_defaults(handler=command_image_resource)

    for command_name, handler, help_text in (("version-resource", command_version_resource, "export or apply a typed VERSION resource"), ("manifest-resource", command_manifest_resource, "export or apply a typed MANIFEST resource"), ("menu-resource", command_menu_resource, "export or apply a typed MENU resource")):
        resource_parser = subparsers.add_parser(command_name, help=help_text)
        resource_parser.add_argument("action", choices=("export", "apply"))
        resource_parser.add_argument("input", type=Path)
        resource_parser.add_argument("--name", default="1")
        resource_parser.add_argument("--language", type=int, required=True)
        resource_parser.add_argument("--output", type=Path, required=True)
        resource_parser.add_argument("--model", type=Path)
        resource_parser.add_argument("--json", action="store_true")
        resource_parser.set_defaults(handler=handler)

    string_table_parser = subparsers.add_parser("string-table", help="export or apply a typed STRINGTABLE block")
    string_table_parser.add_argument("action", choices=("export", "apply"))
    string_table_parser.add_argument("input", type=Path)
    string_table_parser.add_argument("--name", required=True)
    string_table_parser.add_argument("--language", type=int, required=True)
    string_table_parser.add_argument("--output", type=Path, required=True)
    string_table_parser.add_argument("--model", type=Path)
    string_table_parser.add_argument("--json", action="store_true")
    string_table_parser.set_defaults(handler=command_string_table)

    localization_parser = subparsers.add_parser("localization", help="compare or pseudo-localize a localization catalog")
    localization_parser.add_argument("action", choices=("compare", "pseudo"))
    localization_parser.add_argument("input", type=Path)
    localization_parser.add_argument("--source-language", required=True)
    localization_parser.add_argument("--target-language", required=True)
    localization_parser.add_argument("--output", type=Path)
    localization_parser.add_argument("--json", action="store_true")
    localization_parser.set_defaults(handler=command_localization)

    signature_parser = subparsers.add_parser("signature", help="inspect, strip, or test-sign Authenticode")
    signature_parser.add_argument("action", choices=("inspect", "strip", "re-sign", "create-test-cert"))
    signature_parser.add_argument("input", type=Path, nargs="?")
    signature_parser.add_argument("--output", type=Path)
    signature_parser.add_argument("--certificate", type=Path)
    signature_parser.add_argument("--password-env", default="RS_PFX_PASSWORD")
    signature_parser.add_argument("--timestamp-url")
    signature_parser.add_argument("--signtool", type=Path)
    signature_parser.add_argument("--strip-existing", action="store_true")
    signature_parser.add_argument("--subject", default="CN=Resource Studio Test")
    signature_parser.add_argument("--days", type=int, default=365)
    signature_parser.add_argument("--json", action="store_true")
    signature_parser.set_defaults(handler=command_signature)

    dialog_parser = subparsers.add_parser("dialog", help="export or apply a binary Win32 Dialog resource")
    dialog_parser.add_argument("action", choices=("export", "apply"))
    dialog_parser.add_argument("input", type=Path)
    dialog_parser.add_argument("--name", required=True)
    dialog_parser.add_argument("--language", type=int)
    dialog_parser.add_argument("--output", required=True, type=Path)
    dialog_parser.add_argument("--model", type=Path)
    dialog_parser.add_argument("--json", action="store_true")
    dialog_parser.set_defaults(handler=command_dialog)

    version_parser = subparsers.add_parser("version-info", help="convert VersionInfo between RC and JSON")
    version_parser.add_argument("input", type=Path)
    version_parser.add_argument("--input-format", choices=("auto", "rc", "json"), default="auto")
    version_parser.add_argument("--output-format", choices=("rc", "json"), required=True)
    version_parser.add_argument("--output", type=Path)
    version_parser.add_argument("--json", action="store_true")
    version_parser.set_defaults(handler=command_version_info)

    hex_parser = subparsers.add_parser("hex", help="view raw file bytes or a resource slice")
    hex_parser.add_argument("input", type=Path)
    hex_parser.add_argument("--offset", type=int)
    hex_parser.add_argument("--type")
    hex_parser.add_argument("--name")
    hex_parser.add_argument("--language", type=int)
    hex_parser.add_argument("--length", type=int, default=256)
    hex_parser.add_argument("--json", action="store_true")
    hex_parser.set_defaults(handler=command_hex)

    rc_parser = subparsers.add_parser("rc", help="compile the supported RC subset to RES or decompile RES to RC")
    rc_parser.add_argument("action", choices=("compile", "decompile"))
    rc_parser.add_argument("input", type=Path)
    rc_parser.add_argument("--output", required=True, type=Path)
    rc_parser.add_argument("--language", type=int, default=1033)
    rc_parser.add_argument("--json", action="store_true")
    rc_parser.set_defaults(handler=command_rc)

    image_diff_parser = subparsers.add_parser("image-diff", help="compare two image payload files")
    image_diff_parser.add_argument("left", type=Path)
    image_diff_parser.add_argument("right", type=Path)
    image_diff_parser.add_argument("--kind", choices=("bitmap", "icon", "cursor"), default="bitmap")
    image_diff_parser.add_argument("--json", action="store_true")
    image_diff_parser.set_defaults(handler=command_image_diff)

    validate_parser = subparsers.add_parser("validate", help="inspect PE health")
    validate_parser.add_argument("input", type=Path)
    validate_parser.add_argument("--strict", action="store_true", help="fail when warnings exist")
    validate_parser.add_argument("--json", action="store_true")
    validate_parser.set_defaults(handler=command_validate)

    report_parser = subparsers.add_parser("report", help="write a health or diff report")
    report_parser.add_argument("kind", choices=("health", "inspect", "diff", "image-diff"))
    report_parser.add_argument("input", type=Path)
    report_parser.add_argument("right", type=Path, nargs="?")
    report_parser.add_argument("--image-kind", choices=("bitmap", "icon", "cursor"), default="bitmap")
    report_parser.add_argument("--format", choices=sorted(FORMATS), default="json")
    report_parser.add_argument("--output", type=Path)
    report_parser.set_defaults(handler=command_report)
    return root


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command == "evidence-ledger":
        if arguments.action == "append" and arguments.input is None:
            parser().error("evidence-ledger append requires --input")
        if arguments.action == "keygen" and (arguments.private_key is None or arguments.public_key is None):
            parser().error("evidence-ledger keygen requires --private-key and --public-key")
    if arguments.command == "hex":
        resource_mode = all(value is not None for value in (arguments.type, arguments.name, arguments.language))
        if arguments.offset is None and not resource_mode:
            parser().error("hex requires --offset or --type/--name/--language")
        if arguments.offset is not None and resource_mode:
            parser().error("hex cannot combine --offset with resource selectors")
        if arguments.offset is not None and arguments.offset < 0:
            parser().error("hex --offset must be non-negative")
    if arguments.command == "report" and arguments.kind in {"diff", "image-diff"} and arguments.right is None:
        parser().error(f"report {arguments.kind} requires LEFT and RIGHT inputs")
    if arguments.command in {"string-table", "version-resource", "manifest-resource", "menu-resource", "image-resource"} and arguments.action == "apply" and arguments.model is None:
        parser().error("string-table apply requires --model")
    if arguments.command == "image-payload" and arguments.action == "apply" and arguments.payload is None:
        parser().error("image-payload apply requires --payload")
    if arguments.command == "localization" and arguments.action == "pseudo" and arguments.output is None:
        parser().error("localization pseudo requires --output")
    if arguments.command == "signature":
        if arguments.action == "inspect" and arguments.input is None:
            parser().error("signature inspect requires INPUT")
        if arguments.action in {"strip", "re-sign"} and (arguments.input is None or arguments.output is None):
            parser().error(f"signature {arguments.action} requires INPUT and --output")
        if arguments.action == "re-sign" and arguments.certificate is None:
            parser().error("signature re-sign requires --certificate")
        if arguments.action == "create-test-cert" and arguments.output is None:
            parser().error("signature create-test-cert requires --output")
    try:
        return int(arguments.handler(arguments))
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
