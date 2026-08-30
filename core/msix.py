from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_ENTRIES = 100_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024


class MSIXError(RuntimeError):
    pass


def inspect_package(path: Path) -> dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise MSIXError("MSIX package is not a regular file")
    if resolved.stat().st_size > MAX_PACKAGE_BYTES:
        raise MSIXError("MSIX package exceeds the configured size limit")
    try:
        with zipfile.ZipFile(resolved) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_PACKAGE_ENTRIES:
                raise MSIXError("MSIX package contains too many entries")
            entries = []
            for info in infos:
                name = _safe_member(info)
                if info.file_size > MAX_MEMBER_BYTES:
                    raise MSIXError(f"package member exceeds the configured limit: {name}")
                if info.is_dir():
                    continue
                entries.append(
                    {
                        "name": name,
                        "size": info.file_size,
                        "compressedSize": info.compress_size,
                        "sha256": _hash_member(archive, info),
                    }
                )
            names = {item["name"] for item in entries}
            manifest = _read_manifest(archive, names)
            blockmap = _read_blockmap(archive, names)
            pri = [item for item in entries if item["name"].lower().endswith("resources.pri") or item["name"].lower().endswith(".pri")]
            signed = "AppxSignature.p7x" in names or any(name.lower() == "appxsignature.p7x" for name in names)
            is_bundle = any(name.lower().endswith((".msix", ".appx")) for name in names) and "AppxManifest.xml" not in names
            return {
                "schemaVersion": "resource_studio.msix_package.v1",
                "path": str(resolved),
                "sha256": _sha256_file(resolved),
                "size": resolved.stat().st_size,
                "kind": "bundle" if is_bundle else "package",
                "valid": True,
                "signed": signed,
                "entryCount": len(entries),
                "entries": entries,
                "manifest": manifest,
                "blockMap": blockmap,
                "pri": [
                    {
                        "name": item["name"],
                        "size": item["size"],
                        "sha256": item["sha256"],
                        "parser": "zip-metadata-only",
                        "readOnly": True,
                    }
                    for item in pri
                ],
                "limitations": [
                    "PRI binary semantics require MRT Core or MakePri on Windows; this cross-platform layer reports bounded package metadata only.",
                    "MakeAppx performs limited semantic validation; install/Store validation is a separate Windows concern.",
                ],
            }
    except zipfile.BadZipFile as exc:
        raise MSIXError("file is not a valid ZIP-based MSIX/AppX package") from exc


def apply_package_change(
    input_path: Path,
    output_path: Path,
    *,
    action: str,
    member_name: str,
    payload: bytes | None = None,
) -> dict[str, Any]:
    source = Path(input_path).expanduser().resolve()
    output = Path(output_path).expanduser().resolve()
    if source == output:
        raise MSIXError("in-place MSIX mutation is disabled; use a new output path")
    if os.name != "nt":
        raise MSIXError("MSIX rebuild requires Windows SDK MakeAppx.exe")
    before = inspect_package(source)
    if before["kind"] != "package":
        raise MSIXError("bundle mutation is not supported; mutate an inner package separately")
    if before["signed"]:
        raise MSIXError("signed MSIX mutation is blocked; rebuild and sign through an explicit certificate workflow")
    name = _safe_member_name(member_name)
    if name.lower() == "appxsignature.p7x":
        raise MSIXError("AppxSignature.p7x cannot be added or replaced by the generic writer")
    if action not in {"add", "replace", "delete"}:
        raise MSIXError("MSIX action must be add, replace, or delete")
    if action in {"add", "replace"} and payload is None:
        raise MSIXError("payload is required for add and replace")
    with tempfile.TemporaryDirectory(prefix="resource-studio-msix-stage-") as temporary:
        stage = Path(temporary) / "package"
        stage.mkdir()
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                safe_name = _safe_member(info)
                if info.is_dir():
                    continue
                destination = stage / PurePosixPath(safe_name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info))
        target = stage / PurePosixPath(name)
        exists = target.is_file()
        if action == "add" and exists:
            raise MSIXError("package member already exists")
        if action == "replace" and not exists:
            raise MSIXError("package member does not exist")
        if action == "delete":
            if not exists:
                raise MSIXError("package member does not exist")
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bytes(payload or b""))
        output.parent.mkdir(parents=True, exist_ok=True)
        makeappx = shutil.which("makeappx.exe") or shutil.which("makeappx")
        if not makeappx:
            raise MSIXError("MakeAppx.exe was not found in the Windows SDK")
        completed = subprocess.run(
            [makeappx, "pack", "/d", str(stage), "/p", str(output), "/o"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise MSIXError(f"MakeAppx failed with exit code {completed.returncode}")
    after = inspect_package(output)
    if not after["valid"]:
        output.unlink(missing_ok=True)
        raise MSIXError("rebuilt MSIX failed structural validation")
    return {
        "schemaVersion": "resource_studio.msix_mutation.v1",
        "action": action,
        "member": name,
        "beforeSha256": before["sha256"],
        "afterSha256": after["sha256"],
        "outputPath": str(output),
        "before": before,
        "after": after,
        "verified": True,
        "signingRequired": True,
    }


def _safe_member(info: zipfile.ZipInfo) -> str:
    if info.external_attr & 0xF000 == 0xA000:
        raise MSIXError("symbolic-link package members are rejected")
    return _safe_member_name(info.filename)


def _safe_member_name(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise MSIXError("unsafe package member path")
    return path.as_posix()


def _hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info) as stream:
        remaining = info.file_size
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise MSIXError("truncated package member")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _read_manifest(archive: zipfile.ZipFile, names: set[str]) -> dict[str, Any] | None:
    if "AppxManifest.xml" not in names:
        return None
    raw = archive.read("AppxManifest.xml")
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise MSIXError("manifest with DTD or entity declarations is rejected")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise MSIXError("AppxManifest.xml is malformed") from exc
    identity = next((element for element in root.iter() if _local(element.tag) == "Identity"), None)
    applications = [element for element in root.iter() if _local(element.tag) == "Application"]
    return {
        "identity": dict(identity.attrib) if identity is not None else None,
        "applications": [dict(element.attrib) for element in applications],
        "xmlSha256": hashlib.sha256(raw).hexdigest(),
    }


def _read_blockmap(archive: zipfile.ZipFile, names: set[str]) -> dict[str, Any] | None:
    if "AppxBlockMap.xml" not in names:
        return None
    raw = archive.read("AppxBlockMap.xml")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise MSIXError("AppxBlockMap.xml is malformed") from exc
    files = []
    for element in root.iter():
        if _local(element.tag) == "File":
            files.append({"name": element.attrib.get("Name"), "size": element.attrib.get("Size"), "blocks": len([child for child in element if _local(child.tag) == "Block"])})
    return {"hashMethod": root.attrib.get("HashMethod"), "fileCount": len(files), "files": files, "xmlSha256": hashlib.sha256(raw).hexdigest()}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
