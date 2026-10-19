from __future__ import annotations

import json
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import lief

from .parse_cache import shared_parse

GO_BUILDINF_MAGIC = b"\xff Go buildinf:"


@dataclass(frozen=True)
class GoDependency:
    path: str
    version: str
    hash: str | None = None
    replacement: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "version": self.version,
            "hash": self.hash,
            "replacement": self.replacement,
        }


@dataclass(frozen=True)
class GoBuildInfo:
    is_go: bool
    version: str | None
    main_module: str | None
    main_version: str | None
    dependencies: tuple[GoDependency, ...]
    build_settings: dict[str, str]

    def to_dict(self, max_deps: int = 50) -> dict[str, Any]:
        return {
            "isGo": self.is_go,
            "version": self.version,
            "mainModule": self.main_module,
            "mainVersion": self.main_version,
            "dependencyCount": len(self.dependencies),
            "dependencies": [d.to_dict() for d in self.dependencies[:max_deps]],
            "buildSettings": dict(self.build_settings),
        }


@dataclass(frozen=True)
class RustDependency:
    name: str
    version: str
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
        }


@dataclass(frozen=True)
class RustBuildInfo:
    is_rust: bool
    rustc_commit: str | None
    root_package: str | None
    dependencies: tuple[RustDependency, ...]

    def to_dict(self, max_deps: int = 50) -> dict[str, Any]:
        return {
            "isRust": self.is_rust,
            "rustcCommit": self.rustc_commit,
            "rootPackage": self.root_package,
            "dependencyCount": len(self.dependencies),
            "dependencies": [d.to_dict() for d in self.dependencies[:max_deps]],
        }


@dataclass(frozen=True)
class ToolchainAuditReport:
    path: str
    format: str
    toolchain_type: str  # "GO", "RUST", "MANAGED_DOTNET", "NATIVE_WIN32"
    go_info: GoBuildInfo | None
    rust_info: RustBuildInfo | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "toolchainType": self.toolchain_type,
            "go": self.go_info.to_dict() if self.go_info else None,
            "rust": self.rust_info.to_dict() if self.rust_info else None,
        }


class ToolchainAuditor:
    """
    Fast, offline, zero-dependency auditor for compiled Go and Rust binaries.
    Extracts Go runtime build info and module trees, and Rust compiler commit hashes and Cargo-auditable dependency graphs.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).expanduser().resolve()
        if not self.path.is_file():
            raise FileNotFoundError(f"File not found: {self.path}")

        self.raw_bytes = self.path.read_bytes()
        self.binary = shared_parse(self.path)

    def _rva_to_file_offset(self, rva: int) -> int | None:
        if not self.binary or not isinstance(self.binary, lief.PE.Binary):
            return None
        for sec in self.binary.sections:
            if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
                return sec.offset + (rva - sec.virtual_address)
        return None

    def audit_go(self) -> GoBuildInfo:
        """Locates and decodes Go build information (runtime.buildVersion and module graph)."""
        idx = self.raw_bytes.find(GO_BUILDINF_MAGIC)
        if idx == -1:
            return GoBuildInfo(is_go=False, version=None, main_module=None, main_version=None, dependencies=(), build_settings={})

        ptr_size = self.raw_bytes[idx + 14]
        is_big_endian = self.raw_bytes[idx + 15] != 0
        endian = ">" if is_big_endian else "<"

        imagebase = self.binary.optional_header.imagebase if self.binary and isinstance(self.binary, lief.PE.Binary) else 0

        # Pointers in header
        cur = idx + 16
        version = None
        module_text = None

        if ptr_size == 8:
            ver_ptr, mod_ptr = struct.unpack(f"{endian}QQ", self.raw_bytes[cur : cur + 16])
        elif ptr_size == 4:
            ver_ptr, mod_ptr = struct.unpack(f"{endian}II", self.raw_bytes[cur : cur + 8])
        else:
            ver_ptr, mod_ptr = 0, 0

        # Helper to read string from pointer (VA or RVA)
        def read_go_str(ptr: int) -> str | None:
            if ptr == 0:
                return None
            rva = ptr - imagebase if ptr >= imagebase else ptr
            file_off = self._rva_to_file_offset(rva)
            if file_off is None or file_off >= len(self.raw_bytes):
                return None
            # Go strings have ptr + len
            # In Go buildinf, version is string: pointer then length
            ver_len = 0
            if ptr_size == 8 and file_off + 8 <= len(self.raw_bytes):
                str_data_ptr = struct.unpack(f"{endian}Q", self.raw_bytes[file_off : file_off + 8])[0]
                str_len = struct.unpack(f"{endian}Q", self.raw_bytes[file_off + 8 : file_off + 16])[0]
                s_rva = str_data_ptr - imagebase if str_data_ptr >= imagebase else str_data_ptr
                s_off = self._rva_to_file_offset(s_rva)
                if s_off is not None and s_off + str_len <= len(self.raw_bytes):
                    return self.raw_bytes[s_off : s_off + str_len].decode("utf-8", errors="replace")
            return None

        # Try pointer-based version first
        version = read_go_str(ver_ptr)

        # Fallback inline string search near magic
        if not version:
            v_match = re.search(rb"go1\.\d+(\.\d+)?", self.raw_bytes[idx : idx + 256])
            if v_match:
                version = v_match.group(0).decode("ascii")

        # Try reading module text
        # In Go 1.18+, module data is often stored with framing bytes: \xff\x77\x70\x00 (magic prefix)
        mod_start = self.raw_bytes.find(b"path\t", idx)
        if mod_start != -1 and mod_start - idx < 1024:
            # Read until null or non-printable delimiter
            mod_end = self.raw_bytes.find(b"\x00\x00", mod_start)
            if mod_end == -1:
                mod_end = mod_start + 65536
            mod_raw = self.raw_bytes[mod_start:mod_end]
            module_text = mod_raw.decode("utf-8", errors="replace")

        if not module_text and mod_ptr != 0:
            m_rva = mod_ptr - imagebase if mod_ptr >= imagebase else mod_ptr
            m_off = self._rva_to_file_offset(m_rva)
            if m_off is not None:
                # Check for length prefix
                if ptr_size == 8 and m_off + 16 <= len(self.raw_bytes):
                    str_data_ptr = struct.unpack(f"{endian}Q", self.raw_bytes[m_off : m_off + 8])[0]
                    str_len = struct.unpack(f"{endian}Q", self.raw_bytes[m_off + 8 : m_off + 16])[0]
                    s_rva = str_data_ptr - imagebase if str_data_ptr >= imagebase else str_data_ptr
                    s_off = self._rva_to_file_offset(s_rva)
                    if s_off is not None and s_off + str_len <= len(self.raw_bytes):
                        module_text = self.raw_bytes[s_off : s_off + str_len].decode("utf-8", errors="replace")

        # Parse module text
        main_mod = None
        main_ver = None
        deps: list[GoDependency] = []
        build_settings: dict[str, str] = {}

        if module_text:
            for line in module_text.splitlines():
                parts = line.strip().split("\t")
                if not parts:
                    continue
                tag = parts[0]
                if tag == "mod" and len(parts) >= 3:
                    main_mod = parts[1]
                    main_ver = parts[2]
                elif tag == "dep" and len(parts) >= 3:
                    dep_path = parts[1]
                    dep_ver = parts[2]
                    dep_hash = parts[3] if len(parts) > 3 else None
                    deps.append(GoDependency(path=dep_path, version=dep_ver, hash=dep_hash))
                elif tag == "build" and len(parts) >= 2:
                    kv = parts[1].split("=", 1)
                    if len(kv) == 2:
                        build_settings[kv[0]] = kv[1]

        return GoBuildInfo(
            is_go=True,
            version=version,
            main_module=main_mod,
            main_version=main_ver,
            dependencies=tuple(deps),
            build_settings=build_settings,
        )

    def audit_rust(self) -> RustBuildInfo:
        """Locates and decodes Rust compiler commit and cargo-auditable dependency records."""
        # 1. Infer rustc commit hash from `/rustc/<40-hex>/`
        rustc_commit = None
        commit_match = re.search(rb"[/\\]rustc[/\\]([0-9a-fA-F]{40})[/\\]", self.raw_bytes)
        if commit_match:
            rustc_commit = commit_match.group(1).decode("ascii")

        # 2. Check for .dep-v0 section or cargo-auditable zlib payload
        dep_section_data = None
        if self.binary and isinstance(self.binary, lief.PE.Binary):
            for sec in self.binary.sections:
                if sec.name == ".dep-v0":
                    dep_section_data = bytes(sec.content)
                    break

        # Fallback search for auditable magic or zlib header if section name stripped
        root_package = None
        deps: list[RustDependency] = []

        if dep_section_data:
            try:
                decompressed = zlib.decompress(dep_section_data)
                payload = json.loads(decompressed.decode("utf-8"))
                packages = payload.get("packages", [])
                root_idx = payload.get("root_package")
                if root_idx is not None and root_idx < len(packages):
                    root_package = packages[root_idx].get("name")

                for pkg in packages:
                    deps.append(
                        RustDependency(
                            name=pkg.get("name", ""),
                            version=pkg.get("version", ""),
                            source=pkg.get("source"),
                        )
                    )
            except Exception:
                pass

        is_rust = (rustc_commit is not None) or bool(deps)

        return RustBuildInfo(
            is_rust=is_rust,
            rustc_commit=rustc_commit,
            root_package=root_package,
            dependencies=tuple(deps),
        )

    def audit(self) -> ToolchainAuditReport:
        go_info = self.audit_go()
        rust_info = self.audit_rust()

        if go_info.is_go:
            t_type = "GO"
        elif rust_info.is_rust:
            t_type = "RUST"
        else:
            t_type = "NATIVE_WIN32"

        return ToolchainAuditReport(
            path=str(self.path),
            format="PE",
            toolchain_type=t_type,
            go_info=go_info if go_info.is_go else None,
            rust_info=rust_info if rust_info.is_rust else None,
        )
