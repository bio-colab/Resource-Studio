from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import lief

from .parse_cache import shared_parse


@dataclass(frozen=True)
class ManagedResource:
    name: str
    offset: int
    flags: int
    size: int
    data: bytes
    is_public: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "offset": self.offset,
            "flags": hex(self.flags),
            "size": self.size,
            "isPublic": self.is_public,
        }


@dataclass(frozen=True)
class ManagedMetadataReport:
    is_managed: bool
    runtime_version: str | None
    cli_flags: int
    cli_flag_names: tuple[str, ...]
    entry_point_token: str | None
    metadata_version: str | None
    stream_names: tuple[str, ...]
    table_row_counts: dict[str, int]
    manifest_resources: tuple[ManagedResource, ...]
    user_strings: tuple[str, ...]

    def to_dict(self, max_user_strings: int = 50) -> dict[str, Any]:
        return {
            "isManaged": self.is_managed,
            "runtimeVersion": self.runtime_version,
            "cliFlags": hex(self.cli_flags),
            "cliFlagNames": list(self.cli_flag_names),
            "entryPointToken": self.entry_point_token,
            "metadataVersion": self.metadata_version,
            "streamNames": list(self.stream_names),
            "tableRowCounts": dict(self.table_row_counts),
            "resourceCount": len(self.manifest_resources),
            "resources": [r.to_dict() for r in self.manifest_resources],
            "userStringCount": len(self.user_strings),
            "userStrings": list(self.user_strings[:max_user_strings]),
        }


# ECMA-335 Table Names
TABLE_NAMES = [
    "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef", "ParamPtr",
    "Param", "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute", "FieldMarshal",
    "DeclSecurity", "ClassLayout", "FieldLayout", "StandAloneSig", "EventMap", "EventPtr",
    "Event", "PropertyMap", "PropertyPtr", "Property", "MethodSemantics", "MethodImpl",
    "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA", "ENCLog", "ENCMap",
    "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef", "AssemblyRefProcessor",
    "AssemblyRefOS", "File", "ExportedType", "ManifestResource", "NestedClass",
    "GenericParam", "MethodSpec", "GenericParamConstraint",
]

CLI_FLAG_MAP = {
    0x00000001: "il-only",
    0x00000002: "32bit-required",
    0x00000004: "illibrary",
    0x00000008: "strong-name-signed",
    0x00000010: "native-entrypoint",
    0x00010000: "track-debug-data",
    0x00020000: "32bit-preferred",
}


def _read_compressed_uint(data: bytes, offset: int) -> tuple[int, int]:
    """Reads ECMA-335 compressed integer, returns (value, bytes_consumed)."""
    if offset >= len(data):
        return 0, 0
    b0 = data[offset]
    if (b0 & 0x80) == 0:
        return b0, 1
    elif (b0 & 0xC0) == 0x80:
        if offset + 1 >= len(data):
            return 0, 0
        return ((b0 & 0x3F) << 8) | data[offset + 1], 2
    elif (b0 & 0xE0) == 0xC0:
        if offset + 3 >= len(data):
            return 0, 0
        return ((b0 & 0x1F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3], 4
    return 0, 0


class ManagedPEParser:
    """
    Parses PE/CLI headers, ECMA-335 metadata streams, and embedded ManifestResource blobs.
    Zero external CLR or .NET runtime dependencies.
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

    def parse(self) -> ManagedMetadataReport:
        if not self.binary or not isinstance(self.binary, lief.PE.Binary):
            return self._empty_report()

        # Check COM Descriptor (data directory 14)
        data_dirs = self.binary.data_directories
        if len(data_dirs) <= 14:
            return self._empty_report()

        clr_dir = data_dirs[14]
        if clr_dir.rva == 0 or clr_dir.size < 72:
            return self._empty_report()

        cli_offset = self._rva_to_file_offset(clr_dir.rva)
        if cli_offset is None or cli_offset + 72 > len(self.raw_bytes):
            return self._empty_report()

        # Parse IMAGE_COR20_HEADER
        cli_hdr = self.raw_bytes[cli_offset : cli_offset + 72]
        (
            cb,
            major_rt,
            minor_rt,
            meta_rva,
            meta_size,
            flags,
            entry_token,
            res_rva,
            res_size,
        ) = struct.unpack("<IHHIIIIII", cli_hdr[:32])

        flag_names = [name for bit, name in CLI_FLAG_MAP.items() if flags & bit]
        runtime_version = f"{major_rt}.{minor_rt}"
        entry_point_token = hex(entry_token) if entry_token != 0 else None

        # Parse Metadata Root
        meta_offset = self._rva_to_file_offset(meta_rva)
        if meta_offset is None or meta_offset + 16 > len(self.raw_bytes):
            return ManagedMetadataReport(
                is_managed=True,
                runtime_version=runtime_version,
                cli_flags=flags,
                cli_flag_names=tuple(flag_names),
                entry_point_token=entry_point_token,
                metadata_version=None,
                stream_names=(),
                table_row_counts={},
                manifest_resources=(),
                user_strings=(),
            )

        magic = struct.unpack("<I", self.raw_bytes[meta_offset : meta_offset + 4])[0]
        if magic != 0x424A5342:  # "BSJB"
            return self._empty_report()

        ver_len = struct.unpack("<I", self.raw_bytes[meta_offset + 12 : meta_offset + 16])[0]
        ver_bytes = self.raw_bytes[meta_offset + 16 : meta_offset + 16 + ver_len]
        metadata_ver = ver_bytes.split(b"\x00")[0].decode("ascii", errors="replace")

        # Read streams
        stream_hdr_offset = meta_offset + 16 + ver_len
        if stream_hdr_offset + 4 > len(self.raw_bytes):
            return self._empty_report()

        stream_count = struct.unpack("<H", self.raw_bytes[stream_hdr_offset + 2 : stream_hdr_offset + 4])[0]
        cur = stream_hdr_offset + 4

        streams: dict[str, tuple[int, int]] = {}  # name -> (offset, size)
        for _ in range(stream_count):
            if cur + 8 > len(self.raw_bytes):
                break
            s_off, s_size = struct.unpack("<II", self.raw_bytes[cur : cur + 8])
            cur += 8
            name_bytes = bytearray()
            while cur < len(self.raw_bytes) and self.raw_bytes[cur] != 0:
                name_bytes.append(self.raw_bytes[cur])
                cur += 1
            cur += 1  # null terminator
            # 4-byte padding alignment
            pad = (4 - ((len(name_bytes) + 1) % 4)) % 4
            cur += pad
            s_name = name_bytes.decode("ascii", errors="replace")
            streams[s_name] = (meta_offset + s_off, s_size)

        stream_names = tuple(streams.keys())

        # Extract User Strings (#US)
        user_strings: list[str] = []
        if "#US" in streams:
            us_off, us_sz = streams["#US"]
            us_data = self.raw_bytes[us_off : us_off + us_sz]
            idx = 1  # 0th entry is empty
            while idx < len(us_data):
                str_len, consumed = _read_compressed_uint(us_data, idx)
                if consumed == 0 or str_len == 0 or idx + consumed + str_len > len(us_data):
                    break
                idx += consumed
                raw_str = us_data[idx : idx + str_len - 1]  # exclude terminal byte
                idx += str_len
                try:
                    s_text = raw_str.decode("utf-16le")
                    if s_text.strip():
                        user_strings.append(s_text)
                except Exception:
                    pass

        # Parse Strings Stream (#Strings)
        strings_data = b""
        if "#Strings" in streams:
            st_off, st_sz = streams["#Strings"]
            strings_data = self.raw_bytes[st_off : st_off + st_sz]

        def get_string(idx: int) -> str:
            if idx >= len(strings_data):
                return ""
            end = strings_data.find(b"\x00", idx)
            if end == -1:
                end = len(strings_data)
            return strings_data[idx:end].decode("utf-8", errors="replace")

        # Parse Table Stream (#~ or #-)
        table_stream = streams.get("#~") or streams.get("#-")
        table_row_counts: dict[str, int] = {}
        manifest_resources: list[ManagedResource] = []

        if table_stream:
            t_off, t_sz = table_stream
            t_data = self.raw_bytes[t_off : t_off + t_sz]
            if len(t_data) >= 24:
                major, minor, heap_sizes, rid = struct.unpack("<BBBB", t_data[4:8])
                valid, sorted_mask = struct.unpack("<QQ", t_data[8:24])

                string_index_size = 4 if (heap_sizes & 0x01) else 2
                guid_index_size = 4 if (heap_sizes & 0x02) else 2
                blob_index_size = 4 if (heap_sizes & 0x04) else 2

                # Read row counts for each present table
                row_counts: dict[int, int] = {}
                cur_t = 24
                for tid in range(64):
                    if valid & (1 << tid):
                        if cur_t + 4 <= len(t_data):
                            rc = struct.unpack("<I", t_data[cur_t : cur_t + 4])[0]
                            row_counts[tid] = rc
                            if tid < len(TABLE_NAMES):
                                table_row_counts[TABLE_NAMES[tid]] = rc
                            cur_t += 4

                # Decode ManifestResource (Table 0x28 = 40)
                if 40 in row_counts:
                    # Determine sizes of preceding tables to compute Table 40 offset
                    # Helper for coded token index size
                    def coded_index_size(tags_count: int, table_indices: list[int]) -> int:
                        max_rows = max([row_counts.get(t, 0) for t in table_indices] + [0])
                        max_val = max_rows << tags_count.bit_length()
                        return 4 if max_val >= 65536 else 2

                    # Calculate row sizes for tables 0 through 39
                    def get_table_row_size(tid: int) -> int:
                        if tid == 0:  # Module
                            return 2 + string_index_size + (guid_index_size * 3)
                        elif tid == 1:  # TypeRef
                            res_scope_sz = coded_index_size(2, [0, 26, 38, 1])
                            return res_scope_sz + (string_index_size * 2)
                        elif tid == 2:  # TypeDef
                            tdor_sz = coded_index_size(2, [2, 1, 27])
                            fd_sz = 4 if row_counts.get(4, 0) >= 65536 else 2
                            md_sz = 4 if row_counts.get(6, 0) >= 65536 else 2
                            return 4 + (string_index_size * 2) + tdor_sz + fd_sz + md_sz
                        elif tid == 4:  # Field
                            return 2 + string_index_size + blob_index_size
                        elif tid == 6:  # MethodDef
                            param_sz = 4 if row_counts.get(8, 0) >= 65536 else 2
                            return 4 + 2 + 2 + string_index_size + blob_index_size + param_sz
                        elif tid == 8:  # Param
                            return 2 + 2 + string_index_size
                        elif tid == 9:  # InterfaceImpl
                            td_sz = 4 if row_counts.get(2, 0) >= 65536 else 2
                            tdor_sz = coded_index_size(2, [2, 1, 27])
                            return td_sz + tdor_sz
                        elif tid == 10:  # MemberRef
                            mrc_sz = coded_index_size(3, [2, 1, 26, 6, 27])
                            return mrc_sz + string_index_size + blob_index_size
                        elif tid == 11:  # Constant
                            hac_sz = coded_index_size(2, [4, 8, 23])
                            return 2 + hac_sz + blob_index_size
                        elif tid == 12:  # CustomAttribute
                            cat_sz = coded_index_size(5, [6, 10])
                            hca_sz = coded_index_size(5, list(range(40)))
                            return hca_sz + cat_sz + blob_index_size
                        elif tid == 13:  # FieldMarshal
                            hfm_sz = coded_index_size(1, [4, 8])
                            return hfm_sz + blob_index_size
                        elif tid == 14:  # DeclSecurity
                            hds_sz = coded_index_size(2, [2, 6, 32])
                            return 2 + hds_sz + blob_index_size
                        elif tid == 15:  # ClassLayout
                            td_sz = 4 if row_counts.get(2, 0) >= 65536 else 2
                            return 2 + 4 + td_sz
                        elif tid == 16:  # FieldLayout
                            fd_sz = 4 if row_counts.get(4, 0) >= 65536 else 2
                            return 4 + fd_sz
                        elif tid == 17:  # StandAloneSig
                            return blob_index_size
                        elif tid == 18:  # EventMap
                            td_sz = 4 if row_counts.get(2, 0) >= 65536 else 2
                            ev_sz = 4 if row_counts.get(20, 0) >= 65536 else 2
                            return td_sz + ev_sz
                        elif tid == 20:  # Event
                            tdor_sz = coded_index_size(2, [2, 1, 27])
                            return 2 + string_index_size + tdor_sz
                        elif tid == 21:  # PropertyMap
                            td_sz = 4 if row_counts.get(2, 0) >= 65536 else 2
                            pr_sz = 4 if row_counts.get(23, 0) >= 65536 else 2
                            return td_sz + pr_sz
                        elif tid == 23:  # Property
                            return 2 + string_index_size + blob_index_size
                        elif tid == 24:  # MethodSemantics
                            md_sz = 4 if row_counts.get(6, 0) >= 65536 else 2
                            hsa_sz = coded_index_size(1, [20, 23])
                            return 2 + md_sz + hsa_sz
                        elif tid == 25:  # MethodImpl
                            td_sz = 4 if row_counts.get(2, 0) >= 65536 else 2
                            mb_sz = coded_index_size(1, [6, 10])
                            return td_sz + (mb_sz * 2)
                        elif tid == 26:  # ModuleRef
                            return string_index_size
                        elif tid == 27:  # TypeSpec
                            return blob_index_size
                        elif tid == 28:  # ImplMap
                            mdor_sz = coded_index_size(1, [4, 6])
                            mr_sz = 4 if row_counts.get(26, 0) >= 65536 else 2
                            return 2 + mdor_sz + string_index_size + mr_sz
                        elif tid == 29:  # FieldRVA
                            fd_sz = 4 if row_counts.get(4, 0) >= 65536 else 2
                            return 4 + fd_sz
                        elif tid == 32:  # Assembly
                            return 4 + 8 + 4 + blob_index_size + (string_index_size * 2)
                        elif tid == 35:  # AssemblyRef
                            return 8 + 4 + (blob_index_size * 2) + (string_index_size * 2)
                        elif tid == 38:  # File
                            return 4 + string_index_size + blob_index_size
                        elif tid == 39:  # ExportedType
                            impl_sz = coded_index_size(2, [38, 35, 39])
                            return 4 + 4 + (string_index_size * 2) + impl_sz
                        return 0

                    table_40_offset = cur_t
                    for tid in range(40):
                        if valid & (1 << tid):
                            rc = row_counts.get(tid, 0)
                            rs = get_table_row_size(tid)
                            table_40_offset += rc * rs

                    # ManifestResource Row:
                    # Offset (4 bytes)
                    # Flags (4 bytes)
                    # Name (string_index_size bytes)
                    # Implementation (coded_index_size(2, [File, AssemblyRef, ExportedType]))
                    impl_index_size = coded_index_size(2, [38, 35, 39])
                    m_row_size = 4 + 4 + string_index_size + impl_index_size

                    res_base_file_offset = self._rva_to_file_offset(res_rva) if res_rva != 0 else None

                    for r_idx in range(row_counts[40]):
                        row_start = table_40_offset + (r_idx * m_row_size)
                        if row_start + m_row_size > len(t_data):
                            break
                        r_offset, r_flags = struct.unpack("<II", t_data[row_start : row_start + 8])
                        p = row_start + 8
                        if string_index_size == 4:
                            name_idx = struct.unpack("<I", t_data[p : p + 4])[0]
                            p += 4
                        else:
                            name_idx = struct.unpack("<H", t_data[p : p + 2])[0]
                            p += 2

                        if impl_index_size == 4:
                            impl_token = struct.unpack("<I", t_data[p : p + 4])[0]
                        else:
                            impl_token = struct.unpack("<H", t_data[p : p + 2])[0]

                        res_name = get_string(name_idx)
                        res_data = b""
                        res_len = 0

                        # If implementation token is 0, the resource is embedded directly in this PE image
                        if impl_token == 0 and res_base_file_offset is not None:
                            blob_file_off = res_base_file_offset + r_offset
                            if blob_file_off + 4 <= len(self.raw_bytes):
                                res_len = struct.unpack("<I", self.raw_bytes[blob_file_off : blob_file_off + 4])[0]
                                res_data = self.raw_bytes[blob_file_off + 4 : blob_file_off + 4 + res_len]

                        manifest_resources.append(
                            ManagedResource(
                                name=res_name,
                                offset=r_offset,
                                flags=r_flags,
                                size=res_len if res_len else len(res_data),
                                data=res_data,
                                is_public=bool(r_flags & 0x01),
                            )
                        )

        return ManagedMetadataReport(
            is_managed=True,
            runtime_version=runtime_version,
            cli_flags=flags,
            cli_flag_names=tuple(flag_names),
            entry_point_token=entry_point_token,
            metadata_version=metadata_ver,
            stream_names=stream_names,
            table_row_counts=table_row_counts,
            manifest_resources=tuple(manifest_resources),
            user_strings=tuple(user_strings),
        )

    def _empty_report(self) -> ManagedMetadataReport:
        return ManagedMetadataReport(
            is_managed=False,
            runtime_version=None,
            cli_flags=0,
            cli_flag_names=(),
            entry_point_token=None,
            metadata_version=None,
            stream_names=(),
            table_row_counts={},
            manifest_resources=(),
            user_strings=(),
        )
