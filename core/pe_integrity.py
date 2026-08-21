from __future__ import annotations

import ctypes
import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief

from .signature import inspect_signature


@dataclass(frozen=True)
class PEIntegrityReport:
    path: str
    stored_checksum: int
    lief_checksum: int
    windows_checksum: int | None
    windows_status: int | None
    signature_present: bool
    signature_verification: str
    certificate_table: dict[str, int]
    warnings: tuple[str, ...]
    rich_header_sha256: str | None = None

    @property
    def checksum_valid_lief(self) -> bool:
        return bool(self.stored_checksum and self.stored_checksum == self.lief_checksum)

    @property
    def checksum_valid_windows(self) -> bool | None:
        if self.windows_checksum is None:
            return None
        return bool(self.stored_checksum and self.stored_checksum == self.windows_checksum)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "storedChecksum": self.stored_checksum,
            "liefChecksum": self.lief_checksum,
            "windowsChecksum": self.windows_checksum,
            "windowsStatus": self.windows_status,
            "checksumValidLief": self.checksum_valid_lief,
            "checksumValidWindows": self.checksum_valid_windows,
            "signaturePresent": self.signature_present,
            "signatureVerification": self.signature_verification,
            "certificateTable": dict(self.certificate_table),
            "warnings": list(self.warnings),
            "richHeaderSha256": self.rich_header_sha256,
        }


def inspect_integrity(path: Path) -> PEIntegrityReport:
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"file not found: {path}")
    binary = lief.parse(str(path))
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError(f"not a supported PE: {path}")
    signature = inspect_signature(path)
    rich_header_sha256 = _rich_header_sha256(path.read_bytes())
    stored = int(binary.optional_header.checksum)
    lief_checksum = int(binary.compute_checksum())
    windows_checksum, windows_status = _windows_checksum(path)
    warnings: list[str] = []
    if not stored:
        warnings.append("PE checksum field is zero or not populated")
    elif not (stored == lief_checksum or (windows_checksum is not None and stored == windows_checksum)):
        warnings.append("stored PE checksum does not match available computed checksum")
    if signature.present:
        warnings.append("Authenticode state must be re-verified after any write")
    if windows_status not in (None, 0):
        warnings.append(f"MapFileAndCheckSumW returned status {windows_status}")
    return PEIntegrityReport(
        path=str(path),
        stored_checksum=stored,
        lief_checksum=lief_checksum,
        windows_checksum=windows_checksum,
        windows_status=windows_status,
        signature_present=signature.present,
        signature_verification=signature.verification,
        certificate_table=signature.certificate_table,
        warnings=tuple(warnings),
        rich_header_sha256=rich_header_sha256,
    )


def _rich_header_sha256(data: bytes) -> str | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset <= 0 or pe_offset > len(data):
        return None
    rich_end = data.rfind(b"Rich", 0, pe_offset)
    if rich_end < 0 or rich_end + 8 > pe_offset:
        return None
    key = struct.unpack_from("<I", data, rich_end + 4)[0]
    encoded_dans = struct.pack("<I", 0x536E6144 ^ key)
    rich_start = data.rfind(encoded_dans, 0, rich_end)
    if rich_start < 0:
        return None
    return hashlib.sha256(data[rich_start : rich_end + 8]).hexdigest()


def _windows_checksum(path: Path) -> tuple[int | None, int | None]:
    if os.name != "nt":
        return None, None
    imagehlp = ctypes.WinDLL("imagehlp", use_last_error=True)
    imagehlp.MapFileAndCheckSumW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    imagehlp.MapFileAndCheckSumW.restype = ctypes.c_uint32
    header = ctypes.c_uint32(0)
    checksum = ctypes.c_uint32(0)
    status = int(imagehlp.MapFileAndCheckSumW(str(path), ctypes.byref(header), ctypes.byref(checksum)))
    if status != 0:
        return None, status
    return int(checksum.value), status
