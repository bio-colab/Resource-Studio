from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief


@dataclass(frozen=True)
class PESignatureReport:
    path: str
    present: bool
    signature_count: int
    verification: str
    authentihash_sha1: str
    authentihash_sha256: str
    authentihash_sha512: str
    certificate_table: dict[str, int]
    signatures: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "present": self.present,
            "signatureCount": self.signature_count,
            "verification": self.verification,
            "authentihash": {
                "sha1": self.authentihash_sha1,
                "sha256": self.authentihash_sha256,
                "sha512": self.authentihash_sha512,
            },
            "certificateTable": dict(self.certificate_table),
            "signatures": [dict(item) for item in self.signatures],
        }


def inspect_signature(path: Path) -> PESignatureReport:
    path = Path(path).expanduser().resolve()
    binary = lief.parse(str(path))
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise ValueError(f"not a supported PE: {path}")
    signatures = tuple(_signature_record(item) for item in binary.signatures)
    certificate = getattr(binary, "cert_dir", None)
    certificate_table = {
        "rva": int(getattr(certificate, "rva", 0)) if certificate is not None else 0,
        "size": int(getattr(certificate, "size", 0)) if certificate is not None else 0,
    }
    try:
        verification = str(binary.verify_signature())
    except Exception as exc:
        verification = f"ERROR:{type(exc).__name__}"
    return PESignatureReport(
        path=str(path),
        present=bool(binary.has_signatures or signatures or certificate_table["size"]),
        signature_count=len(signatures),
        verification=verification,
        authentihash_sha1=binary.authentihash_sha1.hex(),
        authentihash_sha256=binary.authentihash_sha256.hex(),
        authentihash_sha512=binary.authentihash_sha512.hex(),
        certificate_table=certificate_table,
        signatures=signatures,
    )


def _signature_record(signature: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("version", "digest_algorithm", "content_info", "original_filename", "program_name", "more_info", "signing_time"):
        value = getattr(signature, key, None)
        if value is None:
            continue
        if isinstance(value, bytes):
            result[key] = hashlib.sha256(value).hexdigest()
        else:
            result[key] = str(value)
    return result
