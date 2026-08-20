from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class EvidenceLedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class LedgerVerification:
    valid: bool
    entries: int
    signed: bool
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entries": self.entries,
            "signed": self.signed,
            "errors": list(self.errors),
        }


class EvidenceLedger:
    """Tamper-evident local evidence chain; not a legal chain-of-custody system."""

    FORMAT = "resource_studio.evidence_ledger.v1"

    def __init__(self, path: Path, *, private_key: Path | None = None, public_key: Path | None = None) -> None:
        self.path = Path(path).expanduser().resolve()
        self.private_key = Path(private_key).expanduser().resolve() if private_key else None
        self.public_key = Path(public_key).expanduser().resolve() if public_key else None

    def append(self, evidence: dict[str, Any]) -> dict[str, Any]:
        records = self._read_records()
        previous = records[-1].get("entrySha256") if records else None
        payload = {
            "format": self.FORMAT,
            "createdUtc": datetime.now(UTC).isoformat(),
            "previousEvidenceSha256": previous,
            "evidenceSha256": _sha256_json(evidence),
            "evidence": evidence,
        }
        record = dict(payload)
        signature = _sign(_canonical(payload), self.private_key) if self.private_key else None
        record["signature"] = signature or {"status": "UNSIGNED"}
        record["entrySha256"] = _sha256_json(record)
        self._write_records(records + [record])
        return record

    def verify(self) -> LedgerVerification:
        try:
            records = self._read_records()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return LedgerVerification(False, 0, False, (str(exc),))
        errors: list[str] = []
        previous = None
        signed = False
        for index, record in enumerate(records):
            if record.get("format") != self.FORMAT:
                errors.append(f"entry {index}: unsupported format")
            if record.get("previousEvidenceSha256") != previous:
                errors.append(f"entry {index}: previous hash mismatch")
            evidence = record.get("evidence")
            if not isinstance(evidence, dict) or record.get("evidenceSha256") != _sha256_json(evidence):
                errors.append(f"entry {index}: evidence hash mismatch")
            stored_entry_hash = record.get("entrySha256")
            unsigned = dict(record)
            unsigned.pop("entrySha256", None)
            if stored_entry_hash != _sha256_json(unsigned):
                errors.append(f"entry {index}: entry hash mismatch")
            signature = record.get("signature")
            if isinstance(signature, dict) and signature.get("status") == "SIGNED":
                signed = True
                signed_payload = dict(unsigned)
                signed_payload.pop("signature", None)
                if not _verify(_canonical(signed_payload), signature, self.public_key):
                    errors.append(f"entry {index}: signature verification failed")
            previous = stored_entry_hash
        return LedgerVerification(not errors, len(records), signed, tuple(errors))

    def _read_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("ledger entry must be a JSON object")
                records.append(value)
        return records

    def _write_records(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(records[-1], ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


def generate_ed25519_keypair(private_key: Path, public_key: Path) -> None:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise EvidenceLedgerError("Ed25519 support requires the optional cryptography package") from exc
    private = Ed25519PrivateKey.generate()
    private_path = Path(private_key).expanduser().resolve()
    public_path = Path(public_key).expanduser().resolve()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    try:
        private_path.chmod(0o600)
    except OSError:
        pass


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_json(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _sign(payload: bytes, private_key: Path | None) -> dict[str, Any] | None:
    if private_key is None:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise EvidenceLedgerError("Ed25519 support requires the optional cryptography package") from exc
    key = Ed25519PrivateKey.from_private_bytes(private_key.read_bytes())
    from cryptography.hazmat.primitives import serialization

    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"status": "SIGNED", "algorithm": "Ed25519", "publicKey": base64.b64encode(public).decode("ascii"), "signature": base64.b64encode(key.sign(payload)).decode("ascii")}


def _verify(payload: bytes, signature: dict[str, Any], public_key: Path | None) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False
    try:
        raw_public = public_key.read_bytes() if public_key else base64.b64decode(signature["publicKey"])
        Ed25519PublicKey.from_public_bytes(raw_public).verify(base64.b64decode(signature["signature"]), payload)
        return True
    except (OSError, KeyError, ValueError, TypeError):
        return False
