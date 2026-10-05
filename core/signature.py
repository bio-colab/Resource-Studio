from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief

from .parse_cache import shared_parse
from .util import sha256_file

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


@dataclass(frozen=True)
class SignatureOperationResult:
    operation: str
    input_path: str
    output_path: str
    backup_path: str | None
    before_sha256: str
    after_sha256: str
    before: dict[str, Any]
    after: dict[str, Any]
    authenticode: dict[str, Any] | None
    tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "inputPath": self.input_path,
            "outputPath": self.output_path,
            "backupPath": self.backup_path,
            "beforeSha256": self.before_sha256,
            "afterSha256": self.after_sha256,
            "before": dict(self.before),
            "after": dict(self.after),
            "authenticode": dict(self.authenticode) if self.authenticode else None,
            "tool": self.tool,
        }


class SignatureToolError(RuntimeError):
    pass


def inspect_signature(path: Path, *, binary: Any | None = None) -> PESignatureReport:
    path = Path(path).expanduser().resolve()
    binary = binary if binary is not None else shared_parse(path)
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


def strip_authenticode(
    input_path: Path,
    output_path: Path,
    *,
    backup_existing_output: bool = True,
) -> SignatureOperationResult:
    """Remove the PE certificate table into a new output file; never writes in place."""
    input_path, output_path = _validate_paths(input_path, output_path)
    before = inspect_signature(input_path)
    if not before.present:
        raise SignatureToolError("input PE is not signed; refusing a no-op strip")
    backup_path = _backup_existing(output_path, backup_existing_output)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_path.parent, suffix=output_path.suffix, delete=False) as handle:
            temporary = Path(handle.name)
        _strip_to_path(input_path, temporary)
        os.replace(temporary, output_path)
        temporary = None
        after = inspect_signature(output_path)
        if after.present:
            raise SignatureToolError("certificate table remains after stripping")
        return SignatureOperationResult(
            operation="strip",
            input_path=str(input_path),
            output_path=str(output_path),
            backup_path=str(backup_path) if backup_path else None,
            before_sha256=sha256_file(input_path),
            after_sha256=sha256_file(output_path),
            before=before.to_dict(),
            after=after.to_dict(),
            authenticode=_windows_report(output_path),
        )
    except Exception as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        _restore_output(output_path, backup_path)
        if isinstance(exc, SignatureToolError):
            raise
        raise SignatureToolError(f"Authenticode strip failed: {exc}") from exc


def resign_authenticode(
    input_path: Path,
    output_path: Path,
    certificate_path: Path,
    *,
    password: str | None = None,
    password_env: str | None = None,
    timestamp_url: str | None = None,
    signtool: Path | None = None,
    strip_existing: bool = False,
    backup_existing_output: bool = True,
) -> SignatureOperationResult:
    """Sign a Save-As copy with a PFX certificate through Windows signtool."""
    if os.name != "nt":
        raise SignatureToolError("Authenticode re-signing is available on Windows only")
    input_path, output_path = _validate_paths(input_path, output_path)
    certificate_path = Path(certificate_path).expanduser().resolve()
    if not certificate_path.is_file():
        raise SignatureToolError(f"PFX certificate not found: {certificate_path}")
    before = inspect_signature(input_path)
    if before.present and not strip_existing:
        raise SignatureToolError("input is already signed; pass --strip-existing to replace its signature explicitly")
    tool = find_signtool(signtool)
    secret = password if password is not None else _password_from_env(password_env)
    if not secret:
        raise SignatureToolError("PFX password is required through --password-env or an explicit API argument")
    backup_path = _backup_existing(output_path, backup_existing_output)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_path.parent, suffix=output_path.suffix, delete=False) as handle:
            temporary = Path(handle.name)
        if before.present:
            _strip_to_path(input_path, temporary)
        else:
            shutil.copy2(input_path, temporary)
        os.replace(temporary, output_path)
        temporary = None
        _run_signtool(tool, output_path, certificate_path, secret, timestamp_url)
        after = inspect_signature(output_path)
        if not after.present or after.signature_count < 1:
            raise SignatureToolError("signtool completed but no Authenticode signature was detected")
        return SignatureOperationResult(
            operation="re-sign",
            input_path=str(input_path),
            output_path=str(output_path),
            backup_path=str(backup_path) if backup_path else None,
            before_sha256=sha256_file(input_path),
            after_sha256=sha256_file(output_path),
            before=before.to_dict(),
            after=after.to_dict(),
            authenticode=_windows_report(output_path),
            tool=str(tool),
        )
    except Exception as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        _restore_output(output_path, backup_path)
        if isinstance(exc, SignatureToolError):
            raise
        raise SignatureToolError(f"Authenticode re-sign failed: {exc}") from exc


def create_test_certificate(
    output_path: Path,
    *,
    password: str,
    subject: str = "CN=Resource Studio Test",
    days: int = 365,
) -> dict[str, Any]:
    """Create an exportable local-user Code Signing PFX through PowerShell."""
    if os.name != "nt":
        raise SignatureToolError("test certificate creation is available on Windows only")
    output_path = Path(output_path).expanduser().resolve()
    if output_path.exists():
        raise SignatureToolError(f"refusing to overwrite existing certificate: {output_path}")
    if not password:
        raise SignatureToolError("certificate password cannot be empty")
    if days < 1 or days > 3650:
        raise SignatureToolError("certificate validity must be between 1 and 3650 days")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = (
        "$ErrorActionPreference='Stop'; "
        "$pw=ConvertTo-SecureString -String $env:RS_PFX_PASSWORD -AsPlainText -Force; "
        "$cert=New-SelfSignedCertificate -Type CodeSigningCert "
        "-Subject $env:RS_CERT_SUBJECT -CertStoreLocation 'Cert:\\CurrentUser\\My' "
        "-KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 "
        "-KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays([int]$env:RS_CERT_DAYS); "
        "Export-PfxCertificate -Cert $cert -FilePath $env:RS_PFX_PATH -Password $pw | Out-Null; "
        "[pscustomobject]@{Subject=$cert.Subject;Thumbprint=$cert.Thumbprint;NotAfter=$cert.NotAfter.ToString('o');Path=$env:RS_PFX_PATH} | ConvertTo-Json -Compress"
    )
    environment = {
        **os.environ,
        "RS_PFX_PASSWORD": password,
        "RS_CERT_SUBJECT": subject,
        "RS_CERT_DAYS": str(days),
        "RS_PFX_PATH": str(output_path),
    }
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        output_path.unlink(missing_ok=True)
        raise SignatureToolError(f"test certificate creation failed: {exc}") from exc
    if completed.returncode != 0:
        output_path.unlink(missing_ok=True)
        raise SignatureToolError(completed.stderr.strip() or "PowerShell could not create the test certificate")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        output_path.unlink(missing_ok=True)
        raise SignatureToolError("PowerShell created an unreadable certificate result") from exc


def find_signtool(explicit: Path | None = None) -> Path:
    if explicit is not None:
        candidate = Path(explicit).expanduser().resolve()
        if candidate.is_file():
            return candidate
        raise SignatureToolError(f"signtool was not found: {candidate}")
    found = shutil.which("signtool.exe") or shutil.which("signtool")
    if found:
        return Path(found).resolve()
    roots = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\\Program Files (x86)")) / "Windows Kits" / "10" / "bin",
        Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "Windows Kits" / "10" / "bin",
    ]
    candidates: list[Path] = []
    for root in roots:
        if root.is_dir():
            candidates.extend(root.glob("**/signtool.exe"))
    if candidates:
        return sorted(candidates, key=lambda path: str(path), reverse=True)[0]
    raise SignatureToolError("signtool.exe was not found; install the Windows SDK or pass --signtool")


def _run_signtool(tool: Path, output: Path, certificate: Path, password: str, timestamp_url: str | None) -> None:
    command = (
        "$ErrorActionPreference='Stop'; "
        "& $env:RS_SIGNTOOL sign /fd SHA256 /f $env:RS_PFX_PATH /p $env:RS_PFX_PASSWORD "
    )
    if timestamp_url:
        command += "/tr $env:RS_TIMESTAMP_URL /td SHA256 "
    command += "$env:RS_PE_PATH; exit $LASTEXITCODE"
    environment = {
        **os.environ,
        "RS_SIGNTOOL": str(tool),
        "RS_PFX_PATH": str(certificate),
        "RS_PFX_PASSWORD": password,
        "RS_PE_PATH": str(output),
    }
    if timestamp_url:
        environment["RS_TIMESTAMP_URL"] = timestamp_url
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SignatureToolError(f"signtool invocation failed: {exc}") from exc
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "signtool failed"
        raise SignatureToolError(message)


def _strip_to_path(input_path: Path, output_path: Path) -> None:
    source_bytes = input_path.read_bytes()
    binary = lief.parse(str(input_path))
    if binary is None or not isinstance(binary, lief.PE.Binary):
        raise SignatureToolError(f"not a supported PE: {input_path}")
    certificate = binary.cert_dir
    offset = int(getattr(certificate, "rva", 0))
    size = int(getattr(certificate, "size", 0))
    if size <= 0:
        raise SignatureToolError("input PE has no certificate table")
    certificate.rva = 0
    certificate.size = 0
    binary.write(str(output_path))
    written = output_path.read_bytes()
    if offset > 0 and offset + size == len(source_bytes) and offset < len(written):
        output_path.write_bytes(written[:offset])


def _validate_paths(input_path: Path, output_path: Path) -> tuple[Path, Path]:
    input_path = Path(input_path).expanduser().resolve()
    output_path = Path(output_path).expanduser().resolve()
    if not input_path.is_file():
        raise SignatureToolError(f"input PE not found: {input_path}")
    if input_path == output_path:
        raise SignatureToolError("in-place signature operations are disabled; use Save As")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return input_path, output_path


def _backup_existing(output_path: Path, enabled: bool) -> Path | None:
    if not output_path.exists():
        return None
    if not enabled:
        raise SignatureToolError(f"output already exists: {output_path}")
    backup = output_path.with_suffix(output_path.suffix + ".bak")
    shutil.copy2(output_path, backup)
    return backup


def _restore_output(output_path: Path, backup_path: Path | None) -> None:
    if backup_path and backup_path.is_file():
        shutil.copy2(backup_path, output_path)
    else:
        output_path.unlink(missing_ok=True)


def _password_from_env(name: str | None) -> str:
    if name:
        return os.environ.get(name, "")
    return ""


def _windows_report(path: Path) -> dict[str, Any] | None:
    try:
        from .windows_security import inspect_authenticode_windows

        return inspect_authenticode_windows(path).to_dict()
    except Exception:
        return None


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


