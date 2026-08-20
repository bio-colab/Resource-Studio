from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pe_writer import LiefPEWriter


class BatchError(ValueError):
    pass


@dataclass(frozen=True)
class BatchJob:
    input_path: Path
    output_path: Path
    operations: tuple[dict[str, Any], ...]


class BatchWorkspace:
    """Manifest-driven multi-file PE editing with staged commit and rollback."""

    FORMAT = "resource_studio.batch.v1"

    def __init__(self, manifest_path: Path, jobs: tuple[BatchJob, ...]) -> None:
        self.manifest_path = Path(manifest_path).expanduser().resolve()
        self.jobs = jobs

    @classmethod
    def load(cls, manifest_path: Path) -> BatchWorkspace:
        manifest_path = Path(manifest_path).expanduser().resolve()
        if not manifest_path.is_file():
            raise BatchError(f"batch manifest not found: {manifest_path}")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BatchError(f"invalid batch manifest JSON: {exc}") from exc
        if payload.get("format") != cls.FORMAT:
            raise BatchError(f"unsupported batch format: {payload.get('format')!r}")
        raw_jobs = payload.get("jobs")
        if not isinstance(raw_jobs, list) or not raw_jobs:
            raise BatchError("batch manifest must contain a non-empty jobs list")
        base = manifest_path.parent
        jobs: list[BatchJob] = []
        outputs: set[Path] = set()
        inputs: set[Path] = set()
        for index, raw_job in enumerate(raw_jobs):
            if not isinstance(raw_job, dict):
                raise BatchError(f"job {index} must be an object")
            input_path = _resolve(base, raw_job.get("input"), f"jobs[{index}].input")
            output_path = _resolve(base, raw_job.get("output"), f"jobs[{index}].output")
            if input_path == output_path:
                raise BatchError(f"job {index} uses an in-place output; use Save As")
            if output_path in outputs:
                raise BatchError(f"duplicate output path: {output_path}")
            if not input_path.is_file():
                raise BatchError(f"job {index} input not found: {input_path}")
            operations = raw_job.get("operations")
            if not isinstance(operations, list) or not operations:
                raise BatchError(f"job {index} must contain a non-empty operations list")
            normalized = tuple(_normalize_operation(base, operation, index, op_index) for op_index, operation in enumerate(operations))
            jobs.append(BatchJob(input_path, output_path, normalized))
            outputs.add(output_path)
            inputs.add(input_path)
        overlap = outputs & inputs
        if overlap:
            raise BatchError("batch output cannot overwrite an input: " + ", ".join(str(path) for path in sorted(overlap)))
        return cls(manifest_path, tuple(jobs))

    def plan(self) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="resource-studio-batch-plan-") as temporary:
            results = [self._run_job(job, Path(temporary), commit=False) for job in self.jobs]
        return {
            "format": self.FORMAT,
            "manifest": str(self.manifest_path),
            "mode": "plan",
            "willWrite": all(result["willWrite"] for result in results),
            "jobs": results,
        }

    def apply(self, report_path: Path | None = None) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="resource-studio-batch-apply-") as temporary:
            staged = [(job, self._run_job(job, Path(temporary), commit=True)) for job in self.jobs]
            committed: list[tuple[Path, Path | None]] = []
            try:
                for job, result in staged:
                    backup = _backup_existing(job.output_path)
                    _atomic_copy(Path(result["stagedPath"]), job.output_path)
                    committed.append((job.output_path, backup))
                    result["outputPath"] = str(job.output_path)
                    result["backupPath"] = str(backup) if backup else None
                    result.pop("stagedPath", None)
            except Exception:
                for output, backup in reversed(committed):
                    if backup and backup.is_file():
                        _atomic_copy(backup, output)
                    else:
                        output.unlink(missing_ok=True)
                raise
        payload = {
            "format": self.FORMAT,
            "manifest": str(self.manifest_path),
            "mode": "apply",
            "jobs": [result for _, result in staged],
        }
        if report_path is not None:
            report_path = Path(report_path).expanduser().resolve()
            report_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_text(report_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            payload["reportPath"] = str(report_path)
        return payload

    def _run_job(self, job: BatchJob, temporary: Path, *, commit: bool) -> dict[str, Any]:
        job_dir = temporary / hashlib.sha256(str(job.output_path).encode()).hexdigest()[:12]
        job_dir.mkdir(parents=True, exist_ok=True)
        current = job_dir / job.input_path.name
        shutil.copy2(job.input_path, current)
        writer = LiefPEWriter()
        operation_results: list[dict[str, Any]] = []
        for index, operation in enumerate(job.operations):
            next_path = job_dir / f"step-{index:03d}{job.input_path.suffix}"
            result = _apply_operation(writer, current, next_path, operation)
            operation_results.append({
                "action": operation["action"],
                "type": operation.get("type"),
                "name": operation.get("name"),
                "language": operation.get("language", operation.get("sourceLanguage")),
                "beforeSha256": result.before_sha256,
                "afterSha256": result.after_sha256,
                "verified": result.verified,
                "verification": result.verification,
            })
            current = next_path
        payload = {
            "inputPath": str(job.input_path),
            "outputPath": None,
            "stagedPath": str(current),
            "beforeSha256": _sha256(job.input_path),
            "afterSha256": _sha256(current),
            "operationCount": len(operation_results),
            "operations": operation_results,
            "verified": all(item["verified"] for item in operation_results),
            "willWrite": True,
        }
        if not commit:
            payload.pop("stagedPath", None)
        return payload


def _normalize_operation(base: Path, operation: Any, job_index: int, op_index: int) -> dict[str, Any]:
    if not isinstance(operation, dict) or operation.get("action") not in {"add", "replace", "delete", "change-language"}:
        raise BatchError(f"jobs[{job_index}].operations[{op_index}] has unsupported action")
    action = operation["action"]
    normalized = dict(operation)
    if action in {"add", "replace"}:
        if "type" not in operation or "name" not in operation or "language" not in operation or "dataFile" not in operation:
            raise BatchError(f"jobs[{job_index}].operations[{op_index}] requires type/name/language/dataFile")
        normalized["dataFile"] = str(_resolve(base, operation["dataFile"], f"jobs[{job_index}].operations[{op_index}].dataFile"))
        if not Path(normalized["dataFile"]).is_file():
            raise BatchError(f"operation data file not found: {normalized['dataFile']}")
    elif action == "delete":
        for field in ("type", "name", "language"):
            if field not in operation:
                raise BatchError(f"jobs[{job_index}].operations[{op_index}] requires {field}")
    else:
        for field in ("type", "name", "sourceLanguage", "targetLanguage"):
            if field not in operation:
                raise BatchError(f"jobs[{job_index}].operations[{op_index}] requires {field}")
    return normalized


def _apply_operation(writer: LiefPEWriter, input_path: Path, output_path: Path, operation: dict[str, Any]):
    action = operation["action"]
    resource_type = operation.get("type")
    name = operation.get("name")
    if isinstance(name, str) and name.isdigit():
        name = int(name)
    if action in {"add", "replace"}:
        data = Path(operation["dataFile"]).read_bytes()
        if action == "add":
            if not isinstance(name, int):
                raise BatchError("batch add requires numeric resource name")
            return writer.add_typed_resource(input_path, output_path, str(resource_type), name, int(operation["language"]), data)
        return writer.replace_typed_resource(input_path, output_path, str(resource_type), name, int(operation["language"]), data)
    if action == "delete":
        return writer.delete_resource(input_path, output_path, str(resource_type), name, int(operation["language"]))
    return writer.change_language(input_path, output_path, str(resource_type), name, int(operation["sourceLanguage"]), int(operation["targetLanguage"]))


def _resolve(base: Path, value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise BatchError(f"{field} must be a non-empty path")
    path = Path(value).expanduser()
    return (base / path).resolve() if not path.is_absolute() else path.resolve()


def _backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_suffix(path.suffix + ".batch.bak")
    shutil.copy2(path, backup)
    return backup


def _atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
