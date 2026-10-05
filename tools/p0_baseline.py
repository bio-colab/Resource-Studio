from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
MANIFEST = "<?xml version='1.0'?>\n<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'><assemblyIdentity name='P0Baseline' version='1.0.0.0'/></assembly>"


def cli_run(name: str, arguments: list[str], telemetry_path: Path, working: Path) -> dict[str, object]:
    command = [sys.executable, str(ROOT / "resource_studio_cli.py"), *arguments]
    environment = {**os.environ, "PYTHONPATH": str(ROOT), "RESOURCE_STUDIO_P0_TELEMETRY_PATH": str(telemetry_path)}
    started = time.perf_counter()
    completed = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
    record = {
        "schema": "resource_studio.p0_benchmark.v1",
        "operation": name,
        "elapsedMs": round((time.perf_counter() - started) * 1000, 3),
        "processesSpawned": 1,
        "exitCode": completed.returncode,
        "stdoutBytes": len(completed.stdout.encode("utf-8")),
        "stderrBytes": len(completed.stderr.encode("utf-8")),
    }
    if completed.returncode != 0:
        record["stderr"] = completed.stderr[-1000:]
    return record


def main() -> None:
    if not FIXTURE.is_file():
        raise SystemExit(f"fixture missing: {FIXTURE}")
    source_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="resource-studio-p0-") as temporary:
        working = Path(temporary)
        telemetry_path = working / "telemetry.jsonl"
        records = [
            {"schema": "resource_studio.p0_benchmark.v1", "kind": "metadata", "fixture": str(FIXTURE), "fixtureSha256": source_hash, "fixtureSize": FIXTURE.stat().st_size, "corpusCount": 1, "corpusNote": "Only the repository sample PE is available in this checkout; no large-file claim is made."}
        ]
        records.append(cli_run("cli.list", ["list", str(FIXTURE), "--json"], telemetry_path, working))
        extract_output = working / "manifest.bin"
        records.append(cli_run("cli.extract", ["extract", str(FIXTURE), "--type", "MANIFEST", "--name", "1", "--language", "1033", "--output", str(extract_output), "--json"], telemetry_path, working))
        records.append(cli_run("cli.security", ["security", str(FIXTURE), "--json"], telemetry_path, working))
        records.append(cli_run("cli.evidence-query", ["evidence-query", str(FIXTURE), 'resource.type == "MANIFEST"', "--json"], telemetry_path, working))

        writer_output = working / "writer-output.dll"
        writer_environment = {**os.environ, "PYTHONPATH": str(ROOT), "RESOURCE_STUDIO_P0_TELEMETRY_PATH": str(telemetry_path)}
        writer_code = "from pathlib import Path; from core.p0_telemetry import measure; from core.pe_writer import LiefPEWriter;\nwith measure('writer.replace_manifest') as telemetry:\n    LiefPEWriter().replace_manifest(Path('tests/fixtures/sample.dll'), Path(r'%s'), %r)\n" % (str(writer_output), MANIFEST)
        started = time.perf_counter()
        completed = subprocess.run([sys.executable, "-c", writer_code], cwd=ROOT, env=writer_environment, capture_output=True, text=True, check=False)
        records.append({"schema": "resource_studio.p0_benchmark.v1", "operation": "writer.replace_manifest", "elapsedMs": round((time.perf_counter() - started) * 1000, 3), "processesSpawned": 1, "exitCode": completed.returncode, "stdoutBytes": len(completed.stdout.encode("utf-8")), "stderrBytes": len(completed.stderr.encode("utf-8"))})
        if completed.returncode != 0:
            records[-1]["stderr"] = completed.stderr[-2000:]

        telemetry_records = [json.loads(line) for line in telemetry_path.read_text(encoding="utf-8").splitlines() if line.strip()] if telemetry_path.exists() else []
        output = {"schema": "resource_studio.p0_baseline.v1", "records": records, "telemetry": telemetry_records}
        destination = Path(os.environ.get("P0_BASELINE_OUTPUT", "/home/ubuntu/resource-studio-p0-baseline.json")).expanduser().resolve()
        destination.write_text(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(destination), "fixtureSha256": source_hash, "records": len(records), "telemetryRecords": len(telemetry_records)}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
