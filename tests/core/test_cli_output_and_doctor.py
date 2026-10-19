from __future__ import annotations

import json
from io import StringIO
import pytest
from unittest.mock import patch

from core.cli_output import (
    filter_data,
    estimate_token_count,
    apply_token_window,
    dump_yaml,
    wrap_in_evidence_envelope,
    generate_subcommand_schema,
    run_doctor_checks,
    format_output,
)
import resource_studio_cli


def test_filter_data_nested_and_arrays():
    payload = {
        "identity": {
            "machine": "x64",
            "sections": [
                {"name": ".text", "virtual_size": 4096},
                {"name": ".rsrc", "virtual_size": 2048},
            ],
        },
        "meta": {"tags": ["pe", "windows", "binary"]},
    }

    assert filter_data(payload, "identity.machine") == "x64"
    assert filter_data(payload, "identity.sections[0].name") == ".text"
    assert filter_data(payload, "identity.sections[1].virtual_size") == 2048
    assert filter_data(payload, "meta.tags[2]") == "binary"
    assert filter_data(payload, "identity.missing_key") is None
    assert filter_data(payload, "identity.sections[99]") is None
    assert filter_data(payload, "") == payload


def test_token_accounting_and_window():
    text = "The quick brown fox jumps over the lazy dog. A secondary forensic sentence follows here."
    count = estimate_token_count(text)
    assert count > 10

    # Truncate
    truncated, total = apply_token_window(text, token_limit=5, token_offset=0)
    assert total == count
    assert "[truncated: showing tokens 0-5 of" in truncated

    # Offset window
    windowed, _ = apply_token_window(text, token_limit=4, token_offset=2)
    assert "[truncated: showing tokens 2-6 of" in windowed


def test_yaml_serialization_pure():
    data = {
        "name": "ResourceStudio",
        "enabled": True,
        "count": 42,
        "items": ["alpha", "beta"],
        "nested": {"key": "value: with colon"},
        "multiline": "line1\nline2",
    }
    yaml_str = dump_yaml(data)
    assert "name: ResourceStudio" in yaml_str
    assert "enabled: true" in yaml_str
    assert "count: 42" in yaml_str
    assert "- alpha" in yaml_str
    assert '- "value: with colon"' in yaml_str or '"value: with colon"' in yaml_str
    assert "multiline: |" in yaml_str
    assert "line1" in yaml_str and "line2" in yaml_str


def test_evidence_envelope_hashing():
    data = {"hash": "abc", "status": "analyzed"}
    envelope = wrap_in_evidence_envelope(
        data,
        operation="inspect",
        target_path="tests/fixtures/sample.dll",
        limitations=["Static analysis only."],
    )

    assert envelope["schema"] == "resource_studio.evidence.v1"
    assert envelope["evidenceId"].startswith("ev_")
    assert len(envelope["evidenceId"]) > 20
    assert envelope["subject"] is not None
    assert envelope["subject"]["name"] == "sample.dll"
    assert envelope["normalizedResult"] == data
    assert envelope["provider"]["id"] == "resource-studio-core"
    assert "Static analysis only." in envelope["limitations"]


def test_doctor_diagnostics_structure():
    report = run_doctor_checks()
    assert "status" in report
    assert "checks" in report
    assert "passedChecks" in report
    assert "failedChecks" in report
    assert report["totalChecks"] == len(report["checks"])
    assert report["totalChecks"] >= 7

    check_names = [c["name"] for c in report["checks"]]
    assert "python-runtime" in check_names
    assert "lief-pe-parser" in check_names
    assert "capstone-disassembler" in check_names
    assert "dotnet-sdk" in check_names

    py_check = next(c for c in report["checks"] if c["name"] == "python-runtime")
    assert py_check["ok"] is True
    assert py_check["classification"] == "healthy"


def test_cli_subcommand_schema_generation():
    parser = resource_studio_cli.parser()
    sub_action = getattr(parser, "_subparsers_action", None)
    assert sub_action is not None
    assert "inspect" in sub_action.choices

    inspect_parser = sub_action.choices["inspect"]
    schema = generate_subcommand_schema(inspect_parser)
    assert schema["type"] == "object"
    assert "input" in schema["properties"]
    assert "input" in schema["required"]


def test_cli_global_flags_schema(capsys):
    ret = resource_studio_cli.main(["inspect", "--schema"])
    assert ret == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert data["type"] == "object"
    assert "input" in data["properties"]


def test_cli_llms_manifest(capsys):
    ret = resource_studio_cli.main(["--llms"])
    assert ret == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    assert "commands" in data
    assert data["commandsCount"] > 20
    cmd_names = [c["command"] for c in data["commands"]]
    assert "inspect" in cmd_names
    assert "doctor" in cmd_names
    assert "signature" in cmd_names


def test_cli_filter_output_and_token_limit(capsys):
    ret = resource_studio_cli.main([
        "inspect",
        "tests/fixtures/sample.dll",
        "--json",
        "--filter-output",
        "identity.machine",
    ])
    assert ret == 0
    out = capsys.readouterr().out.strip()
    assert out == '"x64"'


def test_cli_format_yaml(capsys):
    ret = resource_studio_cli.main([
        "inspect",
        "tests/fixtures/sample.dll",
        "--json",
        "--format",
        "yaml",
        "--filter-output",
        "identity.machine",
    ])
    assert ret == 0
    out = capsys.readouterr().out.strip()
    assert out == "x64"


def test_cli_token_count(capsys):
    ret = resource_studio_cli.main([
        "inspect",
        "tests/fixtures/sample.dll",
        "--json",
        "--token-count",
    ])
    assert ret == 0
    out = capsys.readouterr().out.strip()
    assert out.isdigit()
    assert int(out) > 0


def test_cli_evidence_envelope(capsys):
    ret = resource_studio_cli.main([
        "inspect",
        "tests/fixtures/sample.dll",
        "--json",
        "--envelope",
        "--filter-output",
        "identity.machine",
    ])
    assert ret == 0
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["schema"] == "resource_studio.evidence.v1"
    assert data["evidenceId"].startswith("ev_")
    assert data["normalizedResult"] == "x64"


def test_cli_doctor_command_json(capsys):
    ret = resource_studio_cli.main(["doctor", "--json"])
    assert ret in (0, 1)  # 0 if all clean, 1 if warnings (e.g. signtool/ghidra offline)
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert "checks" in data
    assert "passedChecks" in data


def test_cli_structured_error_on_missing_file(capsys):
    ret = resource_studio_cli.main(["inspect", "nonexistent_sample_9999.dll", "--json"])
    assert ret == 2
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["status"] == "error"
    assert data["code"] == "ValueError"
    assert data["category"] == "validation_error"
    assert "nonexistent_sample_9999.dll" in data["message"]
    assert "remediation" in data
