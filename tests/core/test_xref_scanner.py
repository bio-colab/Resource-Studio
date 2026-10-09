from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.mcp_server import create_mcp_server
from core.xref_scanner import scan_pe_xrefs

FIXTURE_SAMPLE = ROOT / "tests" / "fixtures" / "sample.dll"
FIXTURE_HEAVY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy.exe"


def test_xref_sample_dll() -> None:
    report = scan_pe_xrefs(FIXTURE_SAMPLE)
    assert report.path == str(FIXTURE_SAMPLE.resolve())
    assert report.machine == "x64"
    assert report.summary["totalResources"] == 1
    assert report.summary["referenced"] == 1
    assert report.summary["deadOrphans"] == 0

    res = report.resources[0]
    assert res.resource_type == "MANIFEST"
    assert res.status == "REFERENCED"
    assert len(res.references) > 0


def test_xref_heavy_dead_resource_detection() -> None:
    report = scan_pe_xrefs(FIXTURE_HEAVY)
    assert report.summary["totalResources"] == 7
    assert report.summary["deadOrphans"] >= 2  # MENU 101 and DIALOG 201 have 0 code references

    res_map = {(r.resource_type, str(r.name)): r for r in report.resources}
    assert ("DIALOG", "201") in res_map
    assert res_map[("DIALOG", "201")].status == "DEAD_ORPHAN"
    assert len(res_map[("DIALOG", "201")].references) == 0

    assert ("MENU", "101") in res_map
    assert res_map[("MENU", "101")].status == "DEAD_ORPHAN"

    # Named payload in rdata/rsrc
    assert ("RCDATA", "NAMED_PAYLOAD") in res_map
    assert res_map[("RCDATA", "NAMED_PAYLOAD")].status == "REFERENCED"


def test_xref_cli_invocation() -> None:
    res = subprocess.run(
        [sys.executable, str(ROOT / "resource_studio_cli.py"), "xref", str(FIXTURE_SAMPLE), "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["summary"]["referenced"] == 1
    assert data["machine"] == "x64"


def test_xref_mcp_tool() -> None:
    async def _run() -> None:
        server = create_mcp_server()
        _, xref_res = await server.call_tool("scan_resource_xrefs", {"file_path": str(FIXTURE_HEAVY)})
        assert xref_res["summary"]["totalResources"] == 7
        assert xref_res["summary"]["deadOrphans"] >= 2

    asyncio.run(_run())


def main() -> None:
    test_xref_sample_dll()
    test_xref_heavy_dead_resource_detection()
    test_xref_cli_invocation()
    test_xref_mcp_tool()
    print("test_xref_scanner: all 4 test suites passed successfully!")


if __name__ == "__main__":
    main()
