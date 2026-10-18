from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.investigation_pipeline import run_pipeline
from core.pe_identity import classify
from core.pe_metadata import PEMetadataInspector
from core.resource_reader import ResourceReader
from core.string_table import StringTableBlock, string_table_block_id
from core.xref_scanner import scan_pe_xrefs

FIXTURE_SAMPLE = ROOT / "tests" / "fixtures" / "sample.dll"
FIXTURE_HEAVY = ROOT / "tests" / "fixtures" / "mingw_x64_resource_heavy.exe"

SEVENZIP_PATH = Path("C:/Program Files/7-Zip/7zFM.exe")
CHARMAP_PATH = Path("C:/Windows/System32/charmap.exe")


def test_string_table_block_formula_and_mapping() -> None:
    """Verifies Win32 StringTable block index formula and range resolution."""
    # Test block ID calculation: ((StringID - 1) // 16) + 1
    assert string_table_block_id(1) == 1
    assert string_table_block_id(16) == 1
    assert string_table_block_id(17) == 2
    assert string_table_block_id(449) == 29
    assert string_table_block_id(1024) == 64
    assert string_table_block_id(1025) == 65

    # Test StringTableBlock slot range
    block = StringTableBlock(29, tuple(["Sample text" if i == 0 else "" for i in range(16)]))
    assert block.first_string_id == 449
    assert block.get(449) == "Sample text"


def test_mui_architecture_detection_and_companion_resolution(tmp_path: Path) -> None:
    """Verifies detection of MUI base binaries and automatic companion .mui discovery."""
    base_exe = tmp_path / "app.exe"
    shutil.copy2(FIXTURE_SAMPLE, base_exe)

    # In base directory, initially no companions
    meta_initial = PEMetadataInspector.inspect(base_exe)
    assert len(meta_initial.companion_mui_files) == 0

    # Create language companion folder en-US with app.exe.mui
    en_us_dir = tmp_path / "en-US"
    en_us_dir.mkdir()
    mui_file = en_us_dir / "app.exe.mui"
    shutil.copy2(FIXTURE_SAMPLE, mui_file)

    # Manually test companion inspection from .mui side
    meta_mui = PEMetadataInspector.inspect(mui_file)
    assert meta_mui.is_mui is True
    assert meta_mui.base_executable == str(base_exe.resolve())

    # ResourceReader on companion
    reader = ResourceReader(mui_file)
    assert len(reader.entries) > 0


@pytest.mark.skipif(not SEVENZIP_PATH.is_file(), reason="7-Zip not installed on host")
def test_empirical_7zip_resource_accuracy() -> None:
    """Empirically tests that 7zFM.exe has 0 false-positive dead resources with string & rdata table mapping."""
    report = scan_pe_xrefs(SEVENZIP_PATH)
    assert report.summary["totalResources"] == 88
    # All or nearly all resources must be recognized as referenced (0 dead orphans vs 27 previously)
    assert report.summary["deadOrphans"] == 0
    assert report.summary["referenced"] == 88


@pytest.mark.skipif(not CHARMAP_PATH.is_file(), reason="charmap.exe not present on host")
def test_empirical_charmap_mui_architecture() -> None:
    """Empirically tests that charmap.exe is recognized as an MUI base binary with companion .mui files."""
    meta = PEMetadataInspector.inspect(CHARMAP_PATH)
    assert meta.has_mui_resource is True
    assert meta.is_mui_base is True
    assert len(meta.companion_mui_files) >= 1

    # Verify ResourceReader finds localized UI dialogs in companions
    reader = ResourceReader(CHARMAP_PATH)
    companion_entries = reader.read_mui_companion_entries()
    assert len(companion_entries) > 0

    dialog_names = [str(e.name) for e in companion_entries if e.resource_type == "DIALOG"]
    assert "101" in dialog_names or "102" in dialog_names

    # Verify automated investigation pipeline triages MUI base architecture
    inv_report = run_pipeline(CHARMAP_PATH)
    mui_hyp = next((h for h in inv_report.hypotheses if h.target_type == "ARCHITECTURE"), None)
    assert mui_hyp is not None
    assert mui_hyp.verdict == "PROVEN"
    assert mui_hyp.confidence == 1.0
