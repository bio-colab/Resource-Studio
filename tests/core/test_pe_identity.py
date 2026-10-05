from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.pe_identity import classify


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"


def main() -> None:
    # 1. 64-bit DLL
    dll = classify(FIXTURES / "mingw_x64_minimal.dll").to_dict()
    assert dll["format"] == "PE32+"
    assert dll["machine"] == "x64"
    assert dll["kind"] == "dll"
    assert dll["subsystem"] == "console"
    assert dll["signed"] is False
    assert dll["managed"] is False
    assert dll["overlayBytes"] == 0
    assert dll["packerHint"] is None

    # 2. 32-bit GUI EXE
    exe32 = classify(FIXTURES / "mingw_x86_resource_heavy.exe").to_dict()
    assert exe32["format"] == "PE32"
    assert exe32["machine"] == "x86"
    assert exe32["kind"] == "exe"
    assert exe32["subsystem"] == "windows-gui"
    assert exe32["signed"] is False

    # 3. Test-signed PE
    signed_exe = classify(FIXTURES / "mingw_x64_resource_heavy_test_signed.exe").to_dict()
    assert signed_exe["signed"] is True
    notice_codes = [n["code"] for n in signed_exe["notices"]]
    assert "SIGNATURE_WILL_BREAK" in notice_codes

    # 4. UPX packed PE
    upx = classify(FIXTURES / "mingw_x64_resource_heavy_upx.exe").to_dict()
    assert upx["packerHint"] is not None
    assert upx["packerHint"]["name"] == "UPX"
    upx_notice_codes = [n["code"] for n in upx["notices"]]
    assert "PACKER_HINT" in upx_notice_codes

    # 5. Overlay PE
    overlay_exe = classify(FIXTURES / "mingw_x64_resource_heavy_overlay.exe").to_dict()
    assert overlay_exe["overlayBytes"] > 0
    overlay_notice_codes = [n["code"] for n in overlay_exe["notices"]]
    assert "OVERLAY_PRESENT" in overlay_notice_codes

    # 6. MUI Satellite
    with tempfile.TemporaryDirectory() as temporary:
        mui_dir = Path(temporary) / "ar-SA"
        mui_dir.mkdir()
        mui_file = mui_dir / "test.mui"
        shutil.copy2(FIXTURES / "sample.dll", mui_file)
        mui = classify(mui_file).to_dict()
        assert mui["satellite"]["mui"] is True
        assert mui["satellite"]["languageHint"] == "ar-SA"

    # 7. Non-PE rejection
    try:
        classify(FIXTURES / "not-pe.txt")
        assert False, "Should have raised ValueError for non-PE"
    except ValueError:
        pass

    print("pe-identity-tests: passed")


if __name__ == "__main__":
    main()
