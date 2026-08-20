from __future__ import annotations

import ctypes
import os
import shutil
import tempfile
from pathlib import Path

from core.project import Project
from core.windows_resource_oracle import compare_with_lief

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
TYPE_IDS = {"CURSOR": 1, "BITMAP": 2, "ICON": 3, "MENU": 4, "DIALOG": 5, "STRING": 6, "RCDATA": 10, "GROUP_CURSOR": 12, "GROUP_ICON": 14, "VERSION": 16, "MANIFEST": 24}


def main() -> None:
    if os.name != "nt":
        print("win32-update-resource-oracle-tests: skipped (Windows only)")
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_bool]
    kernel32.BeginUpdateResourceW.restype = ctypes.c_void_p
    kernel32.UpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ushort, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.UpdateResourceW.restype = ctypes.c_bool
    kernel32.EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    kernel32.EndUpdateResourceW.restype = ctypes.c_bool

    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / FIXTURE.name
        shutil.copy2(FIXTURE, output)
        project = Project.open_pe(output, Path(temporary) / "project")
        candidate = next((entry for entry in project.entries.values() if entry.resource_type in TYPE_IDS and str(entry.name).isdigit() and entry.language is not None), None)
        if candidate is None:
            print("win32-update-resource-oracle-tests: skipped (no numeric resource candidate)")
            return
        handle = kernel32.BeginUpdateResourceW(str(output), False)
        if not handle:
            raise AssertionError(f"BeginUpdateResourceW failed: {ctypes.get_last_error()}")
        buffer = ctypes.create_string_buffer(candidate.data)
        type_ptr = ctypes.c_void_p(TYPE_IDS[candidate.resource_type])
        name_ptr = ctypes.c_void_p(int(candidate.name))
        ok = kernel32.UpdateResourceW(handle, type_ptr, name_ptr, int(candidate.language), buffer, len(candidate.data))
        if not ok:
            kernel32.EndUpdateResourceW(handle, True)
            raise AssertionError(f"UpdateResourceW failed: {ctypes.get_last_error()}")
        if not kernel32.EndUpdateResourceW(handle, False):
            raise AssertionError(f"EndUpdateResourceW failed: {ctypes.get_last_error()}")
        comparison = compare_with_lief(output)
        assert comparison.matches, comparison.to_dict()
    print("win32-update-resource-oracle-tests: passed")


if __name__ == "__main__":
    main()
