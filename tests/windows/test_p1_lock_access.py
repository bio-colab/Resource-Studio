from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _exclusive_handle(path: Path):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    handle = kernel32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "could not create exclusive test handle")
    return kernel32, handle


def main() -> None:
    if sys.platform != "win32":
        print("p1-lock-access-tests: skipped (Windows only)")
        return
    source = Path(r"C:\Windows\System32\kernel32.dll")
    with tempfile.TemporaryDirectory(prefix="resource-studio-p1-lock-") as temporary:
        target = Path(temporary) / "locked.dll"
        shutil.copy2(source, target)
        kernel32, handle = _exclusive_handle(target)
        try:
            probe = subprocess.run(
                [sys.executable, "-c", "from pathlib import Path; import json; from core.access import path_access_status; from core.health import PEHealth; p=Path(__import__('sys').argv[1]); print(json.dumps({'status': path_access_status(p), 'healthStatus': PEHealth.inspect(p).status}))", str(target)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            assert probe.returncode == 0, f"probe failed: {probe.stdout}\n{probe.stderr}"
            payload = json.loads(probe.stdout)
            assert payload["status"] in {"LOCKED", "ACCESS_DENIED"}, payload
            assert payload["healthStatus"] in {"LOCKED", "ACCESS_DENIED"}, payload
            print(f"p1-lock-access-tests: passed ({payload['status']})")
        finally:
            kernel32.CloseHandle(handle)


if __name__ == "__main__":
    main()
