from __future__ import annotations

import ctypes
import os
from pathlib import Path


def path_access_status(path: Path) -> str:
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        return "NOT_FOUND"
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.CreateFileW(str(path), 0, 7, None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            return "LOCKED" if ctypes.get_last_error() in {32, 33} else "ACCESS_DENIED"
        kernel32.CloseHandle(handle)
        return "READY"
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except PermissionError:
        return "ACCESS_DENIED"
    except OSError:
        return "ACCESS_ERROR"
    return "READY"
