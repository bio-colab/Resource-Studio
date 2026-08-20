from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommitResult:
    source: str
    target: str
    method: str
    flushed: bool
    same_volume: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "method": self.method,
            "flushed": self.flushed,
            "sameVolume": self.same_volume,
        }


class DurableCommitError(RuntimeError):
    pass


def commit_temporary(source: Path, target: Path) -> CommitResult:
    source = Path(source).expanduser().resolve()
    target = Path(target).expanduser().resolve()
    if not source.is_file():
        raise DurableCommitError(f"temporary source not found: {source}")
    if source == target:
        raise DurableCommitError("temporary source and target must differ")
    target.parent.mkdir(parents=True, exist_ok=True)
    flushed = _flush_file(source)
    same_volume = _same_volume(source, target)
    if os.name == "nt" and same_volume:
        method = _windows_replace_or_move(source, target)
    else:
        os.replace(source, target)
        method = "os.replace"
    return CommitResult(str(source), str(target), method, flushed, same_volume)


def _flush_file(path: Path) -> bool:
    flags = os.O_RDWR if os.name == "nt" else os.O_RDONLY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
        return True
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _same_volume(source: Path, target: Path) -> bool:
    try:
        source_stat = source.stat()
        target_stat = target.parent.stat()
        return source_stat.st_dev == target_stat.st_dev
    except OSError:
        return False


def _windows_replace_or_move(source: Path, target: Path) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if target.exists():
        kernel32.ReplaceFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
        kernel32.ReplaceFileW.restype = ctypes.c_bool
        if kernel32.ReplaceFileW(str(target), str(source), None, 0, None, None):
            return "ReplaceFileW"
        replace_error = ctypes.get_last_error()
    else:
        replace_error = 0
    kernel32.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    kernel32.MoveFileExW.restype = ctypes.c_bool
    flags = 0x00000001 | 0x00000008  # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    if kernel32.MoveFileExW(str(source), str(target), flags):
        return "MoveFileExW"
    error = ctypes.get_last_error() or replace_error
    raise DurableCommitError(f"Windows file commit failed: {error}")
