from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from typing import Any


class WindowsIsolationError(RuntimeError):
    pass


@dataclass(frozen=True)
class WindowsJobLimits:
    max_processes: int = 1
    max_memory_bytes: int | None = 256 * 1024 * 1024


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [("ReadOperationCount", ctypes.c_uint64), ("WriteOperationCount", ctypes.c_uint64), ("OtherOperationCount", ctypes.c_uint64), ("ReadTransferCount", ctypes.c_uint64), ("WriteTransferCount", ctypes.c_uint64), ("OtherTransferCount", ctypes.c_uint64)]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BasicLimitInformation), ("IoInfo", _IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    _kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    _kernel32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    _kernel32.SetInformationJobObject.restype = ctypes.c_int
    _kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _kernel32.AssignProcessToJobObject.restype = ctypes.c_int
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = ctypes.c_int
    _kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    _kernel32.TerminateJobObject.restype = ctypes.c_int


class WindowsJob:
    def __init__(self, limits: WindowsJobLimits | None = None) -> None:
        self.limits = limits or WindowsJobLimits()
        self._handle: Any = None

    def __enter__(self) -> "WindowsJob":
        if os.name != "nt":
            raise WindowsIsolationError("Windows Job Objects are only available on Windows")
        self._handle = _kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise WindowsIsolationError(f"CreateJobObjectW failed: {ctypes.get_last_error()}")
        info = _ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = max(1, self.limits.max_processes)
        if self.limits.max_memory_bytes is not None:
            info.BasicLimitInformation.LimitFlags |= _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.ProcessMemoryLimit = self.limits.max_memory_bytes
        ok = _kernel32.SetInformationJobObject(self._handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info))
        if not ok:
            self.close()
            raise WindowsIsolationError(f"SetInformationJobObject failed: {ctypes.get_last_error()}")
        return self

    def assign(self, process: Any) -> None:
        if not self._handle:
            raise WindowsIsolationError("job is not open")
        handle = _kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, int(process.pid))
        if not handle:
            raise WindowsIsolationError(f"OpenProcess failed: {ctypes.get_last_error()}")
        try:
            if not _kernel32.AssignProcessToJobObject(self._handle, handle):
                raise WindowsIsolationError(f"AssignProcessToJobObject failed: {ctypes.get_last_error()}")
        finally:
            _kernel32.CloseHandle(handle)

    def terminate(self, exit_code: int = 1) -> None:
        if self._handle:
            _kernel32.TerminateJobObject(self._handle, exit_code)

    def close(self) -> None:
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
