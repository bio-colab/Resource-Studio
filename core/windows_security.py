from __future__ import annotations

import ctypes
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WindowsAuthenticodeReport:
    path: str
    available: bool
    status: str
    status_message: str
    signer_subject: str | None
    signer_thumbprint: str | None
    signer_not_after: str | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "available": self.available,
            "status": self.status,
            "statusMessage": self.status_message,
            "signer": {
                "subject": self.signer_subject,
                "thumbprint": self.signer_thumbprint,
                "notAfter": self.signer_not_after,
            },
            "error": self.error,
        }


def inspect_authenticode_windows(path: Path) -> WindowsAuthenticodeReport:
    path = Path(path).expanduser().resolve()
    if os.name != "nt":
        return WindowsAuthenticodeReport(str(path), False, "UNAVAILABLE", "Windows only", None, None, None, "not running on Windows")
    command = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:RS_PE_PATH; "
        "$c=$s.SignerCertificate; "
        "[pscustomobject]@{Status=[string]$s.Status;StatusMessage=[string]$s.StatusMessage;"
        "Subject=if($c){[string]$c.Subject}else{$null};Thumbprint=if($c){[string]$c.Thumbprint}else{$null};"
        "NotAfter=if($c){[string]$c.NotAfter}else{$null}} | ConvertTo-Json -Compress"
    )
    environment = {**os.environ, "RS_PE_PATH": str(path)}
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
            env=environment,
        )
        if completed.returncode != 0:
            return WindowsAuthenticodeReport(str(path), True, "ERROR", "PowerShell failed", None, None, None, completed.stderr.strip())
        payload = json.loads(completed.stdout)
        return WindowsAuthenticodeReport(
            str(path), True, str(payload.get("Status", "Unknown")), str(payload.get("StatusMessage", "")),
            payload.get("Subject"), payload.get("Thumbprint"), payload.get("NotAfter"), None,
        )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return WindowsAuthenticodeReport(str(path), True, "ERROR", "Authenticode inspection failed", None, None, None, str(exc))


if os.name == "nt":
    _wintrust = ctypes.WinDLL("wintrust", use_last_error=True)

    class _Guid(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

    class _WintrustFileInfo(ctypes.Structure):
        _fields_ = [("cbStruct", ctypes.c_uint32), ("pcwszFilePath", ctypes.c_wchar_p), ("hFile", ctypes.c_void_p), ("pgKnownSubject", ctypes.POINTER(_Guid))]

    class _WintrustData(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_uint32), ("pPolicyCallbackData", ctypes.c_void_p), ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_uint32), ("fdwRevocationChecks", ctypes.c_uint32), ("dwUnionChoice", ctypes.c_uint32),
            ("pFile", ctypes.POINTER(_WintrustFileInfo)), ("dwStateAction", ctypes.c_uint32), ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p), ("dwProvFlags", ctypes.c_uint32), ("dwUIContext", ctypes.c_uint32),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    _wintrust.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Guid), ctypes.POINTER(_WintrustData)]
    _wintrust.WinVerifyTrust.restype = ctypes.c_long


def verify_authenticode_native(path: Path) -> dict[str, Any]:
    """Run WinVerifyTrust without UI and without network retrieval on Windows."""
    path = Path(path).expanduser().resolve()
    if os.name != "nt":
        return {"available": False, "status": "UNAVAILABLE", "hresult": None, "valid": None, "path": str(path)}
    action = _Guid(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    file_info = _WintrustFileInfo()
    file_info.cbStruct = ctypes.sizeof(_WintrustFileInfo)
    file_info.pcwszFilePath = str(path)
    data = _WintrustData()
    data.cbStruct = ctypes.sizeof(_WintrustData)
    data.dwUIChoice = 2
    data.fdwRevocationChecks = 0
    data.dwUnionChoice = 1
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1
    data.dwProvFlags = 0x00001000
    try:
        hresult = int(_wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)))
    except OSError as exc:
        return {"available": True, "status": "ERROR", "hresult": None, "valid": None, "path": str(path), "error": str(exc)}
    finally:
        data.dwStateAction = 2
        try:
            _wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
        except Exception:
            pass
    unsigned = -2146762496
    return {"available": True, "status": "VALID" if hresult == 0 else ("NOT_SIGNED" if hresult == unsigned else "INVALID"), "hresult": hresult, "valid": hresult == 0, "path": str(path)}
