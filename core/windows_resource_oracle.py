from __future__ import annotations

import ctypes
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class WindowsResourceOracleError(RuntimeError):
    pass


_TYPE_NAMES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATORS",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    24: "MANIFEST",
}


@dataclass(frozen=True)
class WindowsResource:
    resource_type: str
    name: str
    language: int
    size: int
    sha256: str

    @property
    def key(self) -> tuple[str, str, int]:
        return self.resource_type, self.name, self.language

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.resource_type,
            "name": self.name,
            "language": self.language,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class WindowsResourceOracleReport:
    path: str
    resources: tuple[WindowsResource, ...]
    warnings: tuple[str, ...] = ()

    @property
    def resource_count(self) -> int:
        return len(self.resources)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "resourceCount": self.resource_count,
            "resources": [item.to_dict() for item in self.resources],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class WindowsResourceComparison:
    matches: bool
    missing: tuple[tuple[str, str, int], ...]
    extra: tuple[tuple[str, str, int], ...]
    changed: tuple[tuple[str, str, int], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "matches": self.matches,
            "missing": [list(item) for item in self.missing],
            "extra": [list(item) for item in self.extra],
            "changed": [list(item) for item in self.changed],
        }


def inspect(path: Path) -> WindowsResourceOracleReport:
    """Enumerate resources through the Windows loader without executing the PE."""

    if os.name != "nt":
        raise WindowsResourceOracleError("Windows resource oracle is only available on Windows")
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise WindowsResourceOracleError(f"file not found: {path}")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _configure_api(kernel32)
    flags = 0x00000020 | 0x00000040  # LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
    module = kernel32.LoadLibraryExW(str(path), None, flags)
    if not module:
        raise WindowsResourceOracleError(f"LoadLibraryExW failed: {ctypes.get_last_error()}")

    resources: dict[tuple[str, str, int], WindowsResource] = {}
    errors: list[str] = []
    try:
        type_ptrs: list[int] = []

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
        def enum_type(_module: Any, type_ptr: Any, _param: Any) -> bool:
            type_ptrs.append(_pointer(type_ptr))
            return True

        if not kernel32.EnumResourceTypesW(module, enum_type, None):
            error = ctypes.get_last_error()
            if error != 1813:  # ERROR_RESOURCE_TYPE_NOT_FOUND
                errors.append(f"EnumResourceTypesW failed: {error}")

        for type_ptr in type_ptrs:
            type_label = _identifier(type_ptr, type_identifier=True)

            @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
            def enum_name(_module: Any, _type_ptr: Any, name_ptr: Any, _param: Any, *, _type=type_ptr, _label=type_label) -> bool:
                _enumerate_languages(kernel32, module, _type, _pointer(name_ptr), _label, resources, errors)
                return True

            if not kernel32.EnumResourceNamesW(module, ctypes.c_void_p(type_ptr), enum_name, None):
                error = ctypes.get_last_error()
                if error != 1814:  # ERROR_RESOURCE_NAME_NOT_FOUND
                    errors.append(f"EnumResourceNamesW({type_label}) failed: {error}")
    finally:
        kernel32.FreeLibrary(module)

    ordered = tuple(sorted(resources.values(), key=lambda item: item.key))
    return WindowsResourceOracleReport(str(path), ordered, tuple(errors))


def compare_with_lief(path: Path) -> WindowsResourceComparison:
    """Compare Windows-loaded resource identity and bytes with LIEF's resource tree."""

    from .project import _entries_from_lief
    from .pe_writer import LiefPEWriter

    report = inspect(path)
    binary = LiefPEWriter()._parse(Path(path))
    expected = {
        (entry.resource_type, entry.name, int(entry.language or 0)): hashlib.sha256(entry.data).hexdigest()
        for entry in _entries_from_lief(binary)
    }
    actual = {item.key: item.sha256 for item in report.resources}
    expected_keys = set(expected)
    actual_keys = set(actual)
    missing = tuple(sorted(expected_keys - actual_keys))
    extra = tuple(sorted(actual_keys - expected_keys))
    changed = tuple(sorted(key for key in expected_keys & actual_keys if expected[key] != actual[key]))
    return WindowsResourceComparison(not missing and not extra and not changed, missing, extra, changed)


def _enumerate_languages(kernel32: Any, module: Any, type_ptr: int, name_ptr: int, type_label: str, resources: dict[tuple[str, str, int], WindowsResource], errors: list[str]) -> None:
    name_label = _identifier(name_ptr)

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ushort, ctypes.c_void_p)
    def enum_language(_module: Any, _type_ptr: Any, _name_ptr: Any, language: int, _param: Any) -> bool:
        language_id = int(language)
        resource = kernel32.FindResourceExW(module, ctypes.c_void_p(type_ptr), ctypes.c_void_p(name_ptr), language_id)
        if not resource:
            errors.append(f"FindResourceExW({type_label},{name_label},{language_id}) failed: {ctypes.get_last_error()}")
            return True
        size = int(kernel32.SizeofResource(module, resource))
        loaded = kernel32.LoadResource(module, resource)
        address = kernel32.LockResource(loaded) if loaded else None
        if size and not address:
            errors.append(f"LockResource({type_label},{name_label},{language_id}) returned NULL")
            return True
        data = ctypes.string_at(address, size) if size else b""
        item = WindowsResource(type_label, name_label, language_id, size, hashlib.sha256(data).hexdigest())
        resources[item.key] = item
        return True

    if not kernel32.EnumResourceLanguagesW(module, ctypes.c_void_p(type_ptr), ctypes.c_void_p(name_ptr), enum_language, None):
        error = ctypes.get_last_error()
        if error != 1815:  # ERROR_RESOURCE_LANG_NOT_FOUND
            errors.append(f"EnumResourceLanguagesW({type_label},{name_label}) failed: {error}")


def _configure_api(kernel32: Any) -> None:
    kernel32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.LoadLibraryExW.restype = ctypes.c_void_p
    kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
    kernel32.FreeLibrary.restype = ctypes.c_bool
    kernel32.EnumResourceTypesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    kernel32.EnumResourceTypesW.restype = ctypes.c_bool
    kernel32.EnumResourceNamesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    kernel32.EnumResourceNamesW.restype = ctypes.c_bool
    kernel32.EnumResourceLanguagesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    kernel32.EnumResourceLanguagesW.restype = ctypes.c_bool
    kernel32.FindResourceExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ushort]
    kernel32.FindResourceExW.restype = ctypes.c_void_p
    kernel32.SizeofResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.SizeofResource.restype = ctypes.c_uint32
    kernel32.LoadResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.LoadResource.restype = ctypes.c_void_p
    kernel32.LockResource.argtypes = [ctypes.c_void_p]
    kernel32.LockResource.restype = ctypes.c_void_p


def _pointer(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(getattr(value, "value", 0) or 0)


def _identifier(value: int, *, type_identifier: bool = False) -> str:
    if value <= 0xFFFF:
        return _TYPE_NAMES.get(value, str(value)) if type_identifier else str(value)
    return ctypes.wstring_at(value)
