from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
MANIFEST = ROOT / "tests" / "corpus_manifest.json"

C_SOURCE = r'''
#include <windows.h>

__declspec(dllexport) int corpus_value(void) { return 42; }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
'''

EXE_SOURCE = r'''
#include <windows.h>

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show_command) {
    (void)instance; (void)previous; (void)command_line; (void)show_command;
    return 42;
}
'''

RESOURCE_SOURCE = r'''
#include <windows.h>

LANGUAGE 0x09, 0x01

1 RCDATA "payload.bin"
NAMED_PAYLOAD RCDATA { 0x52, 0x53, 0x43, 0x4F, 0x52, 0x50, 0x55, 0x53 }

STRINGTABLE
BEGIN
    1 "English corpus string"
    2 "Named and numeric resources"
END

101 MENU
BEGIN
    POPUP "File"
    BEGIN
        MENUITEM "Exit", 9001
    END
END

201 DIALOGEX 0, 0, 220, 100
STYLE DS_SETFONT | WS_POPUP | WS_CAPTION | WS_SYSMENU
CAPTION "Corpus Dialog"
FONT 9, "Segoe UI"
BEGIN
    LTEXT "Resource-heavy fixture", -1, 8, 8, 160, 12
    EDITTEXT 1001, 8, 26, 160, 12
END

1 VERSIONINFO
FILEVERSION 1,2,3,4
PRODUCTVERSION 1,2,3,4
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "Resource Studio Corpus"
            VALUE "FileDescription", "Benign resource-heavy fixture"
            VALUE "FileVersion", "1.2.3.4"
            VALUE "ProductName", "Resource Studio Corpus"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END

LANGUAGE 0x07, 0x01
STRINGTABLE
BEGIN
    1 "German corpus string"
END
'''


def run(command: list[str], cwd: Path) -> None:
    result = subprocess.run(command, cwd=cwd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_one(temp: Path, output: Path, arch: str, kind: str) -> None:
    prefix = "i686-w64-mingw32" if arch == "x86" else "x86_64-w64-mingw32"
    source = temp / ("library.c" if kind == "dll" else "program.c")
    source.write_text(C_SOURCE if kind == "dll" else EXE_SOURCE, encoding="ascii")
    command = [f"{prefix}-gcc", "-O0", "-g0", "-ffunction-sections", "-fdata-sections"]
    if kind == "dll":
        command.extend(["-shared", "-Wl,--no-insert-timestamp", "-o", str(output), str(source)])
    else:
        command.extend(["-Wl,--subsystem,windows", "-Wl,--no-insert-timestamp", "-o", str(output), str(source)])
    run(command, temp)


def build_resource_heavy(temp: Path, output: Path, arch: str, linker_extra: tuple[str, ...] = ()) -> None:
    prefix = "i686-w64-mingw32" if arch == "x86" else "x86_64-w64-mingw32"
    source = temp / "resource_program.c"
    source.write_text(EXE_SOURCE, encoding="ascii")
    (temp / "payload.bin").write_bytes(bytes(range(256)) * 4)
    rc = temp / "resources.rc"
    rc.write_text(RESOURCE_SOURCE, encoding="ascii")
    res = temp / f"resources-{arch}.o"
    run([f"{prefix}-windres", "--output-format=coff", str(rc), str(res)], temp)
    run([f"{prefix}-gcc", "-O0", "-g0", "-Wl,--subsystem,windows", "-Wl,--no-insert-timestamp", *linker_extra, "-o", str(output), str(source), str(res)], temp)


def add_overlay(source: Path, output: Path) -> None:
    output.write_bytes(source.read_bytes() + b"RS-CORPUS-OVERLAY\x00" + bytes(range(256)) * 64)


def make_manifest(paths: list[tuple[Path, dict]]) -> None:
    entries = [{
        "path": "tests/fixtures/sample.dll",
        "sha256": sha256(FIXTURES / "sample.dll"),
        "kind": "reference-pe",
        "architecture": "x64",
        "toolchain": "fixture-defined",
        "profile": "reference-resource-fixture",
        "expectedParse": "pe",
        "signature": "unsigned-or-fixture-defined",
        "languages": "fixture-defined",
        "resourceCoverage": ["raw", "typed", "multiple-language-as-available"],
        "allowedNormalization": ["resource-section-layout", "padding"],
    }]
    for path, metadata in paths:
        entry = {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path), **metadata}
        entries.append(entry)
    entries.extend([
        {"path": "tests/fixtures/not-pe.txt", "sha256": sha256(FIXTURES / "not-pe.txt"), "kind": "negative-fixture", "expectedParse": "reject"},
        {"path": "tests/fixtures/localization_sample.json", "sha256": sha256(FIXTURES / "localization_sample.json"), "kind": "auxiliary-fixture", "expectedParse": "not-pe"},
    ])
    MANIFEST.write_text(json.dumps({"format": "resource_studio.corpus.v1", "entries": entries}, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="resource-studio-corpus-build-") as directory:
        temp = Path(directory)
        generated: list[tuple[Path, dict]] = []
        for arch in ("x86", "x64"):
            minimal = FIXTURES / f"mingw_{arch}_minimal.dll"
            heavy = FIXTURES / f"mingw_{arch}_resource_heavy.exe"
            build_one(temp, minimal, arch, "dll")
            build_resource_heavy(temp, heavy, arch)
            generated.extend([
                (minimal, {"kind": "generated-pe", "architecture": arch, "toolchain": "MinGW-w64 13.2", "profile": "minimal", "expectedParse": "pe", "signature": "unsigned", "languages": ["unknown"], "resourceCoverage": ["exports", "code"]}),
                (heavy, {"kind": "generated-pe", "architecture": arch, "toolchain": "MinGW-w64 13.2", "profile": "resource-heavy", "expectedParse": "pe", "signature": "unsigned", "languages": ["en-US", "de-DE"], "resourceCoverage": ["numeric", "named", "multiple-language", "STRINGTABLE", "MENU", "DIALOGEX", "VERSIONINFO", "RCDATA"]}),
            ])
        weird_alignment = FIXTURES / "mingw_x64_weird_alignment.exe"
        build_resource_heavy(temp, weird_alignment, "x64", ("-Wl,--section-alignment,0x200", "-Wl,--file-alignment,0x200"))
        packed = FIXTURES / "mingw_x64_resource_heavy_upx.exe"
        packed.unlink(missing_ok=True)
        run(["upx", "--best", "--ultra-brute", "-o", str(packed), str(FIXTURES / "mingw_x64_resource_heavy.exe")], temp)
        overlay = FIXTURES / "mingw_x64_resource_heavy_overlay.exe"
        add_overlay(FIXTURES / "mingw_x64_resource_heavy.exe", overlay)
        key = temp / "corpus-test.key"
        cert = temp / "corpus-test.crt"
        signed = FIXTURES / "mingw_x64_resource_heavy_test_signed.exe"
        signed.unlink(missing_ok=True)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Resource Studio Corpus Test/", "-days", "3650", "-keyout", str(key), "-out", str(cert)], temp)
        run(["osslsigncode", "sign", "-h", "sha256", "-certs", str(cert), "-key", str(key), "-n", "Resource Studio Corpus Test", "-in", str(FIXTURES / "mingw_x64_resource_heavy.exe"), "-out", str(signed)], temp)
        generated.extend([
            (weird_alignment, {"kind": "generated-pe", "architecture": "x64", "toolchain": "MinGW-w64 13.2", "profile": "weird-alignment", "expectedParse": "pe", "signature": "unsigned", "languages": ["en-US", "de-DE"], "resourceCoverage": ["non-page-section-alignment", "resources"]}),
            (packed, {"kind": "generated-pe", "architecture": "x64", "toolchain": "MinGW-w64 13.2 + UPX 4.2.2", "profile": "packed-benign", "expectedParse": "pe", "signature": "unsigned", "languages": ["en-US", "de-DE"], "resourceCoverage": ["packed-code", "resources"], "limitations": ["benign generated payload; UPX profile validates static heuristics, not malware behavior"]}),
            (overlay, {"kind": "generated-pe", "architecture": "x64", "toolchain": "MinGW-w64 13.2", "profile": "overlay", "expectedParse": "pe", "signature": "unsigned", "languages": ["en-US", "de-DE"], "resourceCoverage": ["overlay", "resources"], "limitations": ["overlay bytes are deterministic benign test data"]}),
            (signed, {"kind": "generated-pe", "architecture": "x64", "toolchain": "MinGW-w64 13.2 + osslsigncode 2.8", "profile": "test-signed", "expectedParse": "pe", "signature": "self-signed-test-certificate", "languages": ["en-US", "de-DE"], "resourceCoverage": ["resources", "certificate-table"], "limitations": ["certificate is generated for corpus testing and is not a trusted publisher identity"]}),
        ])
        make_manifest(generated)
    print(json.dumps({"format": "resource_studio.corpus.v1", "generated": len(generated), "manifest": str(MANIFEST)}, indent=2))


if __name__ == "__main__":
    main()
