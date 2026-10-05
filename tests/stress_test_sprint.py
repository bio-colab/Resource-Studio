"""
Comprehensive Stress Test & Edge Boundary Suite for Resource Studio.
Pushes all parsers, CLI handlers, and invariants to the edge.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_DLL = ROOT / "tests" / "fixtures" / "sample.dll"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "resource_studio_cli.py"), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )


def test_corrupt_pe_cli() -> list[str]:
    errors = []
    with tempfile.TemporaryDirectory(prefix="rs-stress-") as td:
        tdp = Path(td)

        # 1. Zero-byte file
        f_zero = tdp / "zero.dll"
        f_zero.write_bytes(b"")

        # 2. Single byte
        f_one = tdp / "one.dll"
        f_one.write_bytes(b"M")

        # 3. MZ only
        f_mz = tdp / "mz.dll"
        f_mz.write_bytes(b"MZ")

        # 4. MZ + invalid e_lfanew
        f_lfanew = tdp / "lfanew.dll"
        header = bytearray(64)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x7FFFFFFF)
        f_lfanew.write_bytes(header)

        # 5. PE header pointing to EOF
        f_pe_eof = tdp / "pe_eof.dll"
        header2 = bytearray(64)
        header2[:2] = b"MZ"
        struct.pack_into("<I", header2, 0x3C, 64)
        header2.extend(b"PE\0\0")
        f_pe_eof.write_bytes(header2)

        # 6. Random noise
        f_noise = tdp / "noise.dll"
        f_noise.write_bytes(os.urandom(1024))

        corrupt_files = [f_zero, f_one, f_mz, f_lfanew, f_pe_eof, f_noise]

        for cf in corrupt_files:
            for subcmd in [
                ["list", str(cf)],
                ["inspect", str(cf), "--json"],
                ["validate", str(cf)],
                ["diff", str(cf), str(FIXTURE_DLL)],
                ["diff", str(FIXTURE_DLL), str(cf)],
                ["recipe", "export", str(cf), str(FIXTURE_DLL), "--output", str(tdp / "rec")],
                ["hex", str(cf), "--offset", "0", "--length", "16"],
            ]:
                res = run_cli(*subcmd)
                # We expect non-zero exit code or clean handled output, NOT uncaught python traceback!
                if "Traceback (most recent call last):" in res.stderr:
                    errors.append(f"UNCAUGHT TRACEBACK in cli {' '.join(subcmd)} on {cf.name}:\n{res.stderr}")
    return errors


def test_parser_boundaries() -> list[str]:
    errors = []

    # Manifest Parser
    from core.manifest import ManifestDocument
    manifest_cases = [
        b"",
        b"   ",
        b"not xml at all",
        b"<unclosed>",
        b"<?xml version='1.0'?><assembly></assembly>",
        b"<?xml version='1.0'?><root><nested>" + b"<a>" * 500 + b"</a>" * 500 + b"</nested></root>",
        b"\xff\xfe\x00\xd8\x00\xdc", # invalid utf-16 surrogate
        b"<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><assembly>&xxe;</assembly>",
    ]
    for i, data in enumerate(manifest_cases):
        try:
            doc = ManifestDocument.from_bytes(data)
            # If accepted, to_bytes shouldn't crash
            _ = doc.to_bytes()
        except Exception as e:
            # Expected to reject invalid, but should be safe exception
            if isinstance(e, (SystemExit, KeyboardInterrupt)):
                raise
            # Any unhandled crash?
            pass

    # Dialog Parser
    from core.dialog_resources import DialogResource, DialogResourceError
    dialog_cases = [
        b"",
        b"\x00" * 4,
        b"\x01\x00\xff\xff", # DIALOGEX signature only
        b"\x01\x00\xff\xff" + b"\x00" * 20,
        b"\x00" * 18 + b"\xff\x00" + b"\x00" * 10, # DIALOG with many controls but no control data
        os.urandom(128),
    ]
    for i, data in enumerate(dialog_cases):
        try:
            DialogResource.parse(data)
        except (DialogResourceError, ValueError, struct.error, IndexError) as e:
            pass
        except Exception as e:
            errors.append(f"Unexpected Dialog parser exception on case {i}: {type(e).__name__}: {e}")

    # Menu Parser
    from core.menu_resources import MenuResource, MenuResourceError
    menu_cases = [
        b"",
        b"\x00" * 2,
        b"\x01\x00\x00\x00", # MENUEX header
        b"\x00" * 4 + b"\xff" * 20,
        os.urandom(64),
    ]
    for i, data in enumerate(menu_cases):
        try:
            MenuResource.parse(data)
        except (MenuResourceError, ValueError, struct.error, IndexError) as e:
            pass
        except Exception as e:
            errors.append(f"Unexpected Menu parser exception on case {i}: {type(e).__name__}: {e}")

    # Version Info Parser
    from core.version_info import VersionInfo
    version_cases = [
        b"",
        b"\x00" * 4,
        b"\x28\x00\x00\x00\x00\x00", # wLength = 40, wValueLength = 0
        b"\xff" * 100,
        os.urandom(256),
    ]
    for i, data in enumerate(version_cases):
        try:
            VersionInfo.from_bytes(data)
        except (ValueError, struct.error, IndexError) as e:
            pass
        except Exception as e:
            errors.append(f"Unexpected Version Info exception on case {i}: {type(e).__name__}: {e}")

    # String Table Parser
    from core.string_table import StringTableBlock
    string_cases = [
        b"",
        b"\x00" * 2,
        b"\xff\xff", # claims string of 65535 chars with 0 bytes left
        b"\x05\x00Hello", # length 5, but odd byte count
        os.urandom(100),
    ]
    for i, data in enumerate(string_cases):
        try:
            StringTableBlock.from_bytes(1, data)
        except (ValueError, struct.error, IndexError, UnicodeDecodeError) as e:
            pass
        except Exception as e:
            errors.append(f"Unexpected String Table exception on case {i}: {type(e).__name__}: {e}")

    # Image / Icon / Bitmap Parser
    from core.image_resources import BitmapResource, IconCursorGroup, ImageResourceError
    image_cases = [
        b"",
        b"BM",
        b"BM" + b"\x00" * 20,
        b"\x00\x00\x01\x00\xff\xff", # Icon with 65535 images
        os.urandom(128),
    ]
    for i, data in enumerate(image_cases):
        try:
            BitmapResource.from_bmp(data)
        except (ImageResourceError, ValueError, struct.error, IndexError) as e:
            pass
        except Exception as e:
            errors.append(f"Unexpected Bitmap bmp exception on case {i}: {type(e).__name__}: {e}")

        try:
            BitmapResource.from_dib(data)
        except (ImageResourceError, ValueError, struct.error, IndexError) as e:
            pass
        except Exception as e:
            errors.append(f"Unexpected Bitmap dib exception on case {i}: {type(e).__name__}: {e}")

        try:
            IconCursorGroup.parse(data)
        except (ImageResourceError, ValueError, struct.error, IndexError) as e:
            pass
        except Exception as e:
            errors.append(f"Unexpected IconGroup exception on case {i}: {type(e).__name__}: {e}")

    return errors


def test_recipe_extreme_scenarios() -> list[str]:
    errors = []
    from core.recipe import create_recipe, RecipeError

    with tempfile.TemporaryDirectory(prefix="rs-recipe-stress-") as td:
        tdp = Path(td)

        # 1. Identical files
        rec_ident = tdp / "rec_ident"
        try:
            res_ident = create_recipe(FIXTURE_DLL, FIXTURE_DLL, rec_ident)
            errors.append(f"Expected RecipeError for identical files, but succeeded with {res_ident}")
        except RecipeError:
            pass # Correct invariant: refuse to create empty recipe on identical PEs
        except Exception as e:
            errors.append(f"Unexpected exception for identical files: {type(e).__name__}: {e}")

        # 2. Non-existent files
        try:
            create_recipe(tdp / "nonexistent1.dll", FIXTURE_DLL, tdp / "rec_err")
            errors.append("Expected FileNotFoundError or RecipeError for non-existent source")
        except (FileNotFoundError, RecipeError, ValueError):
            pass
        except Exception as e:
            errors.append(f"Unexpected exception for missing file: {type(e).__name__}: {e}")

    return errors


def test_typed_diff_stress() -> list[str]:
    errors = []
    from core.resource_reader import ResourceReader
    from core.diff import diff_resources

    entries = ResourceReader(FIXTURE_DLL).entries

    # Diff with empty list
    tree_empty = diff_resources(entries, [], typed=True).to_dict()
    if tree_empty["status"] == "unchanged":
        errors.append("Diff against empty should not be unchanged")

    # Diff with identical list
    tree_same = diff_resources(entries, entries, typed=True).to_dict()
    if tree_same["status"] != "unchanged":
        errors.append(f"Diff against self should be unchanged, got {tree_same['status']}")

    return errors


def main() -> None:
    print("=== STARTING STRESS TEST SPRINT ===")
    all_errors = []

    print("[1/4] Testing Corrupt PE inputs against CLI commands...")
    errs_pe = test_corrupt_pe_cli()
    all_errors.extend(errs_pe)
    print(f"      Corrupt PE CLI errors: {len(errs_pe)}")

    print("[2/4] Testing Parser boundary conditions (Manifest, Dialog, Menu, Version, String, Image)...")
    errs_parsers = test_parser_boundaries()
    all_errors.extend(errs_parsers)
    print(f"      Parser boundary errors: {len(errs_parsers)}")

    print("[3/4] Testing Recipe extreme scenarios...")
    errs_recipe = test_recipe_extreme_scenarios()
    all_errors.extend(errs_recipe)
    print(f"      Recipe extreme scenario errors: {len(errs_recipe)}")

    print("[4/4] Testing Typed Diff stress...")
    errs_diff = test_typed_diff_stress()
    all_errors.extend(errs_diff)
    print(f"      Typed Diff stress errors: {len(errs_diff)}")

    print("====================================")
    if all_errors:
        print(f"FAILED with {len(all_errors)} issues found:")
        for err in all_errors:
            print(f"- {err}")
        sys.exit(1)
    else:
        print("ALL STRESS TESTS PASSED WITH 0 UNHANDLED FAILURES!")


if __name__ == "__main__":
    main()
