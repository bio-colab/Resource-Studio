from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from core.menu_resources import MenuItem, MenuResource
from core.pe_writer import LiefPEWriter
from core.version_info import VersionInfo

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    return subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), *args], capture_output=True, text=True, env=env, check=False)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-wizards-") as temporary:
        root = Path(temporary)
        source = root / "source.dll"
        with_version = root / "with-version.dll"
        with_menu = root / "with-menu.dll"
        shutil.copy2(FIXTURE, source)
        version = VersionInfo(file_version="2.3.4.5", product_version="2.3.4.5", strings={"FileDescription": "Wizard test", "CompanyName": "Resource Studio"}, translations=[0x0409])
        LiefPEWriter().add_typed_resource(source, with_version, "VERSION", 1, 1033, version.to_bytes())
        menu = MenuResource([MenuItem(1, "File", children=[MenuItem(2, "Open")]), MenuItem(0, "", flags=0x0800)])
        LiefPEWriter().add_typed_resource(with_version, with_menu, "MENU", 1, 1033, menu.to_bytes())

        version_model = root / "version.json"
        exported = run_cli("version-resource", "export", str(with_menu), "--language", "1033", "--output", str(version_model), "--json")
        assert exported.returncode == 0, exported.stderr
        assert json.loads(version_model.read_text(encoding="utf-8"))["fileVersion"] == "2.3.4.5"
        version_output = root / "version-output.dll"
        applied = run_cli("version-resource", "apply", str(with_menu), "--language", "1033", "--model", str(version_model), "--output", str(version_output), "--json")
        assert applied.returncode == 0, applied.stderr

        manifest_model = root / "manifest.json"
        exported = run_cli("manifest-resource", "export", str(with_menu), "--language", "1033", "--output", str(manifest_model), "--json")
        assert exported.returncode == 0, exported.stderr
        manifest_payload = json.loads(manifest_model.read_text(encoding="utf-8"))
        assert manifest_payload["format"] == "resource_studio.manifest.v1"
        manifest_payload["xml"] = '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity name="ResourceStudio.Test" version="1.0.0.0" type="win32" /></assembly>'
        manifest_model.write_text(json.dumps(manifest_payload), encoding="utf-8")
        manifest_output = root / "manifest-output.dll"
        applied = run_cli("manifest-resource", "apply", str(with_menu), "--language", "1033", "--model", str(manifest_model), "--output", str(manifest_output), "--json")
        assert applied.returncode == 0, applied.stderr

        menu_model = root / "menu.json"
        exported = run_cli("menu-resource", "export", str(with_menu), "--language", "1033", "--output", str(menu_model), "--json")
        assert exported.returncode == 0, exported.stderr
        assert json.loads(menu_model.read_text(encoding="utf-8"))["items"][0]["text"] == "File"
        menu_output = root / "menu-output.dll"
        applied = run_cli("menu-resource", "apply", str(with_menu), "--language", "1033", "--model", str(menu_model), "--output", str(menu_output), "--json")
        assert applied.returncode == 0, applied.stderr
    print("resource-wizards-cli-tests: passed")


if __name__ == "__main__":
    main()
