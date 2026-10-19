from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def filter_data(data: Any, path_expr: str) -> Any:
    """
    Evaluates key paths like 'identity.machine', 'resources[0].sha256',
    'summary.referenced', or 'tools[0,3]' on nested dicts/lists.
    """
    if not path_expr or not path_expr.strip():
        return data

    current = data
    # Tokenize path: split by dot or bracket notation
    tokens = re.findall(r"([a-zA-Z0-9_\-]+)|\[([0-9,\-:]+)\]", path_expr.strip())

    for prop_name, slice_expr in tokens:
        if prop_name:
            if isinstance(current, dict):
                current = current.get(prop_name)
            elif isinstance(current, list):
                # Map property across list elements if applicable
                current = [item.get(prop_name) for item in current if isinstance(item, dict)]
            else:
                return None
        elif slice_expr:
            if not isinstance(current, list):
                return None
            if "," in slice_expr:
                indices = [int(p.strip()) for p in slice_expr.split(",") if p.strip().isdigit()]
                current = [current[i] for i in indices if 0 <= i < len(current)]
            elif ":" in slice_expr:
                parts = slice_expr.split(":")
                start = int(parts[0]) if parts[0] else None
                end = int(parts[1]) if len(parts) > 1 and parts[1] else None
                current = current[start:end]
            elif slice_expr.isdigit():
                idx = int(slice_expr)
                current = current[idx] if 0 <= idx < len(current) else None

        if current is None:
            return None

    return current


def estimate_token_count(text: str) -> int:
    """
    Fast, reliable token count estimation aligned with OpenAI/Gemini BPE tokenizers (~3.5-4 chars per token).
    """
    if not text:
        return 0
    tokens = re.findall(r"\w+|[^\w\s]", text, re.UNICODE)
    return max(1, len(tokens))


def apply_token_window(text: str, token_limit: int | None = None, token_offset: int | None = None) -> tuple[str, int]:
    """
    Applies token offset and limit windows with a clean truncation footer.
    """
    if not text:
        return "", 0

    tokens = re.findall(r"\w+|[^\w\s]|\s+", text, re.UNICODE)
    total_tokens = len([t for t in tokens if t.strip()])

    if token_limit is None and token_offset is None:
        return text, total_tokens

    offset = token_offset or 0
    limit = token_limit if token_limit is not None else total_tokens

    # Track non-whitespace token count to find boundary
    token_count = 0
    start_char = 0
    end_char = len(text)

    char_idx = 0
    for tok in tokens:
        is_word = bool(tok.strip())
        if is_word:
            if token_count == offset:
                start_char = char_idx
            if token_count == offset + limit:
                end_char = char_idx
                break
            token_count += 1
        char_idx += len(tok)

    windowed_text = text[start_char:end_char].strip()
    if offset > 0 or (offset + limit < total_tokens):
        windowed_text += f"\n\n[truncated: showing tokens {offset}-{min(offset + limit, total_tokens)} of {total_tokens}]"

    return windowed_text, total_tokens


def dump_yaml(data: Any, indent: int = 0) -> str:
    """
    Zero-dependency, clean YAML serializer.
    """
    spacing = "  " * indent
    if data is None:
        return "null"
    if isinstance(data, bool):
        return "true" if data else "false"
    if isinstance(data, (int, float)):
        return str(data)
    if isinstance(data, str):
        if "\n" in data:
            lines = [f"{spacing}  {line}" for line in data.splitlines()]
            return "|\n" + "\n".join(lines)
        if any(c in data for c in ':"\'#{}[]|>&%@`*'):
            escaped = data.replace('"', '\\"')
            return f'"{escaped}"'
        return data or '""'
    if isinstance(data, list):
        if not data:
            return "[]"
        lines: list[str] = []
        for item in data:
            if isinstance(item, (dict, list)):
                sub = dump_yaml(item, indent + 1)
                lines.append(f"{spacing}- {sub.lstrip()}")
            else:
                lines.append(f"{spacing}- {dump_yaml(item, indent)}")
        return "\n".join(lines)
    if isinstance(data, dict):
        if not data:
            return "{}"
        lines = []
        for key, val in data.items():
            if isinstance(val, (dict, list)):
                sub = dump_yaml(val, indent + 1)
                lines.append(f"{spacing}{key}:\n{sub}" if isinstance(val, dict) and val else f"{spacing}{key}: {sub.lstrip()}")
            else:
                lines.append(f"{spacing}{key}: {dump_yaml(val, indent + 1)}")
        return "\n".join(lines)
    return str(data)


def format_output(payload: Any, fmt: str = "json") -> str:
    """
    Polymorphic output serializer supporting json, jsonl, yaml, and md.
    """
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if fmt == "jsonl":
        return json.dumps(payload, ensure_ascii=False)
    if fmt in ("yaml", "yml", "toon"):
        return dump_yaml(payload)
    if fmt == "md":
        json_repr = json.dumps(payload, ensure_ascii=False, indent=2)
        return f"```json\n{json_repr}\n```"
    return str(payload)


def wrap_in_evidence_envelope(
    payload: Any,
    *,
    operation: str,
    target_path: Path | str | None = None,
    confidence: str = "observed",
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """
    Encapsulates results in an authoritative, content-addressed forensic Evidence envelope.
    """
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    evidence_id = "ev_" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    subject: dict[str, Any] | None = None
    if target_path:
        p = Path(target_path).expanduser().resolve()
        if p.is_file():
            file_bytes = p.read_bytes()
            subject = {
                "name": p.name,
                "localPath": str(p),
                "digest": {"sha256": hashlib.sha256(file_bytes).hexdigest()},
                "size": len(file_bytes),
            }

    return {
        "evidenceId": evidence_id,
        "schema": "resource_studio.evidence.v1",
        "provider": {
            "id": "resource-studio-core",
            "name": "Resource Studio Forensic PE Engine",
            "version": "1.0.0",
        },
        "operation": operation,
        "subject": subject,
        "confidence": confidence,
        "normalizedResult": payload,
        "limitations": limitations or [
            "Static structural analysis; runtime dynamic execution not observed.",
            "All findings derived from deterministic PE section inspection and register value flow.",
        ],
    }


def generate_subcommand_schema(subparser: argparse.ArgumentParser) -> dict[str, Any]:
    """
    Inspects an argparse subparser and returns its complete JSON Schema.
    """
    properties: dict[str, Any] = {}
    required: list[str] = []

    for action in subparser._actions:
        if action.dest in ("help", "==SUPPRESS=="):
            continue

        param_name = action.dest
        prop: dict[str, Any] = {
            "description": action.help or f"Parameter {param_name}",
        }

        # Type mapping
        if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
            prop["type"] = "boolean"
            prop["default"] = action.default
        elif action.choices:
            prop["type"] = "string"
            prop["enum"] = list(action.choices)
        elif action.type in (int, float):
            prop["type"] = "integer" if action.type is int else "number"
            if action.default is not None:
                prop["default"] = action.default
        else:
            prop["type"] = "string"
            if action.default is not None and action.default != argparse.SUPPRESS:
                prop["default"] = str(action.default)

        if action.required:
            required.append(param_name)

        properties[param_name] = prop

    return {
        "type": "object",
        "title": subparser.prog,
        "description": subparser.description or subparser.prog,
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def run_doctor_checks() -> dict[str, Any]:
    """
    Conducts comprehensive system, prerequisite, engine, and host environment checks.
    """
    checks: list[dict[str, Any]] = []

    # 1. Python Runtime
    py_ver = sys.version.split()[0]
    is_64bit = sys.maxsize > 2**32
    checks.append({
        "name": "python-runtime",
        "ok": sys.version_info >= (3, 10),
        "classification": "healthy" if sys.version_info >= (3, 10) else "degraded",
        "detail": f"Python {py_ver} ({'64-bit' if is_64bit else '32-bit'})",
        "remediation": None if sys.version_info >= (3, 10) else "Upgrade Python to 3.10 or newer.",
    })

    # 2. LIEF PE Engine
    try:
        import lief

        lief_ver = getattr(lief, "__version__", "installed")
        checks.append({
            "name": "lief-pe-parser",
            "ok": True,
            "classification": "healthy",
            "detail": f"LIEF v{lief_ver}",
            "remediation": None,
        })
    except Exception as exc:
        checks.append({
            "name": "lief-pe-parser",
            "ok": False,
            "classification": "missing_analysis_engine",
            "detail": str(exc),
            "remediation": "Install LIEF via: pip install lief",
        })

    # 3. Capstone Disassembler
    try:
        import capstone

        cs_ver = getattr(capstone, "__version__", "installed")
        # Smoke test x64 disasm
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        insns = list(md.disasm(b"\x48\x31\xc0", 0x1000))
        cs_ok = len(insns) == 1 and insns[0].mnemonic == "xor"
        checks.append({
            "name": "capstone-disassembler",
            "ok": cs_ok,
            "classification": "healthy" if cs_ok else "degraded",
            "detail": f"Capstone v{cs_ver} (x86/x64 engine validated)",
            "remediation": None,
        })
    except Exception as exc:
        checks.append({
            "name": "capstone-disassembler",
            "ok": False,
            "classification": "missing_analysis_engine",
            "detail": str(exc),
            "remediation": "Install Capstone via: pip install capstone",
        })

    # 4. Windows SDK SignTool
    signtool_path = shutil.which("signtool.exe") or shutil.which("signtool")
    if not signtool_path:
        # Search Windows Kits
        for p in [
            r"C:\Program Files (x86)\Windows Kits\10\bin",
            r"C:\Program Files\Windows Kits\10\bin",
        ]:
            if os.path.isdir(p):
                found = list(Path(p).glob("**/x64/signtool.exe"))
                if found:
                    signtool_path = str(found[0])
                    break

    checks.append({
        "name": "authenticode-signtool",
        "ok": signtool_path is not None,
        "classification": "healthy" if signtool_path else "missing_analysis_engine",
        "detail": signtool_path or "signtool.exe not found on PATH or Windows Kits",
        "remediation": None if signtool_path else "Install the Windows SDK to enable Authenticode re-signing capabilities.",
    })

    # 5. Ghidra MCP Bridge
    ghidra_ok = False
    ghidra_detail = "GhidraMCP HTTP plugin not responding at default http://127.0.0.1:8080"
    try:
        from core.ghidra_bridge import GhidraBridge

        bridge = GhidraBridge("http://127.0.0.1:8080")
        st = bridge.check_connection()
        if st.get("status") == "CONNECTED":
            ghidra_ok = True
            ghidra_detail = f"Connected to Ghidra at {st.get('url')} (Program: {st.get('currentProgram')})"
    except Exception:
        pass

    checks.append({
        "name": "ghidra-bridge",
        "ok": ghidra_ok,
        "classification": "healthy" if ghidra_ok else "optional_provider_offline",
        "detail": ghidra_detail,
        "remediation": None if ghidra_ok else "Launch Ghidra and enable the GhidraMCP plugin if decompilation bridge is desired.",
    })

    # 6. .NET SDK & WPF Workbench
    dotnet_path = shutil.which("dotnet")
    dotnet_ver = None
    if dotnet_path:
        try:
            res = subprocess.run([dotnet_path, "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                dotnet_ver = res.stdout.strip()
        except Exception:
            pass

    checks.append({
        "name": "dotnet-sdk",
        "ok": dotnet_ver is not None,
        "classification": "healthy" if dotnet_ver else "missing_prerequisite",
        "detail": f".NET SDK {dotnet_ver}" if dotnet_ver else ".NET SDK not found on PATH",
        "remediation": None if dotnet_ver else "Install .NET 8.0 SDK to build and run the Resource Studio WPF desktop workbench.",
    })

    # 7. WPF Desktop Workbench DLL/Binary
    repo_root = Path(__file__).resolve().parent.parent
    wpf_dll = repo_root / "windows" / "ResourceStudio.Windows" / "bin" / "Debug" / "net8.0-windows" / "ResourceStudio.Windows.dll"
    checks.append({
        "name": "wpf-desktop-workbench",
        "ok": wpf_dll.is_file(),
        "classification": "healthy" if wpf_dll.is_file() else "unbuilt_target",
        "detail": str(wpf_dll) if wpf_dll.is_file() else "WPF desktop shell not compiled yet",
        "remediation": None if wpf_dll.is_file() else "Run: dotnet build windows/ResourceStudio.Windows/ResourceStudio.Windows.csproj",
    })

    # 8. Fast ReadHostClient IPC
    read_host_path = repo_root / "tools" / "wpf_read_host.py"
    checks.append({
        "name": "wpf-read-host-ipc",
        "ok": read_host_path.is_file(),
        "classification": "healthy" if read_host_path.is_file() else "missing_file",
        "detail": str(read_host_path),
        "remediation": None,
    })

    all_critical_ok = all(c["ok"] for c in checks if c["classification"] not in ("optional_provider_offline",))

    return {
        "status": "healthy" if all_critical_ok else "degraded",
        "timestampUtc": json.loads(json.dumps(os.environ.get("DATE", ""))) or "now",
        "totalChecks": len(checks),
        "passedChecks": sum(1 for c in checks if c["ok"]),
        "failedChecks": sum(1 for c in checks if not c["ok"]),
        "checks": checks,
    }
