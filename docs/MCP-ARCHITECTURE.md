# Resource Studio — MCP Architecture & AI Integration Guide
## The Dual-MCP Autonomous Reverse Engineering Paradigm

Resource Studio provides a native **Model Context Protocol (MCP)** server built on FastMCP, enabling Large Language Models (LLMs) like Claude, GPT-4, and specialized agents (in Claude Desktop, Cursor, Antigravity, and autonomous security pipelines) to inspect, validate, disassemble cross-references, and safely mutate Windows PE resources.

---

## 1. The Dual-MCP Architecture

```text
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                              THE DUAL-MCP AGENT PARADIGM                               │
 │                                                                                        │
 │         AI Agent (Claude / Cursor / Antigravity / Autonomous Security LLM)             │
 │                                    │                                                   │
 │                 ┌──────────────────┴──────────────────┐                                │
 │                 ▼                                     ▼                                │
 │     [GhidraMCP: The Code Brain]          [ResourceStudioMCP: The Resource Scalpel]     │
 │     • Decompile functions                • Parse PE Resource Directory (.rsrc)         │
 │     • Trace XRefs & Call Graphs          • DLU text clipping & RTL mirror preview      │
 │     • Map DialogProc & WM_COMMAND        • Safe 9-stage verification contract          │
 │     • Identify resource loader calls     • CI/CD declarative recipes (apply/export)    │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

While **Ghidra / GhidraMCP** focuses on code decompilation, control flow analysis, and function renaming, **Resource Studio** operates as the authoritative, provably safe resource analysis and mutation engine with immutable **Save-As** guarantees.

---

## 2. Server Transports & Running

### stdio (Standard for Local AI Clients)
```bash
python resource_studio_cli.py mcp --transport stdio
```

### SSE / HTTP (For Networked Agents & Services)
```bash
python resource_studio_cli.py mcp --transport sse --host 127.0.0.1 --port 8000
```

### Connecting to Claude Desktop
Add this to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "resource-studio": {
      "command": "python",
      "args": [
        "c:/path/to/Resource-Studio/resource_studio_cli.py",
        "mcp",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

---

## 3. Exposed MCP Tools Catalog

| Tool Name | Parameters | Purpose |
| :--- | :--- | :--- |
| `list_pe_resources` | `file_path` | Enumerate all resources (type, name, language, size, sha256) in PE. |
| `inspect_pe` | `file_path` | Deep PE header inspection: architecture, sections, imports, exports, PDB. |
| `validate_pe` | `file_path`, `strict` | Verify PE integrity, checksums, section alignments, overlay detection. |
| `extract_resource` | `file_path`, `resource_type`, `resource_name`, `language`, `output_path` | Extract raw resource payload, write to file and/or return Base64. |
| `diff_pe_resources` | `left_path`, `right_path`, `typed` | Compare resources between two PE binaries and report structured diffs. |
| `analyze_dialog` | `file_path`, `dialog_name`, `language` | Parse Win32 Dialog template, compute DLU sizes, and detect text clipping risks. |
| `scan_resource_xrefs` | `file_path` | Native PE opcode & import scan to map resource IDs and flag dead/orphaned resources. |
| `correlate_dialog_behavior` | `file_path`, `dialog_name`, `decompiled_code`, `language` | Correlate dialog controls with decompiled DialogProc `WM_COMMAND` logic. |
| `export_recipe` | `original_path`, `edited_path`, `output_dir` | Generate verified, reproducible CI/CD recipe package from PE diff. |
| `apply_recipe` | `target_path`, `recipe_path`, `output_path` | Apply declarative automation recipe with 9-stage verification contract. |
| `generate_developer_code` | `file_path`, `resource_type`, `resource_name`, `language`, `code_kind` | Export resource as C array, C# ReadOnlySpan, Base64, SHA-256, or resource.h. |
| `inspect_security` | `file_path` | Inspect Authenticode digital signature, certificate details, and PDB leak. |

---

## 4. MCP Prompts

1. **`triage_pe_resources(file_path)`**: Guides an AI assistant to systematically audit an unknown PE binary, checking resources, dead orphans, dialog clipping, and security posture.
2. **`plan_resource_patch(original_pe, goal_description)`**: Guides an AI assistant through a provably safe resource editing workflow, concluding with recipe export for CI/CD automation.

---

## 5. Native Code-to-Resource XRef Engine

Legacy resource editors (such as Resource Hacker) only see what is inside `.rsrc`. They are completely blind to whether code in `.text` actually references the resource.

Resource Studio introduces a native, lightweight XRef engine powered by **Capstone Disassembler**:
* Disassembles executable sections (`.text`, `CODE`).
* Inspects immediate operands matching resource IDs (`mov edx, ID`, `push ID`, `mov r8d, ID`).
* Scans `.rdata` and data sections for string names.
* Classifies each resource as:
  * **`REFERENCED`**: Confirmed call site in executable code.
  * **`DEAD_ORPHAN`**: Unreferenced resource wasting binary space (safe to prune).
  * **`CONCEALED_SUSPICIOUS`**: Large raw binary (`RCDATA`) with no standard resource loader calls (indicator of packed or injected payloads).
