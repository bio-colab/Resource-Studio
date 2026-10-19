# Resource Studio v2.1.0 — REA-Calibrated Forensics & AI-Grade Workbench

We are proud to release **Resource Studio v2.1.0**, featuring empirical calibration against **REA** (`reverse-engineer-anything`), high-fidelity byte-for-byte binary conformance, new forensic analysis engines, and a complete architectural overhaul of our CLI and WPF workbench.

---

## 🌟 What's New in v2.1.0

### 🔬 1. Empirical REA Distillation & 100% Byte-for-Byte Fidelity
- **Win32 StringTable Conformance:** Calibrated StringTable block formulas `(bundle_id - 1) * 16 + i`, clean noise-filtering, and automatic detection of MUI/LN architectures.
- **Dialog & Menu Exact Serialization:** Full compliance with `DLGITEMTEMPLATEEX` packing order, DWORD control IDs, and DLU pixel metrics, achieving 100% roundtrip fidelity.
- **Authoritative Raw Resource Fallback:** Independent PE directory traversal engine ensuring non-standard or malformed resource trees are preserved without corruption.

### 🛡️ 2. Advanced Forensic Analysis Engines
- **Register Value-Flow Tracing (`trace-values`):** Disassembles machine code with Capstone to track data flow across general-purpose registers (`EAX`, `EDX`, `ECX`) down to Win32 resource loading APIs.
- **Managed (.NET) Stream Inspector (`managed`):** Extracts CLR headers, metadata directory streams (`#~`, `#Strings`, `#Blob`, `#GUID`), and assembly tables.
- **Compiler Toolchain Auditor (`toolchain`):** Identifies compiler signatures (MSVC, MinGW, Clang, Rust, Go) and detects tampering in COFF timestamps and Rich Headers.
- **Investigation Pipeline & Replay (`investigate` / `replay-investigation`):** Captures end-to-end forensic telemetry in reproducible JSONL journals.

### 💻 3. REA-Grade Agentic CLI Architecture
- **In-Process Output Filtering (`--filter-output`):** Query nested paths and array indices (e.g. `--filter-output identity.machine`) directly without external utilities like `jq`.
- **Token Budgeting & Windowing (`--token-count`, `--token-limit`, `--token-offset`):** Prevents LLM context overflow with precise token counting and clean truncation footers (`[truncated: showing tokens 0-30 of 256]`).
- **Polymorphic Output (`--format yaml|json|toon|md`):** Zero-dependency pure YAML serializer.
- **Self-Documenting Schemas & LLM Manifests (`--schema`, `--llms`, `--llms-full`):** Instant JSON Schema generation for subcommands and automated tool catalogs for autonomous AI agents.
- **Cryptographic Evidence Envelopes (`--envelope`):** Wraps results in content-addressed envelopes with SHA-256 digests (`evidenceId: ev_<sha256>`).
- **Diagnostic Health Check (`resource-studio doctor` / `doctor --json`):** Evaluates 8 engines and toolchains (Python, LIEF, Capstone, SignTool, .NET SDK, WPF DLL, IPC, Ghidra) with actionable remediation guidance.

### 🖥️ 4. WPF Workbench Enhancements
- **Forensic Investigation Tab:** Interactive investigation dashboard with real-time progress bars and structured log output.
- **Register Value-Flow & Disassembly Panel:** Direct visibility into disassembled instruction streams and operand constants.
- **Toolchain & Anomaly Auditor:** Visual indicators for compiler profiles and header anomalies.
- **Managed Stream Explorer:** Instant browsing of .NET metadata heaps.

---

## 📦 Binary Packages & Checksums

| Package | Platform | SHA-256 Checksum |
| :--- | :---: | :--- |
| **`ResourceStudio-v2.1-Windows-x64-Release.zip`** | Windows x64 | `88D30B0D4F20503F6D8F2E3F62B24EEB04A76C354B7B2553ACA75F4198781FCF` |
| **`ResourceStudio-v2.1-Windows-x64-Debug.zip`** | Windows x64 | `0B11527905B77035CE7D0F3DD98B1C76624C3393BAA9E8980029974ADB643CC0` |

### How to Run:
1. Extract `dist/ResourceStudio-v2.1-Windows-x64-Release.zip`.
2. Double-click `ResourceStudio.Windows.exe` to launch the interactive WPF workbench.
3. Or run the CLI directly: `python resource_studio_cli.py doctor`.
