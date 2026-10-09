# Resource Studio v2.0.0 — Next-Gen AI-Empowered PE Resource Workbench

We are thrilled to announce the official release of **Resource Studio v2.0.0**, the modern, provably safe replacement for legacy Win32 resource editors like **Resource Hacker**. This release introduces a breakthrough integration with the **Model Context Protocol (FastMCP)** and a **Native PE Code-to-Resource Cross-Reference Engine**, bringing autonomous AI capabilities and deep static analysis directly to Windows reverse engineering.

---

## 🌟 Key Highlights & Superpowers

### 🧠 1. Native FastMCP AI Server (Dual-MCP Paradigm)
- Built-in **Model Context Protocol** server powered by FastMCP (`stdio` for Claude Desktop / Cursor, and `sse` for remote services).
- **12 Dedicated Tools:** Resource listing, PE geometry inspection, validation, raw extraction, semantic diffing, DLU dialog clipping detection, opcode cross-referencing, behavioral DialogProc correlation, developer code generation, Authenticode forensics, and recipe application.
- **AI Prompts:** Pre-configured guidance prompts (`triage_pe_resources` and `plan_resource_patch`) for autonomous LLM agents.

### 🔍 2. Native Code-to-Resource XRef Engine
- Powered by the **Capstone Disassembler** directly in Python 3.12 without heavy external dependencies.
- Analyzes executable sections (`.text`, `CODE`) and import tables (`IMAGE_DIRECTORY_ENTRY_IMPORT`) for Win32 resource APIs (`FindResourceW`, `DialogBoxParamW`, `LoadStringW`, etc.).
- **Dead Resource Detection:** Automatically identifies unreferenced resources (`DEAD_ORPHAN`) to safely prune binary bloat.
- **Suspicious Payload Detection:** Flags large concealed `RCDATA` payloads without standard Win32 loader calls.

### 🧩 3. GhidraMCP Bridge & Behavioral DialogProc Correlation
- Connects seamlessly to a local `GhidraMCP` HTTP bridge.
- Analyzes decompiled `DialogProc` C pseudocode to correlate Win32 Dialog control IDs (`IDOK`, `IDCANCEL`, custom buttons) with `WM_COMMAND` branching handlers.

### 📐 4. WYSIWYG Dialog Editor & DLU Clipping Detector
- Precise Win32 dialog layout calculations based on Dialog Base Units (DLUs).
- Visual warning indicators and real-time dimension recommendations for clipped or truncated strings.
- **Pseudo-Localization:** 30% text expansion simulation (`［...］`) to stress-test translations before release.
- **RTL Mirroring:** Native preview for right-to-left scripts (Arabic & Hebrew).

### 🛡️ 5. Provably Safe "Save-As Only" Guarantee
- **Zero In-Place Overwrites:** Inputs are strictly treated as immutable.
- **9-Stage Verification Contract:** `PLAN → MUTATE → SERIALIZE → REOPEN → VALIDATE → DIFF → PRESERVE → WINDOWS → COMMIT`.
- Independent Win32 Kernel Oracle validation (`LoadLibraryExW` / `EnumResourceNamesW`).

### ⚡ 6. Developer Micro-Generators & CI/CD Recipes
- Right-click export to: **C/C++ byte array**, **C# 12 `ReadOnlySpan<byte>`**, **Base64**, **SHA-256**, and **Win32 `resource.h`**.
- Declarative CI/CD automation pipeline (`recipe export` and `recipe apply`).

---

## 🎨 UI/UX & WCAG AAA Compliance
- **Modern Responsive CommandBar:** Clean grouped actions (`WORKSPACE`, `EDITORS`, `TOOLS`) with persistent theme toggling.
- **Ultra-High Contrast:** Strict adherence to WCAG AAA contrast ratios (>15:1) ensuring readable text across all dark and light themes.

---

## 📦 Binary Packages & Verification

| Package | Architecture | SHA-256 Checksum |
| :--- | :---: | :--- |
| **`ResourceStudio-v2.0-Windows-x64-Release.zip`** | Windows x64 | `79C8C87E3A3B5D799E8D5AFCB29F896AFC517117CB25BCCDE7D364B86832CFF2` |
| **`ResourceStudio-v2.0-Windows-x64-Debug.zip`** | Windows x64 | `2E717DBEE1ED779EC2A416A711605E866C806332E722B4F0F796B73D10BFB235` |

### Quick Start:
1. Download and extract `ResourceStudio-v2.0-Windows-x64-Release.zip`.
2. Launch `ResourceStudio.Windows.exe`.
3. Open any PE binary (`.exe`, `.dll`, `.sys`, `.mui`) to begin analyzing!
