# About Resource Studio

```text
  ██████╗ ███████╗███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗    ███████╗████████╗██╗   ██╗██████╗ ██╗ ██████╗ 
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝    ██╔════╝╚══██╔══╝██║   ██║██╔══██╗██║██╔═══██╗
  ██████╔╝█████╗  ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗      ███████╗   ██║   ██║   ██║██║  ██║██║██║   ██║
  ██╔══██╗██╔══╝  ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝      ╚════██║   ██║   ██║   ██║██║  ██║██║██║   ██║
  ██║  ██║███████╗███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗    ███████║   ██║   ╚██████╔╝██████╔╝██║╚██████╔╝
  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝ ╚═════╝ 
```

**Resource Studio** is a next-generation, provably safe, and high-performance Win32 PE Resource Workbench for Windows, reverse engineering, and automated CI/CD pipelines.

---

## 📌 Repository Metadata & Positioning

| Metadata Field | Value |
| :--- | :--- |
| **Project Name** | Resource Studio |
| **Version** | `2.0.0` |
| **Short Tagline** | Next-generation, provably safe Win32 PE Resource Workbench for Windows & CI/CD. The high-performance modern replacement for Resource Hacker. |
| **Primary Architecture** | Hybrid (Python 3.12 Engine + .NET 8 WPF Shell) |
| **Safety Invariant** | Non-destructive `Save As only` with 9-stage verification pipeline |
| **License** | Apache License 2.0 |
| **Author & Maintainer** | Elias Sharar ([aliasbio95@gmail.com](mailto:aliasbio95@gmail.com)) |
| **Repository URL** | [https://github.com/bio-colab/Resource-Studio](https://github.com/bio-colab/Resource-Studio) |
| **GitHub Topics** | `pe`, `reverse-engineering`, `resource-hacker`, `wpf`, `windows`, `lief`, `dialog-editor`, `authenticode`, `dotnet8`, `python3`, `binary-forensics`, `csharp`, `win32`, `resource-editor`, `ci-cd`, `recipe-automation` |

---

## 🎯 The Philosophy Behind Resource Studio

For decades, reverse engineers, software translators, and system administrators relied on legacy Win32 utilities such as **Resource Hacker**, **PE Explorer**, and **CFF Explorer**. While pioneering in their era, these tools carry grave limitations in modern security-critical and automated environments:

1. **Destructive In-Place Writing:** Legacy tools overwrite existing binaries directly, frequently invalidating PE checksums, breaking alignment boundaries, and corrupting Authenticode digital signatures.
2. **Zero Verification:** No validation occurs between writing resources and committing them to disk. A single byte mismatch results in an unbootable executable.
3. **No CI/CD Automation:** Legacy tools are tied to interactive GUI clicks, offering no headless declarative workflows or recipe-based patch automation.
4. **Outdated Ergonomics:** Clunky Windows 95/XP interfaces, poor high-DPI scaling, and zero accessibility/contrast design rules.

**Resource Studio solves every single one of these problems from the ground up.**

---

## 🛡️ The 9-Stage Verification Pipeline

Resource Studio treats modifying a PE binary not as a blind write, but as a formal mutation transaction governed by a strict 9-phase contract:

```mermaid
flowchart LR
    P1["1. PLAN"] --> P2["2. MUTATE"]
    P2 --> P3["3. SERIALIZE"]
    P3 --> P4["4. REOPEN"]
    P4 --> P5["5. VALIDATE"]
    P5 --> P6["6. DIFF"]
    P6 --> P7["7. PRESERVE"]
    P7 --> P8["8. ORACLE"]
    P8 --> P9["9. COMMIT"]
```

1. **PLAN:** Verifies the mutation contract and resource coordinates.
2. **MUTATE:** Applies in-memory changes via LIEF.
3. **SERIALIZE:** Writes to an isolated temporary sandbox candidate.
4. **REOPEN:** Re-reads the candidate independently from raw disk bytes.
5. **VALIDATE:** Verifies PE headers, section geometry, alignments, and resource boundaries.
6. **DIFF:** Compares semantic fingerprints before and after the change.
7. **PRESERVE:** Validates that non-resource sections (code, exports, imports, TLS, load config, debug) remain bit-for-bit identical.
8. **ORACLE:** Uses Windows Win32 APIs (`LoadLibraryExW` / `EnumResourceNamesW`) to verify that the Windows kernel accepts the file.
9. **COMMIT:** Performs an atomic file replacement (`ReplaceFileW`) to the target destination. **The original input file is never touched.**

---

## ⚡ What Makes Resource Studio Unique?

* **WYSIWYG Dialog Editor with Intelligence:** Includes automatic text clipping/overflow detection, pseudo-localization testing, and RTL mirror preview for Arabic/Hebrew.
* **Developer Micro-Generators:** Right-click any resource to copy it directly as a C/C++ array, C# 12 `ReadOnlySpan<byte>`, Base64 string, SHA-256 hash, or generate a complete Win32 `resource.h`.
* **CI/CD Recipe Engine:** Compare two PE files and export an automation recipe (`recipe.json`), then apply that recipe across any target executable in CI/CD without writing code.
* **WCAG AAA Contrast System:** Custom dark and light themes with guaranteed 15:1 contrast ratios and responsive command bars.
