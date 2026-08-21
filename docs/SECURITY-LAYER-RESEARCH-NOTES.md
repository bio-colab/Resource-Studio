# Security Layer research notes

## Confirmed boundaries

- Microsoft PE documentation defines RVA separately from file pointer and describes code sections, data directories, optional-header architecture, imports, and exception/unwind data. Static disassembly must therefore record both file offset and RVA and must not confuse them.
- Capstone is a multi-architecture disassembly framework with Python bindings. Its documented SKIPDATA mode is useful for bounded best-effort disassembly where code/data are mixed, but it remains an optional dependency rather than a reason to make the core unusable without it.
- Microsoft ETW is a structured Windows trace system with process create/exit, memory allocation, and other system events. It is appropriate for importing or processing externally captured traces, not for silently executing a PE from the static analysis path.

## Sources

1. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format — Microsoft PE Format
2. https://www.capstone-engine.org/documentation.html — Capstone documentation
3. https://learn.microsoft.com/en-us/windows/apps/trace-processing/overview — Process ETW traces in .NET

## Engineering direction

Implement the safe static layer first: entrypoint/section disassembly when an optional decoder is available, bounded CFG over decoded branch targets, and unpacking indicators based on section/entrypoint/import/overlay/entropy inconsistencies. Represent behavioral telemetry, memory analysis, and API call tracing as validated external-artifact imports with source, capture time, target SHA-256, schema, and limitations. Do not execute samples, inject code, attach debuggers, or read live process memory inside the core Security Layer.
