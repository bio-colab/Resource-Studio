# Low-Level Research Findings

## Microsoft PE Format

Source: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

The Microsoft specification defines PE/COFF as a structured image format with DOS stub, PE signature, COFF header, optional header, section headers, data directories, and special sections such as resources, TLS, relocations, debug, and load configuration. It distinguishes file pointers from RVAs and notes that section raw data is loaded contiguously. The resource table and attribute certificate table are separate PE structures; a Writer therefore needs to validate both on-disk offsets and loaded-image relationships rather than only checking that LIEF can reopen the output.

The specification explicitly documents that the Attribute Certificate Table is an image-only data directory and that certificates associate verifiable statements with an image. This supports a strict invariant policy that treats security-directory placement, section layout, RVAs, raw offsets, alignment, and overlay as first-class post-write checks.

## Microsoft PE Signatures

Source: https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures

Windows PE Authenticode signing does not hash every byte as a flat-file digest. The PE signature calculation excludes selected PE fields, including the checksum and Certificate Table directory, while the certificate table stores the embedded signature. The source also explains that signed PE files can contain catalog signatures or embedded signatures and warns that unvalidated PKCS#7 padding can create trust risks; `EnableCertPaddingCheck` exists to validate padding in certain cases.

Implications for Resource Studio: a generic SHA-256 before/after comparison is not a signature verdict; signature state must be modeled separately. A signed input should be blocked or routed through an explicit strip/re-sign path, and post-write diagnostics should report certificate-table state, signature status, checksum state, and whether the output is unsigned, invalidly signed, or validly re-signed.

## Checksum and Windows Replacement

Source: https://learn.microsoft.com/en-us/windows/win32/api/imagehlp/nf-imagehlp-checksummappedfile

Microsoft documents `CheckSumMappedFile` as the API used by applications that create or modify executable images. It computes a new checksum and returns the original checksum; the caller is responsible for placing the computed checksum into the mapped image and updating the on-disk image. Microsoft notes that valid checksums are required for kernel-mode drivers and some system DLLs. The API is single-threaded and calls must be synchronized.

Implications for Resource Studio: checksum validity should be an explicit post-write invariant and Windows verification should be available as a compatibility oracle, especially for `.sys` and system-DLL corpus members. LIEF's computed checksum and the Windows ImageHlp result should be compared rather than treating one parser's value as sufficient.

Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilea

`ReplaceFile` replaces one file with another, makes the replacement assume the replaced file's name and identity, and can create a backup. Microsoft states that the backup, replaced file, and replacement file must reside on the same volume.

Implications for Resource Studio: the Windows commit adapter should prefer same-volume `ReplaceFile` semantics after writing and validating a temporary file, while preserving the current Save-As contract. Cross-volume output should be treated as a copy/export path, not as an atomic replacement claim. A crash-consistency test should distinguish logical rollback from durable replacement guarantees.

## Coverage-guided Fuzzing and Round-trip Properties

Source: https://llvm.org/docs/LibFuzzer.html

LLVM describes libFuzzer as an in-process, coverage-guided evolutionary fuzzer. A fuzz target accepts arbitrary bytes and must tolerate empty, huge, and malformed input; the engine executes it repeatedly in the same process and mutates a corpus based on coverage. The current LLVM page also points toward structure-aware fuzzing and corpus management.

Implications for Resource Studio: the existing bounded fuzz tests should evolve into parser-specific harnesses for Manifest, VersionInfo, StringTable, Menu, Dialog, RES, DIB/ICON/CURSOR, and resource-tree decoding. The harness should classify expected parse rejection separately from crashes, hangs, excessive allocation, and non-canonical serialization. A small checked-in seed corpus plus a generated artifact corpus is more valuable than broad random bytes alone.

Source: https://www.cis.upenn.edu/~plclub/blog/2023-12-07-round-trip-properties/

The Penn PLClub article defines round-trip properties as applying a printer/serializer and then parsing the result, checking that the resulting structure matches the original. It stresses that round-trip properties need preconditions: generators must produce values within the parser's accepted language, and unparsable generated values must be separated from actual failures.

Implications for Resource Studio: each serializer needs an explicit contract: lossless byte round-trip, semantic round-trip, or canonical round-trip. Tests should not require byte identity where a serializer intentionally canonicalizes padding or ordering; instead they should compare a normalized semantic model plus selected preservation fields. This distinction is crucial for PE resources, where alignment and padding may change while resource meaning remains stable.

## Process Containment and LIEF Boundaries

Source: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects

Microsoft describes Job Objects as groups of processes managed as a unit. Processes can be associated with a job, limits can be applied to all associated processes, and a job can manage a process tree. The documented model includes resource accounting, CPU and memory limits, notifications, and process-tree termination; the `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` behavior is especially relevant to preventing orphaned plugin or CLI descendants.

Implications for Resource Studio: the existing Job Object should be verified as a containment contract, not merely as a handle wrapper. Tests should prove child and grandchild termination, memory/CPU/time ceilings, no escape through secondary process creation, and deterministic cleanup after parent crash or handle close. These are hardening of the existing PluginHost/Windows isolation path, not new user-facing features.

Source: https://lief.re/doc/latest/formats/pe/modifications/resources.html

LIEF exposes PE resource modification both through the low-level resource tree (`ResourceNode.add_child/delete_child`) and through `ResourcesManager`; its documentation also shows transferring a complete resource tree between binaries with `Binary.set_resources()`. LIEF's examples demonstrate that resource nodes carry type/name/language/data relationships and that the resource tree can be printed with offsets and lengths.

Implications for Resource Studio: the project should treat LIEF as a builder/parser backend, not the sole correctness oracle. The current `_find_nodes` and tree mutation operations need independent checks for type/name/language identity, offsets, data lengths, ordering, duplicate leaves, and resource-section bounds after every write. A future transfer/merge capability would be safer only after these existing tree contracts are exhaustively tested; it is not recommended as part of the present stabilization cycle.

## Windows Loader and Native Resource Oracle

Source: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa

Microsoft documents `LOAD_LIBRARY_AS_DATAFILE`, `LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE`, and `LOAD_LIBRARY_AS_IMAGE_RESOURCE` as non-executable mappings usable by resource APIs. With image-resource mapping, PE section alignment is expanded so RVAs can be used directly and the module is prevented from being modified by other processes while loaded. `FindResource` and related functions can use these mappings without loading the module as an executable DLL.

Implications for Resource Studio: Windows-only compatibility tests should load each output as a data/image resource, enumerate type/name/language, call `FindResourceEx`, `SizeofResource`, `LoadResource`, and compare bytes and sizes with the LIEF/Python index. This creates a real Windows loader oracle without executing the target PE and is a high-value strengthening of existing resource coverage.

Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-updateresourcew

`UpdateResourceW` adds, deletes, or replaces raw resource data after a `BeginUpdateResource` handle is obtained; changes accumulate until `EndUpdateResource` writes them. Microsoft specifies that predefined resource data must be valid and properly aligned, and that text data must be Unicode. The API also has restrictions for language-neutral (LN) and MUI files, including constraints on adding, changing, deleting, and adding new languages.

Implications for Resource Studio: the project should add a Windows-only differential oracle test, not replace LIEF with UpdateResource. For selected safe corpus members, apply the same no-op or controlled mutation through both paths, then compare the resulting resource tree and semantic bytes. MUI/LN files should be explicitly classified and either covered by dedicated rules or rejected with a precise diagnostic rather than treated as ordinary PE files.

## Current Architecture Mapping

The current Writer already enforces Save As, refuses in-place writes, blocks signed inputs, writes through a temporary file, validates that LIEF can reopen the output, compares protected PE invariants, and verifies the targeted resource after reopening. The stability pass added rollback preservation for an existing output when validation fails.

The current invariant snapshot protects machine, image base, entry point, non-resource section descriptors, non-resource data directories, imports, exports, overlay, TLS, load configuration, and debug records. It does not yet independently validate the resource tree against the Windows loader, compare Windows checksum results, model certificate-directory semantics in the invariant report, or prove crash durability after the final name replacement.

`PEHealth` checks that resource offsets and sizes exposed by LIEF remain within the file, reports signature presence, and exposes a resource index. It does not yet perform a second parser/loader walk. `WindowsJob` applies active-process, process-memory, and kill-on-job-close limits, but does not yet expose CPU/time limits, notification accounting, or a regression test that proves descendants cannot survive the host.

The WPF shell invokes the Python CLI and now reads stdout and stderr concurrently. Its UI automation proves a stable open/search/theme/Image Wizard/BMP-preview path. The next low-level strengthening is not another panel: it is treating the CLI process boundary, Windows resource loader, checksum API, and file replacement semantics as testable contracts.

## Durable Commit Is Stronger Than Atomic Naming

Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers

Microsoft describes `FlushFileBuffers` as flushing buffered information for a file and causing it to be written to the device. The documentation distinguishes this from simply issuing writes and notes that write-through or unbuffered I/O may be relevant when persistent-media guarantees are required.

Implications for Resource Studio: the existing temporary-file plus replacement protocol should be split into explicit stages: build, validate, flush temporary contents, commit the name, and report the durability level. The product should not claim crash-proof persistence merely because `os.replace` succeeded. A Windows adapter can use `FlushFileBuffers` before `ReplaceFile`; tests can simulate failures around each stage and verify either old or new complete PE, never a partial file.
