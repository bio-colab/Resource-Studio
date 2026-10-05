"""Thread-local, bounded LIEF parse cache for READ-ONLY inspection flows.

Within a single command, several independent organs (health, integrity,
metadata, compatibility, signature inspection, verification context,
invariants snapshot, deep invariants, static analysis, resource reader)
each parsed the same file from scratch — measured at 8 full parses for
one ``inspect`` command and 11 for one edit (Task 9 metabolic census).
Sharing one parsed Binary per (path, size, mtime_ns) removes that
redundant digestion without changing any read-only semantics.

Rules of engagement:

- READ-ONLY consumers only. Anything that mutates the Binary (resource
  surgery, certificate stripping, header edits) MUST keep its private
  ``lief.parse`` — sharing a mutated Binary across organs would corrupt
  every other view. ``LiefPEWriter._parse`` and ``_strip_to_path`` are
  deliberately left private.
- The cache calls ``lief.parse`` dynamically at call time, so the P0
  telemetry hook (``counted_parse``) keeps counting shared hits... it
  does not: shared hits skip a fresh parse by design. The telemetry
  field counts real parses, and sharing is exactly the point.
- Thread-local storage: no Binary crosses a thread boundary, so server
  threading models are safe by construction.
- Bounded: at most 4 entries and 256 MiB of source bytes per thread
  (FIFO eviction), so long-lived server threads cannot balloon.
- Missing/unreadable files return None (mirroring lief.parse's own
  behavior for unreadable paths) instead of raising.
"""
from __future__ import annotations

import threading
from pathlib import Path

_MAX_ENTRIES = 4
_MAX_TOTAL_BYTES = 256 * 1024 * 1024

_local = threading.local()


def shared_parse(path: Path):
    path = Path(path).expanduser().resolve()
    try:
        stat = path.stat()
    except OSError:
        return None
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    cache = getattr(_local, "entries", None)
    if cache is None:
        cache = _local.entries = {}
    hit = cache.get(key)
    if hit is not None:
        return hit
    import lief

    binary = lief.parse(str(path))
    if binary is None:
        return None
    total = getattr(_local, "total_bytes", 0)
    while cache and (len(cache) >= _MAX_ENTRIES or total + stat.st_size > _MAX_TOTAL_BYTES):
        oldest_key, _ = next(iter(cache.items()))
        cache.pop(oldest_key)
        total -= oldest_key[1]
    _local.total_bytes = total + stat.st_size
    cache[key] = binary
    return binary
