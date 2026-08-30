from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class StagedArtifact:
    path: str
    sha256: str
    size: int
    source_name: str
    mode: str = "READ_ONLY_COPY"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "sourceName": self.source_name,
            "mode": self.mode,
        }


def stage_readonly_copy(source: Path, root: Path) -> StagedArtifact:
    """Copy bytes into an isolated directory without executing or replacing an existing artifact."""

    source = Path(source).expanduser().resolve()
    root = Path(root).expanduser().resolve()
    if not source.is_file():
        raise ValueError(f"source is not a regular file: {source}")
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        raise ValueError(f"staging root is not a directory: {root}")
    destination = root / f"{digest[:16]}-{source.name}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError:
        existing = destination.read_bytes()
        if hashlib.sha256(existing).hexdigest() != digest:
            raise ValueError(f"staging collision has a different hash: {destination}")
    else:
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                destination.unlink()
            except OSError:
                # Best-effort staging cleanup; the original error is re-raised.
                pass
            raise
    try:
        destination.chmod(stat.S_IRUSR | stat.S_IRGRP)
    except OSError:
        # Best-effort permissions on filesystems where chmod is unsupported.
        pass
    return StagedArtifact(str(destination), digest, len(data), source.name)


__all__ = ["StagedArtifact", "stage_readonly_copy"]
