from __future__ import annotations

import tempfile
from pathlib import Path

from core.durable_commit import commit_temporary


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "new.tmp"
        target = root / "output.bin"
        source.write_bytes(b"new-content")
        target.write_bytes(b"old-content")
        result = commit_temporary(source, target)
        assert target.read_bytes() == b"new-content"
        assert not source.exists()
        assert result.flushed
        assert result.same_volume
        assert result.method in {"os.replace", "ReplaceFileW", "MoveFileExW"}
    print("durable-commit-tests: passed")


if __name__ == "__main__":
    main()
