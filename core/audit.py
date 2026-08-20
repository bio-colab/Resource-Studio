from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class AuditLog:
    FORMAT = "resource_studio.audit.v1"

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve()

    def append(self, operation: str, **details: Any) -> dict[str, Any]:
        event = {
            "format": self.FORMAT,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "details": details,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return event

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events

    def latest(self) -> dict[str, Any] | None:
        events = self.read()
        return events[-1] if events else None
