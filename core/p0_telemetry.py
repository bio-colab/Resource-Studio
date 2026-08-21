from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path as _Path
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


_LOCK = threading.Lock()
_STATE: threading.local = threading.local()


class P0Telemetry:
    """Opt-in P0 measurement; disabled unless RESOURCE_STUDIO_P0_TELEMETRY_PATH is set."""

    def __init__(self, operation: str, **metadata: Any) -> None:
        self.operation = operation
        self.metadata = metadata
        self.started = time.perf_counter()
        self.counters: dict[str, int] = {
            "liefParse": 0,
            "fullFileReads": 0,
            "temporaryDirectories": 0,
            "temporaryFiles": 0,
            "subprocesses": 0,
        }
        self.values: dict[str, Any] = {}

    def increment(self, counter: str, amount: int = 1) -> None:
        self.counters[counter] = self.counters.get(counter, 0) + amount

    def set(self, key: str, value: Any) -> None:
        self.values[key] = value

    def finish(self, *, status: str = "completed", error: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": "resource_studio.p0_telemetry.v1",
            "operation": self.operation,
            "status": status,
            "elapsedMs": round((time.perf_counter() - self.started) * 1000, 3),
            "counters": dict(self.counters),
            "values": dict(self.values),
            "metadata": dict(self.metadata),
            "pythonPid": os.getpid(),
        }
        if error is not None:
            payload["error"] = error
        path = os.environ.get("RESOURCE_STUDIO_P0_TELEMETRY_PATH")
        if path:
            destination = Path(path).expanduser().resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            with _LOCK:
                with destination.open("a", encoding="utf-8") as stream:
                    stream.write(line)
                    stream.flush()
        return payload


@contextmanager
def measure(operation: str, **metadata: Any) -> Iterator[P0Telemetry]:
    telemetry = P0Telemetry(operation, **metadata)
    previous = getattr(_STATE, "current", None)
    _STATE.current = telemetry
    patches: list[tuple[Any, str, Any]] = []
    enabled = bool(os.environ.get("RESOURCE_STUDIO_P0_TELEMETRY_PATH"))
    if enabled:
        try:
            import lief

            original_parse = lief.parse

            def counted_parse(*args: Any, **kwargs: Any) -> Any:
                telemetry.increment("liefParse")
                return original_parse(*args, **kwargs)

            lief.parse = counted_parse
            patches.append((lief, "parse", original_parse))
        except (ImportError, AttributeError):
            pass

        original_read_bytes = _Path.read_bytes

        def counted_read_bytes(path: _Path) -> bytes:
            telemetry.increment("fullFileReads")
            return original_read_bytes(path)

        _Path.read_bytes = counted_read_bytes
        patches.append((_Path, "read_bytes", original_read_bytes))

        original_temporary_directory = tempfile.TemporaryDirectory

        def counted_temporary_directory(*args: Any, **kwargs: Any) -> Any:
            telemetry.increment("temporaryDirectories")
            return original_temporary_directory(*args, **kwargs)

        tempfile.TemporaryDirectory = counted_temporary_directory
        patches.append((tempfile, "TemporaryDirectory", original_temporary_directory))

        original_named_temporary_file = tempfile.NamedTemporaryFile

        def counted_named_temporary_file(*args: Any, **kwargs: Any) -> Any:
            telemetry.increment("temporaryFiles")
            return original_named_temporary_file(*args, **kwargs)

        tempfile.NamedTemporaryFile = counted_named_temporary_file
        patches.append((tempfile, "NamedTemporaryFile", original_named_temporary_file))
    try:
        yield telemetry
    except Exception as exc:
        telemetry.finish(status="error", error=f"{type(exc).__name__}: {exc}")
        raise
    else:
        telemetry.finish()
    finally:
        for owner, name, original in reversed(patches):
            setattr(owner, name, original)
        _STATE.current = previous


def current() -> P0Telemetry | None:
    return getattr(_STATE, "current", None)


def count(counter: str, amount: int = 1) -> None:
    active = current()
    if active is not None:
        active.increment(counter, amount)


__all__ = ["P0Telemetry", "count", "current", "measure"]
