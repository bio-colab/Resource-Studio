"""Long-lived read host for the WPF shell.

The protocol is intentionally small: one JSON request per line on stdin and one
JSON response per line on stdout. Diagnostics never use stdout. The host keeps a
read-only ResourceReader session for list/search requests and delegates all
other commands to the existing CLI dispatcher in-process.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import traceback
from pathlib import Path
from typing import Any

import resource_studio_cli as cli
from core.resource_reader import ResourceReader


class ReadSession:
    def __init__(self) -> None:
        self._path: Path | None = None
        self._signature: tuple[int, int] | None = None
        self._reader: ResourceReader | None = None

    def reader_for(self, path: Path) -> ResourceReader:
        resolved = path.expanduser().resolve()
        stat = resolved.stat()
        signature = (stat.st_size, stat.st_mtime_ns)
        if self._reader is None or self._path != resolved or self._signature != signature:
            self._reader = ResourceReader(resolved)
            self._path = resolved
            self._signature = signature
        return self._reader

    def list_json(self, path: Path) -> str:
        reader = self.reader_for(path)
        payload = [cli._entry_record(entry) for entry in reader.entries]
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)

    def search_json(self, argv: list[str]) -> str:
        arguments = cli.parser().parse_args(argv)
        reader = self.reader_for(arguments.input)
        entries = reader.entries
        if arguments.type or arguments.language is not None:
            entries = [
                entry
                for entry in entries
                if (not arguments.type or entry.resource_type == arguments.type)
                and (arguments.language is None or entry.language == arguments.language)
            ]
        hits = cli.search_resources(
            entries,
            arguments.query,
            regex=arguments.regex,
            case_sensitive=arguments.case_sensitive,
            hex_query=arguments.hex,
        )
        payload = [hit.to_dict() for hit in hits]
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)

    def handle(self, argv: list[str]) -> tuple[int, str]:
        if not argv:
            return 2, "missing command"
        if argv[0] == "list" and len(argv) >= 3 and "--json" in argv:
            return 0, self.list_json(Path(argv[1]))
        if argv[0] == "search" and len(argv) >= 4 and "--json" in argv:
            return 0, self.search_json(argv)
        return self._dispatch_cli(argv)

    @staticmethod
    def _dispatch_cli(argv: list[str]) -> tuple[int, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = int(cli.main(argv))
        except SystemExit as exc:
            code = int(exc.code) if isinstance(exc.code, int) else 2
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            code = 2
            stderr.write(f"error: {exc}")
        except Exception:
            code = 2
            stderr.write(traceback.format_exc())
        output = stdout.getvalue() if stdout.getvalue().strip() else stderr.getvalue()
        return code, output


def write_response(request_id: Any, code: int, output: str, *, stopped: bool = False) -> None:
    response = {
        "id": request_id,
        "ok": code == 0 and not stopped,
        "exitCode": code,
        "output": output,
        "stopped": stopped,
    }
    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    session = ReadSession()
    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        request_id: Any = None
        try:
            request = json.loads(raw_line)
            request_id = request.get("id")
            argv = request.get("argv")
            if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
                raise ValueError("argv must be a list of strings")
            code, output = session.handle(argv)
            write_response(request_id, code, output)
        except Exception as exc:
            write_response(request_id, 2, f"error: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
