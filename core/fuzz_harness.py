from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class FuzzOutcome:
    parser: str
    input_sha256: str
    input_size: int
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "parser": self.parser,
            "inputSha256": self.input_sha256,
            "inputSize": self.input_size,
            "status": self.status,
            "detail": self.detail,
        }


Parser = Callable[[bytes], Any]


def run_parser_cases(
    parser_name: str,
    parser: Parser,
    cases: Iterable[bytes],
    *,
    max_input_size: int = 2 * 1024 * 1024,
) -> tuple[FuzzOutcome, ...]:
    outcomes: list[FuzzOutcome] = []
    for raw in cases:
        data = bytes(raw)
        digest = hashlib.sha256(data).hexdigest()
        if len(data) > max_input_size:
            outcomes.append(FuzzOutcome(parser_name, digest, len(data), "oversize", f"input exceeds {max_input_size} bytes"))
            continue
        try:
            parser(data)
        except (ValueError, TypeError, UnicodeError, EOFError, struct.error) as exc:
            outcomes.append(FuzzOutcome(parser_name, digest, len(data), "expected-rejected", type(exc).__name__))
        except MemoryError as exc:
            outcomes.append(FuzzOutcome(parser_name, digest, len(data), "excessive-allocation", type(exc).__name__))
        except Exception as exc:
            outcomes.append(FuzzOutcome(parser_name, digest, len(data), "crash", f"{type(exc).__name__}: {exc}"))
        else:
            outcomes.append(FuzzOutcome(parser_name, digest, len(data), "accepted"))
    return tuple(outcomes)


def assert_no_unexpected_failures(outcomes: Iterable[FuzzOutcome]) -> None:
    failures = [item for item in outcomes if item.status in {"crash", "excessive-allocation"}]
    if failures:
        raise AssertionError([item.to_dict() for item in failures])


def structure_aware_cases(seed: bytes, *, max_cases: int = 16, max_size: int = 2 * 1024 * 1024) -> tuple[bytes, ...]:
    """Create bounded mutations at PE structural offsets, not random bytes only."""

    original = bytes(seed[:max_size])
    cases: list[bytes] = [original]
    if len(original) >= 64:
        offsets = [0, 1, 2, 0x3C]
        pe_offset = int.from_bytes(original[0x3C:0x40], "little") if len(original) >= 0x40 else -1
        if 0 <= pe_offset < len(original) - 24:
            offsets.extend([pe_offset, pe_offset + 4, pe_offset + 20])
            optional = pe_offset + 24
            offsets.extend([optional, optional + 2, optional + 64])
            magic = int.from_bytes(original[optional:optional + 2], "little")
            data_directory = optional + (112 if magic == 0x20B else 96)
            offsets.extend([data_directory + 2 * 8, data_directory + 2 * 8 + 4])
        for offset in offsets:
            if 0 <= offset < len(original) and len(cases) < max_cases:
                mutated = bytearray(original)
                mutated[offset] ^= 0xFF
                cases.append(bytes(mutated))
        for length in (1, 2, 0x40, max(0, len(original) // 2)):
            if len(cases) >= max_cases:
                break
            cases.append(original[:length])
        if len(cases) < max_cases:
            cases.append(original + b"\x00" * min(64, max_size - len(original)))
    return tuple(cases[:max_cases])


def run_structure_aware_cases(
    runner_name: str,
    runner: Parser,
    seed: bytes,
    *,
    max_cases: int = 16,
    max_input_size: int = 2 * 1024 * 1024,
) -> tuple[FuzzOutcome, ...]:
    return run_parser_cases(
        runner_name,
        runner,
        structure_aware_cases(seed, max_cases=max_cases, max_size=max_input_size),
        max_input_size=max_input_size,
    )

