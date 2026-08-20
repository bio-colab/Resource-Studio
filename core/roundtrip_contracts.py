from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable


ParseFn = Callable[[bytes], Any]
SerializeFn = Callable[[Any], bytes]
NormalizeFn = Callable[[Any], Any]


@dataclass(frozen=True)
class RoundTripResult:
    contract: str
    kind: str
    input_sha256: str
    output_sha256: str
    byte_equal: bool
    semantic_equal: bool
    canonical_stable: bool
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "kind": self.kind,
            "inputSha256": self.input_sha256,
            "outputSha256": self.output_sha256,
            "byteEqual": self.byte_equal,
            "semanticEqual": self.semantic_equal,
            "canonicalStable": self.canonical_stable,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class RoundTripContract:
    name: str
    kind: str
    parse: ParseFn
    serialize: SerializeFn
    normalize: NormalizeFn

    def evaluate(self, data: bytes) -> RoundTripResult:
        original = bytes(data)
        model = self.parse(original)
        encoded = bytes(self.serialize(model))
        reparsed = self.parse(encoded)
        semantic_equal = self.normalize(model) == self.normalize(reparsed)
        canonical_stable = encoded == bytes(self.serialize(reparsed))
        byte_equal = original == encoded
        passed = semantic_equal and (self.kind != "byte" or byte_equal) and (self.kind != "canonical" or canonical_stable)
        return RoundTripResult(
            contract=self.name,
            kind=self.kind,
            input_sha256=hashlib.sha256(original).hexdigest(),
            output_sha256=hashlib.sha256(encoded).hexdigest(),
            byte_equal=byte_equal,
            semantic_equal=semantic_equal,
            canonical_stable=canonical_stable,
            passed=passed,
        )


class RoundTripContractRegistry:
    def __init__(self) -> None:
        self._contracts: dict[str, RoundTripContract] = {}

    def register(self, contract: RoundTripContract) -> None:
        if not contract.name.strip():
            raise ValueError("round-trip contract name cannot be empty")
        if contract.kind not in {"byte", "semantic", "canonical"}:
            raise ValueError("round-trip contract kind must be byte, semantic, or canonical")
        if contract.name in self._contracts:
            raise ValueError(f"round-trip contract already registered: {contract.name}")
        self._contracts[contract.name] = contract

    def get(self, name: str) -> RoundTripContract:
        try:
            return self._contracts[name]
        except KeyError as exc:
            raise KeyError(f"unknown round-trip contract: {name}") from exc

    def evaluate(self, name: str, data: bytes) -> RoundTripResult:
        return self.get(name).evaluate(data)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._contracts))


def default_registry() -> RoundTripContractRegistry:
    from .manifest import ManifestDocument
    from .menu_resources import MenuResource
    from .version_info import VersionInfo

    registry = RoundTripContractRegistry()
    registry.register(RoundTripContract("raw.bytes", "byte", lambda data: bytes(data), lambda value: bytes(value), lambda value: bytes(value)))
    registry.register(
        RoundTripContract(
            "manifest.xml",
            "canonical",
            lambda data: ManifestDocument.parse(data.decode("utf-8-sig")),
            lambda value: value.to_xml().encode("utf-8"),
            lambda value: value.to_xml(),
        )
    )
    registry.register(
        RoundTripContract(
            "menu.binary",
            "semantic",
            MenuResource.parse,
            lambda value: value.to_bytes(),
            lambda value: value.to_dict(),
        )
    )
    registry.register(
        RoundTripContract(
            "version-info.binary",
            "semantic",
            VersionInfo.from_bytes,
            lambda value: value.to_bytes(),
            lambda value: {
                "fileVersion": value.file_version,
                "productVersion": value.product_version,
                "strings": dict(sorted(value.strings.items())),
                "translations": tuple(value.translations),
            },
        )
    )
    return registry
