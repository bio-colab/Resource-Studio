from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class PureLoaderSelection:
    status: str
    requested_language: int | None
    selected_language: int | None
    candidates: tuple[int, ...]
    resource: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "requestedLanguage": self.requested_language,
            "selectedLanguage": self.selected_language,
            "candidates": list(self.candidates),
            "resource": dict(self.resource) if self.resource is not None else None,
        }


def select_language(requested_language: int | None, available: Iterable[int]) -> int | None:
    languages = sorted({int(language) for language in available})
    if not languages:
        return None
    if requested_language is not None and int(requested_language) in languages:
        return int(requested_language)
    if requested_language not in (None, 0):
        primary = int(requested_language) & 0x03FF
        primary_matches = [language for language in languages if language != 0 and (language & 0x03FF) == primary]
        if primary_matches:
            return min(primary_matches, key=lambda language: (language >> 10 != 0, language))
    if 0 in languages:
        return 0
    return languages[0]


def select_resource(
    leaves: Iterable[Mapping[str, Any]],
    resource_type: str | int,
    resource_name: str | int,
    requested_language: int | None,
) -> PureLoaderSelection:
    target_type = str(resource_type)
    target_name = str(resource_name)
    matches = [
        dict(leaf)
        for leaf in leaves
        if str(leaf.get("type")) == target_type and str(leaf.get("name")) == target_name
    ]
    candidates = tuple(sorted({int(leaf.get("language", 0)) for leaf in matches}))
    selected = select_language(requested_language, candidates)
    resource = next((leaf for leaf in matches if int(leaf.get("language", 0)) == selected), None)
    return PureLoaderSelection(
        status="FOUND" if resource is not None else "NOT_FOUND",
        requested_language=requested_language,
        selected_language=selected,
        candidates=candidates,
        resource=resource,
    )


def select_from_graph(
    graph: Mapping[str, Any],
    resource_type: str | int,
    resource_name: str | int,
    requested_language: int | None,
) -> PureLoaderSelection:
    leaves = graph.get("leaves", [])
    if not isinstance(leaves, list):
        raise ValueError("resource graph leaves must be a list")
    return select_resource(leaves, resource_type, resource_name, requested_language)
