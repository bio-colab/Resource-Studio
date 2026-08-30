from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .image_resources import BitmapResource, IconCursorGroup
from .project import ResourceEntry


@dataclass(frozen=True)
class DiffNode:
    key: str
    kind: str
    status: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    children: tuple[DiffNode, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"key": self.key, "kind": self.kind, "status": self.status}
        if self.before is not None:
            payload["before"] = self.before
        if self.after is not None:
            payload["after"] = self.after
        if self.children:
            payload["children"] = [child.to_dict() for child in self.children]
        return payload


def diff_resources(
    before: Iterable[ResourceEntry],
    after: Iterable[ResourceEntry],
    *,
    max_hex_ranges: int = 128,
) -> DiffNode:
    left = {entry.key: entry for entry in before}
    right = {entry.key: entry for entry in after}
    nodes: list[DiffNode] = []
    for key in sorted(set(left) | set(right)):
        old = left.get(key)
        new = right.get(key)
        label = f"{key[0]}:{key[1]}:{key[2]}"
        if old is None:
            nodes.append(DiffNode(label, "resource", "added", after=_record(new)))
        elif new is None:
            nodes.append(DiffNode(label, "resource", "removed", before=_record(old)))
        elif old.data == new.data:
            nodes.append(DiffNode(label, "resource", "unchanged", before=_record(old), after=_record(new)))
        else:
            nodes.append(
                DiffNode(
                    label,
                    "resource",
                    "modified",
                    before=_record(old),
                    after=_record(new),
                    children=tuple(_hex_nodes(old.data, new.data, max_hex_ranges)),
                )
            )
    return DiffNode("resources", "tree", "modified" if any(node.status != "unchanged" for node in nodes) else "unchanged", children=tuple(nodes))


def diff_image_payloads(
    before: bytes,
    after: bytes,
    *,
    kind: str = "bitmap",
    max_hex_ranges: int = 128,
) -> DiffNode:
    kind = kind.lower()
    before_meta = _image_record(before, kind)
    after_meta = _image_record(after, kind)
    status = "unchanged" if before == after else "modified"
    children = tuple() if status == "unchanged" else tuple(_hex_nodes(before, after, max_hex_ranges))
    return DiffNode(f"image:{kind}", "image", status, before=before_meta, after=after_meta, children=children)


def merge_selected_resources(
    base: Iterable[ResourceEntry],
    incoming: Iterable[ResourceEntry],
    selected: Iterable[tuple[str, str, int | None]],
) -> tuple[ResourceEntry, ...]:
    """Return a new resource set; neither input collection nor original PE is modified."""
    result = {entry.key: entry for entry in base}
    candidates = {entry.key: entry for entry in incoming}
    for key in selected:
        if key in candidates:
            result[key] = candidates[key]
        else:
            result.pop(key, None)
    return tuple(result[key] for key in sorted(result))


def diff_texts(before: Mapping[str, str], after: Mapping[str, str]) -> DiffNode:
    nodes: list[DiffNode] = []
    for key in sorted(set(before) | set(after)):
        old = before.get(key)
        new = after.get(key)
        if old is None:
            nodes.append(DiffNode(key, "text", "added", after={"text": new}))
        elif new is None:
            nodes.append(DiffNode(key, "text", "removed", before={"text": old}))
        elif old == new:
            nodes.append(DiffNode(key, "text", "unchanged", before={"text": old}, after={"text": new}))
        else:
            nodes.append(DiffNode(key, "text", "modified", before={"text": old}, after={"text": new}))
    return DiffNode("texts", "tree", "modified" if any(node.status != "unchanged" for node in nodes) else "unchanged", children=tuple(nodes))


def _image_record(data: bytes, kind: str) -> dict[str, Any]:
    record: dict[str, Any] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    try:
        if kind in {"bitmap", "bmp"}:
            image = BitmapResource.from_bmp(data) if data[:2] == b"BM" else BitmapResource.from_dib(data)
            record.update({"format": "bitmap", "width": image.width, "height": image.height, "bitCount": image.bit_count, "compression": image.compression})
        elif kind in {"icon", "cursor"}:
            group = IconCursorGroup.parse(data)
            record.update({"format": group.kind.lower(), "count": len(group.entries), "dimensions": list(group.dimensions())})
        else:
            record["format"] = kind
    except ValueError:
        record["format"] = kind
        record["parseWarning"] = "payload is not recognized by the typed image parser"
    return record


def _record(entry: ResourceEntry | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    return {
        "type": entry.resource_type,
        "name": entry.name,
        "language": entry.language,
        "size": len(entry.data),
        "sha256": entry.sha256,
    }


def _hex_nodes(before: bytes, after: bytes, max_ranges: int) -> list[DiffNode]:
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    nodes: list[DiffNode] = []
    for index, (tag, before_start, before_end, after_start, after_end) in enumerate(matcher.get_opcodes()):
        if tag == "equal":
            continue
        if index >= max_ranges:
            nodes.append(DiffNode("hex:truncated", "hex", "truncated"))
            break
        status = "added" if tag == "insert" else "removed" if tag == "delete" else "modified"
        nodes.append(
            DiffNode(
                f"hex:{before_start}:{after_start}",
                "hex",
                status,
                before={"offset": before_start, "hex": before[before_start:before_end].hex(" ")},
                after={"offset": after_start, "hex": after[after_start:after_end].hex(" ")},
            )
        )
    return nodes
