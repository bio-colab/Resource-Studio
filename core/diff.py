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
    typed: bool = False,
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
            children = None
            if typed:
                children = _typed_diff_nodes(old, new)
            if children is None:
                children = tuple(_hex_nodes(old.data, new.data, max_hex_ranges))
            else:
                children = tuple(children)
            nodes.append(
                DiffNode(
                    label,
                    "resource",
                    "modified",
                    before=_record(old),
                    after=_record(new),
                    children=children,
                )
            )
    return DiffNode("resources", "tree", "modified" if any(node.status != "unchanged" for node in nodes) else "unchanged", children=tuple(nodes))


def _typed_diff_nodes(old: ResourceEntry, new: ResourceEntry) -> list[DiffNode] | None:
    rtype = old.resource_type.upper()
    try:
        if rtype == "MANIFEST":
            old_text = old.data.decode("utf-8-sig", errors="replace")
            new_text = new.data.decode("utf-8-sig", errors="replace")
            old_lines = old_text.splitlines()
            new_lines = new_text.splitlines()
            diff_lines = list(difflib.unified_diff(old_lines, new_lines, fromfile="before.manifest", tofile="after.manifest", lineterm=""))
            if diff_lines:
                return [DiffNode("manifest:unified-diff", "unified-diff", "modified", before={"text": "\n".join(old_lines[:500])}, after={"text": "\n".join(new_lines[:500]), "unified": "\n".join(diff_lines[:500])})]
        elif rtype in {"VERSION", "VERSIONINFO"}:
            from .version_info import VersionInfo

            old_v = VersionInfo.from_bytes(old.data)
            new_v = VersionInfo.from_bytes(new.data)
            nodes: list[DiffNode] = []
            if old_v.file_version != new_v.file_version:
                nodes.append(DiffNode("fileVersion", "property", "modified", before={"value": old_v.file_version}, after={"value": new_v.file_version}))
            if old_v.product_version != new_v.product_version:
                nodes.append(DiffNode("productVersion", "property", "modified", before={"value": old_v.product_version}, after={"value": new_v.product_version}))
            all_keys = sorted(set(old_v.strings) | set(new_v.strings))
            for k in all_keys:
                ov = old_v.strings.get(k)
                nv = new_v.strings.get(k)
                if ov != nv:
                    st = "added" if ov is None else ("removed" if nv is None else "modified")
                    nodes.append(DiffNode(f"string:{k}", "string", st, before={"value": ov} if ov is not None else None, after={"value": nv} if nv is not None else None))
            return nodes or None
        elif rtype == "STRING":
            from .string_table import StringTableBlock

            name_int = int(old.name) if str(old.name).isdigit() else 1
            old_b = StringTableBlock.from_bytes(name_int, old.data)
            new_b = StringTableBlock.from_bytes(name_int, new.data)
            nodes = []
            for i in range(16):
                sid = old_b.first_string_id + i
                os_ = old_b.strings[i] if i < len(old_b.strings) else ""
                ns_ = new_b.strings[i] if i < len(new_b.strings) else ""
                if os_ != ns_:
                    st = "added" if not os_ else ("removed" if not ns_ else "modified")
                    nodes.append(DiffNode(f"string:{sid}", "string-entry", st, before={"id": sid, "text": os_}, after={"id": sid, "text": ns_}))
            return nodes or None
        elif rtype == "DIALOG":
            from .dialog_resources import DialogResource

            old_d = DialogResource.parse(old.data)
            new_d = DialogResource.parse(new.data)
            nodes = []
            if old_d.title != new_d.title:
                nodes.append(DiffNode("title", "property", "modified", before={"value": old_d.title}, after={"value": new_d.title}))
            if (old_d.x, old_d.y, old_d.width, old_d.height) != (new_d.x, new_d.y, new_d.width, new_d.height):
                nodes.append(DiffNode("geometry", "property", "modified", before={"rect": [old_d.x, old_d.y, old_d.width, old_d.height]}, after={"rect": [new_d.x, new_d.y, new_d.width, new_d.height]}))
            old_ctls = {c.control_id: c for c in old_d.controls}
            new_ctls = {c.control_id: c for c in new_d.controls}
            for cid in sorted(set(old_ctls) | set(new_ctls)):
                oc = old_ctls.get(cid)
                nc = new_ctls.get(cid)
                if oc is None:
                    nodes.append(DiffNode(f"control:{cid}", "control", "added", after=nc.to_dict()))
                elif nc is None:
                    nodes.append(DiffNode(f"control:{cid}", "control", "removed", before=oc.to_dict()))
                elif oc.to_dict() != nc.to_dict():
                    nodes.append(DiffNode(f"control:{cid}", "control", "modified", before=oc.to_dict(), after=nc.to_dict()))
            return nodes or None
        elif rtype == "MENU":
            from .menu_resources import MenuResource

            old_m = MenuResource.parse(old.data)
            new_m = MenuResource.parse(new.data)

            def flatten_menu(items: list[Any], prefix: str = "") -> dict[str | int, dict[str, Any]]:
                flat: dict[str | int, dict[str, Any]] = {}
                for it in items:
                    path = f"{prefix}/{it.text}" if prefix else it.text
                    key = it.item_id if (it.item_id != 0 or not it.children) else f"item_{path}"
                    flat[key] = {"id": it.item_id, "text": it.text, "flags": it.flags, "path": path}
                    if it.children:
                        flat.update(flatten_menu(it.children, path))
                return flat

            old_items = flatten_menu(old_m.items)
            new_items = flatten_menu(new_m.items)
            nodes = []
            for k in sorted(set(old_items) | set(new_items), key=str):
                oi = old_items.get(k)
                ni = new_items.get(k)
                if oi is None:
                    nodes.append(DiffNode(f"menuitem:{k}", "menu-item", "added", after=ni))
                elif ni is None:
                    nodes.append(DiffNode(f"menuitem:{k}", "menu-item", "removed", before=oi))
                elif oi != ni:
                    nodes.append(DiffNode(f"menuitem:{k}", "menu-item", "modified", before=oi, after=ni))
            return nodes or None
        elif rtype in {"BITMAP", "GROUP_ICON", "GROUP_CURSOR"}:
            kind = "bitmap" if rtype == "BITMAP" else ("icon" if "ICON" in rtype else "cursor")
            b_meta = _image_record(old.data, kind)
            n_meta = _image_record(new.data, kind)
            return [DiffNode(f"image:{kind}", "image-meta", "modified", before=b_meta, after=n_meta)]
    except Exception:
        return None
    return None


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
