from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class ManifestDocument:
    root: ET.Element

    @classmethod
    def parse(cls, text: str) -> ManifestDocument:
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ValueError(f"invalid manifest XML: {exc}") from exc
        if _local_name(root.tag) != "assembly":
            raise ValueError("manifest root must be assembly")
        return cls(root)

    def validate(self) -> dict[str, list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        identities = [node for node in self.root.iter() if _local_name(node.tag) == "assemblyIdentity"]
        if not identities:
            errors.append("manifest has no assemblyIdentity")
        for node in self.root.iter():
            if _local_name(node.tag) == "requestedExecutionLevel":
                level = node.attrib.get("level")
                if level not in {"asInvoker", "highestAvailable", "requireAdministrator"}:
                    errors.append("requestedExecutionLevel.level is invalid")
                if node.attrib.get("uiAccess") == "true":
                    warnings.append("uiAccess=true requires a trusted installation location")
        return {"errors": errors, "warnings": warnings, "valid": not errors}

    def set_execution_level(self, level: str, *, ui_access: bool = False) -> None:
        if level not in {"asInvoker", "highestAvailable", "requireAdministrator"}:
            raise ValueError("unsupported execution level")
        node = next(
            (node for node in self.root.iter() if _local_name(node.tag) == "requestedExecutionLevel"),
            None,
        )
        if node is None:
            node = ET.SubElement(self.root, "requestedExecutionLevel")
        node.attrib["level"] = level
        node.attrib["uiAccess"] = "true" if ui_access else "false"

    def to_xml(self) -> str:
        ET.indent(self.root, space="  ")
        return ET.tostring(self.root, encoding="unicode", short_empty_elements=True) + "\n"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
