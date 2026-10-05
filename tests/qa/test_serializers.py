from __future__ import annotations

from core.localization import LocalizationCatalog, LocalizedString
from core.manifest import ManifestDocument
from core.version_info import VersionInfo


MANIFEST = "<assembly xmlns='urn:schemas-microsoft-com:asm.v1'><assemblyIdentity name='Serializer' version='1.0.0.0'/></assembly>"


def main() -> None:
    document = ManifestDocument.parse(MANIFEST)
    assert ManifestDocument.parse(document.to_xml()).validate()["valid"] is True

    version = VersionInfo(file_version="1.2.3.4", product_version="2.3.4.5")
    version.set_string("FileDescription", "Serializer")
    version.set_translation(1033)
    restored_version = VersionInfo.from_json(version.to_json())
    assert restored_version.validate()["valid"] is True
    assert restored_version.strings["FileDescription"] == "Serializer"

    catalog = LocalizationCatalog([LocalizedString("hello", "en-US", "Hello %s")])
    restored_catalog = LocalizationCatalog.from_json(catalog.to_json())
    assert restored_catalog.get("en-US", "hello").text == "Hello %s"
    restored_csv = LocalizationCatalog.from_csv(catalog.to_csv())
    assert restored_csv.get("en-US", "hello").placeholders() == ("%s",)
    print("serializer-tests: passed")


if __name__ == "__main__":
    main()
