from __future__ import annotations

from core.localization import LocalizationCatalog, LocalizedString


def main() -> None:
    catalog = LocalizationCatalog(
        [
            LocalizedString("greeting", "en-US", "Hello %s"),
            LocalizedString("same", "en-US", "Same"),
            LocalizedString("greeting", "ar-SA", "مرحبًا %s"),
            LocalizedString("same", "ar-SA", "Same"),
            LocalizedString("extra", "ar-SA", "إضافي"),
            LocalizedString("bad", "en-US", "Value %d"),
            LocalizedString("bad", "ar-SA", "القيمة {0}"),
        ]
    )
    comparison = catalog.compare("en-US", "ar-SA")
    assert comparison["missing"] == []
    assert comparison["extra"] == ["extra"]
    assert comparison["untranslated"] == ["same"]
    assert catalog.validate_placeholders("en-US", "ar-SA") == [
        {"key": "bad", "source": ("%d",), "target": ("{0}",)}
    ]
    restored = LocalizationCatalog.from_json(catalog.to_json())
    assert restored.get("ar-SA", "greeting").text == "مرحبًا %s"
    csv_restored = LocalizationCatalog.from_csv(catalog.to_csv())
    assert csv_restored.get("ar-SA", "greeting").text == "مرحبًا %s"
    report = catalog.mode_report("en-US", "ar-SA")
    assert report["comparison"] == comparison
    pseudo = catalog.pseudo_localize("en-US")
    assert pseudo.get("qps-ploc", "greeting").text == "［Hélló %s］"
    assert pseudo.get("qps-ploc", "bad").placeholders() == ("%d",)
    print("localization-tests: passed")


if __name__ == "__main__":
    main()
