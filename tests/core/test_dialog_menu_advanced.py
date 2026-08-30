from __future__ import annotations

from core.dialog_resources import DS_SETFONT, DialogControl, DialogResource
from core.menu_resources import MF_CHECKED, MF_DISABLED, MF_POPUP, MF_SEPARATOR, MenuItem, MenuResource


def test_dialog_validate_reports_controls_and_font_requirements() -> None:
    dialog = DialogResource(0, 0, 160, 80, DS_SETFONT, font_size=9, font_name="Segoe UI", controls=[DialogControl(10, 4, 4, 60, 18, class_name=0x0080, title="OK")])
    report = dialog.validate()
    assert report["valid"] is True
    assert report["controlCount"] == 1
    assert dialog.controls[0].class_label == "BUTTON"
    dialog.font_name = None
    assert dialog.validate()["valid"] is False


def test_menu_advanced_operations_preserve_flags_and_validate() -> None:
    menu = MenuResource([MenuItem(1, "File", MF_POPUP, [MenuItem(2, "Open", MF_CHECKED), MenuItem(3, "", MF_SEPARATOR)])])
    assert menu.validate()["valid"] is True
    assert menu.find_id(2).is_checked is True
    menu.add_item(MenuItem(4, "Exit", MF_DISABLED), parent_id=1)
    assert menu.find_id(4).is_disabled is True
    removed = menu.remove_item(3)
    assert removed.is_separator is True
    assert menu.find_id(3) is None
    assert MenuResource.parse(menu.to_bytes()).find_id(4).item_id == 4


if __name__ == "__main__":
    test_dialog_validate_reports_controls_and_font_requirements()
    test_menu_advanced_operations_preserve_flags_and_validate()
    print("dialog-menu-advanced-tests: passed")
