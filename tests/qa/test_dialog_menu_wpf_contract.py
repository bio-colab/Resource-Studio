from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_menu_wpf_exposes_typed_editor_contract() -> None:
    xaml = (ROOT / "windows" / "ResourceStudio.Windows" / "ResourceWizardsWindow.xaml").read_text(encoding="utf-8")
    code = (ROOT / "windows" / "ResourceStudio.Windows" / "ResourceWizardsWindow.xaml.cs").read_text(encoding="utf-8")
    for token in ("MenuItemIdBox", "MenuItemFlagsBox", "MenuAddChild_Click", "MenuDelete_Click", "MenuValidate_Click"):
        assert token in xaml or token in code
    assert "menu-resource" in code


def test_dialog_wpf_exposes_control_properties_and_standard_types() -> None:
    xaml = (ROOT / "windows" / "ResourceStudio.Windows" / "DialogEditorWindow.xaml").read_text(encoding="utf-8")
    code = (ROOT / "windows" / "ResourceStudio.Windows" / "DialogEditorWindow.xaml.cs").read_text(encoding="utf-8")
    for token in ("ControlClassBox", "ControlStyleBox", "ControlExstyleBox", "AddEdit_Click", "AddList_Click", "AddCombo_Click", "DuplicateControl_Click"):
        assert token in xaml or token in code


if __name__ == "__main__":
    test_menu_wpf_exposes_typed_editor_contract()
    test_dialog_wpf_exposes_control_properties_and_standard_types()
    print("dialog-menu-wpf-contract-tests: passed")
