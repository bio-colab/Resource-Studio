from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WINDOWS = ROOT / "windows" / "ResourceStudio.Windows"


def main() -> None:
    names = (
        "ImageResourceWindow.xaml",
        "DialogEditorWindow.xaml",
        "ResourceWizardsWindow.xaml",
        "SignatureToolsWindow.xaml",
        "StringTableEditorWindow.xaml",
    )
    for name in names:
        text = (WINDOWS / name).read_text(encoding="utf-8")
        assert 'Background="{DynamicResource DeepSlateBrush}"' in text, name
        assert 'Foreground="{DynamicResource PaperBrush}"' in text, name
    app = (WINDOWS / "App.xaml").read_text(encoding="utf-8")
    for marker in ('TargetType="ComboBox"', 'TargetType="ComboBoxItem"', 'TargetType="ListBox"', 'TargetType="ListBoxItem"', 'TargetType="PasswordBox"'):
        assert marker in app, marker
    assert 'Background="White"' in (WINDOWS / "DialogEditorWindow.xaml").read_text(encoding="utf-8")
    print("subwindow-theme-contract-tests: passed")


if __name__ == "__main__":
    main()
