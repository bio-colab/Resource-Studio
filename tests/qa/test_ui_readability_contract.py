from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
XAML = (ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml").read_text(encoding="utf-8")
APP = (ROOT / "windows" / "ResourceStudio.Windows" / "App.xaml").read_text(encoding="utf-8")
CODE = (ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml.cs").read_text(encoding="utf-8")


def main() -> None:
    for marker in ("ResourceEmptyState", "PropertyEmptyState", "StopCliButton", "SignalCyanBrush", "MistBrush"):
        assert marker in XAML, marker
    for marker in ("SlateInputColor", "DividerColor", "TargetType=\"TabItem\"", "TargetType=\"DataGrid\"", "DataGridColumnHeader"):
        assert marker in APP, marker
    for marker in ("ApplyThemePalette", "ReadableTextBrush", "Dark mode enabled", "Application.Current.Resources"):
        assert marker in CODE, marker
    assert "SystemColors.GrayTextBrushKey" not in XAML
    assert "TextBlock Text=\"↥\"" in XAML
    print("ui-readability-contract-tests: passed")


if __name__ == "__main__":
    main()
