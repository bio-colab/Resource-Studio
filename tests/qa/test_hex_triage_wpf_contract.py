from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
XAML = ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml"
CS = ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml.cs"


def main() -> None:
    xaml = XAML.read_text(encoding="utf-8")
    code = CS.read_text(encoding="utf-8")
    for marker in ("PreviewFieldsGrid", "PreviewHexBox", "TriageBanner", "ResourceGrid_LoadingRow"):
        assert marker in xaml, marker
    for marker in ("ApplyHexTemplate", "PreviewFieldsGrid_SelectionChanged", "ApplyTriage", "ResourceTriageKey", "visual cue only"):
        assert marker in code, marker
    print("hex-triage-wpf-contract-tests: passed")


if __name__ == "__main__":
    main()
