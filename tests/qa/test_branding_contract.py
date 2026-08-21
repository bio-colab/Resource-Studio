from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    app = (ROOT / "windows" / "ResourceStudio.Windows" / "App.xaml").read_text(encoding="utf-8")
    window = (ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml").read_text(encoding="utf-8")
    project = (ROOT / "windows" / "ResourceStudio.Windows" / "ResourceStudio.Windows.csproj").read_text(encoding="utf-8")
    assert "SignalCyanColor" in app and "DeepSlateColor" in app and "TriageAmberColor" in app
    assert 'Icon="Assets/resource-studio.ico"' in window
    assert "resource-studio-icon-32.png" in window and "PE Resource Workbench" in window
    assert "ApplicationIcon" in project and "resource-studio.ico" in project
    for filename in ("resource-studio-mark.png", "resource-studio-mark-256.png", "resource-studio-icon-16.png", "resource-studio-icon-32.png", "resource-studio-icon-64.png", "resource-studio.ico", "resource-studio-github-banner.png"):
        assert (ROOT / "assets" / "branding" / filename).is_file(), filename
    print("branding-contract-tests: passed")


if __name__ == "__main__":
    main()
