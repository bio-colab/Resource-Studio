from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
XAML = (ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml").read_text(encoding="utf-8")
CS = (ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml.cs").read_text(encoding="utf-8")
ABOUT = (ROOT / "windows" / "ResourceStudio.Windows" / "AboutWindow.xaml").read_text(encoding="utf-8")
ABOUT_CS = (ROOT / "windows" / "ResourceStudio.Windows" / "AboutWindow.xaml.cs").read_text(encoding="utf-8")


def test_about_is_part_of_main_shell() -> None:
    assert 'AutomationProperties.AutomationId="AboutButton"' in XAML
    assert 'Click="About_Click"' in XAML
    assert "new AboutWindow { Owner = this }.ShowDialog()" in CS


def test_about_identity_and_repository_are_present() -> None:
    assert 'Title="About Resource Studio"' in ABOUT
    assert "Resource Studio is a verification-first workbench" in ABOUT
    assert "Elias Sharar" in ABOUT
    assert "aliasbio95@gmail.com" in ABOUT
    assert "https://github.com/bio-colab/Resource-Studio" in ABOUT
    assert "RepositoryHyperlink_RequestNavigate" in ABOUT_CS


def test_about_uses_shared_theme_resources() -> None:
    for resource in ("DeepSlateBrush", "SlatePanelBrush", "SlateElevatedBrush", "PaperBrush", "MistBrush", "SignalCyanBrush", "DividerBrush"):
        assert f"{{DynamicResource {resource}}}" in ABOUT


if __name__ == "__main__":
    test_about_is_part_of_main_shell()
    test_about_identity_and_repository_are_present()
    test_about_uses_shared_theme_resources()
    print("about-wpf-contract-tests: passed")
