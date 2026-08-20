using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class ResourceWizardsWindow : Window
{
    private readonly string _cliPath;

    public ResourceWizardsWindow(string cliPath, string? selectedPe)
    {
        InitializeComponent();
        _cliPath = cliPath;
        VersionPeBox.Text = selectedPe ?? "";
        ManifestPeBox.Text = selectedPe ?? "";
        MenuPeBox.Text = selectedPe ?? "";
    }

    private void VersionExport_Click(object sender, RoutedEventArgs e)
    {
        ExportModel("version-resource", VersionPeBox.Text, VersionNameBox.Text, VersionLanguageBox.Text, value => VersionJsonBox.Text = value);
    }

    private void VersionApply_Click(object sender, RoutedEventArgs e)
    {
        ApplyModel("version-resource", VersionPeBox.Text, VersionNameBox.Text, VersionLanguageBox.Text, VersionJsonBox.Text);
    }

    private void ManifestExport_Click(object sender, RoutedEventArgs e)
    {
        var temporary = TempFile("manifest");
        try
        {
            var result = RunCli("manifest-resource", "export", ManifestPeBox.Text, "--language", ManifestLanguageBox.Text, "--output", temporary, "--json");
            if (result.ExitCode != 0) { SetStatus(result.Output); return; }
            using var document = JsonDocument.Parse(File.ReadAllText(temporary));
            ManifestXmlBox.Text = document.RootElement.GetProperty("xml").GetString() ?? "";
            SetStatus("Manifest loaded from PE.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private void ManifestApply_Click(object sender, RoutedEventArgs e)
    {
        var model = JsonSerializer.Serialize(new { format = "resource_studio.manifest.v1", xml = ManifestXmlBox.Text });
        ApplyModel("manifest-resource", ManifestPeBox.Text, "1", ManifestLanguageBox.Text, model);
    }

    private void MenuExport_Click(object sender, RoutedEventArgs e)
    {
        ExportModel("menu-resource", MenuPeBox.Text, MenuNameBox.Text, MenuLanguageBox.Text, value => MenuJsonBox.Text = value);
    }

    private void MenuApply_Click(object sender, RoutedEventArgs e)
    {
        ApplyModel("menu-resource", MenuPeBox.Text, MenuNameBox.Text, MenuLanguageBox.Text, MenuJsonBox.Text);
    }

    private void ExportModel(string command, string pe, string name, string language, Action<string> setValue)
    {
        if (!File.Exists(pe)) { SetStatus("Choose a PE file first."); return; }
        var temporary = TempFile(command);
        try
        {
            var result = RunCli(command, "export", pe, "--name", name, "--language", language, "--output", temporary, "--json");
            if (result.ExitCode != 0) { SetStatus(result.Output); return; }
            setValue(File.ReadAllText(temporary));
            SetStatus($"{command} loaded from PE.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private void ApplyModel(string command, string pe, string name, string language, string modelText)
    {
        if (!File.Exists(pe)) { SetStatus("Choose a PE file first."); return; }
        var outputDialog = new SaveFileDialog { Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*", FileName = Path.GetFileNameWithoutExtension(pe) + ".edited" + Path.GetExtension(pe) };
        if (outputDialog.ShowDialog() != true) return;
        var temporary = TempFile("model");
        try
        {
            JsonDocument.Parse(modelText);
            File.WriteAllText(temporary, modelText, Encoding.UTF8);
            var result = RunCli(command, "apply", pe, "--name", name, "--language", language, "--model", temporary, "--output", outputDialog.FileName, "--json");
            SetStatus(result.ExitCode == 0 ? $"Applied to {outputDialog.FileName}" : result.Output);
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private static string TempFile(string prefix) => Path.Combine(Path.GetTempPath(), $"resource-studio-{prefix}-{Guid.NewGuid():N}.json");

    private CliResult RunCli(params string[] arguments)
    {
        var info = new ProcessStartInfo("py.exe") { WorkingDirectory = Path.GetDirectoryName(_cliPath) ?? Environment.CurrentDirectory, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        info.ArgumentList.Add("-3.12");
        info.ArgumentList.Add(_cliPath);
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start Python CLI");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new CliResult(process.ExitCode, string.IsNullOrWhiteSpace(stdout) ? stderr : stdout);
    }

    private void SetStatus(string text) => StatusText.Text = text;
    private sealed record CliResult(int ExitCode, string Output);
}
