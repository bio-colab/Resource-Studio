using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class ImageResourceWindow : Window
{
    private readonly string _cliPath;
    private string? _payloadPath;

    public ImageResourceWindow(string cliPath, string? selectedPe)
    {
        InitializeComponent();
        _cliPath = cliPath;
        PePathBox.Text = selectedPe ?? "";
    }

    private string Kind => ((System.Windows.Controls.ComboBoxItem)KindBox.SelectedItem).Content?.ToString() ?? "bitmap";

    private void Load_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(PePathBox.Text)) { SetStatus("Choose a PE file first."); return; }
        var extension = Kind == "bitmap" ? ".bmp" : ".json";
        var temporary = Path.Combine(Path.GetTempPath(), $"resource-studio-image-{Guid.NewGuid():N}{extension}");
        try
        {
            var result = RunCli("image-resource", "export", PePathBox.Text, "--kind", Kind, "--name", NameBox.Text, "--language", LanguageBox.Text, "--output", temporary, "--json");
            if (result.ExitCode != 0) { SetStatus(result.Output); return; }
            _payloadPath = temporary;
            if (Kind == "bitmap")
            {
                ImagePreview.Source = new BitmapImage(new Uri(temporary));
                ModelBox.Text = result.Output;
            }
            else ModelBox.Text = File.ReadAllText(temporary);
            SetStatus("Image resource loaded from PE.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
    }

    private void ChoosePayload_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = Kind == "bitmap" ? "BMP files (*.bmp)|*.bmp|All files (*.*)|*.*" : "Image models (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;
        _payloadPath = dialog.FileName;
        if (Kind == "bitmap") ImagePreview.Source = new BitmapImage(new Uri(dialog.FileName));
        ModelBox.Text = Kind == "bitmap" ? dialog.FileName : File.ReadAllText(dialog.FileName);
        SetStatus("Payload selected.");
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(PePathBox.Text)) { SetStatus("Choose a PE file first."); return; }
        var payload = _payloadPath;
        if (Kind != "bitmap")
        {
            var temporaryModel = Path.Combine(Path.GetTempPath(), $"resource-studio-image-model-{Guid.NewGuid():N}.json");
            File.WriteAllText(temporaryModel, ModelBox.Text, Encoding.UTF8);
            payload = temporaryModel;
        }
        if (payload is null || !File.Exists(payload)) { SetStatus("Choose or load an image payload first."); return; }
        var outputDialog = new SaveFileDialog { Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*", FileName = Path.GetFileNameWithoutExtension(PePathBox.Text) + ".image" + Path.GetExtension(PePathBox.Text) };
        if (outputDialog.ShowDialog() != true) return;
        try
        {
            var result = RunCli("image-resource", "apply", PePathBox.Text, "--kind", Kind, "--name", NameBox.Text, "--language", LanguageBox.Text, "--model", payload, "--output", outputDialog.FileName, "--json");
            SetStatus(result.ExitCode == 0 ? $"Applied to {outputDialog.FileName}" : result.Output);
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { if (payload != _payloadPath) File.Delete(payload); }
    }

    private CliResult RunCli(params string[] arguments)
    {
        var info = new ProcessStartInfo("py.exe") { WorkingDirectory = Path.GetDirectoryName(_cliPath) ?? Environment.CurrentDirectory, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        info.ArgumentList.Add("-3.12"); info.ArgumentList.Add(_cliPath); foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start Python CLI");
        var stdout = process.StandardOutput.ReadToEnd(); var stderr = process.StandardError.ReadToEnd(); process.WaitForExit();
        return new CliResult(process.ExitCode, string.IsNullOrWhiteSpace(stdout) ? stderr : stdout);
    }

    private void SetStatus(string text) => StatusText.Text = text;
    private sealed record CliResult(int ExitCode, string Output);
}
