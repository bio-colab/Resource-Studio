using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class MainWindow : Window
{
    private string? _selectedPe;
    private string? _cliPath;

    public MainWindow()
    {
        InitializeComponent();
        _cliPath = FindCliPath();
    }

    private void OpenPe_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
            Title = "Open PE"
        };
        if (dialog.ShowDialog() != true) return;
        _selectedPe = dialog.FileName;
        PathBox.Text = _selectedPe;
        RunAndShow("inspect", _selectedPe, "--json");
    }

    private void List_Click(object sender, RoutedEventArgs e)
    {
        if (RequirePe()) RunAndShow("list", _selectedPe!, "--json");
    }

    private void Inspect_Click(object sender, RoutedEventArgs e)
    {
        if (RequirePe()) RunAndShow("inspect", _selectedPe!, "--json");
    }

    private void Validate_Click(object sender, RoutedEventArgs e)
    {
        if (RequirePe()) RunAndShow("validate", _selectedPe!, "--json");
    }

    private void OpenPythonGui_Click(object sender, RoutedEventArgs e)
    {
        var gui = Path.Combine(Path.GetDirectoryName(_cliPath ?? string.Empty) ?? string.Empty, "resource_studio_gui.py");
        if (!File.Exists(gui))
        {
            MessageBox.Show("Python GUI was not found next to the CLI.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var python = new ProcessStartInfo("py.exe") { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(gui) };
        python.ArgumentList.Add("-3.12");
        python.ArgumentList.Add(gui);
        Process.Start(python);
    }

    private bool RequirePe()
    {
        if (!string.IsNullOrWhiteSpace(_selectedPe)) return true;
        MessageBox.Show("Open a PE file first.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Information);
        return false;
    }

    private void RunAndShow(params string[] arguments)
    {
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        try
        {
            var command = string.Join(" ", arguments.Select(Quote));
            var info = new ProcessStartInfo
            {
                FileName = "py.exe",
                Arguments = $"-3.12 \"{_cliPath}\" {command}",
                WorkingDirectory = Path.GetDirectoryName(_cliPath),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start Python CLI");
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            OutputBox.Text = string.IsNullOrWhiteSpace(stdout) ? stderr : PrettyJson(stdout);
            StatusText.Text = process.ExitCode == 0 ? "Completed" : $"CLI exited with code {process.ExitCode}";
        }
        catch (Exception exc)
        {
            OutputBox.Text = exc.ToString();
            StatusText.Text = "Failed";
        }
    }

    private static string? FindCliPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && directory is not null; i++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "resource_studio_cli.py");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private static string Quote(string value) => $"\"{value.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";

    private static string PrettyJson(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text);
            return JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
        }
        catch
        {
            return text;
        }
    }
}
