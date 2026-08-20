using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class SignatureToolsWindow : Window
{
    private readonly string _cliPath;
    private readonly string? _selectedPe;

    public SignatureToolsWindow(string cliPath, string? selectedPe)
    {
        InitializeComponent();
        _cliPath = cliPath;
        _selectedPe = selectedPe;
    }

    private void Inspect_Click(object sender, RoutedEventArgs e)
    {
        if (RequirePe()) RunCli("signature", "inspect", _selectedPe!, "--json");
    }

    private void Strip_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var dialog = new SaveFileDialog
        {
            Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
            FileName = DefaultOutput("stripped")
        };
        if (dialog.ShowDialog() == true)
        {
            RunCli("signature", "strip", _selectedPe!, "--output", dialog.FileName, "--json");
        }
    }

    private void CreateCertificate_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(PasswordBox.Password))
        {
            MessageBox.Show("Enter a non-empty test certificate password first.", "Authenticode Tools", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dialog = new SaveFileDialog
        {
            Filter = "PFX certificates (*.pfx)|*.pfx|All files (*.*)|*.*",
            FileName = "resource-studio-test.pfx"
        };
        if (dialog.ShowDialog() == true)
        {
            RunCliWithPassword(PasswordBox.Password, "signature", "create-test-cert", "--output", dialog.FileName, "--password-env", "RS_PFX_PASSWORD", "--json");
            if (File.Exists(dialog.FileName)) CertificatePathBox.Text = dialog.FileName;
        }
    }

    private void Resign_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        if (string.IsNullOrWhiteSpace(CertificatePathBox.Text) || !File.Exists(CertificatePathBox.Text))
        {
            var certificate = new OpenFileDialog { Filter = "PFX certificates (*.pfx)|*.pfx|All files (*.*)|*.*" };
            if (certificate.ShowDialog() != true) return;
            CertificatePathBox.Text = certificate.FileName;
        }
        if (string.IsNullOrEmpty(PasswordBox.Password))
        {
            MessageBox.Show("Enter the PFX password.", "Authenticode Tools", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var output = new SaveFileDialog
        {
            Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
            FileName = DefaultOutput("test-signed")
        };
        if (output.ShowDialog() != true) return;
        var args = new List<string> { "signature", "re-sign", _selectedPe!, "--output", output.FileName, "--certificate", CertificatePathBox.Text, "--password-env", "RS_PFX_PASSWORD" };
        if (ReplaceExistingBox.IsChecked == true) args.Add("--strip-existing");
        args.Add("--json");
        RunCliWithPassword(PasswordBox.Password, args.ToArray());
    }

    private bool RequirePe()
    {
        if (!string.IsNullOrWhiteSpace(_selectedPe) && File.Exists(_selectedPe)) return true;
        MessageBox.Show("Open a PE file first.", "Authenticode Tools", MessageBoxButton.OK, MessageBoxImage.Information);
        return false;
    }

    private string DefaultOutput(string suffix)
    {
        if (string.IsNullOrWhiteSpace(_selectedPe)) return $"output-{suffix}.bin";
        var directory = Path.GetDirectoryName(_selectedPe) ?? Environment.CurrentDirectory;
        return Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(_selectedPe)}.{suffix}{Path.GetExtension(_selectedPe)}");
    }

    private void RunCliWithPassword(string password, params string[] arguments)
    {
        RunCli(arguments, new Dictionary<string, string> { ["RS_PFX_PASSWORD"] = password });
    }

    private void RunCli(params string[] arguments) => RunCli(arguments, null);

    private void RunCli(string[] arguments, Dictionary<string, string>? environment)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = "py.exe",
                WorkingDirectory = Path.GetDirectoryName(_cliPath) ?? Environment.CurrentDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            info.ArgumentList.Add("-3.12");
            info.ArgumentList.Add(_cliPath);
            foreach (var argument in arguments) info.ArgumentList.Add(argument);
            if (environment is not null)
            {
                foreach (var item in environment) info.Environment[item.Key] = item.Value;
            }
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
