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
    private CancellationTokenSource? _cliCancellation;

    public SignatureToolsWindow(string cliPath, string? selectedPe)
    {
        InitializeComponent();
        _cliPath = cliPath;
        _selectedPe = selectedPe;
    }

    private async void Inspect_Click(object sender, RoutedEventArgs e)
    {
        if (RequirePe()) await RunCliAsync(new[] { "signature", "inspect", _selectedPe!, "--json" }, null);
    }

    private async void Strip_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var dialog = new SaveFileDialog
        {
            Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
            FileName = DefaultOutput("stripped")
        };
        if (dialog.ShowDialog() == true)
        {
            await RunCliAsync(new[] { "signature", "strip", _selectedPe!, "--output", dialog.FileName, "--json" }, null);
        }
    }

    private async void CreateCertificate_Click(object sender, RoutedEventArgs e)
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
            await RunCliAsync(new[] { "signature", "create-test-cert", "--output", dialog.FileName, "--password-env", "RS_PFX_PASSWORD", "--json" }, new Dictionary<string, string> { ["RS_PFX_PASSWORD"] = PasswordBox.Password });
            if (File.Exists(dialog.FileName)) CertificatePathBox.Text = dialog.FileName;
        }
    }

    private async void Resign_Click(object sender, RoutedEventArgs e)
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
        await RunCliAsync(args.ToArray(), new Dictionary<string, string> { ["RS_PFX_PASSWORD"] = PasswordBox.Password });
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

    private async Task RunCliAsync(IEnumerable<string> arguments, IReadOnlyDictionary<string, string>? environment)
    {
        using var cancellation = new CancellationTokenSource();
        _cliCancellation = cancellation;
        StopCliButton.IsEnabled = true;
        StatusText.Text = "Authenticode operation running";
        try
        {
            var result = await CliProcessRunner.RunAsync(_cliPath, arguments, cancellation.Token, environment);
            OutputBox.Text = result.Output.TrimStart().StartsWith("{") ? PrettyJson(result.Output) : result.Output;
            var report = VerificationSummary.Format(result.Output);
            VerificationSummaryText.Text = report;
            VerificationSummaryText.Visibility = string.IsNullOrWhiteSpace(report) ? Visibility.Collapsed : Visibility.Visible;
            StatusText.Text = result.Stopped ? "Stopped — input unchanged" : result.ExitCode == 0 ? "Completed" : "CLI operation failed — see details";
        }
        catch (Exception exc)
        {
            OutputBox.Text = exc.ToString();
            VerificationSummaryText.Text = $"FAIL {exc.Message}";
            VerificationSummaryText.Visibility = Visibility.Visible;
            StatusText.Text = "Failed";
        }
        finally
        {
            _cliCancellation = null;
            StopCliButton.IsEnabled = false;
        }
    }

    private void StopCli_Click(object sender, RoutedEventArgs e) => _cliCancellation?.Cancel();

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
