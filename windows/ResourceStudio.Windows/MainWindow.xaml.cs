using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class MainWindow : Window
{
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly List<ResourceRow> _resources = new();
    private string? _selectedPe;
    private string? _cliPath;
    private bool _darkMode;

    public MainWindow()
    {
        InitializeComponent();
        _cliPath = FindCliPath();
        if (SystemParameters.HighContrast) ApplyHighContrastTheme();
    }

    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        _darkMode = !_darkMode;
        if (_darkMode)
        {
            Background = new SolidColorBrush(Color.FromRgb(30, 34, 42));
            Foreground = Brushes.White;
            RootGrid.Background = Background;
        }
        else
        {
            Background = SystemColors.WindowBrush;
            Foreground = SystemColors.WindowTextBrush;
            RootGrid.Background = Background;
        }
        StatusText.Text = _darkMode ? "Dark mode enabled" : "Light mode enabled";
    }

    private void ApplyHighContrastTheme()
    {
        Background = Brushes.Black;
        Foreground = Brushes.Yellow;
        RootGrid.Background = Brushes.Black;
        StatusText.Text = "Windows high contrast detected";
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.O)
        {
            OpenPe_Click(sender, e);
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.F)
        {
            SearchQueryBox.Focus();
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.I)
        {
            Inspect_Click(sender, e);
            e.Handled = true;
        }
        else if (e.Key == Key.F5)
        {
            LoadResources();
            e.Handled = true;
        }
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
        LoadResources();
        Inspect_Click(sender, e);
    }

    private void List_Click(object sender, RoutedEventArgs e) => LoadResources();

    private void Inspect_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var result = RunCliCapture("inspect", _selectedPe!, "--json");
        InspectBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Inspection completed" : $"CLI exited with code {result.ExitCode}";
    }

    private void Validate_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var result = RunCliCapture("validate", _selectedPe!, "--json");
        InspectBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Validation completed" : $"CLI exited with code {result.ExitCode}";
    }

    private void DialogEditor_Click(object sender, RoutedEventArgs e)
    {
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new DialogEditorWindow(_cliPath, _selectedPe) { Owner = this }.Show();
    }

    private void StringTableEditor_Click(object sender, RoutedEventArgs e)
    {
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new StringTableEditorWindow(_cliPath, _selectedPe) { Owner = this }.Show();
    }

    private void ResourceWizards_Click(object sender, RoutedEventArgs e)
    {
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new ResourceWizardsWindow(_cliPath, _selectedPe) { Owner = this }.Show();
    }

    private void ImageWizard_Click(object sender, RoutedEventArgs e)
    {
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new ImageResourceWindow(_cliPath, _selectedPe) { Owner = this }.Show();
    }

    private void AuthenticodeTools_Click(object sender, RoutedEventArgs e)
    {
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new SignatureToolsWindow(_cliPath, _selectedPe) { Owner = this }.Show();
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

    private void ResourceFilterBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) => ApplyResourceFilter();

    private void ResourceGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResourceGrid.SelectedItem is not ResourceRow row) return;
        PropertyGrid.ItemsSource = new[]
        {
            new PropertyRow("Type", row.Type),
            new PropertyRow("Name", row.Name),
            new PropertyRow("Language", row.Language?.ToString() ?? ""),
            new PropertyRow("Size", row.Size.ToString()),
            new PropertyRow("SHA-256", row.Sha256),
        };
        PreviewHeader.Text = $"{row.Type} / {row.Name} / language {row.Language}: raw resource bytes";
        PreviewResource(row);
    }

    private void BatchBrowse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Batch manifests (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() == true) BatchManifestBox.Text = dialog.FileName;
    }

    private void BatchPlan_Click(object sender, RoutedEventArgs e) => RunBatch("plan");

    private void BatchApply_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(BatchManifestBox.Text))
        {
            MessageBox.Show("Choose a batch manifest first.", "Batch Workspace", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var answer = MessageBox.Show("Apply this batch to its Save As outputs? The original inputs must not be overwritten.", "Confirm batch apply", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer == MessageBoxResult.Yes) RunBatch("apply");
    }

    private void RunBatch(string action)
    {
        if (!File.Exists(BatchManifestBox.Text))
        {
            MessageBox.Show("Choose a batch manifest first.", "Batch Workspace", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var manifest = Path.GetFullPath(BatchManifestBox.Text);
        var args = new List<string> { "batch", action, manifest, "--json" };
        if (action == "apply") args.AddRange(new[] { "--report", Path.ChangeExtension(manifest, ".batch-report.json") });
        var result = RunCliCapture(args.ToArray());
        BatchReportBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? $"Batch {action} completed" : $"CLI exited with code {result.ExitCode}";
    }

    private void LocalizationBrowse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Localization catalogs (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() == true) LocalizationCatalogBox.Text = dialog.FileName;
    }

    private void LocalizationCompare_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(LocalizationCatalogBox.Text))
        {
            MessageBox.Show("Choose a localization JSON catalog first.", "Localization", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var result = RunCliCapture("localization", "compare", LocalizationCatalogBox.Text, "--source-language", LocalizationSourceBox.Text, "--target-language", LocalizationTargetBox.Text, "--json");
        LocalizationOutputBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Localization comparison completed" : $"CLI exited with code {result.ExitCode}";
    }

    private void LocalizationPseudo_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(LocalizationCatalogBox.Text))
        {
            MessageBox.Show("Choose a localization JSON catalog first.", "Localization", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dialog = new SaveFileDialog { Filter = "Localization catalogs (*.json)|*.json|All files (*.*)|*.*", FileName = "pseudo-localized.json" };
        if (dialog.ShowDialog() != true) return;
        var result = RunCliCapture("localization", "pseudo", LocalizationCatalogBox.Text, "--source-language", LocalizationSourceBox.Text, "--target-language", LocalizationTargetBox.Text, "--output", dialog.FileName, "--json");
        LocalizationOutputBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Pseudo-localization completed" : $"CLI exited with code {result.ExitCode}";
    }

    private void Search_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        if (string.IsNullOrWhiteSpace(SearchQueryBox.Text))
        {
            MessageBox.Show("Enter a search query first.", "Search", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var args = new List<string> { "search", _selectedPe!, SearchQueryBox.Text };
        if (SearchRegexBox.IsChecked == true) args.Add("--regex");
        if (SearchHexBox.IsChecked == true) args.Add("--hex");
        args.Add("--json");
        var result = RunCliCapture(args.ToArray());
        if (result.ExitCode != 0)
        {
            SearchGrid.ItemsSource = null;
            StatusText.Text = $"CLI exited with code {result.ExitCode}";
            InspectBox.Text = result.StdoutOrError;
            return;
        }
        SearchGrid.ItemsSource = JsonSerializer.Deserialize<List<SearchRow>>(result.StdoutOrError, _jsonOptions) ?? new List<SearchRow>();
        StatusText.Text = "Search completed";
    }

    private void DiffLeftBrowse_Click(object sender, RoutedEventArgs e) => ChooseDiffFile(DiffLeftBox);

    private void DiffRightBrowse_Click(object sender, RoutedEventArgs e) => ChooseDiffFile(DiffRightBox);

    private void CompareDiff_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(DiffLeftBox.Text) || !File.Exists(DiffRightBox.Text))
        {
            MessageBox.Show("Choose two PE files first.", "Diff", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var result = RunCliCapture("diff", DiffLeftBox.Text, DiffRightBox.Text, "--json");
        DiffTree.Items.Clear();
        if (result.ExitCode != 0)
        {
            StatusText.Text = $"CLI exited with code {result.ExitCode}";
            InspectBox.Text = result.StdoutOrError;
            return;
        }
        using var document = JsonDocument.Parse(result.StdoutOrError);
        if (document.RootElement.TryGetProperty("tree", out var tree))
        {
            DiffTree.Items.Add(BuildTreeItem(tree));
        }
        StatusText.Text = "Diff completed";
    }

    private void LoadResources()
    {
        if (!RequirePe()) return;
        var result = RunCliCapture("list", _selectedPe!, "--json");
        if (result.ExitCode != 0)
        {
            StatusText.Text = $"CLI exited with code {result.ExitCode}";
            InspectBox.Text = result.StdoutOrError;
            return;
        }
        _resources.Clear();
        _resources.AddRange(JsonSerializer.Deserialize<List<ResourceRow>>(result.StdoutOrError, _jsonOptions) ?? new List<ResourceRow>());
        ResourceCountText.Text = $"{_resources.Count} resources";
        ApplyResourceFilter();
        StatusText.Text = "Resources loaded";
    }

    private void ApplyResourceFilter()
    {
        var query = ResourceFilterBox.Text.Trim();
        ResourceGrid.ItemsSource = string.IsNullOrEmpty(query)
            ? _resources.ToList()
            : _resources.Where(row => $"{row.Type} {row.Name} {row.Language} {row.Sha256}".Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void PreviewResource(ResourceRow row)
    {
        if (!RequirePe() || row.Language is null)
        {
            PreviewBox.Text = "A numeric language is required for the raw-byte preview.";
            return;
        }
        var result = RunCliCapture("hex", _selectedPe!, "--type", row.Type, "--name", row.Name, "--language", row.Language.Value.ToString(), "--length", "4096", "--json");
        PreviewBox.Text = result.ExitCode == 0 ? PrettyJson(result.StdoutOrError) : result.StdoutOrError;
    }

    private TreeViewItem BuildTreeItem(JsonElement node)
    {
        var label = node.TryGetProperty("label", out var labelValue) ? labelValue.ToString() : "node";
        var status = node.TryGetProperty("status", out var statusValue) ? statusValue.ToString() : "";
        var item = new TreeViewItem { Header = string.IsNullOrEmpty(status) ? label : $"[{status}] {label}" };
        if (node.TryGetProperty("children", out var children) && children.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in children.EnumerateArray()) item.Items.Add(BuildTreeItem(child));
        }
        return item;
    }

    private static void ChooseDiffFile(TextBox target)
    {
        var dialog = new OpenFileDialog { Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*" };
        if (dialog.ShowDialog() == true) target.Text = dialog.FileName;
    }

    private bool RequirePe()
    {
        if (!string.IsNullOrWhiteSpace(_selectedPe) && File.Exists(_selectedPe)) return true;
        MessageBox.Show("Open a PE file first.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Information);
        return false;
    }

    private CliResult RunCliCapture(params string[] arguments)
    {
        if (_cliPath is null) return new CliResult(2, "resource_studio_cli.py was not found.");
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
            using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start Python CLI");
            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return new CliResult(process.ExitCode, string.IsNullOrWhiteSpace(stdout) ? stderr : stdout);
        }
        catch (Exception exc)
        {
            return new CliResult(2, exc.ToString());
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

    private sealed class ResourceRow
    {
        public string Type { get; set; } = "";
        public string Name { get; set; } = "";
        public int? Language { get; set; }
        public int Size { get; set; }
        public string Sha256 { get; set; } = "";
    }

    private sealed class SearchRow
    {
        public string Type { get; set; } = "";
        public string Name { get; set; } = "";
        public int? Language { get; set; }
        public string Field { get; set; } = "";
        public int Offset { get; set; }
        public string Preview { get; set; } = "";
    }

    private sealed record PropertyRow(string Name, string Value);
    private sealed record CliResult(int ExitCode, string StdoutOrError);
}
