using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class MainWindow : Window
{
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly List<ResourceRow> _resources = new();
    private string? _selectedPe;
    private string? _cliPath;
    private bool _darkMode;
    private CliOperationState _cliState = CliOperationState.Idle;
    private Process? _activeCliProcess;
    private CancellationTokenSource? _cliCancellation;
    private ReadHostClient? _readHost;
    private long _requestGeneration;
    private string? _casePath;
    private readonly Dictionary<string, TriageStyle> _resourceTriage = new(StringComparer.Ordinal);

    public MainWindow()
    {
        InitializeComponent();
        _cliPath = FindCliPath();
        Loaded += MainWindow_Loaded;
        Closed += (_, _) => _readHost?.Dispose();
        if (SystemParameters.HighContrast) ApplyHighContrastTheme();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        var arguments = Environment.GetCommandLineArgs();
        var openIndex = Array.FindIndex(arguments, argument => string.Equals(argument, "--open", StringComparison.OrdinalIgnoreCase));
        if (openIndex < 0 || openIndex + 1 >= arguments.Length)
        {
            StatusDetailText.Text = "Open a PE to begin";
            return;
        }
        var path = Path.GetFullPath(arguments[openIndex + 1]);
        if (!File.Exists(path)) { StatusText.Text = "PE not found"; StatusDetailText.Text = path; return; }
        _selectedPe = path;
        PathBox.Text = path;
        await LoadResourcesAsync();
        await InspectCurrentAsync();
    }

    private void About_Click(object sender, RoutedEventArgs e) => new AboutWindow { Owner = this }.ShowDialog();

    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        _darkMode = !_darkMode;
        ApplyThemePalette(_darkMode);
        StatusText.Text = _darkMode ? "Dark mode enabled" : "Light mode enabled";
    }

    private void ApplyThemePalette(bool dark)
    {
        SetBrushColor("DeepSlateBrush", dark ? "#101827" : "#F7FAFC");
        SetBrushColor("SlatePanelBrush", dark ? "#182337" : "#FFFFFF");
        SetBrushColor("SlateElevatedBrush", dark ? "#223149" : "#EEF2F7");
        SetBrushColor("SlateInputBrush", dark ? "#111C2D" : "#FFFFFF");
        SetBrushColor("DividerBrush", dark ? "#34445C" : "#CBD5E1");
        SetBrushColor("PaperBrush", dark ? "#F3F7FB" : "#172033");
        SetBrushColor("MistBrush", dark ? "#B7C4D6" : "#526174");
        SetBrushColor("SignalCyanBrush", dark ? "#2DD4BF" : "#0F766E");
        SetBrushColor("AnalysisBlueBrush", dark ? "#60A5FA" : "#2563EB");
        SetBrushColor("TriageAmberBrush", dark ? "#F59E0B" : "#B45309");
        SetBrushColor("EvidenceRedBrush", dark ? "#EF4444" : "#B91C1C");
        SetBrushColor("VerifiedGreenBrush", dark ? "#34D399" : "#047857");
        Background = (Brush)Application.Current.Resources["DeepSlateBrush"];
        Foreground = (Brush)Application.Current.Resources["PaperBrush"];
        RootGrid.Background = Background;
    }

    private void SetBrushColor(string key, string value)
    {
        if (ColorConverter.ConvertFromString(value) is Color color)
        {
            Application.Current.Resources[key] = new SolidColorBrush(color);
        }
    }

    private void ApplyHighContrastTheme()
    {
        Background = Brushes.Black;
        Foreground = Brushes.Yellow;
        RootGrid.Background = Brushes.Black;
        StatusText.Text = "Windows high contrast detected";
    }

    private async void Window_PreviewKeyDown(object sender, KeyEventArgs e)
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
            await LoadResourcesAsync();
            e.Handled = true;
        }
    }

    private async void OpenPe_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
            Title = "Open PE"
        };
        if (dialog.ShowDialog() != true) return;
        _selectedPe = dialog.FileName;
        PathBox.Text = _selectedPe;
        await LoadResourcesAsync();
        await InspectCurrentAsync();
    }

    private async void List_Click(object sender, RoutedEventArgs e) => await LoadResourcesAsync();

    private async void Inspect_Click(object sender, RoutedEventArgs e) => await InspectCurrentAsync();

    private async Task InspectCurrentAsync()
    {
        if (!RequirePe()) return;
        var result = await RunCliCaptureAsync("inspect", _selectedPe!, "--json");
        if (result.IsStale) return;
        InspectBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Inspection completed" : "Analysis degraded — see Inspect tab";
    }

    private async void Validate_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var result = await RunCliCaptureAsync("validate", _selectedPe!, "--json");
        if (result.IsStale) return;
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
        var arguments = Environment.GetCommandLineArgs();
        var kindIndex = Array.FindIndex(arguments, argument => string.Equals(argument, "--image-kind", StringComparison.OrdinalIgnoreCase));
        var defaultKind = kindIndex >= 0 && kindIndex + 1 < arguments.Length ? arguments[kindIndex + 1] : null;
        new ImageResourceWindow(_cliPath, _selectedPe, defaultKind) { Owner = this }.Show();
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

    private void ResourceGrid_LoadingRow(object sender, DataGridRowEventArgs e)
    {
        if (e.Row.Item is not ResourceRow row || !_resourceTriage.TryGetValue(ResourceTriageKey(row), out var triage))
        {
            e.Row.ClearValue(DataGridRow.BackgroundProperty);
            e.Row.ClearValue(DataGridRow.ForegroundProperty);
            return;
        }
        e.Row.Background = triage.Brush;
        e.Row.Foreground = triage.Level == "HIGH" ? Brushes.White : Brushes.Black;
        e.Row.ToolTip = $"Triage {triage.Level}: {triage.Reason} — visual cue only";
    }

    private void ResourceGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ResourceGrid.SelectedItem is not ResourceRow row) return;
        PropertyEmptyState.Visibility = Visibility.Collapsed;
        PropertyGrid.ItemsSource = new[]
        {
            new PropertyRow("Type", row.Type),
            new PropertyRow("Name", row.Name),
            new PropertyRow("Language", row.Language?.ToString() ?? ""),
            new PropertyRow("Size", row.Size.ToString()),
            new PropertyRow("SHA-256", row.Sha256),
            new PropertyRow("Triage", _resourceTriage.TryGetValue(ResourceTriageKey(row), out var triage) ? $"{triage.Level}: {triage.Reason}" : "NONE"),
        };
        PreviewHeader.Text = $"{row.Type} / {row.Name} / language {row.Language}: typed preview with raw fallback";
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

    private async void RunBatch(string action)
    {
        if (!File.Exists(BatchManifestBox.Text))
        {
            MessageBox.Show("Choose a batch manifest first.", "Batch Workspace", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var manifest = Path.GetFullPath(BatchManifestBox.Text);
        var args = new List<string> { "batch", action, manifest, "--json" };
        if (action == "apply") args.AddRange(new[] { "--report", Path.ChangeExtension(manifest, ".batch-report.json") });
        var result = await RunCliCaptureAsync(args.ToArray());
        if (result.IsStale) return;
        BatchReportBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? $"Batch {action} completed" : $"CLI exited with code {result.ExitCode}";
    }

    private void LocalizationBrowse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Localization catalogs (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() == true) LocalizationCatalogBox.Text = dialog.FileName;
    }

    private async void LocalizationCompare_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(LocalizationCatalogBox.Text))
        {
            MessageBox.Show("Choose a localization JSON catalog first.", "Localization", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var result = await RunCliCaptureAsync("localization", "compare", LocalizationCatalogBox.Text, "--source-language", LocalizationSourceBox.Text, "--target-language", LocalizationTargetBox.Text, "--json");
        if (result.IsStale) return;
        LocalizationOutputBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Localization comparison completed" : $"CLI exited with code {result.ExitCode}";
    }

    private async void LocalizationPseudo_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(LocalizationCatalogBox.Text))
        {
            MessageBox.Show("Choose a localization JSON catalog first.", "Localization", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dialog = new SaveFileDialog { Filter = "Localization catalogs (*.json)|*.json|All files (*.*)|*.*", FileName = "pseudo-localized.json" };
        if (dialog.ShowDialog() != true) return;
        var result = await RunCliCaptureAsync("localization", "pseudo", LocalizationCatalogBox.Text, "--source-language", LocalizationSourceBox.Text, "--target-language", LocalizationTargetBox.Text, "--output", dialog.FileName, "--json");
        if (result.IsStale) return;
        LocalizationOutputBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Pseudo-localization completed" : $"CLI exited with code {result.ExitCode}";
    }

    private async void Search_Click(object sender, RoutedEventArgs e)
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
        var result = await RunCliCaptureAsync(args.ToArray());
        if (result.IsStale) return;
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

    private async void SecurityAnalyze_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var result = await RunCliCaptureAsync("security", _selectedPe!, "--json");
        if (result.IsStale) return;
        SecurityReportBox.Text = PrettyJson(result.StdoutOrError);
        ApplyTriage(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Static security analysis completed" : $"CLI exited with code {result.ExitCode}";
    }

    private void ApplyTriage(string json)
    {
        _resourceTriage.Clear();
        try
        {
            using var document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("resourceTriage", out var triage) || triage.ValueKind != JsonValueKind.Object)
            {
                TriageBannerText.Text = "Triage: not available";
                SetTriageBannerBrush((SolidColorBrush)Application.Current.Resources["SlateElevatedBrush"]);
                ApplyResourceFilter();
                return;
            }
            var global = triage.TryGetProperty("global", out var globalValue) ? globalValue : default;
            var level = global.ValueKind == JsonValueKind.Object && global.TryGetProperty("level", out var levelValue) ? levelValue.GetString() ?? "NONE" : "NONE";
            var color = global.ValueKind == JsonValueKind.Object && global.TryGetProperty("color", out var colorValue) ? colorValue.GetString() ?? "#E5E7EB" : "#E5E7EB";
            var reason = global.ValueKind == JsonValueKind.Object && global.TryGetProperty("reasons", out var reasons) && reasons.ValueKind == JsonValueKind.Array ? string.Join(", ", reasons.EnumerateArray().Select(item => item.ToString()).Take(2)) : "visual cue only";
            TriageBannerText.Text = $"Triage: {level} — {reason}";
            SetTriageBannerBrush(ParseBrush(color, ((SolidColorBrush)Application.Current.Resources["SlateElevatedBrush"]).Color));
            if (triage.TryGetProperty("resources", out var resources) && resources.ValueKind == JsonValueKind.Object)
            {
                foreach (var item in resources.EnumerateObject())
                {
                    var resourceLevelValue = item.Value.TryGetProperty("level", out var itemLevel) ? itemLevel.GetString() ?? "NONE" : "NONE";
                    var itemColor = item.Value.TryGetProperty("color", out var itemColorValue) ? itemColorValue.GetString() ?? "#6B7280" : "#6B7280";
                    var itemReason = item.Value.TryGetProperty("reasons", out var itemReasons) && itemReasons.ValueKind == JsonValueKind.Array ? string.Join(", ", itemReasons.EnumerateArray().Select(value => value.ToString()).Take(2)) : "visual cue only";
                    _resourceTriage[item.Name] = new TriageStyle(resourceLevelValue, ParseBrush(itemColor, Colors.Gray), itemReason);
                }
            }
            ApplyResourceFilter();
        }
        catch (JsonException)
        {
            TriageBannerText.Text = "Triage: invalid report";
            SetTriageBannerBrush(new SolidColorBrush(Color.FromRgb(127, 29, 29)));
            ApplyResourceFilter();
        }
    }

    private static SolidColorBrush ParseBrush(string value, Color fallback)
    {
        try { return new SolidColorBrush((Color)ColorConverter.ConvertFromString(value)!); }
        catch { return new SolidColorBrush(fallback); }
    }

    private void SetTriageBannerBrush(SolidColorBrush brush)
    {
        TriageBanner.Background = brush;
        TriageBannerText.Foreground = ReadableTextBrush(brush.Color);
    }

    private static SolidColorBrush ReadableTextBrush(Color background)
    {
        var luminance = (0.299 * background.R + 0.587 * background.G + 0.114 * background.B) / 255.0;
        return new SolidColorBrush(luminance > 0.62 ? Color.FromRgb(16, 24, 39) : Colors.White);
    }

    private static string ResourceTriageKey(ResourceRow row) => $"resource:{row.Type}/{row.Name}/{row.Language?.ToString() ?? "None"}";

    private sealed record TriageStyle(string Level, SolidColorBrush Brush, string Reason);

    private async void EvidenceGraph_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var result = await RunCliCaptureAsync("evidence-graph", _selectedPe!, "--json");
        if (result.IsStale) return;
        EvidenceGraphBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Evidence graph completed" : $"CLI exited with code {result.ExitCode}";
    }

    private async void EvidenceQuery_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        if (string.IsNullOrWhiteSpace(EvidenceQueryBox.Text))
        {
            MessageBox.Show("Enter an evidence query first.", "Evidence Query", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var result = await RunCliCaptureAsync("evidence-query", _selectedPe!, EvidenceQueryBox.Text, "--json");
        if (result.IsStale) return;
        EvidenceQueryResultsBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Evidence query completed" : $"CLI exited with code {result.ExitCode}";
    }

    private async void CaseCreate_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var dialog = new SaveFileDialog { Filter = "Resource Studio cases (*.case.json)|*.case.json|JSON files (*.json)|*.json", FileName = Path.GetFileNameWithoutExtension(_selectedPe) + ".case.json" };
        if (dialog.ShowDialog() != true) return;
        var result = await RunCliCaptureAsync("case", "create", _selectedPe!, "--output", dialog.FileName, "--json");
        if (result.IsStale) return;
        if (result.ExitCode == 0) _casePath = dialog.FileName;
        CasePathBox.Text = dialog.FileName + Environment.NewLine + PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Case created" : $"CLI exited with code {result.ExitCode}";
    }

    private async void CaseAnalyze_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var casePath = CasePathBox.Text.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault(value => value.EndsWith(".json", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrWhiteSpace(casePath) || !File.Exists(casePath))
        {
            var dialog = new OpenFileDialog { Filter = "Resource Studio cases (*.case.json;*.json)|*.case.json;*.json|All files (*.*)|*.*", Title = "Open case" };
            if (dialog.ShowDialog() != true) return;
            casePath = dialog.FileName;
        }
        _casePath = casePath;
        var result = await RunCliCaptureAsync("case", "analyze", casePath, _selectedPe!, "--json");
        if (result.IsStale) return;
        if (result.ExitCode == 0) _casePath = casePath;
        CasePathBox.Text = casePath + Environment.NewLine + PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Case analyzed" : $"CLI exited with code {result.ExitCode}";
    }

    private async void AddAnnotation_Click(object sender, RoutedEventArgs e)
    {
        if (!TryGetCasePath(out var casePath)) return;
        if (string.IsNullOrWhiteSpace(AnnotationTargetKindBox.Text) || string.IsNullOrWhiteSpace(AnnotationTargetIdBox.Text))
        {
            MessageBox.Show("Enter an annotation target kind and id first.", "Annotation", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var args = new List<string> { "case", "annotate", casePath, "--target-kind", AnnotationTargetKindBox.Text, "--target-id", AnnotationTargetIdBox.Text, "--actor", Environment.UserName, "--json" };
        if (!string.IsNullOrWhiteSpace(AnnotationTagBox.Text)) args.AddRange(new[] { "--tag", AnnotationTagBox.Text });
        if (!string.IsNullOrWhiteSpace(AnnotationNoteBox.Text)) args.AddRange(new[] { "--note", AnnotationNoteBox.Text });
        var result = await RunCliCaptureAsync(args.ToArray());
        if (result.IsStale) return;
        CasePathBox.Text = casePath + Environment.NewLine + PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Annotation added" : $"CLI exited with code {result.ExitCode}";
    }

    private async void ExportSelection_Click(object sender, RoutedEventArgs e)
    {
        if (!TryGetCasePath(out var casePath)) return;
        var dialog = new SaveFileDialog { Filter = "Evidence selections (*.selection.json)|*.selection.json|JSON files (*.json)|*.json", FileName = Path.GetFileNameWithoutExtension(casePath) + ".selection.json" };
        if (dialog.ShowDialog() != true) return;
        var args = new List<string> { "case", "select", casePath, "--output", dialog.FileName, "--json" };
        if (!string.IsNullOrWhiteSpace(AnnotationTagBox.Text)) args.AddRange(new[] { "--tag", AnnotationTagBox.Text });
        var result = await RunCliCaptureAsync(args.ToArray());
        if (result.IsStale) return;
        CasePathBox.Text = casePath + Environment.NewLine + PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Evidence selection exported" : $"CLI exited with code {result.ExitCode}";
    }

    private bool TryGetCasePath(out string casePath)
    {
        casePath = _casePath ?? CasePathBox.Text.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault(value => value.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) ?? string.Empty;
        if (File.Exists(casePath))
        {
            _casePath = casePath;
            return true;
        }
        MessageBox.Show("Create or open a case first.", "Case", MessageBoxButton.OK, MessageBoxImage.Information);
        return false;
    }

    private void DiffLeftBrowse_Click(object sender, RoutedEventArgs e) => ChooseDiffFile(DiffLeftBox);

    private void DiffRightBrowse_Click(object sender, RoutedEventArgs e) => ChooseDiffFile(DiffRightBox);

    private async void CompareDiff_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(DiffLeftBox.Text) || !File.Exists(DiffRightBox.Text))
        {
            MessageBox.Show("Choose two PE files first.", "Diff", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var result = await RunCliCaptureAsync("diff", DiffLeftBox.Text, DiffRightBox.Text, "--json");
        if (result.IsStale) return;
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

    private async Task LoadResourcesAsync()
    {
        if (!RequirePe()) return;
        var result = await RunCliCaptureAsync("list", _selectedPe!, "--json");
        if (result.IsStale) return;
        if (result.ExitCode != 0)
        {
            StatusText.Text = "Resource listing unavailable — see Inspect tab";
            InspectBox.Text = PrettyJson(result.StdoutOrError);
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
        var filtered = string.IsNullOrEmpty(query)
            ? _resources.ToList()
            : _resources.Where(row => $"{row.Type} {row.Name} {row.Language} {row.Sha256}".Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
        ResourceGrid.ItemsSource = filtered;
        ResourceEmptyStateText.Text = _resources.Count == 0 ? "Open a PE to explore its resources" : "No resources match this filter";
        ResourceEmptyState.Visibility = filtered.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        PropertyEmptyState.Visibility = PropertyGrid.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void PreviewResource(ResourceRow row)
    {
        PreviewVisualPanel.Children.Clear();
        if (!RequirePe() || row.Language is null)
        {
            PreviewHexBox.Text = "A numeric language is required for the preview.";
            return;
        }
        string? bitmapOutput = null;
        var arguments = new List<string> { "preview", _selectedPe!, "--type", row.Type, "--name", row.Name, "--language", row.Language.Value.ToString(), "--length", "4096", "--json" };
        if (row.Type.Equals("BITMAP", StringComparison.OrdinalIgnoreCase))
        {
            bitmapOutput = Path.Combine(Path.GetTempPath(), $"resource-studio-preview-{Guid.NewGuid():N}.bmp");
            arguments.AddRange(new[] { "--output", bitmapOutput });
        }
        var result = await RunCliCaptureAsync(arguments.ToArray());
        if (result.IsStale) return;
        PreviewHexBox.Text = result.ExitCode == 0 ? PreviewHexBox.Text : result.StdoutOrError;
        if (result.ExitCode == 0)
        {
            try
            {
                using var document = JsonDocument.Parse(result.StdoutOrError);
                ApplyHexTemplate(document.RootElement);
                RenderVisualPreview(document.RootElement, bitmapOutput);
            }
            catch (Exception exc) { PreviewVisualPanel.Children.Add(new TextBlock { Text = $"Visual preview unavailable: {exc.Message}", TextWrapping = TextWrapping.Wrap }); }
        }
        if (bitmapOutput is not null) File.Delete(bitmapOutput);
    }

    private void ApplyHexTemplate(JsonElement root)
    {
        PreviewFieldsGrid.ItemsSource = null;
        PreviewHexBox.Text = string.Empty;
        if (!root.TryGetProperty("raw", out var raw) || raw.ValueKind != JsonValueKind.Object) return;
        if (raw.TryGetProperty("hex", out var hex)) PreviewHexBox.Text = hex.ToString();
        if (!raw.TryGetProperty("template", out var template) || template.ValueKind != JsonValueKind.Object) return;
        if (!template.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Array) return;
        var rows = new List<HexFieldRow>();
        foreach (var field in fields.EnumerateArray())
        {
            rows.Add(new HexFieldRow(
                field.TryGetProperty("name", out var name) ? name.ToString() : "field",
                field.TryGetProperty("offset", out var offset) ? offset.GetInt32() : 0,
                field.TryGetProperty("length", out var length) ? length.GetInt32() : 0,
                field.TryGetProperty("value", out var value) ? value.ToString() : "",
                field.TryGetProperty("hex", out var bytes) ? bytes.ToString() : ""));
        }
        PreviewFieldsGrid.ItemsSource = rows;
    }

    private void PreviewFieldsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PreviewFieldsGrid.SelectedItem is not HexFieldRow field || string.IsNullOrEmpty(PreviewHexBox.Text)) return;
        var start = Math.Min(PreviewHexBox.Text.Length, field.Offset * 3);
        var length = Math.Min(Math.Max(0, PreviewHexBox.Text.Length - start), Math.Max(0, field.Length * 3 - (field.Length > 0 ? 1 : 0)));
        PreviewHexBox.Focus();
        PreviewHexBox.Select(start, length);
    }

    private void RenderVisualPreview(JsonElement root, string? bitmapOutput)
    {
        var kind = root.TryGetProperty("kind", out var kindValue) ? kindValue.GetString() : "raw";
        var model = root.TryGetProperty("model", out var modelValue) && modelValue.ValueKind == JsonValueKind.Object ? modelValue : default;
        if (kind == "bitmap" && bitmapOutput is not null && File.Exists(bitmapOutput))
        {
            var image = new Image { Stretch = Stretch.Uniform, MaxWidth = 420, MaxHeight = 320 };
            var source = new BitmapImage();
            using (var stream = File.OpenRead(bitmapOutput)) { source.BeginInit(); source.CacheOption = BitmapCacheOption.OnLoad; source.StreamSource = stream; source.EndInit(); }
            image.Source = source; PreviewVisualPanel.Children.Add(image); return;
        }
        if (kind == "menu-tree" && model.ValueKind == JsonValueKind.Object && model.TryGetProperty("items", out var menuItems))
        {
            PreviewVisualPanel.Children.Add(RenderMenuPreview(menuItems)); return;
        }
        if (kind == "dialog" && model.ValueKind == JsonValueKind.Object)
        {
            var canvas = new Canvas { Width = Math.Max(240, ReadDouble(model, "width", 240) * 2), Height = Math.Max(160, ReadDouble(model, "height", 160) * 2), Background = Brushes.WhiteSmoke };
            if (model.TryGetProperty("controls", out var controls) && controls.ValueKind == JsonValueKind.Array)
            {
                foreach (var control in controls.EnumerateArray())
                {
                    var text = control.TryGetProperty("title", out var title) ? title.ToString() : "control";
                    var border = new Border { BorderBrush = Brushes.SlateGray, BorderThickness = new Thickness(1), Background = Brushes.White, Child = new TextBlock { Text = text, Margin = new Thickness(3), TextWrapping = TextWrapping.Wrap }, Width = Math.Max(30, ReadDouble(control, "width", 40) * 2), Height = Math.Max(18, ReadDouble(control, "height", 14) * 2) };
                    Canvas.SetLeft(border, ReadDouble(control, "x", 0) * 2); Canvas.SetTop(border, ReadDouble(control, "y", 0) * 2); canvas.Children.Add(border);
                }
            }
            PreviewVisualPanel.Children.Add(canvas); return;
        }
        if (kind == "xml" && model.ValueKind == JsonValueKind.Object)
        {
            var xml = model.TryGetProperty("xml", out var xmlValue) ? xmlValue.GetString() : "";
            PreviewVisualPanel.Children.Add(new TextBox { Text = xml, IsReadOnly = true, FontFamily = new FontFamily("Consolas"), TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, BorderThickness = new Thickness(1) }); return;
        }
        if (kind == "version-info" && model.ValueKind == JsonValueKind.Object)
        {
            var panel = new StackPanel(); AddPreviewField(panel, "File version", model, "fileVersion"); AddPreviewField(panel, "Product version", model, "productVersion"); AddPreviewField(panel, "String count", model, "stringCount");
            if (model.TryGetProperty("strings", out var strings) && strings.ValueKind == JsonValueKind.Object) foreach (var property in strings.EnumerateObject()) AddPreviewText(panel, $"{property.Name}: {property.Value}");
            PreviewVisualPanel.Children.Add(panel); return;
        }
        if (kind == "string-table" && model.ValueKind == JsonValueKind.Object)
        {
            var panel = new StackPanel(); var first = model.TryGetProperty("firstStringId", out var firstValue) ? firstValue.GetInt32() : 0;
            if (model.TryGetProperty("strings", out var values) && values.ValueKind == JsonValueKind.Array)
            {
                var id = first; foreach (var value in values.EnumerateArray()) { if (!string.IsNullOrEmpty(value.GetString())) AddPreviewText(panel, $"{id}: {value.GetString()}"); id++; }
            }
            PreviewVisualPanel.Children.Add(panel); return;
        }
        if (kind == "image-group" && model.ValueKind == JsonValueKind.Object)
        {
            var panel = new WrapPanel(); if (model.TryGetProperty("entries", out var entries) && entries.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in entries.EnumerateArray()) { var width = entry.TryGetProperty("width", out var w) ? w.ToString() : "?"; var height = entry.TryGetProperty("height", out var h) ? h.ToString() : "?"; var id = entry.TryGetProperty("resourceId", out var rid) ? rid.ToString() : "?"; panel.Children.Add(new Border { BorderBrush = Brushes.SlateGray, BorderThickness = new Thickness(1), Margin = new Thickness(3), Padding = new Thickness(6), Child = new TextBlock { Text = $"{width}x{height}\nID {id}", TextAlignment = TextAlignment.Center } }); }
            }
            PreviewVisualPanel.Children.Add(panel); return;
        }
        PreviewVisualPanel.Children.Add(new TextBlock { Text = "No specialized visual renderer is available; use the raw/typed JSON preview.", TextWrapping = TextWrapping.Wrap });
    }

    private static void AddPreviewField(StackPanel panel, string label, JsonElement model, string property)
    {
        var value = model.TryGetProperty(property, out var element) ? element.ToString() : "";
        AddPreviewText(panel, $"{label}: {value}");
    }

    private static void AddPreviewText(StackPanel panel, string text) => panel.Children.Add(new TextBlock { Text = text, Margin = new Thickness(0, 0, 0, 4), TextWrapping = TextWrapping.Wrap });

    private static StackPanel RenderMenuPreview(JsonElement items)
    {
        var panel = new StackPanel { Orientation = Orientation.Vertical };
        if (items.ValueKind != JsonValueKind.Array) return panel;
        foreach (var item in items.EnumerateArray())
        {
            var text = item.TryGetProperty("text", out var value) ? value.ToString() : "";
            var row = new Border { BorderBrush = Brushes.SlateGray, BorderThickness = new Thickness(1), Background = Brushes.WhiteSmoke, Margin = new Thickness(0, 1, 0, 1), Padding = new Thickness(4), Child = new TextBlock { Text = text } };
            panel.Children.Add(row);
            if (item.TryGetProperty("children", out var children)) { var nested = RenderMenuPreview(children); nested.Margin = new Thickness(18, 0, 0, 0); panel.Children.Add(nested); }
        }
        return panel;
    }

    private static double ReadDouble(JsonElement node, string name, double fallback) => node.TryGetProperty(name, out var value) && value.TryGetDouble(out var number) ? number : fallback;

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

    private async Task<CliResult> RunCliCaptureAsync(params string[] arguments)
    {
        var stopwatch = Stopwatch.StartNew();
        var operation = string.Join(" ", arguments.Take(2));
        var requestId = Interlocked.Increment(ref _requestGeneration);
        _cliCancellation?.Cancel();
        using var cancellation = new CancellationTokenSource();
        _cliCancellation = cancellation;
        if (IsCurrentRequest(requestId)) SetCliState(CliOperationState.Running, $"Running: {operation}");
        Process? ownedProcess = null;
        if (_cliPath is null)
        {
            if (IsCurrentRequest(requestId)) SetCliState(CliOperationState.Failed, "CLI not found — check the project folder");
            _cliCancellation = null;
            return new CliResult(2, "resource_studio_cli.py was not found.", CliOperationState.Failed, stopwatch.ElapsedMilliseconds, !IsCurrentRequest(requestId));
        }
        try
        {
            if (IsReadOnlyHostCommand(arguments) && _cliPath.EndsWith(".py", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    _readHost ??= new ReadHostClient(Path.Combine(Path.GetDirectoryName(_cliPath)!, "tools", "wpf_read_host.py"));
                    var hostResult = await _readHost.RunAsync(arguments, cancellation.Token);
                    var hostState = hostResult.Stopped
                        ? CliOperationState.Stopped
                        : hostResult.ExitCode == 0 ? CliOperationState.Completed : CliOperationState.Failed;
                    var hostDetail = hostState == CliOperationState.Completed
                        ? $"{operation} completed in {stopwatch.Elapsed.TotalSeconds:0.0}s"
                        : hostState == CliOperationState.Stopped
                            ? $"{operation} stopped — input unchanged"
                            : $"{operation} failed — open Inspect for details";
                    var hostIsStale = !IsCurrentRequest(requestId);
                    if (!hostIsStale) SetCliState(hostState, hostDetail);
                    return new CliResult(hostResult.ExitCode, hostResult.Output, hostState, stopwatch.ElapsedMilliseconds, hostIsStale);
                }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
                {
                    var hostIsStale = !IsCurrentRequest(requestId);
                    if (!hostIsStale) SetCliState(CliOperationState.Stopped, $"{operation} stopped — input unchanged");
                    return new CliResult(130, "Operation stopped; input unchanged.", CliOperationState.Stopped, stopwatch.ElapsedMilliseconds, hostIsStale);
                }
                catch
                {
                    _readHost?.Dispose();
                    _readHost = null;
                    // Fall back to the existing one-shot CLI path if the host cannot start.
                }
            }

            var bundledExecutable = _cliPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
            var info = new ProcessStartInfo
            {
                FileName = bundledExecutable ? _cliPath : "py.exe",
                WorkingDirectory = Path.GetDirectoryName(_cliPath) ?? Environment.CurrentDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            if (!bundledExecutable)
            {
                info.ArgumentList.Add("-3.12");
                info.ArgumentList.Add(_cliPath);
            }
            foreach (var argument in arguments) info.ArgumentList.Add(argument);
            using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start Python CLI");
            ownedProcess = process;
            _activeCliProcess = process;
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(stdoutTask, stderrTask, process.WaitForExitAsync(cancellation.Token));
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            var state = process.ExitCode == 0 ? CliOperationState.Completed : CliOperationState.Failed;
            var resultText = string.IsNullOrWhiteSpace(stdout) ? stderr : stdout;
            var detail = state == CliOperationState.Completed
                ? $"{operation} completed in {stopwatch.Elapsed.TotalSeconds:0.0}s"
                : $"{operation} failed — open Inspect for details";
            var processIsStale = !IsCurrentRequest(requestId);
            if (!processIsStale) SetCliState(state, detail);
            return new CliResult(process.ExitCode, resultText, state, stopwatch.ElapsedMilliseconds, processIsStale);
        }
        catch (OperationCanceledException)
        {
            if (ownedProcess is { HasExited: false }) ownedProcess.Kill(entireProcessTree: true);
            var processIsStale = !IsCurrentRequest(requestId);
            if (!processIsStale) SetCliState(CliOperationState.Stopped, $"{operation} stopped — input unchanged");
            return new CliResult(130, "Operation stopped; input unchanged.", CliOperationState.Stopped, stopwatch.ElapsedMilliseconds, processIsStale);
        }
        catch (Exception exc)
        {
            var processIsStale = !IsCurrentRequest(requestId);
            if (!processIsStale) SetCliState(CliOperationState.Failed, "Could not start CLI — see the error details");
            return new CliResult(2, exc.ToString(), CliOperationState.Failed, stopwatch.ElapsedMilliseconds, processIsStale);
        }
        finally
        {
            if (ReferenceEquals(_activeCliProcess, ownedProcess)) _activeCliProcess = null;
            if (ReferenceEquals(_cliCancellation, cancellation)) _cliCancellation = null;
        }
    }

    private static bool IsReadOnlyHostCommand(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0) return false;
        return arguments[0] is "list" or "inspect" or "validate" or "search" or "security" or "evidence-graph" or "evidence-query" or "diff" or "preview"
            || (arguments[0] == "localization" && arguments.Count > 1 && arguments[1] == "compare");
    }

    private bool IsCurrentRequest(long requestId) => Volatile.Read(ref _requestGeneration) == requestId;

    private void StopCli_Click(object sender, RoutedEventArgs e)
    {
        if (_cliState != CliOperationState.Running) return;
        Interlocked.Increment(ref _requestGeneration);
        _cliCancellation?.Cancel();
        if (_activeCliProcess is { HasExited: false }) _activeCliProcess.Kill(entireProcessTree: true);
    }

    private void SetCliState(CliOperationState state, string detail)
    {
        _cliState = state;
        CliStateText.Text = state.ToString();
        StatusDetailText.Text = detail;
        StopCliButton.IsEnabled = state == CliOperationState.Running;
    }

    private static string? FindCliPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && directory is not null; i++, directory = directory.Parent)
        {
            var bundled = Path.Combine(directory.FullName, "ResourceStudioCli.exe");
            if (File.Exists(bundled)) return bundled;
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

    private sealed record HexFieldRow(string Name, int Offset, int Length, string Value, string Hex);

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
    private enum CliOperationState
    {
        Idle,
        Running,
        Completed,
        Failed,
        Stopped,
    }

    private sealed record CliResult(int ExitCode, string StdoutOrError, CliOperationState State, long DurationMilliseconds, bool IsStale = false);
}
