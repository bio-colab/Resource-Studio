using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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
    private bool _darkMode = true;
    private CliOperationState _cliState = CliOperationState.Idle;
    private Process? _activeCliProcess;
    private CancellationTokenSource? _cliCancellation;
    private ReadHostClient? _readHost;
    private long _requestGeneration;
    private JsonElement? _currentIdentity;
    private bool _signedEditConfirmed;

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
        LoadRecentFiles();
        var arguments = Environment.GetCommandLineArgs();
        var openIndex = Array.FindIndex(arguments, argument => string.Equals(argument, "--open", StringComparison.OrdinalIgnoreCase));
        if (openIndex < 0 || openIndex + 1 >= arguments.Length)
        {
            StatusDetailText.Text = "Open a PE to begin";
            return;
        }
        var path = Path.GetFullPath(arguments[openIndex + 1]);
        if (!File.Exists(path)) { StatusText.Text = "PE not found"; StatusDetailText.Text = path; return; }
        await OpenPePathAsync(path);
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
        SetBrushColor("DeepSlateBrush", dark ? "#101827" : "#F8FAFC");
        SetBrushColor("SlatePanelBrush", dark ? "#182337" : "#FFFFFF");
        SetBrushColor("SlateElevatedBrush", dark ? "#223149" : "#F1F5F9");
        SetBrushColor("SlateInputBrush", dark ? "#111C2D" : "#FFFFFF");
        SetBrushColor("DividerBrush", dark ? "#34445C" : "#CBD5E1");
        SetBrushColor("PaperBrush", dark ? "#F3F7FB" : "#0F172A");
        SetBrushColor("MistBrush", dark ? "#B7C4D6" : "#475569");
        SetBrushColor("SignalCyanBrush", dark ? "#2DD4BF" : "#0D9488");
        SetBrushColor("AnalysisBlueBrush", dark ? "#60A5FA" : "#2563EB");
        SetBrushColor("TriageAmberBrush", dark ? "#F59E0B" : "#D97706");
        SetBrushColor("EvidenceRedBrush", dark ? "#EF4444" : "#DC2626");
        SetBrushColor("VerifiedGreenBrush", dark ? "#34D399" : "#059669");
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

    private readonly List<string> _recentFiles = new();
    private static readonly string RecentFilesConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ResourceStudio", "recent_pe.json");

    private void LoadRecentFiles()
    {
        try
        {
            if (File.Exists(RecentFilesConfigPath))
            {
                var json = File.ReadAllText(RecentFilesConfigPath);
                var files = JsonSerializer.Deserialize<List<string>>(json);
                if (files != null)
                {
                    _recentFiles.Clear();
                    _recentFiles.AddRange(files.Where(File.Exists));
                }
            }
        }
        catch { }
        UpdateRecentFilesMenu();
    }

    private void SaveRecentFiles()
    {
        try
        {
            var dir = Path.GetDirectoryName(RecentFilesConfigPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(RecentFilesConfigPath, JsonSerializer.Serialize(_recentFiles));
        }
        catch { }
    }

    private void AddRecentFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        var fullPath = Path.GetFullPath(path);
        _recentFiles.RemoveAll(p => string.Equals(p, fullPath, StringComparison.OrdinalIgnoreCase));
        _recentFiles.Insert(0, fullPath);
        if (_recentFiles.Count > 8) _recentFiles.RemoveRange(8, _recentFiles.Count - 8);
        SaveRecentFiles();
        UpdateRecentFilesMenu();
    }

    private void UpdateRecentFilesMenu()
    {
        RecentFilesMenu.Items.Clear();
        if (_recentFiles.Count == 0)
        {
            var empty = new MenuItem { Header = "(No recent files)", IsEnabled = false };
            RecentFilesMenu.Items.Add(empty);
            return;
        }
        foreach (var file in _recentFiles)
        {
            var item = new MenuItem { Header = file, ToolTip = file };
            item.Click += async (_, _) => await OpenPePathAsync(file);
            RecentFilesMenu.Items.Add(item);
        }
        RecentFilesMenu.Items.Add(new Separator());
        var clear = new MenuItem { Header = "Clear Recent Files" };
        clear.Click += (_, _) =>
        {
            _recentFiles.Clear();
            SaveRecentFiles();
            UpdateRecentFilesMenu();
        };
        RecentFilesMenu.Items.Add(clear);
    }

    private void RecentFiles_Click(object sender, RoutedEventArgs e)
    {
        RecentFilesMenu.PlacementTarget = sender as UIElement;
        RecentFilesMenu.IsOpen = true;
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }
        e.Handled = true;
    }

    private async void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop) && e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
        {
            var path = files[0];
            if (File.Exists(path))
            {
                await OpenPePathAsync(path);
            }
        }
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
            var resourcesTab = (TabItem)FindName("ResourcesTab");
            if (resourcesTab != null && resourcesTab.IsSelected)
            {
                ResourceFilterBox.Focus();
                ResourceFilterBox.SelectAll();
            }
            else
            {
                SearchQueryBox.Focus();
                SearchQueryBox.SelectAll();
            }
            e.Handled = true;
        }
        else if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.D)
        {
            var diffTab = (TabItem)FindName("DiffTab");
            if (diffTab != null)
            {
                var tabControl = (TabControl)diffTab.Parent;
                tabControl.SelectedItem = diffTab;
            }
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
        else if (e.Key == Key.Escape)
        {
            if (ResourceFilterBox.IsFocused)
            {
                ResourceFilterBox.Text = string.Empty;
                Keyboard.ClearFocus();
                e.Handled = true;
            }
        }
    }

    private async void OpenPe_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "PE files (*.exe;*.dll;*.sys;*.mui)|*.exe;*.dll;*.sys;*.mui|All files (*.*)|*.*",
            Title = "Open PE"
        };
        if (dialog.ShowDialog() != true) return;
        await OpenPePathAsync(dialog.FileName);
    }

    public async Task OpenPePathAsync(string path)
    {
        if (!File.Exists(path)) return;
        _selectedPe = Path.GetFullPath(path);
        AddRecentFile(_selectedPe);
        _signedEditConfirmed = false;
        _currentIdentity = null;
        IdentityPanel.Visibility = Visibility.Collapsed;
        NoticeBanner.Visibility = Visibility.Collapsed;
        PathBox.Text = _selectedPe;
        DiffLeftBox.Text = _selectedPe;
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
        if (result.ExitCode == 0)
        {
            try
            {
                using var doc = JsonDocument.Parse(result.StdoutOrError);
                if (doc.RootElement.TryGetProperty("identity", out var identity))
                {
                    _currentIdentity = identity.Clone();
                    UpdateIdentityUI(identity);
                }
            }
            catch { }
        }
    }

    private async void Validate_Click(object sender, RoutedEventArgs e)
    {
        if (!RequirePe()) return;
        var result = await RunCliCaptureAsync("validate", _selectedPe!, "--json");
        if (result.IsStale) return;
        InspectBox.Text = PrettyJson(result.StdoutOrError);
        StatusText.Text = result.ExitCode == 0 ? "Validation completed" : $"CLI exited with code {result.ExitCode}";
    }

    private bool ConfirmSignedEditOnce()
    {
        if (_signedEditConfirmed || _currentIdentity == null) return true;
        if (_currentIdentity.Value.TryGetProperty("signed", out var s) && s.GetBoolean())
        {
            var answer = MessageBox.Show(
                "This PE file is digitally signed.\n\nEditing and saving resources will invalidate the Authenticode signature, and the file will need to be re-signed.\n\nDo you want to proceed with editing?",
                "Authenticode Notice",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes) return false;
            _signedEditConfirmed = true;
        }
        return true;
    }

    private void UpdateIdentityUI(JsonElement id)
    {
        IdentityPanel.Children.Clear();
        NoticePanel.Children.Clear();

        void AddChip(string text, Brush? borderBrush = null, Brush? fgBrush = null, string? tooltip = null)
        {
            var b = new Border
            {
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(7, 2, 7, 2),
                Margin = new Thickness(0, 0, 6, 0),
                Background = (Brush)FindResource("SlateElevatedBrush"),
                BorderBrush = borderBrush ?? (Brush)FindResource("DividerBrush"),
                BorderThickness = new Thickness(1),
                ToolTip = tooltip
            };
            var tb = new TextBlock
            {
                Text = text,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                Foreground = fgBrush ?? (Brush)FindResource("PaperBrush")
            };
            b.Child = tb;
            IdentityPanel.Children.Add(b);
        }

        var machine = id.TryGetProperty("machine", out var m) ? m.GetString() : "";
        var fmt = id.TryGetProperty("format", out var f) ? f.GetString() : "";
        var kind = id.TryGetProperty("kind", out var k) ? k.GetString() : "";
        var sub = id.TryGetProperty("subsystem", out var s) ? s.GetString() : "";

        AddChip($"{machine} · {fmt}", (Brush)FindResource("AnalysisBlueBrush"));
        AddChip($"{kind?.ToUpperInvariant()} ({sub})");

        if (id.TryGetProperty("signed", out var sig) && sig.GetBoolean())
        {
            AddChip("Signed", (Brush)FindResource("VerifiedGreenBrush"), (Brush)FindResource("VerifiedGreenBrush"), "Digitally signed with Authenticode");
        }
        else
        {
            AddChip("Unsigned", (Brush)FindResource("DividerBrush"), (Brush)FindResource("MistBrush"));
        }

        if (id.TryGetProperty("managed", out var mg) && mg.GetBoolean())
        {
            AddChip(".NET Assembly", (Brush)FindResource("SignalCyanBrush"), (Brush)FindResource("SignalCyanBrush"), "CLR Managed Binary");
        }

        if (id.TryGetProperty("packerHint", out var ph) && ph.ValueKind == JsonValueKind.Object)
        {
            var pName = ph.TryGetProperty("name", out var pn) ? pn.GetString() : "Packer";
            AddChip($"{pName} Hint", (Brush)FindResource("TriageAmberBrush"), (Brush)FindResource("TriageAmberBrush"), "Packed PE binary");
        }

        if (id.TryGetProperty("overlayBytes", out var ob) && ob.GetInt32() > 0)
        {
            AddChip($"+{ob.GetInt32():N0} B Overlay", (Brush)FindResource("DividerBrush"), (Brush)FindResource("MistBrush"));
        }

        if (id.TryGetProperty("pdbPath", out var pdb) && pdb.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(pdb.GetString()))
        {
            var p = pdb.GetString()!;
            var filename = System.IO.Path.GetFileName(p);
            var pdbChip = new Border
            {
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(7, 2, 7, 2),
                Margin = new Thickness(0, 0, 6, 0),
                Background = (Brush)FindResource("SlateElevatedBrush"),
                BorderBrush = (Brush)FindResource("AnalysisBlueBrush"),
                BorderThickness = new Thickness(1),
                Cursor = Cursors.Hand,
                ToolTip = $"Full PDB path: {p}\nClick to copy path"
            };
            pdbChip.Child = new TextBlock
            {
                Text = $"PDB: {filename}",
                FontSize = 11,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("PaperBrush")
            };
            pdbChip.MouseLeftButtonDown += (s, e) =>
            {
                Clipboard.SetText(p);
                StatusText.Text = $"Copied PDB path to clipboard: {p}";
            };
            IdentityPanel.Children.Add(pdbChip);
        }

        if (id.TryGetProperty("satellite", out var sat) && sat.ValueKind == JsonValueKind.Object)
        {
            if (sat.TryGetProperty("mui", out var mui) && mui.GetBoolean())
            {
                var lang = sat.TryGetProperty("languageHint", out var lh) ? lh.GetString() : null;
                AddChip(lang != null ? $"MUI ({lang})" : "MUI", (Brush)FindResource("SignalCyanBrush"));
            }
        }

        IdentityPanel.Visibility = IdentityPanel.Children.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        if (id.TryGetProperty("notices", out var notices) && notices.ValueKind == JsonValueKind.Array && notices.GetArrayLength() > 0)
        {
            foreach (var notice in notices.EnumerateArray())
            {
                var msg = notice.TryGetProperty("message", out var msgEl) ? msgEl.GetString() : "";
                var tb = new TextBlock
                {
                    Text = $"⚠ {msg}",
                    FontSize = 11,
                    FontWeight = FontWeights.Medium,
                    Foreground = (Brush)FindResource("TriageAmberBrush"),
                    Margin = new Thickness(0, 1, 0, 1)
                };
                NoticePanel.Children.Add(tb);
            }
            NoticeBanner.Visibility = Visibility.Visible;
        }
        else
        {
            NoticeBanner.Visibility = Visibility.Collapsed;
        }
    }

    private void DialogEditor_Click(object sender, RoutedEventArgs e)
    {
        if (!ConfirmSignedEditOnce()) return;
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new DialogEditorWindow(_cliPath, _selectedPe) { Owner = this }.Show();
    }

    private void StringTableEditor_Click(object sender, RoutedEventArgs e)
    {
        if (!ConfirmSignedEditOnce()) return;
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new StringTableEditorWindow(_cliPath, _selectedPe) { Owner = this }.Show();
    }

    private void ResourceWizards_Click(object sender, RoutedEventArgs e)
    {
        if (!ConfirmSignedEditOnce()) return;
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        new ResourceWizardsWindow(_cliPath, _selectedPe) { Owner = this }.Show();
    }

    private void ImageWizard_Click(object sender, RoutedEventArgs e)
    {
        if (!ConfirmSignedEditOnce()) return;
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
        };
        PreviewHeader.Text = $"{row.Type} / {row.Name} / language {row.Language}: typed preview with raw fallback";
        PreviewResource(row);
    }

    private void ResourceGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        OpenEditorForSelectedResource();
    }

    private void ResourceGrid_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            OpenEditorForSelectedResource();
        }
    }

    private void OpenEditorForSelectedResource()
    {
        if (ResourceGrid.SelectedItem is not ResourceRow row) return;
        if (!RequirePe()) return;
        if (!ConfirmSignedEditOnce()) return;
        if (_cliPath is null)
        {
            MessageBox.Show("resource_studio_cli.py was not found.", "Resource Studio", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var rType = row.Type?.ToUpperInvariant() ?? "";
        if (rType == "DIALOG")
        {
            new DialogEditorWindow(_cliPath, _selectedPe, row.Name, row.Language) { Owner = this }.Show();
        }
        else if (rType == "STRING")
        {
            new StringTableEditorWindow(_cliPath, _selectedPe, row.Name, row.Language) { Owner = this }.Show();
        }
        else if (rType is "VERSION" or "MANIFEST" or "MENU")
        {
            new ResourceWizardsWindow(_cliPath, _selectedPe, rType, row.Name, row.Language) { Owner = this }.Show();
        }
        else if (rType is "BITMAP" or "ICON" or "CURSOR" or "GROUP_ICON" or "GROUP_CURSOR")
        {
            var kind = rType.Contains("ICON") ? "icon" : (rType.Contains("CURSOR") ? "cursor" : "bitmap");
            new ImageResourceWindow(_cliPath, _selectedPe, kind, row.Name, row.Language) { Owner = this }.Show();
        }
        else
        {
            var previewTab = (TabItem)FindName("PreviewTab");
            if (previewTab != null)
            {
                var tabControl = (TabControl)previewTab.Parent;
                tabControl.SelectedItem = previewTab;
            }
        }
    }

    private void EditSelectedResource_Click(object sender, RoutedEventArgs e) => OpenEditorForSelectedResource();

    private static string SanitizeIdentifier(string name)
    {
        var sanitized = Regex.Replace(name, @"[^a-zA-Z0-9_]", "_");
        if (string.IsNullOrEmpty(sanitized) || char.IsDigit(sanitized[0]))
        {
            sanitized = "_" + sanitized;
        }
        return sanitized;
    }

    private static string FormatByteArray(byte[] bytes, int bytesPerLine = 12)
    {
        var sb = new StringBuilder(bytes.Length * 6);
        for (var i = 0; i < bytes.Length; i++)
        {
            if (i % bytesPerLine == 0)
            {
                if (i > 0) sb.AppendLine();
                sb.Append("    ");
            }
            sb.Append($"0x{bytes[i]:X2}");
            if (i < bytes.Length - 1) sb.Append(", ");
        }
        return sb.ToString();
    }

    private async Task<byte[]?> GetSelectedResourceBytesAsync(ResourceRow row)
    {
        if (!RequirePe() || _cliPath is null) return null;

        if (row.Size > 10 * 1024 * 1024)
        {
            var proceed = MessageBox.Show(
                $"This resource is {row.Size / (1024.0 * 1024.0):F1} MB. Extracting and converting large binaries to text may consume significant memory. Continue?",
                "Large Resource",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (proceed != MessageBoxResult.Yes) return null;
        }

        var tempFile = Path.Combine(Path.GetTempPath(), $"rs-export-{Guid.NewGuid():N}.bin");
        try
        {
            var args = new List<string> { "extract", _selectedPe!, "--type", row.Type, "--name", row.Name, "--output", tempFile };
            if (row.Language.HasValue)
            {
                args.AddRange(new[] { "--language", row.Language.Value.ToString() });
            }
            var result = await RunCliCaptureAsync(args.ToArray());
            if (result.ExitCode != 0 || !File.Exists(tempFile))
            {
                StatusText.Text = $"Failed to extract resource: {result.StdoutOrError}";
                return null;
            }
            return await File.ReadAllBytesAsync(tempFile);
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error reading resource: {ex.Message}";
            return null;
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                try { File.Delete(tempFile); } catch { /* ignore */ }
            }
        }
    }

    private async void CopyAsCArray_Click(object sender, RoutedEventArgs e)
    {
        if (ResourceGrid.SelectedItem is not ResourceRow row) return;
        StatusText.Text = "Extracting resource for C/C++ array...";
        var bytes = await GetSelectedResourceBytesAsync(row);
        if (bytes is null) return;

        var ident = SanitizeIdentifier($"{row.Type}_{row.Name}");
        var formatted = await Task.Run(() => FormatByteArray(bytes));
        var code = new StringBuilder();
        code.AppendLine($"// Resource: {row.Type} / {row.Name} ({bytes.Length} bytes)");
        if (!string.IsNullOrEmpty(row.Sha256)) code.AppendLine($"// SHA-256: {row.Sha256}");
        code.AppendLine($"const unsigned char res_{ident}[] = {{");
        code.AppendLine(formatted);
        code.AppendLine("};");
        code.AppendLine($"const unsigned int res_{ident}_len = {bytes.Length};");

        Clipboard.SetText(code.ToString());
        StatusText.Text = $"Copied {bytes.Length:N0} bytes as C/C++ array to clipboard";
    }

    private async void CopyAsCSharpSpan_Click(object sender, RoutedEventArgs e)
    {
        if (ResourceGrid.SelectedItem is not ResourceRow row) return;
        StatusText.Text = "Extracting resource for C# ReadOnlySpan...";
        var bytes = await GetSelectedResourceBytesAsync(row);
        if (bytes is null) return;

        var ident = SanitizeIdentifier($"{row.Type}_{row.Name}");
        var formatted = await Task.Run(() => FormatByteArray(bytes));
        var code = new StringBuilder();
        code.AppendLine($"// Resource: {row.Type} / {row.Name} ({bytes.Length} bytes)");
        if (!string.IsNullOrEmpty(row.Sha256)) code.AppendLine($"// SHA-256: {row.Sha256}");
        code.AppendLine($"ReadOnlySpan<byte> res_{ident} = [");
        code.AppendLine(formatted);
        code.AppendLine("];");

        Clipboard.SetText(code.ToString());
        StatusText.Text = $"Copied {bytes.Length:N0} bytes as C# ReadOnlySpan to clipboard";
    }

    private async void CopyAsBase64_Click(object sender, RoutedEventArgs e)
    {
        if (ResourceGrid.SelectedItem is not ResourceRow row) return;
        StatusText.Text = "Extracting resource for Base64...";
        var bytes = await GetSelectedResourceBytesAsync(row);
        if (bytes is null) return;

        var b64 = Convert.ToBase64String(bytes);
        Clipboard.SetText(b64);
        StatusText.Text = $"Copied Base64 string ({b64.Length:N0} chars) to clipboard";
    }

    private void CopySha256_Click(object sender, RoutedEventArgs e)
    {
        if (ResourceGrid.SelectedItem is not ResourceRow row) return;
        if (!string.IsNullOrEmpty(row.Sha256))
        {
            Clipboard.SetText(row.Sha256);
            StatusText.Text = $"Copied SHA-256 to clipboard: {row.Sha256}";
        }
        else
        {
            StatusText.Text = "No SHA-256 hash available for this resource";
        }
    }

    private string GenerateResourceHeaderContent()
    {
        var sb = new StringBuilder();
        sb.AppendLine("//{{NO_DEPENDENCIES}}");
        sb.AppendLine("// Microsoft Visual C++ generated include file.");
        sb.AppendLine("// Generated by Resource Studio");
        sb.AppendLine("//");
        sb.AppendLine("#pragma once");
        sb.AppendLine();

        var usedIds = new HashSet<int>();
        var entries = new List<(string Symbol, int Id)>();

        foreach (var row in _resources)
        {
            if (int.TryParse(row.Name, out var num))
            {
                usedIds.Add(num);
            }
        }

        int nextAutoId = 101;
        var seenSymbols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in _resources.GroupBy(r => (r.Type, r.Name)).Select(g => g.First()))
        {
            var type = row.Type.ToUpperInvariant();
            string prefix = type switch
            {
                "DIALOG" or "DIALOGEX" => "IDD",
                "ICON" or "GROUP_ICON" => "IDI",
                "CURSOR" or "GROUP_CURSOR" => "IDC",
                "BITMAP" => "IDB",
                "MENU" => "IDM",
                "STRING" => "IDS",
                "ACCELERATOR" => "IDA",
                "HTML" => "IDR_HTML",
                _ => $"IDR_{SanitizeIdentifier(type)}"
            };

            int id;
            string symbol;
            if (int.TryParse(row.Name, out var numId))
            {
                id = numId;
                symbol = $"{prefix}_{numId}";
            }
            else
            {
                symbol = SanitizeIdentifier(row.Name).ToUpperInvariant();
                if (!symbol.StartsWith("ID", StringComparison.OrdinalIgnoreCase))
                {
                    symbol = $"{prefix}_{symbol}";
                }
                while (usedIds.Contains(nextAutoId)) nextAutoId++;
                id = nextAutoId++;
                usedIds.Add(id);
            }

            if (seenSymbols.Add(symbol))
            {
                entries.Add((symbol, id));
            }
        }

        foreach (var (sym, id) in entries.OrderBy(e => e.Id))
        {
            sb.AppendLine($"#define {sym,-32} {id}");
        }

        sb.AppendLine();
        sb.AppendLine("// Next default values for new objects");
        sb.AppendLine("// ");
        sb.AppendLine("#ifdef APSTUDIO_INVOKED");
        sb.AppendLine("#ifndef APSTUDIO_READONLY_SYMBOLS");
        sb.AppendLine($"#define _APS_NEXT_RESOURCE_VALUE        {Math.Max(101, (usedIds.Count > 0 ? usedIds.Max() : 100) + 1)}");
        sb.AppendLine("#define _APS_NEXT_COMMAND_VALUE         40001");
        sb.AppendLine("#define _APS_NEXT_CONTROL_VALUE         1001");
        sb.AppendLine("#define _APS_NEXT_SYMED_VALUE           101");
        sb.AppendLine("#endif");
        sb.AppendLine("#endif");

        return sb.ToString();
    }

    private void GenerateResourceHeader_Click(object sender, RoutedEventArgs e)
    {
        if (_resources.Count == 0)
        {
            MessageBox.Show("No resources loaded. Open a PE file first.", "Generate resource.h", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var headerContent = GenerateResourceHeaderContent();
        var saveDialog = new SaveFileDialog
        {
            Title = "Save Win32 resource.h",
            Filter = "C/C++ Header (*.h)|*.h|All files (*.*)|*.*",
            FileName = "resource.h"
        };

        if (saveDialog.ShowDialog() == true)
        {
            try
            {
                File.WriteAllText(saveDialog.FileName, headerContent, Encoding.UTF8);
                Clipboard.SetText(headerContent);
                StatusText.Text = $"Exported resource.h to {Path.GetFileName(saveDialog.FileName)} (also copied to clipboard)";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save resource.h:\n{ex.Message}", "Save Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        else
        {
            Clipboard.SetText(headerContent);
            StatusText.Text = "resource.h copied to clipboard";
        }
    }

    public void LaunchDiffComparison(string originalPath, string editedPath)
    {
        DiffLeftBox.Text = originalPath;
        DiffRightBox.Text = editedPath;
        var diffTab = (TabItem)FindName("DiffTab");
        if (diffTab != null)
        {
            var tabControl = (TabControl)diffTab.Parent;
            tabControl.SelectedItem = diffTab;
        }
        CompareDiff_Click(this, new RoutedEventArgs());
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
        try
        {
            SearchGrid.ItemsSource = JsonSerializer.Deserialize<List<SearchRow>>(result.StdoutOrError, _jsonOptions) ?? new List<SearchRow>();
            StatusText.Text = "Search completed";
        }
        catch (JsonException)
        {
            SearchGrid.ItemsSource = null;
            StatusText.Text = "Failed to parse search results";
            InspectBox.Text = result.StdoutOrError;
        }
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
        var args = new List<string> { "diff", DiffLeftBox.Text, DiffRightBox.Text };
        if (DiffTypedCheck?.IsChecked == true) args.Add("--typed");
        args.Add("--json");
        var result = await RunCliCaptureAsync(args.ToArray());
        if (result.IsStale) return;
        DiffTree.Items.Clear();
        if (result.ExitCode != 0)
        {
            StatusText.Text = $"CLI exited with code {result.ExitCode}";
            InspectBox.Text = result.StdoutOrError;
            return;
        }
        try
        {
            using var document = JsonDocument.Parse(result.StdoutOrError);
            if (document.RootElement.TryGetProperty("tree", out var tree))
            {
                var isUnchanged = tree.TryGetProperty("status", out var s) && s.GetString() == "unchanged";
                if (isUnchanged)
                {
                    var okItem = new TreeViewItem
                    {
                        Header = "✓ Files are identical — zero resource differences found",
                        Foreground = new SolidColorBrush(Color.FromRgb(46, 160, 67)),
                        FontWeight = FontWeights.SemiBold,
                        FontSize = 13,
                        Padding = new Thickness(6, 4, 6, 4)
                    };
                    DiffTree.Items.Add(okItem);
                }
                else
                {
                    DiffTree.Items.Add(BuildTreeItem(tree));
                }
            }
            StatusText.Text = "Diff completed";
        }
        catch (JsonException)
        {
            StatusText.Text = "Diff output was not valid JSON";
            InspectBox.Text = result.StdoutOrError;
        }
    }

    private async void ExportRecipe_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(DiffLeftBox.Text) || !File.Exists(DiffRightBox.Text))
        {
            MessageBox.Show("Choose original and edited PE files first in the Diff tab.", "Export Recipe", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new OpenFolderDialog
        {
            Title = "Select Destination Folder for Automation Recipe"
        };
        if (dialog.ShowDialog() != true) return;

        var outputDir = dialog.FolderName;
        var result = await RunCliCaptureAsync("recipe", "export", DiffLeftBox.Text, DiffRightBox.Text, "--output", outputDir, "--json");
        if (result.IsStale) return;

        if (result.ExitCode != 0)
        {
            StatusText.Text = "Recipe export failed";
            InspectBox.Text = result.StdoutOrError;
            MessageBox.Show($"Recipe export failed:\n{result.StdoutOrError}", "Recipe Export", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        StatusText.Text = "Automation recipe exported successfully";
        MessageBox.Show($"Automation recipe exported to:\n{outputDir}\n\nManifest: recipe.json", "Recipe Export", MessageBoxButton.OK, MessageBoxImage.Information);
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
        try
        {
            var rows = JsonSerializer.Deserialize<List<ResourceRow>>(result.StdoutOrError, _jsonOptions) ?? new List<ResourceRow>();
            _resources.AddRange(rows);
            ResourceCountText.Text = $"{_resources.Count} resources";
            ApplyResourceFilter();
            StatusText.Text = "Resources loaded";
        }
        catch (JsonException)
        {
            ResourceCountText.Text = "0 resources";
            ApplyResourceFilter();
            StatusText.Text = "Failed to parse resource listing — see Inspect tab";
            InspectBox.Text = result.StdoutOrError;
        }
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
            var canvas = new Canvas { Width = Math.Max(240, ReadDouble(model, "width", 240) * 2), Height = Math.Max(160, ReadDouble(model, "height", 160) * 2), Background = (Brush)Application.Current.Resources["SlateInputBrush"] };
            if (model.TryGetProperty("controls", out var controls) && controls.ValueKind == JsonValueKind.Array)
            {
                foreach (var control in controls.EnumerateArray())
                {
                    var text = control.TryGetProperty("title", out var title) ? title.ToString() : "control";
                    var border = new Border { BorderBrush = (Brush)Application.Current.Resources["DividerBrush"], BorderThickness = new Thickness(1), Background = (Brush)Application.Current.Resources["SlateElevatedBrush"], Child = new TextBlock { Text = text, Margin = new Thickness(3), TextWrapping = TextWrapping.Wrap, Foreground = (Brush)Application.Current.Resources["PaperBrush"] }, Width = Math.Max(30, ReadDouble(control, "width", 40) * 2), Height = Math.Max(18, ReadDouble(control, "height", 14) * 2) };
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
                foreach (var entry in entries.EnumerateArray()) { var width = entry.TryGetProperty("width", out var w) ? w.ToString() : "?"; var height = entry.TryGetProperty("height", out var h) ? h.ToString() : "?"; var id = entry.TryGetProperty("resourceId", out var rid) ? rid.ToString() : "?"; panel.Children.Add(new Border { BorderBrush = (Brush)Application.Current.Resources["DividerBrush"], Background = (Brush)Application.Current.Resources["SlateElevatedBrush"], BorderThickness = new Thickness(1), Margin = new Thickness(3), Padding = new Thickness(6), Child = new TextBlock { Text = $"{width}x{height}\nID {id}", TextAlignment = TextAlignment.Center, Foreground = (Brush)Application.Current.Resources["PaperBrush"] } }); }
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
            var row = new Border { BorderBrush = (Brush)Application.Current.Resources["DividerBrush"], BorderThickness = new Thickness(1), Background = (Brush)Application.Current.Resources["SlateElevatedBrush"], Margin = new Thickness(0, 1, 0, 1), Padding = new Thickness(4), Child = new TextBlock { Text = text, Foreground = (Brush)Application.Current.Resources["PaperBrush"] } };
            panel.Children.Add(row);
            if (item.TryGetProperty("children", out var children)) { var nested = RenderMenuPreview(children); nested.Margin = new Thickness(18, 0, 0, 0); panel.Children.Add(nested); }
        }
        return panel;
    }

    private static double ReadDouble(JsonElement node, string name, double fallback) => node.TryGetProperty(name, out var value) && value.TryGetDouble(out var number) ? number : fallback;

    private TreeViewItem BuildTreeItem(JsonElement node)
    {
        var label = node.TryGetProperty("key", out var keyValue) ? keyValue.GetString() :
                    (node.TryGetProperty("label", out var labelValue) ? labelValue.ToString() : "node");
        var status = node.TryGetProperty("status", out var statusValue) ? statusValue.ToString() : "";
        var kind = node.TryGetProperty("kind", out var kindValue) ? kindValue.ToString() : "";

        var headerText = string.IsNullOrEmpty(status) ? label : $"[{status}] {label}";
        if (!string.IsNullOrEmpty(kind) && kind != "tree" && kind != "node")
        {
            if (node.TryGetProperty("before", out var before) && node.TryGetProperty("after", out var after))
            {
                if (before.TryGetProperty("val", out var bVal) && after.TryGetProperty("val", out var aVal))
                    headerText = $"[{status}] {label}: \"{bVal}\" \u2192 \"{aVal}\"";
                else if (before.TryGetProperty("text", out var bTxt) && after.TryGetProperty("text", out var aTxt))
                    headerText = $"[{status}] {label}: \"{bTxt}\" \u2192 \"{aTxt}\"";
            }
            else if (node.TryGetProperty("after", out var onlyAfter))
            {
                if (onlyAfter.TryGetProperty("val", out var aVal))
                    headerText = $"[{status}] {label}: \"{aVal}\"";
                else if (onlyAfter.TryGetProperty("text", out var aTxt))
                    headerText = $"[{status}] {label}: \"{aTxt}\"";
            }
            else if (node.TryGetProperty("before", out var onlyBefore))
            {
                if (onlyBefore.TryGetProperty("val", out var bVal))
                    headerText = $"[{status}] {label}: \"{bVal}\"";
                else if (onlyBefore.TryGetProperty("text", out var bTxt))
                    headerText = $"[{status}] {label}: \"{bTxt}\"";
            }
        }

        var item = new TreeViewItem { Header = headerText, IsExpanded = true };

        if (status == "added")
            item.Foreground = new SolidColorBrush(Color.FromRgb(46, 160, 67));
        else if (status == "removed")
            item.Foreground = new SolidColorBrush(Color.FromRgb(248, 81, 73));
        else if (status == "modified")
            item.Foreground = new SolidColorBrush(Color.FromRgb(210, 153, 34));

        if (kind == "unified-diff" && node.TryGetProperty("after", out var diffAfter) && diffAfter.TryGetProperty("unified", out var unifiedText))
        {
            var lines = unifiedText.GetString()?.Split('\n') ?? Array.Empty<string>();
            foreach (var line in lines.Take(30))
            {
                var clean = line.TrimEnd('\r');
                if (string.IsNullOrEmpty(clean)) continue;
                var lineItem = new TreeViewItem
                {
                    Header = clean,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 11
                };
                if (clean.StartsWith("+"))
                    lineItem.Foreground = new SolidColorBrush(Color.FromRgb(46, 160, 67));
                else if (clean.StartsWith("-"))
                    lineItem.Foreground = new SolidColorBrush(Color.FromRgb(248, 81, 73));
                item.Items.Add(lineItem);
            }
        }

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
        return arguments[0] is "list" or "inspect" or "validate" or "search" or "diff" or "preview"
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
        OperationProgressBar.Visibility = state == CliOperationState.Running ? Visibility.Visible : Visibility.Collapsed;
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
