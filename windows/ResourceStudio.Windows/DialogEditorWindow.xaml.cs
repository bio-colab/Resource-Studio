using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Path = System.IO.Path;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class DialogEditorWindow : Window
{
    private sealed class ControlModel
    {
        public int ControlId { get; set; }
        public int X { get; set; }
        public int Y { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public int Style { get; set; }
        public int Exstyle { get; set; }
        public object Class { get; set; } = "";
        public object Title { get; set; } = "";
        public string CreationDataHex { get; set; } = "";
        public int HelpId { get; set; }
        public string Display => $"{ControlId}: {Title}";
    }

    private sealed class DialogModel
    {
        public int X { get; set; }
        public int Y { get; set; }
        public int Width { get; set; } = 220;
        public int Height { get; set; } = 120;
        public int Style { get; set; }
        public int Exstyle { get; set; }
        public string Title { get; set; } = "Dialog";
        public object Menu { get; set; } = "";
        public object WindowClass { get; set; } = "";
        public int? FontSize { get; set; } = 9;
        public string? FontName { get; set; } = "Segoe UI";
        public int FontWeight { get; set; } = 400;
        public bool FontItalic { get; set; }
        public int FontCharset { get; set; } = 1;
        public bool Extended { get; set; }
        public int HelpId { get; set; }
        public int Version { get; set; } = 1;
        public List<ControlModel> Controls { get; set; } = new();
    }

    private DialogModel _model = NewModel();
    private string? _cliPath;
    private CancellationTokenSource? _cliCancellation;
    private Canvas? _draggedVisual;
    private Point _dragStart;
    private int _dragStartX;

    public DialogEditorWindow(string? cliPath, string? pePath = null)
    {
        InitializeComponent();
        _cliPath = cliPath;
        PePathBox.Text = pePath ?? "";
        ResourceNameBox.Text = "1";
        LanguageBox.Text = "1033";
        RefreshEditor();
    }

    private static DialogModel NewModel() => new()
    {
        Title = "New Dialog",
        Width = 220,
        Height = 120,
        Controls = new List<ControlModel>
        {
            new() { ControlId = 100, X = 16, Y = 18, Width = 70, Height = 20, Class = 0x0082, Title = "Hello" },
            new() { ControlId = 101, X = 130, Y = 82, Width = 70, Height = 20, Class = 0x0080, Title = "OK" },
        },
    };

    private void RefreshEditor()
    {
        DialogTitleBox.Text = _model.Title;
        DialogWidthBox.Text = _model.Width.ToString();
        DialogHeightBox.Text = _model.Height.ToString();
        ControlsList.ItemsSource = null;
        ControlsList.ItemsSource = _model.Controls;
        DesignCanvas.Children.Clear();
        var frame = new Rectangle { Width = Math.Max(20, _model.Width * 2), Height = Math.Max(20, _model.Height * 2), Stroke = Brushes.DimGray, Fill = Brushes.WhiteSmoke, StrokeThickness = 1 };
        Canvas.SetLeft(frame, 0);
        Canvas.SetTop(frame, 0);
        DesignCanvas.Children.Add(frame);
        foreach (var control in _model.Controls)
        {
            var visual = CreateControlVisual(control);
            Canvas.SetLeft(visual, control.X * 2);
            Canvas.SetTop(visual, control.Y * 2);
            DesignCanvas.Children.Add(visual);
        }
        StatusText.Text = $"{_model.Controls.Count} controls; WYSIWYG preview uses dialog units ×2";
        RefreshSelectedProperties();
    }

    private FrameworkElement CreateControlVisual(ControlModel control)
    {
        var text = control.Title?.ToString() ?? "";
        var classNumber = GetClassNumber(control.Class);
        FrameworkElement visual = classNumber == 0x0080
            ? new Button { Content = text }
            : classNumber == 0x0082
                ? new Label { Content = text, BorderBrush = Brushes.LightGray, BorderThickness = new Thickness(1) }
                : classNumber == 0x0083
                    ? new ListBox { ItemsSource = new[] { text, "Item 2", "Item 3" } }
                    : classNumber == 0x0085
                        ? new ComboBox { ItemsSource = new[] { text, "Item 2", "Item 3" }, SelectedIndex = 0 }
                        : new TextBox { Text = text };
        visual.Width = Math.Max(8, control.Width * 2);
        visual.Height = Math.Max(8, control.Height * 2);
        visual.Tag = control;
        visual.AllowDrop = false;
        visual.MouseLeftButtonDown += Control_MouseLeftButtonDown;
        return visual;
    }

    private void ControlsList_SelectionChanged(object sender, SelectionChangedEventArgs e) => RefreshSelectedProperties();

    private ControlModel? SelectedControl => ControlsList.SelectedItem as ControlModel;

    private void RefreshSelectedProperties()
    {
        var control = SelectedControl;
        if (control is null)
        {
            ControlIdBox.Text = "";
            ControlHelpIdBox.Text = "";
            ControlClassBox.Text = "";
            ControlTextBox.Text = "";
            ControlXBox.Text = "";
            ControlYBox.Text = "";
            ControlWidthBox.Text = "";
            ControlHeightBox.Text = "";
            ControlStyleBox.Text = "";
            ControlExstyleBox.Text = "";
            return;
        }
        ControlIdBox.Text = control.ControlId.ToString();
        ControlHelpIdBox.Text = control.HelpId.ToString();
        ControlClassBox.Text = FormatValue(control.Class);
        ControlTextBox.Text = control.Title?.ToString() ?? "";
        ControlXBox.Text = control.X.ToString();
        ControlYBox.Text = control.Y.ToString();
        ControlWidthBox.Text = control.Width.ToString();
        ControlHeightBox.Text = control.Height.ToString();
        ControlStyleBox.Text = $"0x{control.Style:X}";
        ControlExstyleBox.Text = $"0x{control.Exstyle:X}";
    }

    private void DialogProperty_LostFocus(object sender, RoutedEventArgs e)
    {
        _model.Title = DialogTitleBox.Text;
        if (int.TryParse(DialogWidthBox.Text, out var width)) _model.Width = Math.Clamp(width, 1, 32767);
        if (int.TryParse(DialogHeightBox.Text, out var height)) _model.Height = Math.Clamp(height, 1, 32767);
        RefreshEditor();
    }

    private void ControlProperty_LostFocus(object sender, RoutedEventArgs e)
    {
        var control = SelectedControl;
        if (control is null) return;
        if (int.TryParse(ControlIdBox.Text, out var controlId)) control.ControlId = Math.Clamp(controlId, 0, 65535);
        if (int.TryParse(ControlHelpIdBox.Text, out var helpId)) control.HelpId = Math.Max(0, helpId);
        control.Class = ParseValue(ControlClassBox.Text);
        control.Title = ControlTextBox.Text;
        if (int.TryParse(ControlXBox.Text, out var x)) control.X = Math.Clamp(x, -32768, 32767);
        if (int.TryParse(ControlYBox.Text, out var y)) control.Y = Math.Clamp(y, -32768, 32767);
        if (int.TryParse(ControlWidthBox.Text, out var width)) control.Width = Math.Clamp(width, 1, 32767);
        if (int.TryParse(ControlHeightBox.Text, out var height)) control.Height = Math.Clamp(height, 1, 32767);
        if (TryParseInteger(ControlStyleBox.Text, out var style)) control.Style = style;
        if (TryParseInteger(ControlExstyleBox.Text, out var exstyle)) control.Exstyle = exstyle;
        RefreshEditor();
        ControlsList.SelectedItem = control;
    }

    private void AddButton_Click(object sender, RoutedEventArgs e)
    {
        _model.Controls.Add(new ControlModel { ControlId = NextId(), X = 16, Y = 30 + _model.Controls.Count * 24, Width = 70, Height = 20, Class = 0x0080, Title = "Button" });
        RefreshEditor();
    }

    private void AddLabel_Click(object sender, RoutedEventArgs e)
    {
        _model.Controls.Add(new ControlModel { ControlId = NextId(), X = 16, Y = 30 + _model.Controls.Count * 24, Width = 100, Height = 18, Class = 0x0082, Title = "Label" });
        RefreshEditor();
    }

    private void AddEdit_Click(object sender, RoutedEventArgs e) => AddControl(0x0081, "Edit", 110, 20);

    private void AddList_Click(object sender, RoutedEventArgs e) => AddControl(0x0083, "List", 120, 45);

    private void AddCombo_Click(object sender, RoutedEventArgs e) => AddControl(0x0085, "Combo", 120, 22);

    private void AddControl(int className, string title, int width, int height)
    {
        _model.Controls.Add(new ControlModel { ControlId = NextId(), X = 16, Y = 30 + _model.Controls.Count * 24, Width = width, Height = height, Class = className, Title = title });
        RefreshEditor();
        ControlsList.SelectedIndex = _model.Controls.Count - 1;
    }

    private void DeleteControl_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedControl is not ControlModel control) return;
        _model.Controls.Remove(control);
        RefreshEditor();
    }

    private void DuplicateControl_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedControl is not ControlModel control) return;
        var copy = new ControlModel { ControlId = NextId(), X = control.X + 8, Y = control.Y + 8, Width = control.Width, Height = control.Height, Style = control.Style, Exstyle = control.Exstyle, Class = control.Class, Title = control.Title, CreationDataHex = control.CreationDataHex, HelpId = control.HelpId };
        _model.Controls.Add(copy);
        RefreshEditor();
        ControlsList.SelectedItem = copy;
    }

    private int NextId() => _model.Controls.Count == 0 ? 100 : _model.Controls.Max(item => item.ControlId) + 1;

    private void Control_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not FrameworkElement visual || visual.Tag is not ControlModel control) return;
        ControlsList.SelectedItem = control;
        _draggedVisual = DesignCanvas;
        _dragStart = e.GetPosition(DesignCanvas);
        _dragStartX = control.X;
        _draggedVisual.Tag = control;
        DesignCanvas.CaptureMouse();
        e.Handled = true;
    }

    private void Canvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) { }

    private void Canvas_MouseMove(object sender, MouseEventArgs e)
    {
        if (_draggedVisual is null || e.LeftButton != MouseButtonState.Pressed || _draggedVisual.Tag is not ControlModel control) return;
        var point = e.GetPosition(DesignCanvas);
        control.X = Math.Clamp(_dragStartX + (int)((point.X - _dragStart.X) / 2), -32768, 32767);
        control.Y = Math.Clamp(control.Y + (int)((point.Y - _dragStart.Y) / 2), -32768, 32767);
        _dragStart = point;
        _dragStartX = control.X;
        RefreshEditor();
        ControlsList.SelectedItem = control;
    }

    private void Canvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        _draggedVisual = null;
        DesignCanvas.ReleaseMouseCapture();
    }

    private void LoadJson_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Dialog JSON (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;
        try
        {
            _model = JsonSerializer.Deserialize<DialogModel>(File.ReadAllText(dialog.FileName), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? NewModel();
            RefreshEditor();
        }
        catch (Exception exc) { MessageBox.Show(exc.Message, "Dialog JSON", MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void SaveJson_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "Dialog JSON (*.json)|*.json", FileName = "dialog.json" };
        if (dialog.ShowDialog() != true) return;
        File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(_model, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
        StatusText.Text = "Dialog JSON saved";
    }

    private async void LoadFromPe_Click(object sender, RoutedEventArgs e)
    {
        if (_cliPath is null || !File.Exists(_cliPath)) { MessageBox.Show("resource_studio_cli.py was not found."); return; }
        if (!File.Exists(PePathBox.Text)) { MessageBox.Show("Select a PE path first."); return; }
        var temp = Path.Combine(Path.GetTempPath(), "resource-studio-dialog-" + Guid.NewGuid().ToString("N") + ".json");
        var result = await RunCliAsync("dialog", "export", PePathBox.Text, "--name", ResourceNameBox.Text, "--language", LanguageBox.Text, "--output", temp, "--json");
        if (result.ExitCode != 0) return;
        try { _model = JsonSerializer.Deserialize<DialogModel>(File.ReadAllText(temp), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? NewModel(); RefreshEditor(); }
        finally { TryDelete(temp); }
    }

    private async void SaveAsPe_Click(object sender, RoutedEventArgs e)
    {
        if (_cliPath is null || !File.Exists(_cliPath)) { MessageBox.Show("resource_studio_cli.py was not found."); return; }
        if (!File.Exists(PePathBox.Text)) { MessageBox.Show("Select a PE path first."); return; }
        var dialog = new SaveFileDialog { Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*", FileName = "dialog-edited.dll" };
        if (dialog.ShowDialog() != true) return;
        var model = Path.Combine(Path.GetTempPath(), "resource-studio-dialog-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(model, JsonSerializer.Serialize(_model, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
        try { await RunCliAsync("dialog", "apply", PePathBox.Text, "--name", ResourceNameBox.Text, "--language", LanguageBox.Text, "--model", model, "--output", dialog.FileName, "--json"); }
        finally { TryDelete(model); }
    }

    private async Task<CliProcessRunner.Result> RunCliAsync(params string[] arguments)
    {
        using var cancellation = new CancellationTokenSource();
        _cliCancellation = cancellation;
        StopCliButton.IsEnabled = true;
        StatusText.Text = "Dialog operation running";
        try
        {
            var result = await CliProcessRunner.RunAsync(_cliPath!, arguments, cancellation.Token);
            var report = VerificationSummary.Format(result.Output);
            VerificationSummaryText.Text = report;
            VerificationSummaryText.Visibility = string.IsNullOrWhiteSpace(report) ? Visibility.Collapsed : Visibility.Visible;
            StatusText.Text = result.Stopped ? "Stopped — input unchanged" : result.ExitCode == 0 ? "Dialog operation completed" : "Dialog operation failed — see details";
            if (result.ExitCode != 0 && !result.Stopped) MessageBox.Show(result.Output, "Dialog operation failed", MessageBoxButton.OK, MessageBoxImage.Error);
            return result;
        }
        catch (Exception exc)
        {
            StatusText.Text = "Dialog operation failed — see details";
            VerificationSummaryText.Text = $"FAIL {exc.Message}";
            VerificationSummaryText.Visibility = Visibility.Visible;
            MessageBox.Show(exc.Message, "Dialog operation failed", MessageBoxButton.OK, MessageBoxImage.Error);
            return new CliProcessRunner.Result(2, exc.ToString(), false);
        }
        finally
        {
            _cliCancellation = null;
            StopCliButton.IsEnabled = false;
        }
    }

    private void StopCli_Click(object sender, RoutedEventArgs e) => _cliCancellation?.Cancel();

    private static string FormatValue(object value) => value is JsonElement element ? element.ToString() : value?.ToString() ?? "";

    private static int? GetClassNumber(object value)
    {
        if (value is int number) return number;
        if (value is JsonElement element && element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var parsed)) return parsed;
        return null;
    }

    private static object ParseValue(string text)
    {
        text = text.Trim();
        return TryParseInteger(text, out var value) ? value : text;
    }

    private static bool TryParseInteger(string text, out int value)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return int.TryParse(text[2..], System.Globalization.NumberStyles.HexNumber, null, out value);
        return int.TryParse(text, out value);
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}
