using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class ImageResourceWindow : Window
{
    private readonly string _cliPath;
    private string? _payloadPath;
    private string? _individualPreviewPath;
    private readonly List<GroupEntry> _entries = new();
    private CancellationTokenSource? _cliCancellation;

    public ImageResourceWindow(string cliPath, string? selectedPe, string? defaultKind = null)
    {
        InitializeComponent();
        _cliPath = cliPath;
        PePathBox.Text = selectedPe ?? "";
        if (string.Equals(defaultKind, "icon", StringComparison.OrdinalIgnoreCase)) KindBox.SelectedIndex = 1;
        else if (string.Equals(defaultKind, "cursor", StringComparison.OrdinalIgnoreCase)) KindBox.SelectedIndex = 2;
    }

    private string Kind => ((System.Windows.Controls.ComboBoxItem)KindBox.SelectedItem).Content?.ToString() ?? "bitmap";

    private async void Load_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(PePathBox.Text)) { SetStatus("Choose a PE file first."); return; }
        var extension = Kind == "bitmap" ? ".bmp" : ".json";
        var temporary = Path.Combine(Path.GetTempPath(), $"resource-studio-image-{Guid.NewGuid():N}{extension}");
        try
        {
            var result = await RunCliAsync("image-resource", "export", PePathBox.Text, "--kind", Kind, "--name", NameBox.Text, "--language", LanguageBox.Text, "--output", temporary, "--json");
            if (result.ExitCode != 0) { SetStatus(result.Output); return; }
            _payloadPath = temporary;
            if (Kind == "bitmap")
            {
                ImagePreview.Source = new BitmapImage(new Uri(temporary));
                ModelBox.Text = result.Output;
                GroupEntriesList.ItemsSource = null;
            }
            else
            {
                ModelBox.Text = File.ReadAllText(temporary);
                LoadGroupModel(ModelBox.Text);
            }
            SetStatus("Image resource loaded from PE.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
    }

    private void ChoosePayload_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = Kind == "bitmap" ? "BMP files (*.bmp)|*.bmp|All files (*.*)|*.*" : "Image models (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;
        _payloadPath = dialog.FileName;
        if (Kind == "bitmap")
        {
            ImagePreview.Source = new BitmapImage(new Uri(dialog.FileName));
            GroupEntriesList.ItemsSource = null;
        }
        else
        {
            ModelBox.Text = File.ReadAllText(dialog.FileName);
            LoadGroupModel(ModelBox.Text);
        }
        SetStatus("Payload selected.");
    }

    private async void GroupEntriesList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (GroupEntriesList.SelectedItem is not GroupEntry entry) return;
        EntryWidthBox.Text = entry.Width.ToString();
        EntryHeightBox.Text = entry.Height.ToString();
        EntryIdBox.Text = entry.ResourceId.ToString();
        await LoadSelectedPayloadPreviewAsync(entry);
    }

    private async Task LoadSelectedPayloadPreviewAsync(GroupEntry entry)
    {
        if (Kind == "bitmap" || !File.Exists(PePathBox.Text)) return;
        try
        {
            var temporary = Path.Combine(Path.GetTempPath(), $"resource-studio-icon-preview-{Guid.NewGuid():N}.bmp");
            var result = await RunCliAsync("image-payload", "export", PePathBox.Text, "--kind", Kind, "--resource-id", entry.ResourceId.ToString(), "--language", LanguageBox.Text, "--output", temporary, "--format", "bmp", "--json");
            if (result.ExitCode != 0) { SetStatus($"Payload preview unavailable: {result.Output}"); return; }
            if (_individualPreviewPath is not null) TryDelete(_individualPreviewPath);
            _individualPreviewPath = temporary;
            ImagePreview.Source = LoadBitmap(temporary);
            System.Windows.Automation.AutomationProperties.SetName(ImagePreview, $"BMP preview {entry.Label}");
            SetStatus($"Previewing {entry.Label} as BMP.");
        }
        catch (Exception exc) { SetStatus($"Payload preview unavailable: {exc.Message}"); }
    }

    private void UpdateEntry_Click(object sender, RoutedEventArgs e)
    {
        if (GroupEntriesList.SelectedItem is not GroupEntry entry) { SetStatus("Select an image entry first."); return; }
        if (!int.TryParse(EntryWidthBox.Text, out var width) || !int.TryParse(EntryHeightBox.Text, out var height) || !int.TryParse(EntryIdBox.Text, out var id) || width < 0 || width > 255 || height < 0 || height > 255 || id < 0 || id > 65535)
        {
            SetStatus("Width, height, and resource ID are invalid."); return;
        }
        entry.Width = width; entry.Height = height; entry.ResourceId = id;
        GroupEntriesList.Items.Refresh();
        SyncGroupModel();
        SetStatus("Image entry updated; apply Save As to commit it.");
    }

    private void AddEntry_Click(object sender, RoutedEventArgs e)
    {
        if (Kind == "bitmap") { SetStatus("Bitmap resources do not contain a group list."); return; }
        var entry = new GroupEntry { Width = 32, Height = 32, BytesInResource = 1, PlanesOrHotspotX = 1, BitCountOrHotspotY = 32, ResourceId = _entries.Count + 1 };
        _entries.Add(entry); GroupEntriesList.Items.Refresh(); GroupEntriesList.SelectedItem = entry; SyncGroupModel();
        SetStatus("Image entry added; supply its resource ID before applying.");
    }

    private void RemoveEntry_Click(object sender, RoutedEventArgs e)
    {
        if (GroupEntriesList.SelectedItem is not GroupEntry entry) { SetStatus("Select an image entry first."); return; }
        _entries.Remove(entry); GroupEntriesList.Items.Refresh(); SyncGroupModel();
        SetStatus("Image entry removed; apply Save As to commit it.");
    }

    private void LoadGroupModel(string text)
    {
        try
        {
            var model = JsonSerializer.Deserialize<GroupModel>(text, JsonOptions) ?? throw new InvalidOperationException("image group model is empty");
            _entries.Clear(); _entries.AddRange(model.Entries ?? new List<GroupEntry>());
            GroupEntriesList.ItemsSource = _entries;
            if (_entries.Count > 0) GroupEntriesList.SelectedIndex = 0;
        }
        catch (Exception exc) { GroupEntriesList.ItemsSource = null; SetStatus($"Group model unavailable: {exc.Message}"); }
    }

    private void SyncGroupModel()
    {
        if (Kind == "bitmap") return;
        var model = new GroupModel { Format = "resource_studio.image_group.v1", Kind = Kind.ToUpperInvariant(), Entries = _entries };
        ModelBox.Text = JsonSerializer.Serialize(model, JsonOptions);
    }

    private async void ExportPayload_Click(object sender, RoutedEventArgs e)
    {
        if (Kind == "bitmap" || GroupEntriesList.SelectedItem is not GroupEntry entry) { SetStatus("Select an Icon/Cursor entry first."); return; }
        var dialog = new SaveFileDialog { Filter = "Bitmap files (*.bmp)|*.bmp|All files (*.*)|*.*", FileName = $"{Kind}-{entry.ResourceId}.bmp" };
        if (dialog.ShowDialog() != true) return;
        var result = await RunCliAsync("image-payload", "export", PePathBox.Text, "--kind", Kind, "--resource-id", entry.ResourceId.ToString(), "--language", LanguageBox.Text, "--output", dialog.FileName, "--format", "bmp", "--json");
        SetStatus(result.ExitCode == 0 ? $"Payload exported to {dialog.FileName}" : result.Output);
    }

    private async void ApplyPayload_Click(object sender, RoutedEventArgs e)
    {
        if (Kind == "bitmap" || GroupEntriesList.SelectedItem is not GroupEntry entry) { SetStatus("Select an Icon/Cursor entry first."); return; }
        var payloadDialog = new OpenFileDialog { Filter = "Image files (*.bmp;*.png)|*.bmp;*.png|Bitmap files (*.bmp)|*.bmp|PNG files (*.png)|*.png|All files (*.*)|*.*" };
        if (payloadDialog.ShowDialog() != true) return;
        var outputDialog = new SaveFileDialog { Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*", FileName = Path.GetFileNameWithoutExtension(PePathBox.Text) + ".payload" + Path.GetExtension(PePathBox.Text) };
        if (outputDialog.ShowDialog() != true) return;
        var result = await RunCliAsync("image-payload", "apply", PePathBox.Text, "--kind", Kind, "--resource-id", entry.ResourceId.ToString(), "--language", LanguageBox.Text, "--payload", payloadDialog.FileName, "--format", "bmp", "--output", outputDialog.FileName, "--json");
        SetStatus(result.ExitCode == 0 ? $"Payload applied to {outputDialog.FileName}" : result.Output);
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(PePathBox.Text)) { SetStatus("Choose a PE file first."); return; }
        if (Kind != "bitmap") SyncGroupModel();
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
            var result = await RunCliAsync("image-resource", "apply", PePathBox.Text, "--kind", Kind, "--name", NameBox.Text, "--language", LanguageBox.Text, "--model", payload, "--output", outputDialog.FileName, "--json");
            SetStatus(result.ExitCode == 0 ? $"Applied to {outputDialog.FileName}" : result.Output);
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { if (payload != _payloadPath) File.Delete(payload); }
    }

    private static BitmapImage LoadBitmap(string path)
    {
        var image = new BitmapImage();
        image.BeginInit(); image.CacheOption = BitmapCacheOption.OnLoad; image.UriSource = new Uri(path); image.EndInit(); image.Freeze();
        return image;
    }

    private static void TryDelete(string path) { try { File.Delete(path); } catch { } }

    private async Task<CliProcessRunner.Result> RunCliAsync(params string[] arguments)
    {
        using var cancellation = new CancellationTokenSource();
        _cliCancellation = cancellation;
        StopCliButton.IsEnabled = true;
        SetStatus("Image operation running");
        try
        {
            var result = await CliProcessRunner.RunAsync(_cliPath, arguments, cancellation.Token);
            ShowVerificationSummary(result.Output);
            SetStatus(result.Stopped ? "Stopped — input unchanged" : result.ExitCode == 0 ? "Image operation completed" : "Image operation failed — see details");
            return result;
        }
        catch (Exception exc)
        {
            ShowVerificationSummary($"{{\"errors\":[\"{exc.Message.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"]}}");
            SetStatus($"Image operation failed: {exc.Message}");
            return new CliProcessRunner.Result(2, exc.ToString(), false);
        }
        finally
        {
            _cliCancellation = null;
            StopCliButton.IsEnabled = false;
        }
    }

    private void StopCli_Click(object sender, RoutedEventArgs e) => _cliCancellation?.Cancel();

    private void ShowVerificationSummary(string output)
    {
        var report = VerificationSummary.Format(output);
        VerificationSummaryText.Text = report;
        VerificationSummaryText.Visibility = string.IsNullOrWhiteSpace(report) ? Visibility.Collapsed : Visibility.Visible;
    }

    private void SetStatus(string text) => StatusText.Text = text;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
    private sealed class GroupModel
    {
        [JsonPropertyName("format")] public string Format { get; set; } = "resource_studio.image_group.v1";
        [JsonPropertyName("kind")] public string Kind { get; set; } = "ICON";
        [JsonPropertyName("entries")] public List<GroupEntry> Entries { get; set; } = new();
    }
    private sealed class GroupEntry
    {
        [JsonPropertyName("width")] public int Width { get; set; }
        [JsonPropertyName("height")] public int Height { get; set; }
        [JsonPropertyName("colorCount")] public int ColorCount { get; set; }
        [JsonPropertyName("planesOrHotspotX")] public int PlanesOrHotspotX { get; set; }
        [JsonPropertyName("bitCountOrHotspotY")] public int BitCountOrHotspotY { get; set; }
        [JsonPropertyName("bytesInResource")] public int BytesInResource { get; set; }
        [JsonPropertyName("resourceId")] public int ResourceId { get; set; }
        [JsonIgnore] public string Label => $"{Width}x{Height} · ID {ResourceId}";
    }
}
