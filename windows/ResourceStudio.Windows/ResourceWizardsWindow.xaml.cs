using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class ResourceWizardsWindow : Window
{
    private readonly string _cliPath;
    private CancellationTokenSource? _cliCancellation;

    public ResourceWizardsWindow(string cliPath, string? selectedPe)
    {
        InitializeComponent();
        _cliPath = cliPath;
        VersionPeBox.Text = selectedPe ?? "";
        ManifestPeBox.Text = selectedPe ?? "";
        MenuPeBox.Text = selectedPe ?? "";
    }

    private async void VersionExport_Click(object sender, RoutedEventArgs e)
    {
        await ExportModelAsync("version-resource", VersionPeBox.Text, VersionNameBox.Text, VersionLanguageBox.Text, value => VersionJsonBox.Text = value);
    }

    private async void VersionApply_Click(object sender, RoutedEventArgs e)
    {
        await ApplyModelAsync("version-resource", VersionPeBox.Text, VersionNameBox.Text, VersionLanguageBox.Text, VersionJsonBox.Text);
    }

    private async void ManifestExport_Click(object sender, RoutedEventArgs e)
    {
        var temporary = TempFile("manifest");
        try
        {
            var result = await RunCliAsync("manifest-resource", "export", ManifestPeBox.Text, "--language", ManifestLanguageBox.Text, "--output", temporary, "--json");
            if (result.ExitCode != 0) { SetStatus(result.Output); return; }
            using var document = JsonDocument.Parse(File.ReadAllText(temporary));
            ManifestXmlBox.Text = document.RootElement.GetProperty("xml").GetString() ?? "";
            SetStatus("Manifest loaded from PE.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private async void ManifestApply_Click(object sender, RoutedEventArgs e)
    {
        var model = JsonSerializer.Serialize(new { format = "resource_studio.manifest.v1", xml = ManifestXmlBox.Text });
        await ApplyModelAsync("manifest-resource", ManifestPeBox.Text, "1", ManifestLanguageBox.Text, model);
    }

    private async void MenuExport_Click(object sender, RoutedEventArgs e)
    {
        await ExportModelAsync("menu-resource", MenuPeBox.Text, MenuNameBox.Text, MenuLanguageBox.Text, value => MenuJsonBox.Text = value);
    }

    private void MenuJsonBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        MenuTree.Items.Clear();
        try
        {
            using var document = JsonDocument.Parse(MenuJsonBox.Text);
            if (!document.RootElement.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array) return;
            foreach (var item in items.EnumerateArray()) MenuTree.Items.Add(BuildMenuNode(item));
        }
        catch (JsonException) { }
    }

    private static System.Windows.Controls.TreeViewItem BuildMenuNode(JsonElement item)
    {
        var id = item.TryGetProperty("id", out var idValue) ? idValue.ToString() : "?";
        var text = item.TryGetProperty("text", out var textValue) ? textValue.ToString() : "";
        var node = new System.Windows.Controls.TreeViewItem { Header = $"{id}: {text}", Tag = int.TryParse(id, out var numericId) ? numericId : null };
        if (item.TryGetProperty("children", out var children) && children.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in children.EnumerateArray()) node.Items.Add(BuildMenuNode(child));
        }
        return node;
    }

    private void MenuTree_PreviewMouseMove(object sender, MouseEventArgs e)
    {
        if (e.LeftButton != MouseButtonState.Pressed || MenuTree.SelectedItem is not System.Windows.Controls.TreeViewItem node || node.Tag is not int itemId) return;
        DragDrop.DoDragDrop(node, itemId, DragDropEffects.Move);
    }

    private void MenuTree_Drop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(typeof(int)) || !int.TryParse(e.Data.GetData(typeof(int))?.ToString(), out var itemId)) return;
        var target = FindTreeItem(e.OriginalSource as DependencyObject);
        var parentId = target?.Tag is int targetId && targetId != itemId ? targetId : (int?)null;
        try
        {
            var root = JsonNode.Parse(MenuJsonBox.Text)?.AsObject() ?? throw new InvalidOperationException("invalid menu JSON");
            var items = root["items"]?.AsArray() ?? throw new InvalidOperationException("menu JSON has no items");
            if (!RemoveMenuNode(items, itemId, out var moved)) throw new InvalidOperationException("dragged menu item was not found");
            if (parentId is int destination && ContainsMenuId(moved, destination)) throw new InvalidOperationException("cannot move a menu item below its descendant");
            var destinationItems = parentId is int parent ? FindMenuNode(items, parent)?["children"]?.AsArray() : items;
            if (destinationItems is null)
            {
                if (parentId is int) throw new InvalidOperationException("drop target was not found");
                destinationItems = items;
            }
            destinationItems.Add(moved);
            MenuJsonBox.Text = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
            SetStatus("Menu item moved; apply Save As to commit it.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
    }

    private static System.Windows.Controls.TreeViewItem? FindTreeItem(DependencyObject? source)
    {
        while (source is not null && source is not System.Windows.Controls.TreeViewItem) source = VisualTreeHelper.GetParent(source);
        return source as System.Windows.Controls.TreeViewItem;
    }

    private static bool RemoveMenuNode(JsonArray items, int id, out JsonNode? removed)
    {
        for (var index = 0; index < items.Count; index++)
        {
            var node = items[index];
            if (node?["id"]?.GetValue<int>() == id) { removed = node; items.RemoveAt(index); return true; }
            if (node?["children"] is JsonArray children && RemoveMenuNode(children, id, out removed)) return true;
        }
        removed = null;
        return false;
    }

    private static JsonObject? FindMenuNode(JsonArray items, int id)
    {
        foreach (var node in items)
        {
            if (node is not JsonObject obj) continue;
            if (obj["id"]?.GetValue<int>() == id) return obj;
            if (obj["children"] is JsonArray children)
            {
                var result = FindMenuNode(children, id);
                if (result is not null) return result;
            }
        }
        return null;
    }

    private static bool ContainsMenuId(JsonNode? node, int id)
    {
        if (node?["id"]?.GetValue<int>() == id) return true;
        return node?["children"] is JsonArray children && children.Any(child => ContainsMenuId(child, id));
    }

    private async void MenuApply_Click(object sender, RoutedEventArgs e)
    {
        await ApplyModelAsync("menu-resource", MenuPeBox.Text, MenuNameBox.Text, MenuLanguageBox.Text, MenuJsonBox.Text);
    }

    private async Task ExportModelAsync(string command, string pe, string name, string language, Action<string> setValue)
    {
        if (!File.Exists(pe)) { SetStatus("Choose a PE file first."); return; }
        var temporary = TempFile(command);
        try
        {
            var result = await RunCliAsync(command, "export", pe, "--name", name, "--language", language, "--output", temporary, "--json");
            if (result.ExitCode != 0) { SetStatus(result.Output); return; }
            setValue(File.ReadAllText(temporary));
            SetStatus($"{command} loaded from PE.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private async Task ApplyModelAsync(string command, string pe, string name, string language, string modelText)
    {
        if (!File.Exists(pe)) { SetStatus("Choose a PE file first."); return; }
        var outputDialog = new SaveFileDialog { Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*", FileName = Path.GetFileNameWithoutExtension(pe) + ".edited" + Path.GetExtension(pe) };
        if (outputDialog.ShowDialog() != true) return;
        var temporary = TempFile("model");
        try
        {
            JsonDocument.Parse(modelText);
            File.WriteAllText(temporary, modelText, Encoding.UTF8);
            var result = await RunCliAsync(command, "apply", pe, "--name", name, "--language", language, "--model", temporary, "--output", outputDialog.FileName, "--json");
            SetStatus(result.ExitCode == 0 ? $"Applied to {outputDialog.FileName}" : result.Output);
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private static string TempFile(string prefix) => Path.Combine(Path.GetTempPath(), $"resource-studio-{prefix}-{Guid.NewGuid():N}.json");

    private async Task<CliProcessRunner.Result> RunCliAsync(params string[] arguments)
    {
        using var cancellation = new CancellationTokenSource();
        _cliCancellation = cancellation;
        StopCliButton.IsEnabled = true;
        SetStatus("Resource operation running");
        try
        {
            var result = await CliProcessRunner.RunAsync(_cliPath, arguments, cancellation.Token);
            var report = VerificationSummary.Format(result.Output);
            VerificationSummaryText.Text = report;
            VerificationSummaryText.Visibility = string.IsNullOrWhiteSpace(report) ? Visibility.Collapsed : Visibility.Visible;
            SetStatus(result.Stopped ? "Stopped — input unchanged" : result.ExitCode == 0 ? "Resource operation completed" : "Resource operation failed — see details");
            return result;
        }
        catch (Exception exc)
        {
            SetStatus($"Resource operation failed: {exc.Message}");
            VerificationSummaryText.Text = $"FAIL {exc.Message}";
            VerificationSummaryText.Visibility = Visibility.Visible;
            return new CliProcessRunner.Result(2, exc.ToString(), false);
        }
        finally
        {
            _cliCancellation = null;
            StopCliButton.IsEnabled = false;
        }
    }

    private void StopCli_Click(object sender, RoutedEventArgs e) => _cliCancellation?.Cancel();

    private void SetStatus(string text) => StatusText.Text = text;
}
