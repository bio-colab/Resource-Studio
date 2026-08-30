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
        RefreshMenuSelection();
    }

    private void MenuTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e) => RefreshMenuSelection();

    private int? SelectedMenuId => MenuTree.SelectedItem is System.Windows.Controls.TreeViewItem node && node.Tag is int id ? id : null;

    private void RefreshMenuSelection()
    {
        if (SelectedMenuId is not int id || !TryGetMenuNode(id, out var node, out _, out _))
        {
            MenuItemIdBox.Text = "";
            MenuItemTextBox.Text = "";
            MenuItemFlagsBox.Text = "";
            MenuItemKindText.Text = "No item selected";
            return;
        }
        MenuItemIdBox.Text = node!["id"]?.ToString() ?? "";
        MenuItemTextBox.Text = node["text"]?.ToString() ?? "";
        var flags = node["flags"]?.GetValue<int>() ?? 0;
        MenuItemFlagsBox.Text = $"0x{flags:X}";
        var children = node["children"] as JsonArray;
        var kind = (flags & 0x0800) != 0 ? "SEPARATOR" : (flags & 0x0010) != 0 || children is { Count: > 0 } ? "POPUP" : "ITEM";
        MenuItemKindText.Text = $"{kind} • flags 0x{flags:X} • children {children?.Count ?? 0}";
    }

    private static System.Windows.Controls.TreeViewItem BuildMenuNode(JsonElement item)
    {
        var id = item.TryGetProperty("id", out var idValue) ? idValue.ToString() : "?";
        var text = item.TryGetProperty("text", out var textValue) ? textValue.ToString() : "";
        var flags = item.TryGetProperty("flags", out var flagsValue) && flagsValue.TryGetInt32(out var parsedFlags) ? parsedFlags : 0;
        var kind = (flags & 0x0800) != 0 ? "[SEP]" : (flags & 0x0010) != 0 ? "[POPUP]" : "[ITEM]";
        var node = new System.Windows.Controls.TreeViewItem { Header = $"{id}: {kind} {text} 0x{flags:X}", Tag = int.TryParse(id, out var numericId) ? numericId : null };
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

    private bool TryGetMenuNode(int id, out JsonObject? node, out JsonArray? parent, out int index)
    {
        try
        {
            var root = JsonNode.Parse(MenuJsonBox.Text)?.AsObject();
            var items = root?["items"] as JsonArray;
            node = null;
            parent = null;
            index = -1;
            return items is not null && FindMenuNodeWithParent(items, id, out node, out parent, out index);
        }
        catch (JsonException)
        {
            node = null;
            parent = null;
            index = -1;
            return false;
        }
    }

    private static bool FindMenuNodeWithParent(JsonArray items, int id, out JsonObject? node, out JsonArray? parent, out int index)
    {
        for (var i = 0; i < items.Count; i++)
        {
            if (items[i] is not JsonObject candidate) continue;
            if (candidate["id"]?.GetValue<int>() == id) { node = candidate; parent = items; index = i; return true; }
            if (candidate["children"] is JsonArray children && FindMenuNodeWithParent(children, id, out node, out parent, out index)) return true;
        }
        node = null;
        parent = null;
        index = -1;
        return false;
    }

    private static int NextMenuId(JsonArray items)
    {
        var ids = new List<int>();
        foreach (var item in items)
        {
            if (item?["id"]?.GetValue<int>() is int id) ids.Add(id);
            if (item?["children"] is JsonArray children) ids.Add(NextMenuId(children));
        }
        return ids.Count == 0 ? 1 : ids.Max() + 1;
    }

    private void MenuItemProperty_LostFocus(object sender, RoutedEventArgs e)
    {
        if (SelectedMenuId is not int selectedId || !TryGetMenuNode(selectedId, out var node, out _, out _)) return;
        if (!int.TryParse(MenuItemIdBox.Text, out var newId) || newId < 0) { SetStatus("Menu item ID must be a non-negative integer."); return; }
        if (!TryParseInteger(MenuItemFlagsBox.Text, out var flags) || flags < 0) { SetStatus("Menu flags must be decimal or hexadecimal."); return; }
        node!["id"] = newId;
        node["text"] = MenuItemTextBox.Text;
        node["flags"] = flags;
        MenuJsonBox.Text = JsonNode.Parse(MenuJsonBox.Text)!.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        SetStatus("Menu item updated; apply Save As to commit it.");
    }

    private void MenuAddRoot_Click(object sender, RoutedEventArgs e) => AddMenuItem(null, 0, "New Item");

    private void MenuAddChild_Click(object sender, RoutedEventArgs e) => AddMenuItem(SelectedMenuId, 0, "New Item");

    private void MenuAddSeparator_Click(object sender, RoutedEventArgs e) => AddMenuItem(SelectedMenuId, 0x0800, "");

    private void AddMenuItem(int? parentId, int flags, string text)
    {
        try
        {
            var root = JsonNode.Parse(MenuJsonBox.Text)?.AsObject() ?? throw new InvalidOperationException("invalid menu JSON");
            var items = root["items"] as JsonArray ?? throw new InvalidOperationException("menu JSON has no items");
            var item = new JsonObject { ["id"] = NextMenuId(items), ["text"] = text, ["flags"] = flags, ["children"] = new JsonArray() };
            if (parentId is int parent)
            {
                var target = FindMenuNode(items, parent) ?? throw new InvalidOperationException("selected menu parent was not found");
                target["flags"] = (target["flags"]?.GetValue<int>() ?? 0) | 0x0010;
                var children = target["children"] as JsonArray ?? new JsonArray();
                target["children"] = children;
                children.Add(item);
            }
            else items.Add(item);
            MenuJsonBox.Text = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
            SetStatus("Menu item added; apply Save As to commit it.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
    }

    private void MenuDelete_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedMenuId is not int id) return;
        try
        {
            var root = JsonNode.Parse(MenuJsonBox.Text)?.AsObject() ?? throw new InvalidOperationException("invalid menu JSON");
            var items = root["items"] as JsonArray ?? throw new InvalidOperationException("menu JSON has no items");
            if (items.Count == 1 && FindMenuNodeWithParent(items, id, out _, out var parent, out _) && parent == items) { SetStatus("A menu must retain at least one root item."); return; }
            if (!RemoveMenuNode(items, id, out _)) throw new InvalidOperationException("selected menu item was not found");
            MenuJsonBox.Text = root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
            SetStatus("Menu item deleted; apply Save As to commit it.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
    }

    private void MenuMoveUp_Click(object sender, RoutedEventArgs e) => MoveMenuItem(-1);

    private void MenuMoveDown_Click(object sender, RoutedEventArgs e) => MoveMenuItem(1);

    private void MoveMenuItem(int delta)
    {
        if (SelectedMenuId is not int id || !TryGetMenuNode(id, out var node, out var parent, out var index) || parent is null) return;
        var target = index + delta;
        if (target < 0 || target >= parent.Count) return;
        parent.RemoveAt(index);
        parent.Insert(target, node);
        MenuJsonBox.Text = JsonNode.Parse(MenuJsonBox.Text)!.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        SetStatus("Menu order updated; apply Save As to commit it.");
    }

    private void MenuValidate_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var root = JsonNode.Parse(MenuJsonBox.Text)?.AsObject() ?? throw new InvalidOperationException("invalid menu JSON");
            var items = root["items"] as JsonArray;
            if (items is null || items.Count == 0) throw new InvalidOperationException("menu must contain at least one root item");
            var ids = new HashSet<int>();
            ValidateMenuItems(items, ids);
            SetStatus($"Menu valid: {ids.Count} unique items.");
        }
        catch (Exception exc) { SetStatus($"Menu invalid: {exc.Message}"); }
    }

    private static void ValidateMenuItems(JsonArray items, HashSet<int> ids)
    {
        foreach (var item in items)
        {
            var id = item?["id"]?.GetValue<int>() ?? throw new InvalidOperationException("menu item ID is required");
            var flags = item?["flags"]?.GetValue<int>() ?? 0;
            if (!(id == 0 && (flags & 0x0800) != 0) && !ids.Add(id)) throw new InvalidOperationException($"duplicate menu item ID {id}");
            if (item?["children"] is JsonArray children) ValidateMenuItems(children, ids);
        }
    }

    private static bool TryParseInteger(string value, out int result)
    {
        value = value.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return int.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out result);
        return int.TryParse(value, out result);
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
