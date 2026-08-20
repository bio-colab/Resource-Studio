using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;

namespace ResourceStudio.Windows;

public partial class StringTableEditorWindow : Window
{
    private readonly List<StringRow> _rows = new();
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly string _cliPath;

    public StringTableEditorWindow(string cliPath, string? selectedPe)
    {
        InitializeComponent();
        _cliPath = cliPath;
        if (!string.IsNullOrWhiteSpace(selectedPe)) PePathBox.Text = selectedPe;
        ResetRows(1);
    }

    private void LoadPe_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(PePathBox.Text))
        {
            MessageBox.Show("Choose a PE file first.", "StringTable", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!int.TryParse(BlockBox.Text, out var block) || block is < 1 or > 65535 || !int.TryParse(LanguageBox.Text, out var language))
        {
            SetStatus("Block must be 1..65535 and language must be numeric.");
            return;
        }
        var temporary = Path.Combine(Path.GetTempPath(), $"resource-studio-string-{Guid.NewGuid():N}.json");
        try
        {
            var result = RunCli("string-table", "export", PePathBox.Text, "--name", block.ToString(), "--language", language.ToString(), "--output", temporary, "--json");
            if (result.ExitCode != 0) { SetStatus(result.Output); return; }
            LoadModel(JsonSerializer.Deserialize<StringTableModel>(File.ReadAllText(temporary), _jsonOptions) ?? throw new InvalidDataException("empty StringTable model"));
            SetStatus("StringTable loaded from PE.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private void LoadJson_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "StringTable JSON (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;
        try
        {
            LoadModel(JsonSerializer.Deserialize<StringTableModel>(File.ReadAllText(dialog.FileName), _jsonOptions) ?? throw new InvalidDataException("empty StringTable model"));
            SetStatus("StringTable JSON loaded.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
    }

    private void SaveJson_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "StringTable JSON (*.json)|*.json|All files (*.*)|*.*", FileName = "string-table.json" };
        if (dialog.ShowDialog() != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(BuildModel(), new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
            SetStatus("StringTable JSON saved.");
        }
        catch (Exception exc) { SetStatus(exc.Message); }
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(PePathBox.Text)) { SetStatus("Choose a PE file first."); return; }
        var outputDialog = new SaveFileDialog { Filter = "PE files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*", FileName = Path.GetFileNameWithoutExtension(PePathBox.Text) + ".stringtable" + Path.GetExtension(PePathBox.Text) };
        if (outputDialog.ShowDialog() != true) return;
        var temporary = Path.Combine(Path.GetTempPath(), $"resource-studio-string-{Guid.NewGuid():N}.json");
        try
        {
            var model = BuildModel();
            File.WriteAllText(temporary, JsonSerializer.Serialize(model, new JsonSerializerOptions { WriteIndented = true }), Encoding.UTF8);
            var result = RunCli("string-table", "apply", PePathBox.Text, "--name", BlockBox.Text, "--language", LanguageBox.Text, "--model", temporary, "--output", outputDialog.FileName, "--json");
            SetStatus(result.ExitCode == 0 ? $"Applied to {outputDialog.FileName}" : result.Output);
        }
        catch (Exception exc) { SetStatus(exc.Message); }
        finally { File.Delete(temporary); }
    }

    private void LoadModel(StringTableModel model)
    {
        if (model.Format != "resource_studio.string_table.v1" || model.Strings is null || model.Strings.Count != 16 || model.Strings.Any(value => value is null)) throw new InvalidDataException("StringTable model must contain exactly 16 strings.");
        BlockBox.Text = model.BlockId.ToString();
        ResetRows(model.BlockId);
        for (var index = 0; index < 16; index++) _rows[index].Text = model.Strings[index] ?? "";
        StringsGrid.Items.Refresh();
    }

    private StringTableModel BuildModel()
    {
        if (!int.TryParse(BlockBox.Text, out var block) || block is < 1 or > 65535) throw new InvalidDataException("Block must be 1..65535.");
        if (_rows.Count != 16) throw new InvalidDataException("StringTable must contain 16 slots.");
        if (_rows.Any(row => row.Text.Contains('\0') || row.Text.Length > 65535)) throw new InvalidDataException("StringTable text contains NUL or is too long.");
        return new StringTableModel("resource_studio.string_table.v1", block, _rows.Select(row => row.Text).ToList());
    }

    private void ResetRows(int block)
    {
        _rows.Clear();
        var first = (block - 1) * 16 + 1;
        for (var index = 0; index < 16; index++) _rows.Add(new StringRow(first + index, ""));
        StringsGrid.ItemsSource = _rows;
    }

    private CliResult RunCli(params string[] arguments)
    {
        var info = new ProcessStartInfo("py.exe") { WorkingDirectory = Path.GetDirectoryName(_cliPath) ?? Environment.CurrentDirectory, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        info.ArgumentList.Add("-3.12");
        info.ArgumentList.Add(_cliPath);
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start Python CLI");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new CliResult(process.ExitCode, string.IsNullOrWhiteSpace(stdout) ? stderr : stdout);
    }

    private void SetStatus(string text) => StatusText.Text = text;

    private sealed class StringRow
    {
        public int Id { get; }
        public string Text { get; set; }
        public StringRow(int id, string text) { Id = id; Text = text; }
    }

    private sealed record StringTableModel(string Format, int BlockId, List<string> Strings);
    private sealed record CliResult(int ExitCode, string Output);
}
