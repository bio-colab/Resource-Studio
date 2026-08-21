using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ResourceStudio.Windows;

internal sealed class ReadHostClient : IDisposable
{
    internal sealed record Result(int ExitCode, string Output, bool Stopped);

    private readonly string _hostPath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private Task? _stderrDrain;
    private int _nextId;

    public ReadHostClient(string hostPath)
    {
        _hostPath = hostPath;
    }

    public async Task<Result> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        var started = Stopwatch.GetTimestamp();
        try
        {
            await EnsureStartedAsync(cancellationToken);
            var process = _process ?? throw new InvalidOperationException("Read host is not running");
            var request = new
            {
                id = Interlocked.Increment(ref _nextId),
                argv = arguments,
            };
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(request));
            await process.StandardInput.FlushAsync(cancellationToken);
            var line = await process.StandardOutput.ReadLineAsync(cancellationToken);
            if (line is null) throw new InvalidOperationException("Read host closed its protocol stream");
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var exitCode = root.TryGetProperty("exitCode", out var exit) ? exit.GetInt32() : 2;
            var output = root.TryGetProperty("output", out var payload) ? payload.GetString() ?? string.Empty : string.Empty;
            var stopped = root.TryGetProperty("stopped", out var stoppedValue) && stoppedValue.GetBoolean();
            AppendTelemetry(arguments, exitCode, stopped, started);
            return new Result(exitCode, output, stopped);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            StopProcess();
            AppendTelemetry(arguments, 130, true, started);
            return new Result(130, "Operation stopped; input unchanged.", true);
        }
        catch
        {
            StopProcess();
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        StopProcess();
        _gate.Dispose();
    }

    private async Task EnsureStartedAsync(CancellationToken cancellationToken)
    {
        if (_process is { HasExited: false }) return;
        if (!File.Exists(_hostPath)) throw new FileNotFoundException("WPF read host was not found", _hostPath);
        var info = new ProcessStartInfo("py.exe")
        {
            WorkingDirectory = Path.GetDirectoryName(_hostPath) is { } directory ? Directory.GetParent(directory)?.FullName ?? directory : Environment.CurrentDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        info.ArgumentList.Add("-3.12");
        info.ArgumentList.Add(_hostPath);
        _process = Process.Start(info) ?? throw new InvalidOperationException("Could not start WPF read host");
        _stderrDrain = _process.StandardError.ReadToEndAsync(cancellationToken);
        await Task.Yield();
    }

    private void StopProcess()
    {
        var process = _process;
        _process = null;
        if (process is null) return;
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) { }
        finally
        {
            process.Dispose();
            _stderrDrain = null;
        }
    }

    private static void AppendTelemetry(IReadOnlyList<string> arguments, int exitCode, bool stopped, long started)
    {
        var destination = Environment.GetEnvironmentVariable("RESOURCE_STUDIO_P0_TELEMETRY_PATH");
        if (string.IsNullOrWhiteSpace(destination)) return;
        var payload = new
        {
            schema = "resource_studio.p3_wpf_read_host_telemetry.v1",
            operation = "wpf.read-host",
            elapsedMs = Math.Round(Stopwatch.GetElapsedTime(started).TotalMilliseconds, 3),
            processSpawned = 0,
            arguments,
            exitCode,
            stopped,
            processId = Environment.ProcessId,
        };
        try
        {
            var fullPath = Path.GetFullPath(destination);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory);
            File.AppendAllText(fullPath, JsonSerializer.Serialize(payload) + Environment.NewLine, Encoding.UTF8);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
