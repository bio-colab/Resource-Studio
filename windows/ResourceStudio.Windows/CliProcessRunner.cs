using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace ResourceStudio.Windows;

internal sealed class CliHostStartupException : InvalidOperationException
{
    public CliHostStartupException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Persistent CLI executor process (tools/wpf_cli_host.py). One JSON request
/// per line in, one JSON response per line out. The host is stateless: every
/// request re-runs the CLI from scratch, so semantics are identical to
/// process-per-action without the per-action startup/import cost.
/// </summary>
internal sealed class CliHostConnection : IDisposable
{
    internal sealed record Roundtrip(bool StartedNew, int ExitCode, string Output, bool Stopped);

    private readonly string _cliPath;
    private readonly string _hostPath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private Task? _stderrDrain;
    private int _nextId;

    public CliHostConnection(string cliPath)
    {
        _cliPath = cliPath;
        _hostPath = Path.Combine(Path.GetDirectoryName(cliPath) ?? Environment.CurrentDirectory, "tools", "wpf_cli_host.py");
    }

    public async Task<Roundtrip> RunAsync(IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string>? environment, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var startedNew = await EnsureStartedAsync(cancellationToken);
            var process = _process ?? throw new InvalidOperationException("CLI host is not running");
            var request = new
            {
                id = Interlocked.Increment(ref _nextId),
                argv = arguments,
                env = environment,
            };
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(request));
            await process.StandardInput.FlushAsync(cancellationToken);
            var line = await process.StandardOutput.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                StopProcess();
                throw new InvalidOperationException("CLI host closed its protocol stream");
            }
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var exitCode = root.TryGetProperty("exitCode", out var exit) ? exit.GetInt32() : 2;
            var output = root.TryGetProperty("output", out var payload) ? payload.GetString() ?? string.Empty : string.Empty;
            var stopped = root.TryGetProperty("stopped", out var stoppedValue) && stoppedValue.GetBoolean();
            return new Roundtrip(startedNew, exitCode, output, stopped);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            StopProcess();
            throw;
        }
        catch
        {
            // Any protocol failure poisons the connection: the request status is
            // unknown, so never auto-retry through it. The next call starts fresh.
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

    private async Task<bool> EnsureStartedAsync(CancellationToken cancellationToken)
    {
        if (_process is { HasExited: false }) return false;
        if (!File.Exists(_hostPath)) throw new CliHostStartupException($"CLI host was not found: {_hostPath}");
        var info = new ProcessStartInfo("py.exe")
        {
            WorkingDirectory = Path.GetDirectoryName(_cliPath) ?? Environment.CurrentDirectory,
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
        try
        {
            _process = Process.Start(info) ?? throw new CliHostStartupException("Could not start CLI host");
        }
        catch (Win32Exception exc)
        {
            throw new CliHostStartupException("Could not start CLI host (py.exe)", exc);
        }
        _stderrDrain = _process.StandardError.ReadToEndAsync(cancellationToken);
        await Task.Yield();
        return true;
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
}

internal static class CliProcessRunner
{
    internal sealed record Result(int ExitCode, string Output, bool Stopped);

    // One persistent CLI host per CLI script path, shared across windows.
    // The host process exits on stdin EOF, i.e. when the WPF app exits.
    private static readonly ConcurrentDictionary<string, CliHostConnection> Hosts = new(StringComparer.OrdinalIgnoreCase);

    public static async Task<Result> RunAsync(string cliPath, IEnumerable<string> arguments, CancellationToken cancellationToken, IReadOnlyDictionary<string, string>? environment = null)
    {
        var started = Stopwatch.GetTimestamp();
        var argumentList = arguments.ToArray();
        var bundledExecutable = cliPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        if (!bundledExecutable)
        {
            var key = Path.GetFullPath(cliPath);
            var host = Hosts.GetOrAdd(key, _ => new CliHostConnection(cliPath));
            try
            {
                var roundtrip = await host.RunAsync(argumentList, environment, cancellationToken);
                var hostResult = new Result(roundtrip.ExitCode, roundtrip.Output, roundtrip.Stopped);
                AppendTelemetry(cliPath, argumentList, hostResult, started, mode: "host", processSpawned: roundtrip.StartedNew ? 1 : 0);
                return hostResult;
            }
            catch (CliHostStartupException)
            {
                // Host unavailable (missing tools/ or py.exe): degrade to the
                // classic per-action spawn so the operation still works.
                if (Hosts.TryRemove(key, out var broken)) broken.Dispose();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                var stopped = new Result(130, "Operation stopped; input unchanged.", true);
                AppendTelemetry(cliPath, argumentList, stopped, started, mode: "host", processSpawned: 0);
                return stopped;
            }
            catch
            {
                // Protocol failure: never auto-retry; the request status is unknown.
                var error = new Result(2, "error: CLI host stopped responding; the operation status is unknown. Retry the operation.", false);
                AppendTelemetry(cliPath, argumentList, error, started, mode: "host", processSpawned: 0);
                return error;
            }
        }

        var result = await SpawnAsync(cliPath, argumentList, cancellationToken, environment);
        AppendTelemetry(cliPath, argumentList, result, started, mode: "spawn", processSpawned: 1);
        return result;
    }

    private static async Task<Result> SpawnAsync(string cliPath, IReadOnlyList<string> argumentList, CancellationToken cancellationToken, IReadOnlyDictionary<string, string>? environment)
    {
        var bundledExecutable = cliPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        var info = new ProcessStartInfo(bundledExecutable ? cliPath : "py.exe")
        {
            WorkingDirectory = Path.GetDirectoryName(cliPath) ?? Environment.CurrentDirectory,
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
            info.ArgumentList.Add(cliPath);
        }
        foreach (var argument in argumentList) info.ArgumentList.Add(argument);
        if (environment is not null)
        {
            foreach (var pair in environment) info.Environment[pair.Key] = pair.Value;
        }

        using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start Python CLI");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        try
        {
            await Task.WhenAll(stdoutTask, stderrTask, process.WaitForExitAsync(cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            return new Result(130, "Operation stopped; input unchanged.", true);
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        return new Result(process.ExitCode, string.IsNullOrWhiteSpace(stdout) ? stderr : stdout, false);
    }

    private static void AppendTelemetry(string cliPath, IReadOnlyList<string> arguments, Result result, long started, string mode, int processSpawned)
    {
        var destination = Environment.GetEnvironmentVariable("RESOURCE_STUDIO_P0_TELEMETRY_PATH");
        if (string.IsNullOrWhiteSpace(destination)) return;
        var payload = new
        {
            schema = "resource_studio.p0_wpf_telemetry.v1",
            operation = "wpf.cli-process",
            elapsedMs = Math.Round(Stopwatch.GetElapsedTime(started).TotalMilliseconds, 3),
            processSpawned,
            mode,
            cliPath,
            arguments,
            exitCode = result.ExitCode,
            stopped = result.Stopped,
            processId = Environment.ProcessId,
        };
        try
        {
            var fullPath = Path.GetFullPath(destination);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory);
            lock (TelemetryLock)
            {
                File.AppendAllText(fullPath, JsonSerializer.Serialize(payload) + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch (IOException)
        {
            // P0 telemetry must never change the user-visible operation result.
        }
        catch (UnauthorizedAccessException)
        {
            // P0 telemetry must never change the user-visible operation result.
        }
    }

    private static readonly object TelemetryLock = new();
}
