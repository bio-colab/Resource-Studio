using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace ResourceStudio.Windows;

internal static class CliProcessRunner
{
    internal sealed record Result(int ExitCode, string Output, bool Stopped);

    public static async Task<Result> RunAsync(string cliPath, IEnumerable<string> arguments, CancellationToken cancellationToken, IReadOnlyDictionary<string, string>? environment = null)
    {
        var started = Stopwatch.GetTimestamp();
        var argumentList = arguments.ToArray();
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
            var stopped = new Result(130, "Operation stopped; input unchanged.", true);
            AppendTelemetry(cliPath, argumentList, stopped, started);
            return stopped;
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var result = new Result(process.ExitCode, string.IsNullOrWhiteSpace(stdout) ? stderr : stdout, false);
        AppendTelemetry(cliPath, argumentList, result, started);
        return result;
    }

    private static void AppendTelemetry(string cliPath, IReadOnlyList<string> arguments, Result result, long started)
    {
        var destination = Environment.GetEnvironmentVariable("RESOURCE_STUDIO_P0_TELEMETRY_PATH");
        if (string.IsNullOrWhiteSpace(destination)) return;
        var payload = new
        {
            schema = "resource_studio.p0_wpf_telemetry.v1",
            operation = "wpf.cli-process",
            elapsedMs = Math.Round(Stopwatch.GetElapsedTime(started).TotalMilliseconds, 3),
            processSpawned = 1,
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
