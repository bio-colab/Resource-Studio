using System.Diagnostics;
using System.IO;
using System.Text;

namespace ResourceStudio.Windows;

internal static class CliProcessRunner
{
    internal sealed record Result(int ExitCode, string Output, bool Stopped);

    public static async Task<Result> RunAsync(string cliPath, IEnumerable<string> arguments, CancellationToken cancellationToken, IReadOnlyDictionary<string, string>? environment = null)
    {
        var info = new ProcessStartInfo("py.exe")
        {
            WorkingDirectory = Path.GetDirectoryName(cliPath) ?? Environment.CurrentDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        info.ArgumentList.Add("-3.12");
        info.ArgumentList.Add(cliPath);
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
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
}
