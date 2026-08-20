using System.Text;
using System.Text.Json;

namespace ResourceStudio.Windows;

internal static class VerificationSummary
{
    public static string Format(string output)
    {
        try
        {
            using var document = JsonDocument.Parse(output);
            if (!document.RootElement.TryGetProperty("verification", out var verification) || verification.ValueKind != JsonValueKind.Object)
            {
                return string.Empty;
            }

            var lines = new List<string>();
            var passed = verification.TryGetProperty("passed", out var passedValue) && passedValue.ValueKind == JsonValueKind.True;
            lines.Add($"{Mark(PhasePassed(verification, "STRUCTURAL_VALIDATION"))} Output is valid PE");

            var targetChanged = verification.TryGetProperty("targetChanged", out var targetValue) && targetValue.ValueKind == JsonValueKind.True;
            var roundTrip = verification.TryGetProperty("resourceRoundTrip", out var roundTripValue) && roundTripValue.ValueKind == JsonValueKind.True;
            lines.Add($"{Mark(targetChanged || IsNoOp(verification))} Target resource {(targetChanged ? "changed" : "unchanged (no-op preserved)")}");
            lines.Add($"{Mark(roundTrip)} Resource round-trip passed");

            var graphPassed = PhasePassed(verification, "RESOURCE_GRAPH_VALIDATION");
            lines.Add($"{Mark(graphPassed)} Resource graph valid");
            var preservation = verification.TryGetProperty("preservation", out var preservationValue) && preservationValue.ValueKind == JsonValueKind.Object;
            var preservationPassed = preservation && preservationValue.EnumerateObject().All(item => item.Value.ValueKind == JsonValueKind.True);
            lines.Add($"{Mark(preservationPassed)} Non-target PE structures preserved");

            var windowsStatus = ReadStatus(verification, "windows");
            var signatureStatus = ReadStatus(verification, "signature");
            lines.Add($"INFO Windows validation: {windowsStatus}");
            lines.Add($"INFO Signature state: {signatureStatus}");

            var commit = ReadPhase(verification, "COMMIT");
            lines.Add($"INFO Commit: {commit}");

            if (verification.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0)
            {
                foreach (var error in errors.EnumerateArray()) lines.Add($"FAIL {error}");
            }

            lines.Insert(0, passed ? "Verification passed" : "Verification failed");
            return string.Join(Environment.NewLine, lines);
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }

    private static bool IsNoOp(JsonElement verification)
    {
        if (!verification.TryGetProperty("semanticDiff", out var diff) || diff.ValueKind != JsonValueKind.Object) return false;
        var added = Count(diff, "added");
        var removed = Count(diff, "removed");
        var changed = Count(diff, "changed");
        return added == 0 && removed == 0 && changed == 0;
    }

    private static int Count(JsonElement parent, string property) => parent.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Array ? value.GetArrayLength() : 0;

    private static string ReadStatus(JsonElement verification, string property)
    {
        if (!verification.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.Object) return "SKIPPED";
        return value.TryGetProperty("status", out var status) ? status.ToString() : "UNKNOWN";
    }

    private static bool PhasePassed(JsonElement verification, string name)
    {
        if (!verification.TryGetProperty("phases", out var phases) || phases.ValueKind != JsonValueKind.Array) return false;
        foreach (var phase in phases.EnumerateArray())
        {
            if (phase.TryGetProperty("name", out var phaseName) && string.Equals(phaseName.ToString(), name, StringComparison.OrdinalIgnoreCase))
            {
                return phase.TryGetProperty("passed", out var value) && value.ValueKind == JsonValueKind.True;
            }
        }
        return false;
    }

    private static string ReadPhase(JsonElement verification, string name)
    {
        if (!verification.TryGetProperty("phases", out var phases) || phases.ValueKind != JsonValueKind.Array) return "not reported";
        foreach (var phase in phases.EnumerateArray())
        {
            if (phase.TryGetProperty("name", out var phaseName) && string.Equals(phaseName.ToString(), name, StringComparison.OrdinalIgnoreCase))
            {
                return phase.TryGetProperty("detail", out var detail) ? detail.ToString() : "reported";
            }
        }
        return "not reported";
    }

    private static string Mark(bool value) => value ? "PASS" : "FAIL";
}
