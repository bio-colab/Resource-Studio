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

            AppendForensicEvidence(document.RootElement, lines);
            lines.Insert(0, passed ? "Verification passed" : "Verification failed");
            return string.Join(Environment.NewLine, lines);
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }

    private static void AppendForensicEvidence(JsonElement root, List<string> lines)
    {
        if (!root.TryGetProperty("forensicEvidence", out var evidence) || evidence.ValueKind != JsonValueKind.Object) return;
        var difference = evidence.TryGetProperty("forensicDifference", out var differenceValue) && differenceValue.ValueKind == JsonValueKind.Object ? differenceValue : default;
        var forensicPassed = difference.ValueKind == JsonValueKind.Object && difference.TryGetProperty("passed", out var passed) && passed.ValueKind == JsonValueKind.True;
        lines.Add("Technical evidence");
        lines.Add($"{Mark(forensicPassed)} Forensic evidence: {(forensicPassed ? "passed" : "failed")}");
        if (difference.ValueKind != JsonValueKind.Object) return;
        if (difference.TryGetProperty("targeted", out var targeted) && targeted.ValueKind == JsonValueKind.Object)
        {
            var changed = targeted.TryGetProperty("changed", out var changedValue) && changedValue.ValueKind == JsonValueKind.True;
            lines.Add($"INFO Target attribution: {(changed ? "target changed" : "target unchanged/no-op")}");
            lines.Add($"INFO Target before SHA-256: {ReadString(targeted, "beforeSha256")}");
            lines.Add($"INFO Target after SHA-256: {ReadString(targeted, "afterSha256")}");
        }
        if (difference.TryGetProperty("resourceTree", out var tree) && tree.ValueKind == JsonValueKind.Object)
        {
            lines.Add($"INFO Resource-tree unintended changes: {ReadString(tree, "unintendedChanges")}");
        }
        if (difference.TryGetProperty("pePreservation", out var preservation) && preservation.ValueKind == JsonValueKind.Object)
        {
            var failed = preservation.EnumerateObject().Where(item => item.Value.ValueKind == JsonValueKind.False).Select(item => item.Name).ToArray();
            lines.Add(failed.Length == 0 ? "PASS PE preservation: all reported structures preserved" : $"FAIL PE preservation: {string.Join(", ", failed)}");
        }
        if (evidence.TryGetProperty("baseline", out var baseline) && baseline.ValueKind == JsonValueKind.Object)
        {
            lines.Add($"INFO Baseline SHA-256: {ReadString(baseline, "sha256")}");
        }
        if (evidence.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object)
        {
            lines.Add($"INFO Result SHA-256: {ReadString(result, "sha256")}");
        }
    }

    private static string ReadString(JsonElement parent, string property) => parent.TryGetProperty(property, out var value) ? value.ToString() : "unknown";

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
