from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAIN_WINDOW = (ROOT / "windows" / "ResourceStudio.Windows" / "MainWindow.xaml.cs").read_text(encoding="utf-8")
READ_HOST = (ROOT / "windows" / "ResourceStudio.Windows" / "ReadHostClient.cs").read_text(encoding="utf-8")


def test_main_window_rejects_stale_results_and_owns_cancellation() -> None:
    assert "private long _requestGeneration;" in MAIN_WINDOW
    assert "Interlocked.Increment(ref _requestGeneration)" in MAIN_WINDOW
    assert "if (result.IsStale) return;" in MAIN_WINDOW
    assert "ReferenceEquals(_cliCancellation, cancellation)" in MAIN_WINDOW
    assert "ReferenceEquals(_activeCliProcess, ownedProcess)" in MAIN_WINDOW
    assert "Analysis degraded — see Inspect tab" in MAIN_WINDOW
    assert "Resources loaded" in MAIN_WINDOW
    assert "Resource listing unavailable — see Inspect tab" in MAIN_WINDOW


def test_read_host_serializes_requests_and_stops_its_owned_process() -> None:
    assert "private readonly SemaphoreSlim _gate" in READ_HOST
    assert "await _gate.WaitAsync(cancellationToken)" in READ_HOST
    assert "StopProcess();" in READ_HOST
    assert 'schema = "resource_studio.p3_wpf_read_host_telemetry.v1"' in READ_HOST


if __name__ == "__main__":
    test_main_window_rejects_stale_results_and_owns_cancellation()
    test_read_host_serializes_requests_and_stops_its_owned_process()
    print("p4-wpf-session-contract-tests: passed")
