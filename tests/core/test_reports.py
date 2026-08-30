from __future__ import annotations

from core.reports import render_report


PAYLOAD = {"changes": [{"status": "modified", "before": {"name": "<old>"}, "after": {"name": "new"}}]}


def main() -> None:
    assert '"status": "modified"' in render_report(PAYLOAD, "json")
    assert "status" in render_report(PAYLOAD, "csv")
    assert "| status |" in render_report(PAYLOAD, "markdown")
    assert "&lt;old&gt;" in render_report(PAYLOAD, "html")
    try:
        render_report(PAYLOAD, "xml")
    except ValueError:
        pass
    else:
        raise AssertionError("unsupported report format was accepted")
    print("report-tests: passed")


if __name__ == "__main__":
    main()
