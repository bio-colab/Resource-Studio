from __future__ import annotations

import csv
import html
import io
import json
from typing import Any


FORMATS = frozenset({"json", "csv", "markdown", "html"})


def render_report(payload: Any, report_format: str) -> str:
    if report_format not in FORMATS:
        raise ValueError(f"unsupported report format: {report_format}")
    if report_format == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    rows = _rows(payload)
    if report_format == "csv":
        return _csv(rows)
    if report_format == "markdown":
        return _markdown(rows)
    return _html(rows)


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("changes"), list):
        rows = []
        for change in payload["changes"]:
            row = {key: value for key, value in change.items() if not isinstance(value, (dict, list))}
            if "before" in change:
                row["before"] = json.dumps(change["before"], ensure_ascii=False, sort_keys=True)
            if "after" in change:
                row["after"] = json.dumps(change["after"], ensure_ascii=False, sort_keys=True)
            rows.append(row)
        return rows
    if isinstance(payload, list):
        return [item if isinstance(item, dict) else {"value": item} for item in payload]
    if isinstance(payload, dict):
        return [{key: value for key, value in payload.items() if not isinstance(value, (dict, list))}]
    return [{"value": payload}]


def _columns(rows: list[dict[str, Any]]) -> list[str]:
    return sorted({key for row in rows for key in row}) if rows else ["value"]


def _csv(rows: list[dict[str, Any]]) -> str:
    columns = _columns(rows)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _markdown(rows: list[dict[str, Any]]) -> str:
    columns = _columns(rows)
    lines = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(column, "")).replace("|", "\\|") for column in columns) + " |")
    return "\n".join(lines) + "\n"


def _html(rows: list[dict[str, Any]]) -> str:
    columns = _columns(rows)
    header = "".join(f"<th>{html.escape(column)}</th>" for column in columns)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(row.get(column, '')))}</td>" for column in columns) + "</tr>"
        for row in rows
    )
    return f"<!doctype html><meta charset=\"utf-8\"><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>\n"
