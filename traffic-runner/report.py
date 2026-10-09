#!/usr/bin/env python3
"""Rendering of a traffic-run report into text, Markdown, or JSON.

Consumes the structured report produced by :mod:`runner` and turns it into one
of the supported presentation formats. The same renderers serve both standard
output and the ``--output-file`` destination.
"""

from __future__ import annotations

import json

_NOTE_TABLE_LIMIT = 70

_COLUMNS = [
    ("#", "number"),
    ("flow", "flow_source"),
    ("method", "method"),
    ("route", "route"),
    ("kind", "kind"),
    ("status", "status_label"),
    ("blocked", "blocked_label"),
    ("sink", "sink_label"),
    ("verdict", "verdict"),
    ("note", "note"),
]


def render(report, output_format):
    """Renders a report in the requested presentation format.

    @param report Structured report mapping with ``summary`` and ``results`` keys.
    @param output_format One of ``"table"``, ``"markdown"``, or ``"json"``.
    @returns The rendered report as a single string.
    @raises ValueError When the format is not supported.
    """
    if output_format == "json":
        return json.dumps(report, indent=2)
    if output_format == "markdown":
        return _render_markdown(report)
    if output_format == "table":
        return _render_table(report)
    raise ValueError(f"Unsupported report format: {output_format!r}")


def _rows(report):
    """Flattens result records into the display columns shared by every renderer."""
    rows = []
    for position, result in enumerate(report["results"], start=1):
        status = result["status"]
        rows.append({
            "number": str(position),
            "flow_source": result["flow_source"],
            "method": result["method"],
            "route": result["route"],
            "kind": "EXPLOIT" if result["is_exploit"] else "benign",
            "status_label": "ERR" if status is None else str(status),
            "blocked_label": "yes" if result["blocked"] else "no",
            "sink_label": "yes" if result["sink_reached"] else "-",
            "verdict": result["verdict"],
            "note": result["note"],
        })
    return rows


def _summary_lines(summary):
    """Builds the human-readable summary block shared by text and Markdown output."""
    counts = summary["counts"]
    return [
        f"Vulnerability : {summary['vuln_id']}",
        f"Target        : {summary['target']}",
        f"Requests      : {summary['total']} "
        f"({summary['exploit_count']} exploit, {summary['benign_count']} benign)",
        f"Exploit block : {summary['exploit_block_rate']} blocked",
        f"Benign pass   : {summary['benign_pass_rate']} allowed",
        f"Confusion     : TP={counts['TP']} FN={counts['FN']} "
        f"TN={counts['TN']} FP={counts['FP']} ERROR={counts['ERROR']}",
        f"Overall       : {summary['overall']}",
    ]


def _render_table(report):
    """Renders the report as an aligned fixed-width text table with a summary."""
    rows = _rows(report)
    for row in rows:
        if len(row["note"]) > _NOTE_TABLE_LIMIT:
            row["note"] = row["note"][:_NOTE_TABLE_LIMIT - 1] + "…"
    headers = [title for title, _ in _COLUMNS]
    keys = [key for _, key in _COLUMNS]
    widths = [len(title) for title in headers]
    for row in rows:
        for index, key in enumerate(keys):
            widths[index] = max(widths[index], len(row[key]))

    def format_row(values):
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values))

    lines = [format_row(headers), format_row(["-" * width for width in widths])]
    for row in rows:
        lines.append(format_row([row[key] for key in keys]))
    lines.append("")
    lines.extend(_summary_lines(report["summary"]))
    return "\n".join(lines)


def _render_markdown(report):
    """Renders the report as a Markdown table preceded by a summary list."""
    rows = _rows(report)
    headers = [title for title, _ in _COLUMNS]
    keys = [key for _, key in _COLUMNS]
    lines = ["## Traffic run report", ""]
    lines.extend(f"- {line}" for line in _summary_lines(report["summary"]))
    lines.append("")
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        cells = [row[key].replace("|", "\\|") for key in keys]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)
