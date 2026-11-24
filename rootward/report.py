"""Report output: a colour-coded terminal table and a labelled local JSON report.

Two public functions, so cli.py only has to call them:
  print_report(result, findings, summary)   -> shows the scan on the terminal
  write_json_report(result, findings, summary, scope) -> saves it under output/

Data handling: nothing here touches the network. The JSON file is written only to
a local directory (default `output/`, which .gitignore excludes) and its name carries
the hostname and a timestamp, so every report is clearly labelled and traceable.
"""
from __future__ import annotations

import json
import os
import re
import socket
from datetime import datetime
from pathlib import Path

from rootward.models import Severity

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
except ImportError:  # rich is optional at runtime: fall back to plain text
    Console = None

TOOL_NAME = "RootWard"
TOOL_VERSION = "1.0.0"
DEFAULT_OUTPUT_DIR = "output"
WIDE_LAYOUT_MIN_WIDTH = 100  # terminal columns needed for the findings table

# One colour per severity (rich style names).
SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def _clean_label(value: str, fallback: str) -> str:
    """Make a string safe to use inside a file name (no slashes, spaces or leading dots)."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", value).strip(".-")
    return cleaned or fallback


def _hostname() -> str:
    try:
        return socket.gethostname() or "unknown-host"
    except OSError:
        return "unknown-host"


def _plain_report(result, findings, summary) -> str:
    """Plain-text version of the report (used when `rich` is not installed)."""
    if result.dry_run:
        return ("Dry run: no system checks were performed.\n"
                "Planned checks: " + (", ".join(result.checks_planned) or "none"))
    lines = [
        f"Checks completed: {len(result.checks_run)}; findings: {summary['total']}",
        f"Risk: {summary['overall_rating']} (score {summary['risk_score']}/100)",
    ]
    for finding in findings:
        lines += [
            f"\n[{finding.severity.name}] {finding.title} ({finding.check_id})",
            f"  Path: {finding.path}",
            f"  Finding: {finding.explanation}",
            f"  Remediation: {finding.remediation}",
        ]
        if finding.escalation_note:
            lines.append(f"  Risk correlation: {finding.escalation_note}")
    lines += _status_lines(result)
    return "\n".join(lines)


def _status_lines(result) -> list:
    """Check errors and the closing status line, shared by both output styles."""
    lines = []
    if result.errors:
        lines.append("\nCheck issues:")
        lines += [f"  {check_id}: {message}"
                  for check_id, message in sorted(result.errors.items())]
    if result.aborted:
        lines.append("\nScan stopped by the kill switch; remaining checks were skipped.")
    else:
        lines.append(f"\nScan finished in {result.duration:.2f}s.")
    return lines


def _findings_table(findings) -> "Table":
    table = Table(show_lines=True, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Path", overflow="fold")
    table.add_column("Finding", overflow="fold", ratio=2)
    table.add_column("Remediation", overflow="fold", ratio=2)
    for finding in findings:
        # Text objects (not markup strings) so paths such as "PATH[0] = /tmp" print literally
        explanation = Text(finding.explanation)
        if finding.escalation_note:
            explanation.append("\nRisk correlation: " + finding.escalation_note, style="bold")
        table.add_row(
            Text(finding.severity.name, style=SEVERITY_STYLES[finding.severity]),
            Text(finding.check_id),
            Text(finding.path),
            explanation,
            Text(finding.remediation),
        )
    return table


def _print_findings_list(console, findings) -> None:
    """One block per finding, for terminals too narrow for the table. The table repeats the
    path in two columns, so at 80 columns three findings took 125 lines."""
    for finding in findings:
        console.print()
        console.print(Text.assemble(
            (f"[{finding.severity.name}]", SEVERITY_STYLES[finding.severity]),
            f" {finding.title} ({finding.check_id})"))
        console.print(Text(f"  Path: {finding.path}"))
        console.print(Text(f"  Finding: {finding.explanation}"))
        console.print(Text(f"  Remediation: {finding.remediation}"))
        if finding.escalation_note:
            console.print(Text(f"  Risk correlation: {finding.escalation_note}", style="bold"))


def print_report(result, findings, summary, console=None) -> None:
    """Print the scan to the terminal, worst finding first, then the summary.

    On a terminal at least WIDE_LAYOUT_MIN_WIDTH columns wide the findings are shown as a
    table; on a narrower one they are shown as a list of blocks, which stays readable
    (record demos at 120 columns or more).

    `findings` should be the list returned by scoring.apply_scoring and `summary` the dict
    from scoring.summarize. Pass `console` to capture the output (used by the tests).
    """
    if Console is None:
        print(_plain_report(result, findings, summary))
        return
    console = console or Console()
    if result.dry_run:
        console.print(Text("Dry run: no system checks were performed."))
        console.print(Text("Planned checks: " + (", ".join(result.checks_planned) or "none")))
        return

    console.print(Text(f"Checks completed: {len(result.checks_run)}; "
                       f"findings: {summary['total']}"))
    rating = Severity[summary["overall_rating"]]
    console.print(Text.assemble(
        "Risk: ", (summary["overall_rating"], SEVERITY_STYLES[rating]),
        f" (score {summary['risk_score']}/100)"))
    counts = Text("Counts: ")
    for name, count in summary["counts"].items():
        counts.append(f"{name} {count}  ", style=SEVERITY_STYLES[Severity[name]])
    console.print(counts)
    if findings:
        if console.width >= WIDE_LAYOUT_MIN_WIDTH:
            console.print(_findings_table(findings))
        else:
            _print_findings_list(console, findings)
    for line in _status_lines(result):
        console.print(Text(line))


def _report_data(result, findings, summary, scope, generated_at: datetime) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": generated_at.isoformat(),
        "hostname": _hostname(),
        "scope": scope,
        "checks_run": list(result.checks_run),
        "checks_skipped": list(result.checks_skipped),
        "errors": dict(result.errors),
        "aborted": result.aborted,
        "duration_seconds": round(result.duration, 3),
        "summary": summary,
        "findings": [finding.to_dict() for finding in findings],
    }


def _open_new_file(directory: Path, stem: str):
    """Create `<stem>.json` (or `<stem>-2.json`, ...) without overwriting an older report.
    The file is created owner-only (0600 on POSIX): it describes weaknesses of this machine."""
    counter = 1
    while True:
        name = f"{stem}.json" if counter == 1 else f"{stem}-{counter}.json"
        path = directory / name
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            counter += 1
            continue
        return path, os.fdopen(fd, "w", encoding="utf-8")


def write_json_report(result, findings, summary, scope,
                      out_dir=DEFAULT_OUTPUT_DIR, now: datetime | None = None) -> Path | None:
    """Save the scan as JSON in `out_dir` and return the file path.

    The file is named rootward-<hostname>-<YYYYmmdd-HHMMSS>.json. Partial results from a
    scan stopped by the kill switch are saved too, with "aborted": true.

    A dry run inspects nothing, so no file is written and the result is None.

    Raises OSError when the report cannot be written: PermissionError if `out_dir` is not
    writable, FileExistsError or NotADirectoryError if `out_dir` exists but is a file. The
    caller (cli.py) should catch OSError and report it without hiding the scan results.
    """
    if result.dry_run:
        return None
    generated_at = now or datetime.now().astimezone()
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stem = (f"rootward-{_clean_label(_hostname(), 'host')}-"
            f"{generated_at.strftime('%Y%m%d-%H%M%S')}")
    path, handle = _open_new_file(directory, stem)
    with handle:
        json.dump(_report_data(result, findings, summary, scope, generated_at),
                  handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path
