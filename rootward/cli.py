"""Command-line interface for the read-only RootWard auditor."""
from __future__ import annotations

import argparse
import signal
import sys

from rootward.ethics import (
    DEFAULT_SCOPE,
    DISCLAIMER,
    ScopeError,
    request_abort,
    reset_abort,
    validate_scope,
)
from rootward.report import DEFAULT_OUTPUT_DIR, print_report, write_json_report
from rootward.scanner import discover_checks, run_scan
from rootward.scoring import apply_scoring, summarize


BANNER = r"""
 _____             _   __          __
|  __ \           | |  \ \        / /
| |__) |___   ___ | |_  \ \  /\  / /
|  _  // _ \ / _ \| __|  \ \/  \/ /
| | \ \ (_) | (_) | |_    \  /\  /
|_|  \_\___/ \___/ \__|    \/  \/
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rootward",
        description="Read-only Linux privilege-escalation misconfiguration auditor.",
        epilog="Use only on systems you own or are explicitly authorized to assess.",
    )
    parser.add_argument(
        "--scope",
        default=DEFAULT_SCOPE,
        help=f"authorized scope marker; loopback only (default: {DEFAULT_SCOPE})",
    )
    parser.add_argument(
        "--checks",
        help="comma-separated check IDs to run (default: all discovered checks)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list the checks that would run without inspecting the system",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="list available checks and exit",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_DIR,
        metavar="DIR",
        help=f"folder for the local JSON report (default: {DEFAULT_OUTPUT_DIR}/)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="do not write a JSON report file",
    )
    return parser


def _confirm_authorization() -> bool:
    """Require an explicit authorization acknowledgement before a real scan."""
    try:
        answer = input(
            'Confirm you own this system or have permission to assess it. '
            'Type "I AUTHORIZE" to continue: '
        )
    except (EOFError, KeyboardInterrupt):
        print("Authorization not confirmed; scan cancelled.", file=sys.stderr)
        return False
    if answer.strip() != "I AUTHORIZE":
        print("Authorization not confirmed; scan cancelled.", file=sys.stderr)
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    """Run RootWard and return a process exit code."""
    args = _parser().parse_args(argv)
    print(BANNER.strip("\n"))
    print(DISCLAIMER)

    try:
        scope = validate_scope(args.scope)
    except ScopeError as exc:
        print(f"Scope rejected: {exc}", file=sys.stderr)
        return 2

    if args.list_checks:
        for check_id, check_cls in discover_checks().items():
            print(f"{check_id}: {check_cls.description or check_cls.title}")
        return 0

    selected = None
    if args.checks:
        selected = [item.strip() for item in args.checks.split(",") if item.strip()]
        if not selected:
            print("No check IDs were provided.", file=sys.stderr)
            return 2

    if not args.dry_run and not _confirm_authorization():
        return 2

    print(f"Authorized scope: {scope} (local system checks only)")
    print("Kill switch: press Ctrl+C to stop after the current safe point.\n")

    reset_abort()
    previous_handlers = {}

    def stop_handler(_signum, _frame):
        request_abort()

    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                previous_handlers[sig] = signal.signal(sig, stop_handler)
            except (ValueError, OSError):
                # Signal handlers can only be installed from the main thread.
                pass
    try:
        result = run_scan(selected=selected, dry_run=args.dry_run)
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)

    # Dry runs are intentionally report-free: they do not inspect the host or
    # create an output directory or file.
    if result.dry_run:
        print_report(result, [], summarize([]))
        return 1 if result.errors else 0

    findings = apply_scoring(result.findings)
    summary = summarize(findings)
    print_report(result, findings, summary)

    if not args.no_report:
        try:
            report_path = write_json_report(
                result, findings, summary, scope, out_dir=args.output
            )
        except OSError as exc:
            print(f"could not save report: {exc}", file=sys.stderr)
            return 1
        print(f"JSON report saved to {report_path}")

    return 130 if result.aborted else (1 if result.errors else 0)


if __name__ == "__main__":
    raise SystemExit(main())
