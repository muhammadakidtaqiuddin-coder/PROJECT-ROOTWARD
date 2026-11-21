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
from rootward.scanner import discover_checks, run_scan
from rootward.scoring import apply_scoring, summarize


BANNER = r"""
 ____ גם ____
|  _ \ ___  _ __ | |___      ____ _ _ __ __| |
| |_) / _ \| '_ \| __\ \ /\ / / _` | '__/ _` |
|  _ < (_) | |_) | |_ \ V  V / (_| | | | (_| |
|_| \_\___/| .__/ \__| \_/\_/ \__,_|_|  \__,_|
           |_|
""".replace("גם", "")


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
    return parser


def _print_result(result) -> None:
    if result.dry_run:
        print("Dry run: no system checks were performed.")
        print("Planned checks: " + (", ".join(result.checks_planned) or "none"))
        return

    findings = apply_scoring(result.findings)
    summary = summarize(findings)
    print(f"Checks completed: {len(result.checks_run)}; findings: {summary['total']}")
    print(f"Risk: {summary['overall_rating']} (score {summary['risk_score']}/100)")
    for finding in findings:
        print(f"\n[{finding.severity.name}] {finding.title} ({finding.check_id})")
        print(f"  Path: {finding.path}")
        print(f"  Finding: {finding.explanation}")
        print(f"  Remediation: {finding.remediation}")
        if finding.escalation_note:
            print(f"  Risk correlation: {finding.escalation_note}")

    if result.errors:
        print("\nCheck issues:")
        for check_id, message in sorted(result.errors.items()):
            print(f"  {check_id}: {message}")
    if result.aborted:
        print("\nScan stopped by the kill switch; remaining checks were skipped.")
    else:
        print(f"\nScan finished in {result.duration:.2f}s.")


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

    _print_result(result)
    return 130 if result.aborted else (1 if result.errors else 0)


if __name__ == "__main__":
    raise SystemExit(main())
