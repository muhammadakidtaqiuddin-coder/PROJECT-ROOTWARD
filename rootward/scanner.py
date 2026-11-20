"""Discovers checks, runs them safely and collects the findings."""
import importlib
import inspect
import pkgutil
import time
from dataclasses import dataclass, field

from rootward import checks as checks_pkg
from rootward.checks.base import BaseCheck
from rootward.ethics import should_abort
from rootward.models import Finding


@dataclass
class ScanResult:
    findings: list = field(default_factory=list)       # list[Finding]
    checks_run: list = field(default_factory=list)     # ids that finished
    checks_planned: list = field(default_factory=list) # ids listed in dry-run
    checks_skipped: list = field(default_factory=list) # ids skipped by abort
    errors: dict = field(default_factory=dict)         # check_id -> message
    aborted: bool = False
    dry_run: bool = False
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)


def discover_checks(errors: dict | None = None) -> dict:
    """Import every module in rootward/checks and return {check_id: class}.

    Adding a new check only needs a new file; nothing here changes.
    A module that fails to import is recorded in `errors`, not fatal.
    """
    found = {}
    for info in pkgutil.iter_modules(checks_pkg.__path__):
        if info.name == "base":
            continue
        try:
            module = importlib.import_module(f"{checks_pkg.__name__}.{info.name}")
        except Exception as exc:  # a broken check must not kill the scan
            if errors is not None:
                errors[info.name] = f"import failed: {type(exc).__name__}: {exc}"
            continue
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if (issubclass(cls, BaseCheck) and cls is not BaseCheck
                    and not inspect.isabstract(cls)
                    and cls.__module__ == module.__name__):
                found[cls.check_id] = cls
    return dict(sorted(found.items()))


def run_scan(selected=None, dry_run: bool = False) -> ScanResult:
    """Run all (or the selected) checks and return a ScanResult.

    * dry_run: only list the checks that would run, touch nothing.
    * kill switch: when triggered, remaining checks are skipped and the
      partial results collected so far are still returned.
    """
    result = ScanResult(dry_run=dry_run, started_at=time.time())
    available = discover_checks(result.errors)

    if selected:
        for check_id in selected:
            if check_id not in available:
                result.errors[check_id] = "unknown check id"
        available = {k: v for k, v in available.items() if k in selected}

    for check_id, cls in available.items():
        if should_abort():
            result.aborted = True
            result.checks_skipped.append(check_id)
            continue
        if dry_run:
            result.checks_planned.append(check_id)
            continue
        try:
            findings = cls().run()
            result.findings.extend(f for f in findings if isinstance(f, Finding))
            result.checks_run.append(check_id)
        except PermissionError as exc:
            result.errors[check_id] = f"permission denied: {exc}"
        except Exception as exc:  # isolate failures per check
            result.errors[check_id] = f"{type(exc).__name__}: {exc}"
        if should_abort():
            result.aborted = True

    result.finished_at = time.time()
    return result
