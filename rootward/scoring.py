"""Scoring engine: escalates risky combinations and summarises risk.

Two kinds of escalation:
  1. Tag rules  - one finding carries a dangerous combination of tags.
  2. Path chains - a path that unprivileged users can write is also
     executed with elevated privileges (SUID, root cron, sudo NOPASSWD,
     a binary holding a dangerous file capability).
     This correlates findings from DIFFERENT checks, which no single
     check can see on its own.

Path convention for check authors: Finding.path is the file or directory
that matters (the binary, the script a job runs, the PATH directory).
"""
from dataclasses import dataclass

from rootward.models import Finding, Severity

KNOWN_TAGS = {
    "suid", "sgid", "root-owned", "world-writable", "writable-by-user",
    "cron", "script-writable", "sudo-nopasswd", "sudo-wildcard", "sudo-env-keep",
    "capability", "path-writable",
}

WRITABLE_TAGS = {"world-writable", "writable-by-user",
                 "script-writable", "path-writable"}
PRIVILEGED_EXEC_TAGS = {"suid", "cron", "sudo-nopasswd", "capability"}

WEIGHTS = {
    Severity.INFO: 0, Severity.LOW: 5, Severity.MEDIUM: 15,
    Severity.HIGH: 35, Severity.CRITICAL: 60,
}


@dataclass(frozen=True)
class TagRule:
    required_tags: frozenset
    severity: Severity
    reason: str


TAG_RULES = (
    TagRule(frozenset({"cron", "root-owned", "script-writable"}), Severity.CRITICAL,
            "Root cron job runs a script that unprivileged users can modify"),
    TagRule(frozenset({"suid", "root-owned", "world-writable"}), Severity.CRITICAL,
            "SUID-root binary is writable by any user"),
    TagRule(frozenset({"sudo-nopasswd", "sudo-wildcard"}), Severity.CRITICAL,
            "Passwordless sudo rule with a wildcard can be abused to run arbitrary commands"),
    TagRule(frozenset({"capability", "writable-by-user"}), Severity.HIGH,
            "Binary with a dangerous capability can be modified by a normal user"),
)


def validate_tags(findings) -> list:
    """Return (check_id, tag) pairs using tags outside KNOWN_TAGS.

    Catches vocabulary drift between team members, which would
    silently stop chain escalation from working.
    """
    return [(f.check_id, t) for f in findings for t in sorted(f.tags - KNOWN_TAGS)]


def _covers(writable_path: str, other_path: str) -> bool:
    """A writable file covers itself; a writable directory covers its contents."""
    w = writable_path.rstrip("/")
    return other_path == w or other_path.startswith(w + "/")


def _apply_tag_rules(findings) -> None:
    for f in findings:
        for rule in TAG_RULES:
            if rule.required_tags <= f.tags:
                f.escalate(rule.severity, rule.reason)


def _apply_path_chains(findings) -> None:
    writable = [f for f in findings if f.tags & WRITABLE_TAGS]
    privileged = [f for f in findings if f.tags & PRIVILEGED_EXEC_TAGS]
    for w in writable:
        for p in privileged:
            if w is p or not _covers(w.path, p.path):
                continue
            w.escalate(Severity.CRITICAL,
                       f"Chain: writable path is executed with elevated privileges ({p.check_id}: {p.path})")
            p.escalate(Severity.CRITICAL,
                       f"Chain: path can be modified by unprivileged users ({w.check_id}: {w.path})")


def apply_scoring(findings) -> list:
    """Escalate findings in place and return them sorted, worst first."""
    findings = list(findings)
    _apply_tag_rules(findings)
    _apply_path_chains(findings)
    return sorted(findings, key=lambda f: (-int(f.severity), f.path))


def risk_score(findings) -> int:
    """Overall 0-100 risk score (sum of severity weights, capped)."""
    return min(100, sum(WEIGHTS[f.severity] for f in findings))


def summarize(findings) -> dict:
    counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[f.severity.name] += 1
    worst = max((f.severity for f in findings), default=Severity.INFO)
    return {
        "total": len(findings),
        "counts": counts,
        "risk_score": risk_score(findings),
        "overall_rating": worst.name,
    }