"""Data models shared across RootWard."""
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    """One misconfiguration discovered by a check."""

    check_id: str
    title: str
    path: str
    severity: Severity
    explanation: str
    remediation: str
    tags: set = field(default_factory=set)
    escalation_note: str = ""

    def escalate(self, new_severity: Severity, reason: str) -> None:
        """Raise severity (never lower it) and record why."""
        if new_severity > self.severity:
            self.severity = new_severity
            self.escalation_note = reason

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "path": self.path,
            "severity": self.severity.name,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "tags": sorted(self.tags),
            "escalation_note": self.escalation_note,
        }
