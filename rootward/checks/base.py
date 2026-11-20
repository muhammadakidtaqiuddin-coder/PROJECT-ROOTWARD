"""Base class that every RootWard check must extend."""
from abc import ABC, abstractmethod

from rootward.ethics import should_abort
from rootward.models import Finding, Severity


class BaseCheck(ABC):
    """Contract for all checks.

    Rules every check must follow:
      * read-only: never modify, exploit or exfiltrate anything
      * return a list of Finding objects from run()
      * call self.aborted() inside loops and stop early when it is True
    """

    check_id: str = "base"
    title: str = "Base check"
    description: str = ""

    @abstractmethod
    def run(self) -> list[Finding]:
        """Inspect the local system and return any findings."""

    def aborted(self) -> bool:
        """True once the user triggers the kill switch (Ctrl+C)."""
        return should_abort()

    def finding(self, title: str, path: str, severity: Severity,
                explanation: str, remediation: str, tags=None) -> Finding:
        """Build a Finding stamped with this check's id."""
        return Finding(
            check_id=self.check_id,
            title=title,
            path=path,
            severity=severity,
            explanation=explanation,
            remediation=remediation,
            tags=set(tags or []),
        )