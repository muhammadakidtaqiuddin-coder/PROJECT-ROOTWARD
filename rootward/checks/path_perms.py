"""Check: writable or relative directories in $PATH (command hijacking)."""
import os
import stat

from rootward.checks._common import writable_by_current_user
from rootward.checks.base import BaseCheck
from rootward.ethics import should_abort
from rootward.models import Finding, Severity

SYSTEM_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


class PathPermsCheck(BaseCheck):
    check_id = "path_perms"
    title = "Writable directories in PATH"

    def __init__(self, path_value=None):
        super().__init__()
        self.path_value = os.environ.get("PATH", "") if path_value is None else path_value

    def run(self) -> list:
        findings = []
        entries = self.path_value.split(os.pathsep)
        first_system = next((i for i, e in enumerate(entries) if e in SYSTEM_DIRS), len(entries))
        seen = set()
        for index, entry in enumerate(entries):
            if should_abort():
                break
            if entry in seen:
                continue
            seen.add(entry)
            finding = self._assess(index, entry, index < first_system)
            if finding:
                findings.append(finding)
        return findings

    def _assess(self, index: int, entry: str, before_system: bool):
        if not entry.startswith("/"):
            label = entry or "(empty entry)"
            return self._finding(
                f"Relative PATH entry: {label}", Severity.HIGH, label, ["path-writable"],
                "An empty or relative PATH entry makes the shell search the current directory, "
                "so a planted program there gets executed.")
        try:
            st = os.stat(entry)
        except FileNotFoundError:
            parent = os.path.dirname(entry.rstrip("/")) or "/"
            if os.path.isdir(parent) and writable_by_current_user(parent):
                return self._finding(
                    f"Missing PATH directory can be created: {entry}", Severity.MEDIUM, entry,
                    ["path-writable", "writable-by-user"],
                    "The directory does not exist but its parent is writable, so it can be created.")
            return None
        except OSError:
            return None
        if not stat.S_ISDIR(st.st_mode):
            return None
        tags = []
        if st.st_mode & stat.S_IWOTH:
            tags.append("world-writable")
        if writable_by_current_user(entry):
            tags.append("writable-by-user")
        if not tags:
            return None
        severity = Severity.CRITICAL if before_system else Severity.HIGH
        position = "before the system directories" if before_system else "in PATH"
        return self._finding(
            f"Writable PATH directory: {entry}", severity, f"PATH[{index}] = {entry} "
            f"({stat.filemode(st.st_mode)})", ["path-writable", *tags],
            f"{entry} is writable and listed {position}. A planted program with a common "
            "command name can be run by a privileged user whose PATH includes it.")

    def _finding(self, title, severity, evidence, tags, description) -> Finding:
        return Finding(self.check_id, title, severity, description,
                       "Remove the entry from PATH, or chmod go-w it and make it root-owned. "
                       "Never put '.' or an empty entry in PATH.", evidence, tags)


if __name__ == "__main__":
    for item in PathPermsCheck().run():
        print(item)
