"""Check: writable or relative directories in $PATH (command hijacking)."""
import os
import stat

try:
    import grp
except ImportError:  # not a POSIX system
    grp = None

from rootward.checks._common import write_sources, writable_by_current_user, writable_tags
from rootward.checks.base import BaseCheck
from rootward.models import Severity

SYSTEM_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


def _group_name(gid: int) -> str:
    if grp is not None:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            pass
    return str(gid)


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
            if self.aborted():
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
        sources = write_sources(entry)
        if not sources:
            return None
        if sources == {"group"} and entry in SYSTEM_DIRS:
            # e.g. Debian/Kali ship /usr/local/bin as root:staff 2775 on purpose: worth a note,
            # but no "writable-by-user" tag, so scoring does not chain it to CRITICAL
            group = _group_name(st.st_gid)
            return self._finding(
                f"System PATH directory writable by group {group}: {entry}", Severity.MEDIUM,
                f"PATH[{index}] = {entry} ({stat.filemode(st.st_mode)} group {group})",
                ["path-writable"],
                f"{entry} is a standard system directory writable only by the non-root group "
                f"{group} (a Debian/Kali default for /usr/local). Members of that group can plant "
                "programs that root runs; keep the group's membership small.", path=entry)
        tags = writable_tags(entry)
        severity = Severity.CRITICAL if before_system else Severity.HIGH
        position = "before the system directories" if before_system else "in PATH"
        return self._finding(
            f"Writable PATH directory: {entry}", severity, f"PATH[{index}] = {entry} "
            f"({stat.filemode(st.st_mode)})", ["path-writable", *tags],
            f"{entry} is writable and listed {position}. A planted program with a common "
            "command name can be run by a privileged user whose PATH includes it.", path=entry)

    def _finding(self, title, severity, evidence, tags, description, path=None):
        return self.finding(title, path or evidence, severity,
                            f"{description} Evidence: {evidence}.",
                            "Remove the entry from PATH, or chmod go-w it and make it root-owned. "
                            "Never put '.' or an empty entry in PATH.", tags)


if __name__ == "__main__":
    for item in PathPermsCheck().run():
        print(item)
