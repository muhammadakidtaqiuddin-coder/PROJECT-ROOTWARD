"""Check: cron jobs whose files or scripts a low-privileged user can modify."""
import glob
import os
import re
import stat

from rootward.checks._common import can_replace, writable_by_current_user
from rootward.checks.base import BaseCheck
from rootward.ethics import should_abort
from rootward.models import Finding, Severity

SYSTEM_CRONTABS = ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*"))
USER_SPOOLS = ("/var/spool/cron/crontabs", "/var/spool/cron")
SCRIPT_DIRS = ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")

_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_PATH_RE = re.compile(r"(?<![\w.~-])(/[\w./+-]+)")
_INTERPRETERS = ("sh", "bash", "dash", "python", "python3", "perl", "ruby", "php", "node")
_IGNORED_PREFIXES = ("/dev/", "/proc/", "/sys/")
_WILDCARD_TOOLS = ("tar", "rsync", "chown", "chmod")


def parse_cron_line(line: str, system: bool = True):
    """Return (user, command) for a crontab line, or None for comments/blank/env lines.
    `user` is None for per-user crontabs, which have no user column."""
    line = line.strip()
    if not line or line.startswith("#") or _ENV_RE.match(line):
        return None
    if line.startswith("@"):
        parts = line.split(None, 2 if system else 1)
        needed = 3 if system else 2
    else:
        parts = line.split(None, 6 if system else 5)
        needed = 7 if system else 6
    if len(parts) < needed:
        return None
    return (parts[-2] if system else None), parts[-1]


def _writable_tags(path: str) -> list:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return []
    tags = []
    if mode & stat.S_IWOTH:
        tags.append("world-writable")
    if writable_by_current_user(path):
        tags.append("writable-by-user")
    return tags


def _plausible_targets(command: str) -> list:
    """Absolute paths in a cron command that are probably executed: existing executable
    files, or a missing file in the command/interpreter position."""
    tokens = command.split()
    head = set(tokens[:1])
    if tokens and os.path.basename(tokens[0]) in _INTERPRETERS:
        head.update(t for t in tokens[1:3] if not t.startswith("-"))
    targets = []
    for path in _PATH_RE.findall(command):
        if path.startswith(_IGNORED_PREFIXES):
            continue
        if os.path.isfile(path) and os.stat(path).st_mode & 0o111:
            targets.append(path)
        elif not os.path.exists(path) and path in head:
            targets.append(path)
    return targets


class CronCheck(BaseCheck):
    check_id = "cron"
    title = "Writable cron jobs and scripts"

    def __init__(self, crontabs=None, script_dirs=None):
        super().__init__()
        # crontabs: list of (path, is_system_crontab, owner_or_None); None = discover
        self.crontabs = crontabs if crontabs is not None else self._discover()
        self.script_dirs = SCRIPT_DIRS if script_dirs is None else script_dirs

    @staticmethod
    def _discover() -> list:
        found = [(p, True, None) for p in SYSTEM_CRONTABS if os.path.isfile(p)]
        for spool in USER_SPOOLS:
            if os.path.isdir(spool):
                found += [(p, False, os.path.basename(p)) for p in sorted(glob.glob(spool + "/*"))
                          if os.path.isfile(p)]
        return found

    def run(self) -> list:
        findings = []
        for path, system, owner in self.crontabs:
            if should_abort():
                return findings
            findings += self._audit_crontab(path, system, owner)
        for directory in self.script_dirs:
            if should_abort():
                return findings
            findings += self._audit_script_dir(directory)
        return findings

    def _audit_crontab(self, path: str, system: bool, owner) -> list:
        findings = []
        tags = _writable_tags(path)
        if tags:
            findings.append(self._finding(
                f"Writable crontab: {path}", Severity.HIGH, path, ["cron", *tags],
                "The crontab itself can be edited, so its jobs can be replaced with any command."))
        try:
            with open(path, errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError:
            return findings
        for line in lines:
            if should_abort():
                break
            parsed = parse_cron_line(line, system)
            if parsed:
                user = parsed[0] or owner
                findings += self._audit_command(path, user, parsed[1])
        return findings

    def _audit_command(self, source: str, user: str, command: str) -> list:
        findings = []
        as_root = user == "root"
        for target in _plausible_targets(command):
            tags = _writable_tags(target)
            if not tags and can_replace(target):
                tags = ["writable-by-user"]
            if not tags:
                continue
            severity = Severity.CRITICAL if as_root else Severity.HIGH
            findings.append(self._finding(
                f"Writable cron script run as {user}: {target}", severity, f"{source}: {command}",
                ["cron", *(["root-owned"] if as_root else []), "script-writable", *tags],
                f"{target} is executed by cron as {user} but can be modified by an unprivileged user."))
        if any(tool in command.split() for tool in _WILDCARD_TOOLS) and "*" in command:
            findings.append(self._finding(
                f"Wildcard in cron command run as {user}", Severity.MEDIUM, f"{source}: {command}",
                ["cron"], "A wildcard passed to tar/rsync/chown/chmod can be abused with crafted "
                          "file names (wildcard injection)."))
        return findings

    def _audit_script_dir(self, directory: str) -> list:
        if not os.path.isdir(directory):
            return []
        findings = []
        for name in sorted(os.listdir(directory)):
            if should_abort():
                break
            path = os.path.join(directory, name)
            tags = _writable_tags(path)
            if not tags and can_replace(path):
                tags = ["writable-by-user"]
            if tags:
                findings.append(self._finding(
                    f"Writable cron script: {path}", Severity.CRITICAL, path,
                    ["cron", "root-owned", "script-writable", *tags],
                    "Scripts in this directory are run by cron as root but can be modified."))
        return findings

    def _finding(self, title, severity, evidence, tags, description) -> Finding:
        return Finding(self.check_id, title, severity, description,
                       "Make cron files and scripts owned by root with mode 644/755, and make "
                       "their directories non-writable for other users.", evidence, tags)


if __name__ == "__main__":
    for item in CronCheck().run():
        print(item)
