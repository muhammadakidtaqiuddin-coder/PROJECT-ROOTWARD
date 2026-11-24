"""Check: cron jobs whose files or scripts a low-privileged user can modify."""
import glob
import os
import re

try:
    import pwd
except ImportError:  # not a POSIX system: no account lookup
    pwd = None

from rootward.checks._common import can_replace, writable_tags
from rootward.checks.base import BaseCheck
from rootward.models import Finding, Severity

SYSTEM_CRONTAB = "/etc/crontab"
CRON_D_GLOB = "/etc/cron.d/*"  # globbed when discovering, so tests can patch it
USER_SPOOLS = ("/var/spool/cron/crontabs", "/var/spool/cron")
SCRIPT_DIRS = ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")

_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
_PATH_RE = re.compile(r"(?<![\w.~-])(/[\w./+-]+)")
_INTERPRETERS = ("sh", "bash", "dash", "python", "python3", "perl", "ruby", "php", "node")
_IGNORED_PREFIXES = ("/dev/", "/proc/", "/sys/")
_WILDCARD_TOOLS = ("tar", "rsync", "chown", "chmod")
_RUN_PARTS_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")  # Debian run-parts skips other names


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


def _uid_of(user):
    """uid of an account name, or None when unknown (then no owner exemption applies)."""
    if pwd is None or not user:
        return None
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


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
        system = [SYSTEM_CRONTAB] + sorted(glob.glob(CRON_D_GLOB))
        found = [(p, True, None) for p in system if os.path.isfile(p)]
        for spool in USER_SPOOLS:
            if os.path.isdir(spool):
                found += [(p, False, os.path.basename(p)) for p in sorted(glob.glob(spool + "/*"))
                          if os.path.isfile(p)]
        return found

    def run(self) -> list:
        findings = []
        for path, system, owner in self.crontabs:
            if self.aborted():
                return findings
            findings += self._audit_crontab(path, system, owner)
        for directory in self.script_dirs:
            if self.aborted():
                return findings
            findings += self._audit_script_dir(directory)
        return findings

    def _audit_crontab(self, path: str, system: bool, owner) -> list:
        findings = []
        # a system crontab (or root's own) runs its jobs as root; a user's spool file does not.
        # A user editing their own spool crontab is normal, so the owner is exempt there.
        runs_as_root = system or owner == "root"
        tags = writable_tags(path, None if system else _uid_of(owner))
        if tags:
            findings.append(self._finding(
                f"Writable crontab: {path}",
                Severity.CRITICAL if runs_as_root else Severity.HIGH, path,
                [*(["cron"] if runs_as_root else []), *tags],
                "The crontab itself can be edited, so its jobs can be replaced with any command"
                + (", and they run as root: this is root code execution." if runs_as_root
                   else ".")))
        try:
            with open(path, errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError:
            return findings
        for line in lines:
            if self.aborted():
                break
            parsed = parse_cron_line(line, system)
            if parsed:
                user = parsed[0] or owner
                findings += self._audit_command(path, user, parsed[1])
        return findings

    def _audit_command(self, source: str, user: str, command: str) -> list:
        findings = []
        as_root = user == "root"
        uid = _uid_of(user)  # the account running the job: its own files are not an escalation
        for target in _plausible_targets(command):
            tags = writable_tags(target, uid)
            if not tags and can_replace(target, uid):
                tags = ["writable-by-user"]
            if not tags:
                continue
            severity = Severity.CRITICAL if as_root else Severity.HIGH
            findings.append(self._finding(
                f"Writable cron script run as {user}: {target}", severity, target,
                # the "cron" tag (privileged execution for scoring) only for jobs that run as root
                [*(["cron", "root-owned"] if as_root else []), "script-writable", *tags],
                f"{target} is executed by cron as {user} but can be modified by an unprivileged user.",
                f"{source}: {command}"))
        if (any(os.path.basename(tok) in _WILDCARD_TOOLS for tok in command.split())
                and "*" in command):
            findings.append(self._finding(
                f"Wildcard in cron command run as {user}", Severity.MEDIUM, source,
                ["cron"] if as_root else [],
                "A wildcard passed to tar/rsync/chown/chmod can be abused with crafted "
                          "file names (wildcard injection).", f"{source}: {command}"))
        return findings

    def _audit_script_dir(self, directory: str) -> list:
        if not os.path.isdir(directory):
            return []
        findings = []
        for name in sorted(os.listdir(directory)):
            if self.aborted():
                break
            path = os.path.join(directory, name)
            # run-parts only runs executable files with plain names; others are not executed
            if (not _RUN_PARTS_NAME_RE.match(name) or not os.path.isfile(path)
                    or not os.stat(path).st_mode & 0o111):
                continue
            tags = writable_tags(path)
            if not tags and can_replace(path):
                tags = ["writable-by-user"]
            if tags:
                findings.append(self._finding(
                    f"Writable cron script: {path}", Severity.CRITICAL, path,
                    ["cron", "root-owned", "script-writable", *tags],
                    "Scripts in this directory are run by cron as root but can be modified."))
        return findings

    def _finding(self, title, severity, path, tags, description, evidence="") -> Finding:
        return self.finding(title, path, severity,
                            f"{description} Evidence: {evidence}." if evidence else description,
                            "Make cron files and scripts owned by root with mode 644/755, and make "
                            "their directories non-writable for other users.", tags)


if __name__ == "__main__":
    for item in CronCheck().run():
        print(item)
