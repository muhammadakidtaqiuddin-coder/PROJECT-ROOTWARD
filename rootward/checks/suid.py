"""Check: SUID/SGID binaries that could be abused for privilege escalation."""
import os
import stat

from rootward.checks._common import GTFO_BINARIES, base_name, iter_files, writable_by_current_user
from rootward.checks.base import BaseCheck
from rootward.models import Severity

# SUID/SGID programs shipped by mainstream distributions. These are expected and not reported.
STANDARD_BINARIES = frozenset({
    "su", "sudo", "sudoedit", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "chage",
    "expiry", "mount", "umount", "fusermount", "fusermount3", "pkexec",
    "polkit-agent-helper-1", "ping", "ping6", "traceroute6.iputils", "crontab", "at",
    "wall", "write", "bsd-write", "ssh-agent", "ssh-keysign", "unix_chkpwd",
    "unix_update", "pam_extrausers_chkpwd", "pam_timestamp_check", "newuidmap", "newgidmap", "dotlockfile",
    "mount.nfs", "mount.cifs", "Xorg.wrap", "dbus-daemon-launch-helper", "ntfs-3g",
    "chrome-sandbox", "utempter", "plocate", "mlocate", "locate", "lockfile", "ksu",
    "vmware-user-suid-wrapper", "staprun",
})
USER_WRITABLE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")


class SuidCheck(BaseCheck):
    check_id = "suid"
    title = "SUID/SGID binaries"

    def __init__(self, roots=None):
        super().__init__()
        self.roots = roots

    def run(self) -> list:
        findings = []
        for path, st in iter_files(self.roots):
            if self.aborted():
                break
            if not st.st_mode & 0o111:
                continue  # SUID/SGID bit on a non-executable file is not usable
            if not st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                continue
            finding = self._assess(path, st)
            if finding:
                findings.append(finding)
        return findings

    def _assess(self, path: str, st: os.stat_result):
        mode, name = st.st_mode, os.path.basename(path)
        is_suid = bool(mode & stat.S_ISUID)
        tags = ["suid" if is_suid else "sgid"]
        if st.st_uid == 0:
            tags.append("root-owned")
        if mode & stat.S_IWOTH:
            tags.append("world-writable")
        if writable_by_current_user(path):
            tags.append("writable-by-user")

        if "world-writable" in tags or "writable-by-user" in tags:
            severity, reason = Severity.CRITICAL, "the file can be replaced by an unprivileged user"
        elif base_name(name) in GTFO_BINARIES:
            severity = Severity.CRITICAL if (is_suid and st.st_uid == 0) else Severity.HIGH
            reason = "it is a known shell-escape / file-access binary (GTFOBins style)"
        elif path.startswith(USER_WRITABLE_PREFIXES):
            severity, reason = Severity.HIGH, "it sits in a user-writable location"
        elif name not in STANDARD_BINARIES:
            severity, reason = Severity.MEDIUM, "it is not a standard SUID/SGID program"
        else:
            return None

        kind = "SUID" if is_suid else "SGID"
        return self.finding(
            f"{kind} binary: {path}", path, severity,
            f"{path} runs with the privileges of its owner/group because {reason}. "
            f"Evidence: {stat.filemode(mode)} uid={st.st_uid} gid={st.st_gid}.",
            f"If it is not required: chmod u-s,g-s {path}. Confirm it belongs to an "
            "installed package (dpkg -S / rpm -qf) and remove it if it does not.",
            tags)


if __name__ == "__main__":
    for item in SuidCheck().run():
        print(item)
