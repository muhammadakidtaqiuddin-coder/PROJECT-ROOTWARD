"""Check: executables carrying dangerous Linux file capabilities (read from xattrs, read-only)."""
import os
import stat

from rootward.checks._common import iter_files, writable_tags
from rootward.checks.base import BaseCheck
from rootward.models import Severity

CAP_NAMES = (
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
    "setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw",
    "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod",
    "lease", "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
    "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
)
CRITICAL_CAPS = frozenset({"setuid", "setgid", "sys_admin", "sys_module", "dac_override"})
HIGH_CAPS = frozenset({"dac_read_search", "sys_ptrace", "chown", "fowner", "setfcap"})
_VFS_CAP_REVISION_MASK = 0xFF000000
_VFS_CAP_FLAGS_EFFECTIVE = 0x1


def decode_caps(data: bytes):
    """Decode a `security.capability` xattr into (permitted capability names, effective flag)."""
    if len(data) < 12:
        return [], False
    magic = int.from_bytes(data[0:4], "little")
    permitted = int.from_bytes(data[4:8], "little")
    if (magic & _VFS_CAP_REVISION_MASK) != 0x01000000 and len(data) >= 20:
        permitted |= int.from_bytes(data[12:16], "little") << 32  # revision 2/3: upper 32 bits
    names = [CAP_NAMES[i] for i in range(len(CAP_NAMES)) if permitted >> i & 1]
    return names, bool(magic & _VFS_CAP_FLAGS_EFFECTIVE)


class CapabilitiesCheck(BaseCheck):
    check_id = "capabilities"
    title = "Dangerous file capabilities"

    def __init__(self, roots=None):
        super().__init__()
        self.roots = roots

    def run(self) -> list:
        if not hasattr(os, "getxattr"):
            return []  # not Linux
        findings = []
        for path, st in iter_files(self.roots):
            if self.aborted():
                break
            if not st.st_mode & 0o111:
                continue
            try:
                raw = os.getxattr(path, "security.capability", follow_symlinks=False)
            except OSError:
                continue  # no capability set (or not readable)
            names, effective = decode_caps(raw)
            finding = self._assess(path, st, names, effective)
            if finding:
                findings.append(finding)
        return findings

    def _assess(self, path, st, names, effective):
        critical = sorted(CRITICAL_CAPS & set(names))
        high = sorted(HIGH_CAPS & set(names))
        if not critical and not high:
            return None
        flags = "+ep" if effective else "+p"
        listing = ",".join(f"cap_{n}" for n in names)
        # a writable binary that holds a capability lets a normal user take it over; the
        # tags let the scoring rule {capability, writable-by-user} (and path chains) fire
        tags = ["capability", *writable_tags(path)]
        writable_note = (" It can also be modified by an ordinary user, so the capability "
                         "can be hijacked." if len(tags) > 1 else "")
        return self.finding(
            f"Dangerous capability on {path}", path,
            Severity.CRITICAL if critical else Severity.HIGH,
            f"{path} holds {', '.join('cap_' + n for n in critical + high)}. "
            "Programs with these capabilities can often be used to become root "
            f"without being SUID.{writable_note} Evidence: {listing}{flags} ({stat.filemode(st.st_mode)}).",
            f"Remove it if not needed: setcap -r {path}",
            tags)


if __name__ == "__main__":
    for item in CapabilitiesCheck().run():
        print(item)
