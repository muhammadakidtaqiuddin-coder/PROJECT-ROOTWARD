"""Shared read-only helpers for the RootWard checks (this module is not a check)."""
import os
import re
import stat
from collections.abc import Iterator

from rootward.ethics import should_abort
from rootward.models import Severity

# Directories walked by the filesystem checks. /proc, /sys, /dev and /run are never entered.
DEFAULT_ROOTS = ("/usr", "/bin", "/sbin", "/opt", "/home", "/tmp", "/var", "/srv")
SKIP_DIRS = frozenset({"/proc", "/sys", "/dev", "/run", "/snap"})

# Programs that give a shell or arbitrary file access when run with elevated rights
# (small subset inspired by the public GTFOBins catalogue).
GTFO_BINARIES = frozenset({
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox", "expect",
    "find", "vim", "vi", "view", "nano", "ed", "less", "more", "awk", "gawk", "mawk",
    "nawk", "sed", "python", "perl", "ruby", "php", "lua", "node", "nodejs", "tclsh",
    "nmap", "cp", "mv", "dd", "tar", "zip", "unzip", "rsync", "env", "nice", "ionice",
    "timeout", "time", "strace", "ltrace", "gdb", "docker", "make", "git", "ftp", "wget",
    "curl", "base64", "xxd", "tee", "ssh", "scp", "systemctl", "journalctl", "apt",
    "apt-get", "pip", "mysql", "sqlite3", "openssl",
})

_SEVERITY_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def base_name(path: str) -> str:
    """'/usr/bin/python3.11' -> 'python' (strips directory and trailing version digits)."""
    return re.sub(r"[\d.]+$", "", os.path.basename(path))


def bump(severity: Severity, steps: int = 1) -> Severity:
    """Raise a severity by `steps` levels, capped at CRITICAL."""
    index = min(_SEVERITY_ORDER.index(severity) + steps, len(_SEVERITY_ORDER) - 1)
    return _SEVERITY_ORDER[index]


def writable_by_current_user(path: str) -> bool:
    """True if the user running the scan can write `path`. Always False for root,
    because root can write everything and that is not a privilege-escalation path."""
    return os.geteuid() != 0 and os.access(path, os.W_OK)


def can_replace(path: str) -> bool:
    """True if the current user could swap `path` by writing to its parent directory.
    A sticky parent (like /tmp) only allows this when the user owns the file."""
    parent = os.path.dirname(path) or "/"
    try:
        if not writable_by_current_user(parent):
            return False
        if os.stat(parent).st_mode & stat.S_ISVTX:
            return os.stat(path).st_uid == os.geteuid()
    except FileNotFoundError:
        return True  # file missing but the directory is writable: it can be created
    except OSError:
        return False
    return True


def iter_files(roots=None) -> Iterator[tuple]:
    """Yield (path, lstat_result) for every regular file under `roots`.
    Read-only; never follows symlinks; stops early when the kill switch fires."""
    reals = {os.path.realpath(r) for r in (roots or DEFAULT_ROOTS)}
    # drop missing roots and roots nested inside another root (e.g. /sbin -> /usr/sbin)
    top_level = sorted(r for r in reals if os.path.isdir(r)
                       and not any(r != o and r.startswith(o.rstrip("/") + "/") for o in reals))
    for real in top_level:
        for dirpath, dirnames, filenames in os.walk(real, followlinks=False):
            if should_abort():
                return
            dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in SKIP_DIRS]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    yield path, st
