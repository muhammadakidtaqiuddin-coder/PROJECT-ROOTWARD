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


_VARIANT_SUFFIX_RE = re.compile(r"\.(basic|tiny|nox|gtk\d*|gnome|athena|traditional|original|openbsd)$")


def base_name(path: str) -> str:
    """'/usr/bin/python3.11' -> 'python', '/usr/bin/vim.basic' -> 'vim'
    (strips the directory, Debian alternative suffixes such as .basic/.tiny, and version digits)."""
    name = _VARIANT_SUFFIX_RE.sub("", os.path.basename(path))
    return re.sub(r"[\d.]+$", "", name)


def bump(severity: Severity, steps: int = 1) -> Severity:
    """Raise a severity by `steps` levels, capped at CRITICAL."""
    index = min(_SEVERITY_ORDER.index(severity) + steps, len(_SEVERITY_ORDER) - 1)
    return _SEVERITY_ORDER[index]


def writable_by_current_user(path: str) -> bool:
    """True if an ordinary (non-root) user could write `path`.

    Decided only from the permission bits, so the answer does not depend on who runs the scan
    (a scan as root reports the same as a scan as a normal user). Writable means: writable by
    everyone, writable by a group that is not root, or writable by an owner that is not root.
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    if st.st_mode & stat.S_IWOTH:
        return True
    if st.st_mode & stat.S_IWGRP and st.st_gid != 0:
        return True
    return bool(st.st_mode & stat.S_IWUSR and st.st_uid != 0)


def writable_tags(path: str) -> list:
    """Tags for the ways an ordinary user can write `path`: 'world-writable' (other-write
    bit) and/or 'writable-by-user' (see writable_by_current_user). Empty if not writable."""
    tags = []
    try:
        if os.stat(path).st_mode & stat.S_IWOTH:
            tags.append("world-writable")
    except OSError:
        return tags
    if writable_by_current_user(path):
        tags.append("writable-by-user")
    return tags


def can_replace(path: str) -> bool:
    """True if an ordinary user could swap `path` by writing to its parent directory.
    A sticky parent (like /tmp) only allows this for the file's owner, so a file owned by
    a non-root account counts (that account can replace it) and a root-owned one does not."""
    parent = os.path.dirname(path) or "/"
    try:
        if not writable_by_current_user(parent):
            return False
        if os.stat(parent).st_mode & stat.S_ISVTX:
            return os.stat(path).st_uid != 0
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
