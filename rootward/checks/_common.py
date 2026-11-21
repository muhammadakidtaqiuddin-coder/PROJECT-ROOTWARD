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


def write_sources(path: str, run_as_uid=None) -> set:
    """Which kinds of non-root user can write `path`, decided only from its permission bits so
    the answer does not depend on who runs the scan:
      'world': the other-write bit is set;
      'group': the group-write bit is set and the group is not root;
      'owner': the owner-write bit is set, the owner is not root, and the owner is not
               `run_as_uid` (the account that runs the file: editing your own file, such as
               your own crontab, is not an escalation).
    """
    try:
        st = os.stat(path)
    except OSError:
        return set()
    sources = set()
    if st.st_mode & stat.S_IWOTH:
        sources.add("world")
    if st.st_mode & stat.S_IWGRP and st.st_gid != 0:
        sources.add("group")
    if st.st_mode & stat.S_IWUSR and st.st_uid not in (0, run_as_uid):
        sources.add("owner")
    return sources


def writable_by_current_user(path: str, run_as_uid=None) -> bool:
    """True if an ordinary (non-root) user could write `path` (see write_sources)."""
    return bool(write_sources(path, run_as_uid))


def writable_tags(path: str, run_as_uid=None) -> list:
    """Tags for the ways an ordinary user can write `path`: 'world-writable' (other-write
    bit) and/or 'writable-by-user' (any write source). Empty if not writable."""
    sources = write_sources(path, run_as_uid)
    tags = []
    if "world" in sources:
        tags.append("world-writable")
    if sources:
        tags.append("writable-by-user")
    return tags


def can_replace(path: str, run_as_uid=None) -> bool:
    """True if an ordinary user could swap `path` by writing to its parent directory.
    A sticky parent (like /tmp) only allows this for the file's owner, so a file owned by
    a non-root account counts (that account can replace it) and a root-owned one does not.
    `run_as_uid` is the account that runs the file: its own files and directories are ignored."""
    parent = os.path.dirname(path) or "/"
    try:
        if not writable_by_current_user(parent, run_as_uid):
            return False
        if os.stat(parent).st_mode & stat.S_ISVTX:
            return os.stat(path).st_uid not in (0, run_as_uid)
    except FileNotFoundError:
        return True  # file missing but the directory is writable: it can be created
    except OSError:
        return False
    return True


def _same_device(path: str, device: int) -> bool:
    try:
        return os.lstat(path).st_dev == device
    except OSError:
        return False


def iter_files(roots=None, cross_mounts: bool = False) -> Iterator[tuple]:
    """Yield (path, lstat_result) for every regular file under `roots`.
    Read-only; never follows symlinks; stops early when the kill switch fires.
    Unless `cross_mounts` is set, a directory on another filesystem than its root (a Docker
    overlay, an NFS share, a mounted disk) is not entered; each root is still scanned."""
    reals = {os.path.realpath(r) for r in (roots or DEFAULT_ROOTS)}
    # drop missing roots and roots nested inside another root (e.g. /sbin -> /usr/sbin)
    top_level = sorted(r for r in reals if os.path.isdir(r)
                       and not any(r != o and r.startswith(o.rstrip("/") + "/") for o in reals))
    for real in top_level:
        try:
            root_device = os.lstat(real).st_dev
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(real, followlinks=False):
            if should_abort():
                return
            dirnames[:] = [
                d for d in dirnames
                if os.path.join(dirpath, d) not in SKIP_DIRS
                and (cross_mounts or _same_device(os.path.join(dirpath, d), root_device))
            ]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    yield path, st
