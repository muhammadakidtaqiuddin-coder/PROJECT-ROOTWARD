#!/usr/bin/env bash
# RootWard demo: DELIBERATELY misconfigures this machine so the auditor has something to find.
#
#   !!  TEST VM ONLY  !!  Never run this on a real, shared or production system.
#   It creates a user, a world-writable directory, a SUID copy of a binary, a cron job,
#   a sudoers.d rule and a file capability. Undo everything with cleanup_misconfig.sh.
#
# Usage:  sudo ./setup_misconfig.sh [--dry-run] [--yes-test-vm]
set -euo pipefail

DEMO_USER="rwdemo"
DEMO_DIR="/opt/rootward-demo"
CRON_FILE="/etc/cron.d/rootward-demo"
SUDOERS_FILE="/etc/sudoers.d/rootward-demo"
DRY=0
YES=0

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --yes-test-vm) YES=1 ;;
    -h | --help) usage 0 ;;
    *) echo "Unknown option: $arg" >&2; usage 1 ;;
  esac
done

say() { printf '%s\n' "$*"; }
act() { # run a command, or only print it in dry-run mode
  if ((DRY)); then printf '[dry-run] %s\n' "$*"; else "$@"; fi
}
put() { # put <path> <mode> <content>: write a file with a given mode
  local path="$1" mode="$2" content="$3"
  if ((DRY)); then
    printf '[dry-run] write %s (mode %s)\n' "$path" "$mode"
  else
    printf '%s\n' "$content" >"$path"
    chmod "$mode" "$path"
  fi
}

# ---- safety gates ---------------------------------------------------------------------
[[ "$(uname -s)" == "Linux" ]] || { say "Linux only."; exit 1; }
if ((!DRY)) && [[ "$EUID" -ne 0 ]]; then
  say "Run as root (sudo) on the test VM, or use --dry-run to preview."; exit 1
fi
if [[ -e "$DEMO_DIR" || -e "$CRON_FILE" || -e "$SUDOERS_FILE" ]] && ((!DRY)); then
  say "Demo files already exist. Run cleanup_misconfig.sh first."; exit 1
fi
if ((!YES)) && ((!DRY)); then
  say "This will weaken the security of THIS machine on purpose."
  read -r -p 'Type "TEST VM" to confirm this is a disposable test machine: ' answer
  [[ "$answer" == "TEST VM" ]] || { say "Aborted."; exit 1; }
fi

say "== RootWard demo misconfiguration =="

# 1. unprivileged demo user (password locked: use `runuser`/`sudo -u`, not a login)
if ((DRY)) || ! id "$DEMO_USER" >/dev/null 2>&1; then
  act useradd -m -s /bin/bash "$DEMO_USER"
  act passwd -l "$DEMO_USER"
fi

# 2. demo directory: root-owned, plus a WORLD-WRITABLE bin directory (PATH hijack / chain)
act mkdir -p "$DEMO_DIR/bin"
act chmod 755 "$DEMO_DIR"
act chmod 777 "$DEMO_DIR/bin"

# 3. SUID root GTFOBins-style binary (copy of find): expected CRITICAL (suid)
act cp /usr/bin/find "$DEMO_DIR/find"
act chown root:root "$DEMO_DIR/find"
act chmod 4755 "$DEMO_DIR/find"

# 4. unusual SUID root binary inside the world-writable dir: MEDIUM alone, escalated to
#    CRITICAL by the scoring chain (writable directory + SUID inside it)
act cp /usr/bin/id "$DEMO_DIR/bin/rw-report"
act chown root:root "$DEMO_DIR/bin/rw-report"
act chmod 4755 "$DEMO_DIR/bin/rw-report"

# 5. root cron job running a WORLD-WRITABLE script: expected CRITICAL (cron chain)
put "$DEMO_DIR/backup.sh" 0777 '#!/bin/sh
# harmless demo job: only appends a timestamp
date >> /opt/rootward-demo/backup.log'
put "$CRON_FILE" 0644 '# RootWard demo job (removed by cleanup_misconfig.sh)
*/5 * * * * root /opt/rootward-demo/backup.sh'

# 6. risky sudo rules for the demo user (validated with visudo before installing)
SUDO_RULES="Defaults:$DEMO_USER env_keep+=LD_PRELOAD
$DEMO_USER ALL=(root) NOPASSWD: /usr/bin/vim, /usr/bin/rsync *"
if ((DRY)); then
  printf '[dry-run] write %s (mode 0440), after visudo -cf check:\n%s\n' "$SUDOERS_FILE" "$SUDO_RULES"
else
  tmp="$(mktemp)"
  printf '%s\n' "$SUDO_RULES" >"$tmp"
  if visudo -cf "$tmp" >/dev/null; then
    install -m 0440 -o root -g root "$tmp" "$SUDOERS_FILE"
  else
    rm -f "$tmp"; say "sudoers syntax check failed; nothing was installed."; exit 1
  fi
  rm -f "$tmp"
fi

# 7. dangerous file capability (cap_setuid on a copy of python3): expected CRITICAL
PY="$(command -v python3 || true)"
if [[ -z "$PY" ]]; then
  say "python3 not found; skipping the capability step."
elif ! command -v setcap >/dev/null 2>&1 && ((!DRY)); then
  say "setcap not found (apt install libcap2-bin); skipping the capability step."
else
  act cp "$(readlink -f "$PY")" "$DEMO_DIR/python3-cap"
  act setcap cap_setuid+ep "$DEMO_DIR/python3-cap"
fi

say ""
say "Done. Run the audit as the demo user:  ./run_demo.sh"
say "Undo everything with:                  sudo ./cleanup_misconfig.sh"
