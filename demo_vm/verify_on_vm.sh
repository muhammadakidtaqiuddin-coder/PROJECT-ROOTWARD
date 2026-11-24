#!/usr/bin/env bash
# RootWard demo: end-to-end verification, to be run BY THE OWNER ON THE TEST VM (Kali/Debian).
#
#   !!  TEST VM ONLY  !!  The real run plants deliberate misconfigurations (see setup_misconfig.sh)
#   and removes them again at the end, even if something fails (cleanup runs from a trap).
#
# What it does, and saves to demo-verify-<host>-<time>.log next to this script:
#   1. environment: OS, Python, and /usr/local/bin ownership (the Debian "staff" case)
#   2. the REAL path_perms check on this machine's actual PATH directories
#   3. a snapshot of the system before, setup_misconfig.sh, proof that the misconfigurations exist
#   4. run_demo.sh: the audit as the demo user (the output to screenshot)
#   5. cleanup_misconfig.sh, a snapshot after, and a check that the system is back as it was
#
# Usage:  ./verify_on_vm.sh --dry-run     print the plan and the environment only (safe, no sudo)
#         ./verify_on_vm.sh               real run (asks for sudo; setup asks you to type: TEST VM)
# Run it from a clone of the repository: these scripts live in <repo>/demo_vm.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." 2>/dev/null && pwd || true)"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1
LOG="$HERE/demo-verify-$(hostname)-$(date +%Y%m%d-%H%M%S).log"
SETUP_STARTED=0

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
hr() { say ""; say "================ $* ================"; }
run() { say "\$ $*"; "$@" 2>&1 | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }

snapshot() { # print the parts of the system the demo touches, in a stable form
  echo "-- user rwdemo: $(getent passwd rwdemo || echo none)"
  echo "-- /opt/rootward-demo: $(ls -d /opt/rootward-demo 2>/dev/null || echo none)"
  echo "-- /etc/cron.d: $(ls /etc/cron.d 2>/dev/null | tr '\n' ' ')"
  echo "-- /etc/sudoers.d: $(ls /etc/sudoers.d 2>/dev/null | tr '\n' ' ')"
  echo "-- accounts: $(getent passwd | wc -l) users, $(getent group | wc -l) groups"
  echo "-- passwd/group checksum: $(cat /etc/passwd /etc/group | sha256sum | cut -c1-16)"
  echo "-- SUID files under /opt /usr/local /home /tmp: $(find /opt /usr/local /home /tmp -xdev -perm -4000 -type f 2>/dev/null | sort | tr '\n' ' ')"
  echo "-- PATH dirs: $(stat -c '%n %a %U:%G' /usr/local/bin /usr/local/sbin 2>/dev/null | tr '\n' ';')"
}

cleanup_on_exit() {
  if ((SETUP_STARTED)) && [[ -e /opt/rootward-demo || -e /etc/cron.d/rootward-demo || -e /etc/sudoers.d/rootward-demo ]]; then
    hr "SAFETY CLEANUP (trap): demo files still present, removing them"
    sudo "$HERE/cleanup_misconfig.sh" 2>&1 | tee -a "$LOG"
  fi
}
trap cleanup_on_exit EXIT

say "RootWard demo verification: $(date '+%Y-%m-%d %A %H:%M %z') on $(hostname)"
say "log file: $LOG"
[[ -f "$REPO/rootward/scanner.py" ]] || { say "ERROR: $REPO is not the RootWard repository; run this script from <repo>/demo_vm."; exit 1; }
[[ "$(uname -s)" == "Linux" ]] || { say "Linux only."; exit 1; }

hr "1. Environment"
run bash -c '. /etc/os-release; echo "OS: $PRETTY_NAME"'
run python3 --version
run ls -ld /usr/local/bin /usr/local/sbin /usr/sbin /usr/bin /bin
run getent group staff
run bash -c 'id; command -v sudo setcap visudo'
run git -C "$REPO" log -1 --format='repo HEAD: %h %s'

hr "2. The real path_perms check on this machine (the Debian 'staff' case)"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$REPO" PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  python3 - <<'PY' 2>&1 | tee -a "$LOG"
from rootward.checks.path_perms import PathPermsCheck
found = PathPermsCheck().run()
print(f"findings for the standard system PATH: {len(found)}")
for f in found:
    print(f"  [{f.severity.name}] {f.title} | tags={sorted(f.tags)}")
print("expected on stock Debian (/usr/local/bin and /usr/local/sbin are both root:staff 2775): TWO MEDIUM findings (one per directory), each with tags=[]")
print("expected on Kali and Ubuntu (root:root 755): no finding")
PY

if ((DRY)); then
  hr "DRY RUN: stopping here. Planned real steps"
  say "3. snapshot before -> sudo ./setup_misconfig.sh -> proof of plants"
  say "4. sudo ./run_demo.sh (the audit as rwdemo)"
  say "5. sudo ./cleanup_misconfig.sh -> snapshot after -> compare"
  say "Nothing was changed."
  trap - EXIT; exit 0
fi

hr "3. Snapshot BEFORE, then setup (type TEST VM when asked)"
snapshot | tee -a "$LOG" > "$HERE/.before.snapshot"
SETUP_STARTED=1
sudo "$HERE/setup_misconfig.sh" 2>&1 | tee -a "$LOG"
hr "3b. Proof that the misconfigurations exist"
run ls -l /opt/rootward-demo /opt/rootward-demo/bin
run cat /etc/cron.d/rootward-demo
run sudo cat /etc/sudoers.d/rootward-demo
run getcap /opt/rootward-demo/python3-cap
run sudo -l -U rwdemo

hr "4. The audit as the demo user: SCREENSHOT THIS (terminal at 120+ columns)"
sudo "$HERE/run_demo.sh" 2>&1 | tee -a "$LOG"
say ""
say "On stock Debian (not Kali or Ubuntu) one extra MEDIUM line ('System PATH directory writable by group staff', /usr/local/bin) is normal."
say "The distribution's own SUID programs may add MEDIUM lines below the CRITICAL ones."
say "For the screenshot run the real tool by hand:  sudo ./run_demo.sh --cli   (type I AUTHORIZE yourself)."
say "Expected (see README.md in this folder): CRITICAL for find, cron backup.sh, sudo vim and rsync *, python3-cap and the PATH directory;"
say "rw-report is MEDIUM alone but CRITICAL with a 'Risk correlation: Chain' line; env_keep LD_PRELOAD is HIGH."

hr "5. Cleanup, snapshot AFTER, compare"
sudo "$HERE/cleanup_misconfig.sh" 2>&1 | tee -a "$LOG"
snapshot | tee -a "$LOG" > "$HERE/.after.snapshot"
if diff -q "$HERE/.before.snapshot" "$HERE/.after.snapshot" >/dev/null; then
  say "CLEANUP OK: users, groups, SUID files, cron.d, sudoers.d and the PATH directories match the snapshot taken before setup (it does not compare everything on the system)."
else
  say "CLEANUP DIFFERS from the snapshot before setup:"; diff "$HERE/.before.snapshot" "$HERE/.after.snapshot" | tee -a "$LOG"
fi
rm -f "$HERE/.before.snapshot" "$HERE/.after.snapshot"
hr "Done"
say "Send this log file back (it contains hostnames and paths of this VM only). Screenshot step 4."
