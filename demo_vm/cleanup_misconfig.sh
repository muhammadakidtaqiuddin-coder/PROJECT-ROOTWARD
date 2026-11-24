#!/usr/bin/env bash
# RootWard demo: removes everything setup_misconfig.sh created. Touches only these fixed paths:
#   user rwdemo (and its home), /opt/rootward-demo, /etc/cron.d/rootward-demo,
#   /etc/sudoers.d/rootward-demo, /var/log/rootward-demo.log
#
# Usage:  sudo ./cleanup_misconfig.sh [--dry-run]
set -euo pipefail

DEMO_USER="rwdemo"
DEMO_DIR="/opt/rootward-demo"
CRON_FILE="/etc/cron.d/rootward-demo"
SUDOERS_FILE="/etc/sudoers.d/rootward-demo"
DRY=0

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    -h | --help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

act() { if ((DRY)); then printf '[dry-run] %s\n' "$*"; else "$@"; fi; }

[[ "$(uname -s)" == "Linux" ]] || { echo "Linux only."; exit 1; }
if ((!DRY)) && [[ "$EUID" -ne 0 ]]; then
  echo "Run as root (sudo), or use --dry-run to preview."; exit 1
fi

echo "== RootWard demo cleanup =="

# remove the risky config first, so the machine is safe again even if a later step fails
[[ -e "$CRON_FILE" ]] && act rm -f -- "$CRON_FILE"
[[ -e "$SUDOERS_FILE" ]] && act rm -f -- "$SUDOERS_FILE"

# demo user: stop its processes, then delete the account and its home
if id "$DEMO_USER" >/dev/null 2>&1; then
  act pkill -u "$DEMO_USER" || true
  act userdel -r "$DEMO_USER" || true
fi

# demo directory: fixed literal path only, never a variable that could be empty or changed
if [[ -d "/opt/rootward-demo" ]]; then
  act rm -rf -- "/opt/rootward-demo"
fi
[[ -e /var/log/rootward-demo.log ]] && act rm -f -- /var/log/rootward-demo.log

echo "Done. Verify:"
echo "  id $DEMO_USER                  (should say: no such user)"
echo "  ls $DEMO_DIR $CRON_FILE $SUDOERS_FILE   (should say: no such file)"
