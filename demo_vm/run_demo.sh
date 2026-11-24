#!/usr/bin/env bash
# RootWard demo: runs the real checks, scanner and scoring AS THE DEMO USER (rwdemo),
# read-only, against the machine prepared by setup_misconfig.sh.
#
# Uses the repo's own code (this folder sits at the repository root).
#
# Usage:  sudo ./run_demo.sh          short list of findings (works anywhere, good for logs)
#         sudo ./run_demo.sh --cli    the real tool: banner, authorization prompt (type I AUTHORIZE
#                                     yourself), coloured table; nothing is written (--no-report)
set -euo pipefail

DEMO_USER="rwdemo"
DEMO_DIR="/opt/rootward-demo"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

[[ "$EUID" -eq 0 ]] || { echo "Run with sudo (needed only to switch to $DEMO_USER)."; exit 1; }
id "$DEMO_USER" >/dev/null 2>&1 || { echo "Run setup_misconfig.sh first."; exit 1; }
[[ -d "$DEMO_DIR" ]] || { echo "Run setup_misconfig.sh first."; exit 1; }

# assemble a temp tree with a copy of the repo code (the demo user cannot read every path)
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cp -r "$REPO/rootward" "$T/"
chmod -R a+rX "$T"

cat >"$T/demo_scan.py" <<'PY'
from rootward.scanner import run_scan
from rootward.scoring import apply_scoring, summarize, validate_tags

result = run_scan()
findings = apply_scoring(result.findings)
print(f"checks run: {result.checks_run}   errors: {result.errors}")
for f in findings:
    note = f"  <- {f.escalation_note}" if f.escalation_note else ""
    print(f"[{f.severity.name:8}] {f.check_id:12} {f.path}{note}")
summary = summarize(findings)
print("\nsummary:", summary["counts"], "risk score:", summary["risk_score"], summary["overall_rating"])
unknown = validate_tags(findings)
if unknown:
    print("unknown tags:", unknown)
PY
chmod a+r "$T/demo_scan.py"

echo "== read-only audit as $DEMO_USER (PATH includes the writable demo bin first) =="
if (( 8#$(stat -c %a /usr/local/bin 2>/dev/null || echo 0) & 8#020 )); then
  echo "(This PATH also contains /usr/local/bin, which is group-writable here: expect one extra MEDIUM 'System PATH directory writable by group staff' finding.)"
fi
cd "$T"   # a directory the demo user can read (the caller's cwd may not be)
if [[ "${1:-}" == "--cli" ]]; then
  runuser -u "$DEMO_USER" -- env \
    PATH="$DEMO_DIR/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONPATH="$T" PYTHONDONTWRITEBYTECODE=1 \
    python3 -m rootward --no-report
  exit $?
fi
runuser -u "$DEMO_USER" -- env \
  PATH="$DEMO_DIR/bin:/usr/local/bin:/usr/bin:/bin" \
  PYTHONPATH="$T" PYTHONDONTWRITEBYTECODE=1 \
  python3 "$T/demo_scan.py"
