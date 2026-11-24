# RootWard demo VM (Role B)

Scripts that deliberately misconfigure a **disposable Linux test VM** so RootWard has something to find during the live PoC. Everything is reversible and limited to fixed paths.

> **TEST VM ONLY.** Never run these on a real, shared or production machine. Only audit systems you own or are authorised to test (Computer Crimes Act 1997).
>
> The setup makes the machine rootable by any local user on purpose (SUID `find`, a world-writable root cron script). `setup_misconfig.sh` therefore refuses to run unless `systemd-detect-virt` reports a VM, container or WSL (override: `--allow-bare-metal`, almost never wanted).

## Lab safety
1. Take a VM snapshot before the first run, so you can roll back whatever happens.
2. Use NAT or host-only networking while the demo files exist.
3. Run `sudo ./cleanup_misconfig.sh` straight after the demo (`verify_on_vm.sh` does it for you).
4. Prerequisites: `sudo apt install python3 vim rsync libcap2-bin sudo` (`visudo` comes with `sudo`; without `setcap` only the capability step is skipped).

## Files
| File | Purpose |
|------|---------|
| `setup_misconfig.sh` | Plants the misconfigurations (`--dry-run` previews, `--yes-test-vm` skips the confirmation prompt) |
| `run_demo.sh` | Runs the five checks + scanner + scoring as the demo user `rwdemo`, read-only; `--cli` runs the real tool instead |
| `cleanup_misconfig.sh` | Removes everything (user, directory, cron file, sudoers file); exits non-zero if the user is still there |

## One-command check on a test VM
`verify_on_vm.sh` runs every step, saves a log (`demo-verify-<host>-<time>.log`, ignored by git) and checks that the cleanup restored the system. Clone the repository on the VM first.
```bash
cd demo_vm && chmod +x *.sh
./verify_on_vm.sh --dry-run    # safe: prints the environment and runs the real path_perms check, changes nothing
./verify_on_vm.sh              # real run: asks for sudo, then you type TEST VM
```
The dry run shows how this distribution treats `/usr/local`. Stock Debian ships `/usr/local/bin` and `/usr/local/sbin` as `root:staff 2775`, so `path_perms` reports two MEDIUM findings (one per directory) with no tags. Kali and Ubuntu use `root:root 755` and report nothing (checked on Kali Rolling in VirtualBox: 0 findings). For screenshots use a terminal at least 120 columns wide.

## Order
```bash
cd demo_vm
chmod +x *.sh
./setup_misconfig.sh --dry-run     # preview, safe, needs no root
sudo ./setup_misconfig.sh          # type: TEST VM
sudo ./run_demo.sh                 # the audit
sudo ./cleanup_misconfig.sh        # undo
```
Optional, for the screenshot: `sudo ./run_demo.sh --cli` runs the real tool as `rwdemo` (banner, authorization prompt, coloured table, `--no-report` so nothing is written). Type `I AUTHORIZE` yourself.

## What is planted and what RootWard should report
| Plant | Check | Expected |
|-------|-------|----------|
| `/opt/rootward-demo/find`: SUID root copy of `find` | `suid` | CRITICAL (shell-escape binary, SUID root) |
| `/opt/rootward-demo/bin/rw-report`: SUID root copy of `id` in a world-writable directory | `suid` + `path_perms` | MEDIUM alone, **escalated to CRITICAL by the scoring chain** |
| `/etc/cron.d/rootward-demo` runs `/opt/rootward-demo/backup.sh` (mode 777) as root | `cron` | CRITICAL (root cron job + writable script) |
| sudoers rule: `rwdemo` may run `vim` and `rsync *` as root without a password | `sudo_rules` | CRITICAL (NOPASSWD + shell-escape binary, wildcard) |
| `Defaults:rwdemo env_keep+=LD_PRELOAD` | `sudo_rules` | HIGH, tag `sudo-env-keep` |
| `/opt/rootward-demo/python3-cap` with `cap_setuid+ep` | `capabilities` | CRITICAL |
| `PATH` starts with the world-writable `/opt/rootward-demo/bin` (set by `run_demo.sh`) | `path_perms` | CRITICAL (writable, before the system directories) |
| *(not planted)* `run_demo.sh` also puts `/usr/local/bin` in `PATH`; on stock Debian it is `root:staff 2775` | `path_perms` | one extra MEDIUM "System PATH directory writable by group staff" on Debian only; absent on Kali and Ubuntu |
| *(not planted)* the SUID programs the distribution already has | `suid` | MEDIUM each when they are not on the allowlist; on Kali Rolling with Kismet installed that is about 14 lines (`kismet_cap_*`, `rsh-redone-*`, `pppd`); they sort below the CRITICAL findings |

The cron job only appends a timestamp to `/opt/rootward-demo/backup.log`; nothing here exploits anything.

## Notes
- `run_demo.sh` copies the repository's `rootward/` package to a temporary directory so the demo user can read it, and removes the copy afterwards.
- The sudo check runs `sudo -n -l` for the current user, so the audit must run as `rwdemo` (which `run_demo.sh` does).
- Verified before use: `bash -n` syntax check and `--dry-run` of setup and cleanup. `verify_on_vm.sh --dry-run` also verified on Ubuntu WSL (2026-11-23). Real run on Kali Rolling (VirtualBox) on 2026-11-24: all seven planted findings reported as listed above, the `rw-report` chain shown, cleanup restored the system (`CLEANUP OK`).
