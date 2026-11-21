"""Check: risky sudo rules reported by `sudo -n -l` (NOPASSWD, wildcards, shell-escape binaries)."""
import os
import re
import shutil
import subprocess

from rootward.checks._common import GTFO_BINARIES, base_name, bump
from rootward.checks.base import BaseCheck
from rootward.ethics import should_abort
from rootward.models import Finding, Severity

_RULE_RE = re.compile(r"^\s+\((?P<runas>[^)]*)\)\s*(?P<rest>.+)$")
_OPTION_RE = re.compile(r"^([A-Z_]+):\s*")
_DANGEROUS_ENV_RE = re.compile(r"env_keep\s*\+?=.*\b(LD_PRELOAD|LD_LIBRARY_PATH)\b")


def _make(title, path, severity, explanation, remediation, tags=None) -> Finding:
    return Finding(check_id="sudo_rules", title=title, path=path, severity=severity,
                   explanation=explanation, remediation=remediation, tags=set(tags or []))


def _info(title: str, description: str) -> Finding:
    return _make(title, "sudo", Severity.INFO, description,
                 "Run RootWard from the account you want to audit, in an interactive session.")


def _runs_as_root(runas: str) -> bool:
    """True if the (runas) part of a sudo rule includes root or ALL, e.g. 'root', 'ALL : ALL'."""
    return bool({"root", "ALL"} & set(re.split(r"[\s,:]+", runas)))


def _assess_rule(runas: str, options: set, command: str) -> Finding:
    nopasswd = "NOPASSWD" in options
    allows_all = command == "ALL"
    as_root = _runs_as_root(runas)
    # the tags below mean "can reach root"; a rule that only runs as another account gets none,
    # so the scoring rules (which assume root) do not escalate it
    tags = ["sudo-nopasswd"] if nopasswd and as_root else []
    severity = Severity.MEDIUM if nopasswd else Severity.LOW

    if allows_all:
        if nopasswd:
            severity = Severity.CRITICAL
    else:
        if base_name(command.split()[0]) in GTFO_BINARIES:
            severity = bump(severity, 2)
        if "*" in command:
            if as_root:
                tags.append("sudo-wildcard")
            severity = bump(severity, 1)
    if not as_root and severity > Severity.HIGH:
        severity = Severity.HIGH  # full control of another account is serious, but it is not root

    password = "without a password" if nopasswd else "with a password"
    # path = the program sudo runs, so scoring can chain it with a writable file
    path = command.split()[0] if command != "ALL" else "ALL"
    return _make(
        f"sudo rule: {command}", path, severity,
        f"The current user may run {command} as ({runas}) {password}. "
        "Shell-escape binaries and wildcard arguments can turn this into a root shell. "
        f"Evidence: ({runas}) {'NOPASSWD: ' if nopasswd else ''}{command}.",
        "Remove NOPASSWD where possible, avoid wildcards, and do not allow editors, "
        "interpreters or file tools through sudo (use sudoedit). Edit with visudo.",
        tags)


def parse_sudo_output(text: str) -> list:
    """Turn the text printed by `sudo -l` into findings (pure function, easy to unit test)."""
    findings = []
    for line in text.splitlines():
        if should_abort():
            break
        if _DANGEROUS_ENV_RE.search(line) or "!env_reset" in line:
            findings.append(_make(
                "sudo keeps dangerous environment variables", "/etc/sudoers", Severity.HIGH,
                "env_keep exposes LD_PRELOAD/LD_LIBRARY_PATH (or env_reset is disabled), "
                f"which lets a user load their own library into a sudo command. Evidence: {line.strip()}.",
                "Remove LD_PRELOAD and LD_LIBRARY_PATH from env_keep and keep env_reset enabled.",
                ["sudo-env-keep"]))
        match = _RULE_RE.match(line)
        if not match:
            continue
        rest, options = match.group("rest").strip(), set()
        while (option := _OPTION_RE.match(rest)):
            options.add(option.group(1))
            rest = rest[option.end():]
        for command in (c.strip() for c in rest.split(",")):
            if command and not command.startswith("!"):  # "!cmd" forbids a command: not a risk
                findings.append(_assess_rule(match.group("runas").strip(), options, command))
    return findings


class SudoRulesCheck(BaseCheck):
    check_id = "sudo_rules"
    title = "Risky sudo rules"

    def __init__(self, sudo_output=None):
        super().__init__()
        self.sudo_output = sudo_output  # inject text for testing; None = ask sudo

    def run(self) -> list:
        text = self.sudo_output
        if text is None:
            if shutil.which("sudo") is None:
                return [_info("sudo is not installed", "No sudo binary found, nothing to audit.")]
            try:
                proc = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True,
                                      timeout=10, stdin=subprocess.DEVNULL,
                                      env={**os.environ, "LC_ALL": "C"})
            except (OSError, subprocess.TimeoutExpired):
                return [_info("sudo could not be queried", "Running `sudo -n -l` failed or timed out.")]
            if proc.returncode != 0:
                return [_info("sudo rights not readable",
                              "`sudo -n -l` needs a password or this user has no sudo rights.")]
            text = proc.stdout
        return parse_sudo_output(text)


if __name__ == "__main__":
    for item in SudoRulesCheck().run():
        print(item)
