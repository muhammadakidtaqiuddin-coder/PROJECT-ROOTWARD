"""Quick checks for Role B. Run with run_tests.sh (assembles the stubs + checks first)."""
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from rootward.checks.capabilities import CapabilitiesCheck, decode_caps
from rootward.checks.cron import CronCheck, parse_cron_line
from rootward.checks.path_perms import PathPermsCheck
from rootward.checks.sudo_rules import SudoRulesCheck, parse_sudo_output
from rootward.checks.suid import SuidCheck
from rootward.models import Severity


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def make(self, name, mode, content="#!/bin/sh\nexit 0\n"):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as handle:
            handle.write(content)
        os.chmod(path, mode)
        return path


class SuidTests(Tmp):
    def test_gtfo_suid_flagged(self):
        self.make("find", 0o4755)
        found = SuidCheck(roots=[self.tmp]).run()
        self.assertEqual(len(found), 1)
        self.assertIn(found[0].severity, (Severity.HIGH, Severity.CRITICAL))
        self.assertIn("suid", found[0].tags)

    def test_world_writable_is_critical(self):
        self.make("tool", 0o4777)
        found = SuidCheck(roots=[self.tmp]).run()
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        self.assertIn("world-writable", found[0].tags)

    def test_standard_binary_ignored_and_plain_file_ignored(self):
        self.make("passwd", 0o4555)  # read-only, so not user-writable
        self.make("plain", 0o755)
        # the temp dir lives under /tmp, which would trigger the user-writable-location rule
        with mock.patch("rootward.checks.suid.USER_WRITABLE_PREFIXES", ()):
            self.assertEqual(SuidCheck(roots=[self.tmp]).run(), [])


class WalkTests(Tmp):
    def test_nested_roots_not_scanned_twice(self):
        from rootward.checks._common import iter_files
        sub = os.path.join(self.tmp, "sub")
        os.mkdir(sub)
        self.make("sub/f", 0o755)
        paths = [p for p, _ in iter_files([self.tmp, sub])]
        self.assertEqual(len(paths), 1)


class SudoTests(unittest.TestCase):
    SAMPLE = """Matching Defaults entries for obey on host:
    env_reset, env_keep+=LD_PRELOAD

User obey may run the following commands on host:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/vim, /usr/bin/rsync *
    (root) /usr/bin/ls
    (ALL) NOPASSWD: ALL
"""

    def test_parse(self):
        found = parse_sudo_output(self.SAMPLE)
        sev = lambda title: [f.severity for f in found if f.title == title]
        self.assertEqual(sev("sudo rule: /usr/bin/vim"), [Severity.CRITICAL])
        self.assertEqual(sev("sudo rule: /usr/bin/ls"), [Severity.LOW])
        # "ALL" appears twice: with password (LOW) and NOPASSWD (CRITICAL)
        self.assertEqual(sorted(s.name for s in sev("sudo rule: ALL")), ["CRITICAL", "LOW"])
        rsync = [f for f in found if f.title == "sudo rule: /usr/bin/rsync *"][0]
        self.assertEqual(rsync.severity, Severity.CRITICAL)
        self.assertIn("sudo-wildcard", rsync.tags)
        env = [f for f in found if "sudo-env-keep" in f.tags]
        self.assertEqual(env[0].severity, Severity.HIGH)

    def test_injected_output_used(self):
        self.assertTrue(SudoRulesCheck(sudo_output=self.SAMPLE).run())


class CronTests(Tmp):
    def test_parse_lines(self):
        self.assertEqual(parse_cron_line("*/5 * * * * root /opt/a.sh --x"), ("root", "/opt/a.sh --x"))
        self.assertEqual(parse_cron_line("@daily bob /opt/b.sh"), ("bob", "/opt/b.sh"))
        self.assertEqual(parse_cron_line("0 1 * * * /opt/c.sh", system=False), (None, "/opt/c.sh"))
        self.assertIsNone(parse_cron_line("# comment"))
        self.assertIsNone(parse_cron_line("MAILTO=root"))
        self.assertIsNone(parse_cron_line(""))

    def test_writable_script_run_by_root(self):
        script = self.make("backup.sh", 0o777)
        tab = self.make("crontab", 0o444, f"SHELL=/bin/sh\n*/5 * * * * root {script}\n")
        found = CronCheck(crontabs=[(tab, True, None)], script_dirs=[]).run()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        for tag in ("cron", "root-owned", "script-writable", "world-writable"):
            self.assertIn(tag, found[0].tags)

    def test_safe_script_not_reported(self):
        script = self.make("ok.sh", 0o755)
        tab = self.make("crontab", 0o444, f"*/5 * * * * root {script}\n")
        found = CronCheck(crontabs=[(tab, True, None)], script_dirs=[]).run()
        self.assertEqual([f for f in found if "script-writable" in f.tags and
                          "world-writable" in f.tags], [])


class CapabilityTests(Tmp):
    def test_decode(self):
        raw = struct.pack("<IIIII", 0x02000001, (1 << 7) | (1 << 1), 0, 0, 0)
        names, effective = decode_caps(raw)
        self.assertEqual(sorted(names), ["dac_override", "setuid"])
        self.assertTrue(effective)

    def test_check_flags_setuid_cap(self):
        self.make("python3", 0o555)  # no write bits: only the capability tag applies
        raw = struct.pack("<IIIII", 0x02000001, 1 << 7, 0, 0, 0)
        with mock.patch("os.getxattr", return_value=raw):
            found = CapabilitiesCheck(roots=[self.tmp]).run()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        self.assertEqual(found[0].tags, {"capability"})

    def test_harmless_cap_ignored(self):
        self.make("ping", 0o755)
        raw = struct.pack("<IIIII", 0x02000001, 1 << 13, 0, 0, 0)  # cap_net_raw
        with mock.patch("os.getxattr", return_value=raw):
            self.assertEqual(CapabilitiesCheck(roots=[self.tmp]).run(), [])


class PathTests(Tmp):
    def test_writable_dir_and_relative_entry(self):
        os.chmod(self.tmp, 0o777)
        found = PathPermsCheck(path_value=f"{self.tmp}:/usr/bin:.").run()
        titles = {f.title: f for f in found}
        self.assertEqual(titles[f"Writable PATH directory: {self.tmp}"].severity, Severity.CRITICAL)
        self.assertIn("Relative PATH entry: .", titles)

    def test_clean_path(self):
        self.assertEqual(PathPermsCheck(path_value="/usr/bin:/bin").run(), [])


if __name__ == "__main__":
    unittest.main()
