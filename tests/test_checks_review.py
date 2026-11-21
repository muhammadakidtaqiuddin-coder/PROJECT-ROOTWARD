"""Regression tests for the review of PR #1 (cron basename, writable-by-mode, sudo parsing,
capability tags, run-parts rules, lazy crontab discovery, GTFOBins name variants)."""
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from rootward.checks._common import base_name, can_replace, writable_by_current_user, writable_tags
from rootward.checks.capabilities import CapabilitiesCheck
from rootward.checks.cron import CronCheck
from rootward.checks.sudo_rules import parse_sudo_output
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


def fake_stat(mode, gid, uid=1000):
    """A stat result for a regular file with the given permission bits, group and owner."""
    return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


class WritableByModeTests(Tmp):
    """Review point 3: the answer must not depend on who runs the scan."""

    def test_group_writable_counts_when_scan_runs_as_root(self):
        with mock.patch("os.geteuid", return_value=0), \
                mock.patch("os.stat", return_value=fake_stat(0o100664, gid=1000)):
            self.assertTrue(writable_by_current_user("/anything"))

    def test_group_writable_by_the_root_group_is_not_counted(self):
        with mock.patch("os.geteuid", return_value=0), \
                mock.patch("os.stat", return_value=fake_stat(0o100664, gid=0, uid=0)):
            self.assertFalse(writable_by_current_user("/anything"))

    def test_world_writable_counts_when_scan_runs_as_root(self):
        path = self.make("w", 0o666)
        with mock.patch("os.geteuid", return_value=0):
            self.assertTrue(writable_by_current_user(path))
            self.assertEqual(writable_tags(path), ["world-writable", "writable-by-user"])

    def test_root_owned_plain_file_is_not_writable(self):
        for euid in (0, 1000):  # same answer whoever runs the scan
            with self.subTest(euid=euid), mock.patch("os.geteuid", return_value=euid),                     mock.patch("os.stat", return_value=fake_stat(0o100644, gid=0, uid=0)):
                self.assertFalse(writable_by_current_user("/anything"))
                self.assertEqual(writable_tags("/anything"), [])

    def test_file_writable_by_a_non_root_owner_counts_for_every_scan_user(self):
        for euid in (0, 1000):
            with self.subTest(euid=euid), mock.patch("os.geteuid", return_value=euid),                     mock.patch("os.stat", return_value=fake_stat(0o100644, gid=0, uid=1000)):
                self.assertTrue(writable_by_current_user("/anything"))

    def test_file_with_no_write_bits_is_not_writable(self):
        path = self.make("ro", 0o555)
        self.assertFalse(writable_by_current_user(path))

    def test_missing_path_is_not_writable(self):
        self.assertFalse(writable_by_current_user(os.path.join(self.tmp, "nope")))

    @unittest.skipIf(os.geteuid() == 0, "needs a non-root owner of the file")
    def test_sticky_dir_file_owned_by_a_user_can_be_replaced(self):
        os.chmod(self.tmp, 0o1777)
        path = self.make("mine", 0o644)  # owned by the (non-root) test user
        self.assertTrue(can_replace(path))


class CronReviewTests(Tmp):
    def test_wildcard_found_when_tool_has_full_path(self):  # review point 2
        tab = self.make("crontab", 0o444, "*/5 * * * * root /usr/bin/tar czf /tmp/x.tgz /data/*\n")
        found = CronCheck(crontabs=[(tab, True, None)], script_dirs=[]).run()
        self.assertTrue([f for f in found if f.title.startswith("Wildcard in cron command")])

    def test_wildcard_not_reported_for_other_tools(self):
        tab = self.make("crontab", 0o444, "*/5 * * * * root /usr/bin/ls /data/*\n")
        self.assertEqual(CronCheck(crontabs=[(tab, True, None)], script_dirs=[]).run(), [])

    def test_job_run_by_non_root_has_no_privileged_cron_tag(self):
        script = self.make("job.sh", 0o777)
        tab = self.make("crontab", 0o444, f"*/5 * * * * bob {script}\n")
        found = CronCheck(crontabs=[(tab, True, None)], script_dirs=[]).run()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.HIGH)
        self.assertIn("script-writable", found[0].tags)
        self.assertNotIn("cron", found[0].tags)
        self.assertNotIn("root-owned", found[0].tags)

    def test_script_dir_skips_dotted_and_non_executable_names(self):
        directory = os.path.join(self.tmp, "cron.daily")
        os.mkdir(directory)
        for name, mode in (("backup", 0o777), ("backup.sh", 0o777), ("noexec", 0o666)):
            path = os.path.join(directory, name)
            open(path, "w").close()
            os.chmod(path, mode)
        found = CronCheck(crontabs=[], script_dirs=[directory]).run()
        self.assertEqual([f.path.rsplit("/", 1)[-1] for f in found], ["backup"])

    def test_system_crontabs_are_globbed_when_discovering(self):
        spool = os.path.join(self.tmp, "cron.d")
        os.mkdir(spool)
        main_tab = self.make("crontab", 0o644, "")
        job = os.path.join(spool, "job")
        open(job, "w").close()
        with mock.patch("rootward.checks.cron.SYSTEM_CRONTAB", main_tab), \
                mock.patch("rootward.checks.cron.CRON_D_GLOB", spool + "/*"), \
                mock.patch("rootward.checks.cron.USER_SPOOLS", ()):
            paths = [p for p, _, _ in CronCheck._discover()]
        self.assertEqual(paths, [main_tab, job])


class SudoReviewTests(unittest.TestCase):
    def parse(self, rule):
        return parse_sudo_output(f"User x may run the following commands on host:\n    {rule}\n")

    def test_negated_command_is_not_reported(self):  # review point 4a
        found = self.parse("(root) NOPASSWD: ALL, !/usr/bin/su")
        self.assertEqual([f.title for f in found], ["sudo rule: ALL"])

    def test_only_negated_commands_give_no_findings(self):
        self.assertEqual(self.parse("(root) NOPASSWD: !/usr/bin/su, !/usr/bin/passwd"), [])

    def test_all_as_non_root_user_is_not_critical(self):  # review point 4b
        found = self.parse("(www-data) NOPASSWD: ALL")
        self.assertEqual(found[0].severity, Severity.HIGH)
        self.assertEqual(found[0].tags, set())

    def test_wildcard_as_non_root_user_gets_no_root_tags(self):
        found = self.parse("(www-data) NOPASSWD: /usr/bin/rsync *")
        self.assertLessEqual(found[0].severity, Severity.HIGH)
        self.assertEqual(found[0].tags, set())

    def test_root_and_all_runas_stay_critical(self):
        for runas in ("(root)", "(ALL)", "(ALL : ALL)", "(root, www-data)"):
            with self.subTest(runas=runas):
                found = self.parse(f"{runas} NOPASSWD: ALL")
                self.assertEqual(found[0].severity, Severity.CRITICAL)
                self.assertIn("sudo-nopasswd", found[0].tags)


class CapabilityReviewTests(Tmp):
    RAW_SETUID = struct.pack("<IIIII", 0x02000001, 1 << 7, 0, 0, 0)

    def run_check(self, mode, root):
        self.make("python3", mode)
        with mock.patch("os.getxattr", return_value=self.RAW_SETUID), \
                mock.patch("os.geteuid", return_value=0 if root else os.geteuid()):
            return CapabilitiesCheck(roots=[self.tmp]).run()

    def test_writable_binary_gets_writable_tags(self):  # review point 1
        found = self.run_check(0o777, root=True)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].tags, {"capability", "world-writable", "writable-by-user"})

    def test_read_only_binary_keeps_only_capability_tag(self):
        found = self.run_check(0o555, root=True)
        self.assertEqual(found[0].tags, {"capability"})


class BaseNameTests(unittest.TestCase):
    def test_debian_alternative_suffixes_are_stripped(self):
        for path, expected in (("/usr/bin/vim.basic", "vim"), ("/usr/bin/vim.tiny", "vim"),
                               ("/usr/bin/vim.gtk3", "vim"), ("/usr/bin/python3.11", "python"),
                               ("/usr/bin/find", "find"), ("nodejs", "nodejs")):
            with self.subTest(path=path):
                self.assertEqual(base_name(path), expected)


if __name__ == "__main__":
    unittest.main()
