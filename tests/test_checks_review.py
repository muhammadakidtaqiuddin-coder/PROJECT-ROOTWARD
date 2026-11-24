"""Regression tests for the review of PR #1 (cron basename, writable-by-mode, sudo parsing,
capability tags, run-parts rules, lazy crontab discovery, GTFOBins name variants)."""
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from rootward.checks._common import (base_name, can_replace, iter_files, write_sources,
                                     writable_by_current_user, writable_tags)
from rootward.checks.capabilities import CapabilitiesCheck
from rootward.checks.cron import CronCheck, _uid_of
from rootward.checks.path_perms import PathPermsCheck
from rootward.checks.sudo_rules import parse_sudo_output
from rootward.models import Finding, Severity
from rootward.scoring import apply_scoring


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


def dir_stat(mode, uid, gid):
    """A stat result for a directory with the given permission bits, owner and group."""
    return fake_stat(0o40000 | mode, gid, uid)


def patch_stat(overrides):
    """Patch os.stat so the given paths return fake results and every other path stays real."""
    real = os.stat

    def fake(path, *args, **kwargs):
        return overrides[path] if path in overrides else real(path, *args, **kwargs)

    return mock.patch("os.stat", side_effect=fake)


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

    def test_sticky_dir_file_owned_by_a_user_can_be_replaced(self):
        parent, path = "/tmp/sticky", "/tmp/sticky/f"  # fake stats: never skipped, any scan user
        sticky = dir_stat(0o1777, uid=0, gid=0)
        with patch_stat({parent: sticky, path: fake_stat(0o100644, gid=1000, uid=1000)}):
            self.assertTrue(can_replace(path))
            self.assertFalse(can_replace(path, run_as_uid=1000))  # the account's own file
        with patch_stat({parent: sticky, path: fake_stat(0o100644, gid=0, uid=0)}):
            self.assertFalse(can_replace(path))  # root-owned: a normal user cannot replace it


class WriteSourceTests(unittest.TestCase):
    """Review point A: owner-write counts unless the owner is the account that runs the file."""

    def sources(self, stat_result, **kwargs):
        with mock.patch("os.stat", return_value=stat_result):
            return write_sources("/anything", **kwargs)

    def test_owner_write_counts_for_other_accounts(self):
        mine = fake_stat(0o100600, gid=1000, uid=1000)
        self.assertEqual(self.sources(mine), {"owner"})
        self.assertEqual(self.sources(mine, run_as_uid=1001), {"owner"})

    def test_owner_write_is_ignored_for_the_account_that_runs_the_file(self):
        self.assertEqual(self.sources(fake_stat(0o100600, gid=1000, uid=1000), run_as_uid=1000), set())

    def test_group_and_world_still_count_for_the_runner(self):
        self.assertEqual(self.sources(fake_stat(0o100660, gid=100, uid=1000), run_as_uid=1000), {"group"})
        self.assertEqual(self.sources(fake_stat(0o100666, gid=0, uid=0), run_as_uid=1000), {"world"})

    def test_root_owned_file_has_no_sources(self):
        self.assertEqual(self.sources(fake_stat(0o100644, gid=0, uid=0)), set())


class IterFilesDeviceTests(Tmp):
    """Review point E: do not cross into other filesystems unless asked."""

    def test_other_filesystems_are_not_entered(self):
        main, mount = os.path.join(self.tmp, "a"), os.path.join(self.tmp, "mnt")
        os.mkdir(main)
        os.mkdir(mount)
        open(os.path.join(main, "f"), "w").close()
        open(os.path.join(mount, "g"), "w").close()
        real = os.lstat

        def fake(path, *args, **kwargs):
            st = real(path, *args, **kwargs)
            if path == mount:  # pretend this directory is a mount of another filesystem
                fields = list(st)
                fields[2] = st.st_dev + 1
                return os.stat_result(tuple(fields[:10]))
            return st

        def names(**kw):
            return sorted(os.path.basename(p) for p, _ in iter_files([self.tmp], **kw))

        with mock.patch("os.lstat", side_effect=fake):
            self.assertEqual(names(), ["f"])
            self.assertEqual(names(cross_mounts=True), ["f", "g"])


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

    def test_unreadable_script_dir_is_skipped_not_fatal(self):
        with mock.patch("rootward.checks.cron.os.listdir", side_effect=PermissionError("denied")):
            found = CronCheck(crontabs=[], script_dirs=[self.tmp]).run()
        self.assertEqual(found, [])

    def test_script_that_vanishes_between_listing_and_stat_is_skipped(self):
        self.make("job", 0o777)
        with mock.patch("rootward.checks.cron.os.stat", side_effect=FileNotFoundError):
            found = CronCheck(crontabs=[], script_dirs=[self.tmp]).run()
        self.assertEqual(found, [])

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


class CronOwnerTests(Tmp):
    """Review points A and C for cron."""

    def test_users_own_spool_crontab_is_not_flagged(self):
        tab = self.make("alice", 0o600, "*/5 * * * * echo hi\n")
        with patch_stat({tab: fake_stat(0o100600, gid=100, uid=1000)}), \
                mock.patch("rootward.checks.cron._uid_of", return_value=1000):
            found = CronCheck(crontabs=[(tab, False, "alice")], script_dirs=[]).run()
        self.assertEqual(found, [])

    def test_spool_crontab_writable_by_others_is_high_without_cron_tag(self):
        tab = self.make("alice", 0o600, "*/5 * * * * echo hi\n")
        with patch_stat({tab: fake_stat(0o100666, gid=100, uid=1000)}), \
                mock.patch("rootward.checks.cron._uid_of", return_value=1000):
            found = CronCheck(crontabs=[(tab, False, "alice")], script_dirs=[]).run()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.HIGH)
        self.assertNotIn("cron", found[0].tags)

    def test_writable_system_crontab_is_critical(self):  # review point C
        tab = self.make("crontab", 0o644, "")
        with patch_stat({tab: fake_stat(0o100666, gid=0, uid=0)}):
            found = CronCheck(crontabs=[(tab, True, None)], script_dirs=[]).run()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        self.assertIn("cron", found[0].tags)
        self.assertIn("world-writable", found[0].tags)

    def run_job(self, user):
        script = self.make("job.sh", 0o755)
        tab = self.make("crontab", 0o444, f"*/5 * * * * {user} {script}\n")
        stats = {script: fake_stat(0o100755, gid=1000, uid=1000),  # owned by account 1000
                 self.tmp: dir_stat(0o755, uid=0, gid=0)}
        with patch_stat(stats), mock.patch("rootward.checks.cron._uid_of",
                                           side_effect=lambda name: {"alice": 1000}.get(name)):
            return CronCheck(crontabs=[(tab, True, None)], script_dirs=[]).run()

    def test_uid_lookup(self):
        self.assertEqual(_uid_of("root"), 0)
        self.assertIsNone(_uid_of("no-such-account-rootward"))  # unknown: no owner exemption
        self.assertIsNone(_uid_of(None))

    def test_script_owned_by_the_account_that_runs_it_is_not_flagged(self):
        self.assertEqual(self.run_job("alice"), [])

    def test_script_owned_by_a_normal_user_but_run_by_root_is_critical(self):
        found = self.run_job("root")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        for tag in ("cron", "root-owned", "script-writable", "writable-by-user"):
            self.assertIn(tag, found[0].tags)


class PathGroupTests(unittest.TestCase):
    """Review points B and the third review: Debian ships /usr/local/bin as root:staff 2775."""

    def check(self, path_value, stats, group="staff"):
        with patch_stat(stats), mock.patch("rootward.checks.path_perms._group_name",
                                           return_value=group):
            return PathPermsCheck(path_value=path_value).run()

    def test_debian_default_group_writable_dir_is_medium_with_no_tags(self):
        found = self.check("/usr/local/bin:/usr/bin", {"/usr/local/bin": dir_stat(0o2775, 0, 50)})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, Severity.MEDIUM)
        self.assertEqual(found[0].tags, set())  # scoring treats even "path-writable" as writable

    def test_exemption_covers_usr_local_sbin_and_a_trailing_slash(self):
        for entry in ("/usr/local/sbin", "/usr/local/bin/"):
            with self.subTest(entry=entry):
                found = self.check(f"{entry}:/usr/bin", {entry: dir_stat(0o2775, 0, 50)})
                self.assertEqual([f.severity for f in found], [Severity.MEDIUM])
                self.assertEqual(found[0].path, entry.rstrip("/"))

    def test_other_system_directories_are_not_exempt(self):
        for entry in ("/usr/bin", "/usr/sbin", "/bin"):
            with self.subTest(entry=entry):
                found = self.check(f"{entry}:/usr/local/bin", {entry: dir_stat(0o2775, 0, 50)})
                self.assertEqual(len(found), 1)
                self.assertGreaterEqual(found[0].severity, Severity.HIGH)
                self.assertIn("writable-by-user", found[0].tags)

    def test_usr_local_bin_writable_by_another_group_is_not_exempt(self):
        found = self.check("/usr/local/bin:/usr/bin", {"/usr/local/bin": dir_stat(0o2775, 0, 100)},
                           group="users")
        self.assertGreaterEqual(found[0].severity, Severity.HIGH)
        self.assertIn("writable-by-user", found[0].tags)

    def test_usr_local_bin_writable_by_everyone_is_not_exempt(self):
        found = self.check("/usr/local/bin:/usr/bin", {"/usr/local/bin": dir_stat(0o777, 0, 50)})
        self.assertGreaterEqual(found[0].severity, Severity.HIGH)
        self.assertIn("world-writable", found[0].tags)

    def test_other_group_writable_directory_is_still_flagged(self):
        found = self.check("/opt/shared:/usr/bin", {"/opt/shared": dir_stat(0o2775, 0, 100)},
                           group="devs")
        self.assertEqual(len(found), 1)
        self.assertGreaterEqual(found[0].severity, Severity.HIGH)
        self.assertIn("writable-by-user", found[0].tags)

    def test_trailing_slash_does_not_hide_a_system_directory_from_the_before_system_rule(self):
        found = self.check("/opt/bin:/usr/bin/", {"/opt/bin": dir_stat(0o777, 0, 0)})
        self.assertEqual(found[0].severity, Severity.CRITICAL)  # listed before the system dirs


class PathScoringTests(unittest.TestCase):
    """End to end with scoring.py: the exempt finding must not chain to CRITICAL."""

    @staticmethod
    def suid_in(directory):
        return Finding(check_id="suid", title=f"SUID binary: {directory}/tool", path=f"{directory}/tool",
                       severity=Severity.MEDIUM, explanation="not a standard SUID program",
                       remediation="remove it", tags={"suid", "root-owned"})

    def path_finding(self, path_value, entry, stat_result, group="staff"):
        with patch_stat({entry: stat_result}), mock.patch(
                "rootward.checks.path_perms._group_name", return_value=group):
            return PathPermsCheck(path_value=path_value).run()[0]

    def test_group_only_system_dir_and_a_suid_binary_inside_it_stay_medium(self):
        path = self.path_finding("/usr/local/bin:/usr/bin", "/usr/local/bin", dir_stat(0o2775, 0, 50))
        suid = self.suid_in("/usr/local/bin")
        apply_scoring([path, suid])
        self.assertEqual(path.severity, Severity.MEDIUM)
        self.assertEqual(suid.severity, Severity.MEDIUM)

    def test_world_writable_dir_still_chains_with_a_suid_binary_inside_it(self):
        path = self.path_finding("/opt/bin:/usr/bin", "/opt/bin", dir_stat(0o777, 0, 0))
        suid = self.suid_in("/opt/bin")
        apply_scoring([path, suid])
        self.assertEqual(path.severity, Severity.CRITICAL)
        self.assertEqual(suid.severity, Severity.CRITICAL)


class SudoReviewTests(unittest.TestCase):
    def parse(self, rule):
        return parse_sudo_output(f"User x may run the following commands on host:\n    {rule}\n")

    def test_negated_command_is_not_reported(self):  # review point 4a
        found = self.parse("(root) NOPASSWD: ALL, !/usr/bin/su")
        self.assertEqual([f.title for f in found], ["sudo rule: ALL"])

    def test_password_tag_overrides_an_earlier_nopasswd(self):
        found = self.parse("(root) NOPASSWD: /usr/bin/id, PASSWD: /usr/bin/ls")
        by_command = {f.title: f for f in found}
        self.assertEqual(set(by_command), {"sudo rule: /usr/bin/id", "sudo rule: /usr/bin/ls"})
        self.assertIn("sudo-nopasswd", by_command["sudo rule: /usr/bin/id"].tags)
        self.assertNotIn("sudo-nopasswd", by_command["sudo rule: /usr/bin/ls"].tags)
        self.assertIn("with a password", by_command["sudo rule: /usr/bin/ls"].explanation)

    def test_nopasswd_applies_to_every_command_after_it(self):
        found = self.parse("(root) NOPASSWD: /usr/bin/id, /usr/bin/ls")
        self.assertEqual([("sudo-nopasswd" in f.tags) for f in found], [True, True])

    def test_nopasswd_after_a_password_command_applies_only_to_what_follows(self):
        found = self.parse("(root) PASSWD: /usr/bin/id, NOPASSWD: /usr/bin/ls")
        self.assertEqual([("sudo-nopasswd" in f.tags) for f in found], [False, True])

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
