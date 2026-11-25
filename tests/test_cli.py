"""Tests for rootward.cli.main: exit codes, the authorization prompt, report writing and the kill
switch wiring. The scan itself is replaced by a stub, so no real file system walk happens."""
import contextlib
import io
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rootward import cli, ethics
from rootward.models import Finding, Severity
from rootward.scanner import ScanResult


def make_result(**overrides):
    result = ScanResult(checks_run=["suid", "cron"], started_at=100.0, finished_at=101.0)
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


def a_finding():
    return Finding("suid", "SUID binary: /usr/bin/x", "/usr/bin/x", Severity.HIGH,
                   "it can be abused", "chmod u-s it", {"suid"})


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()  # reports go here, never into the real output/
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name) / "reports"
        self.addCleanup(ethics.reset_abort)

    def run_cli(self, *argv, answer="I AUTHORIZE", result=None, report_error=None):
        """Run main() with a stubbed scan and a scripted prompt.

        Returns (exit_code, stdout, stderr, run_scan_mock)."""
        result = result if result is not None else make_result(findings=[a_finding()])
        out, err = io.StringIO(), io.StringIO()
        prompt = (mock.Mock(side_effect=answer) if isinstance(answer, BaseException)
                  else mock.Mock(return_value=answer))
        # rich reads the width of the real terminal even when stdout is redirected. A wide
        # terminal switches the report to the table layout, which does not print the finding
        # title, so pin the width to keep the output the same on every machine.
        with mock.patch("rootward.cli.run_scan", return_value=result) as run_scan, \
                mock.patch("builtins.input", prompt), \
                mock.patch.dict(os.environ, {"COLUMNS": "80"}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if report_error is None:
                code = cli.main(list(argv))
            else:
                with mock.patch("rootward.cli.write_json_report", side_effect=report_error):
                    code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue(), run_scan

    def reports(self):
        return sorted(self.out.glob("*.json")) if self.out.exists() else []


class ScopeAndListingTests(CliTestCase):
    def test_a_non_loopback_scope_is_rejected_before_anything_runs(self):
        code, _, err, run_scan = self.run_cli("--scope", "10.0.0.5", "--output", str(self.out))
        self.assertEqual(code, 2)
        self.assertIn("Scope rejected", err)
        run_scan.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_a_hostname_is_not_a_valid_scope(self):
        code, _, err, _ = self.run_cli("--scope", "example.com")
        self.assertEqual(code, 2)
        self.assertIn("Scope rejected", err)

    def test_ipv6_loopback_is_accepted(self):
        code, out, _, _ = self.run_cli("--scope", "::1", "--output", str(self.out))
        self.assertEqual(code, 0)
        self.assertIn("Authorized scope: ::1", out)

    def test_list_checks_prints_the_checks_and_never_prompts(self):
        code, out, _, run_scan = self.run_cli("--list-checks", answer=AssertionError("prompted"))
        self.assertEqual(code, 0)
        for check_id in ("suid", "sudo_rules", "cron", "capabilities", "path_perms"):
            self.assertIn(f"{check_id}:", out)
        run_scan.assert_not_called()

    def test_the_legal_notice_is_always_printed(self):
        _, out, _, _ = self.run_cli("--list-checks")
        self.assertIn("Computer Crimes Act 1997", out)

    def test_empty_check_list_is_a_usage_error(self):
        code, _, err, run_scan = self.run_cli("--checks", ",")
        self.assertEqual(code, 2)
        self.assertIn("No check IDs", err)
        run_scan.assert_not_called()

    def test_selected_checks_are_passed_on_trimmed(self):
        _, _, _, run_scan = self.run_cli("--checks", "suid, cron", "--output", str(self.out))
        run_scan.assert_called_once_with(selected=["suid", "cron"], dry_run=False)


class AuthorizationPromptTests(CliTestCase):
    def assertCancelled(self, **kwargs):
        code, _, err, run_scan = self.run_cli("--output", str(self.out), **kwargs)
        self.assertEqual(code, 2)
        self.assertIn("Authorization not confirmed", err)
        run_scan.assert_not_called()
        self.assertEqual(self.reports(), [])

    def test_a_wrong_answer_cancels_the_scan(self):
        self.assertCancelled(answer="yes")

    def test_the_phrase_is_case_sensitive(self):
        self.assertCancelled(answer="i authorize")

    def test_an_empty_answer_cancels_the_scan(self):
        self.assertCancelled(answer="")

    def test_end_of_input_cancels_the_scan(self):
        self.assertCancelled(answer=EOFError())

    def test_ctrl_c_at_the_prompt_cancels_the_scan(self):
        self.assertCancelled(answer=KeyboardInterrupt())

    def test_surrounding_spaces_are_ignored(self):
        code, _, _, run_scan = self.run_cli("--output", str(self.out), answer="  I AUTHORIZE \n")
        self.assertEqual(code, 0)
        run_scan.assert_called_once()

    def test_a_dry_run_does_not_ask(self):
        code, _, _, _ = self.run_cli("--dry-run", answer=AssertionError("prompted"),
                                     result=make_result(dry_run=True, checks_planned=["cron"]))
        self.assertEqual(code, 0)


class ExitCodeTests(CliTestCase):
    def test_a_clean_scan_exits_0(self):
        code, _, _, _ = self.run_cli("--output", str(self.out))
        self.assertEqual(code, 0)

    def test_a_check_error_exits_1(self):
        result = make_result(errors={"cron": "PermissionError: denied"})
        code, out, _, _ = self.run_cli("--output", str(self.out), result=result)
        self.assertEqual(code, 1)
        self.assertIn("cron: PermissionError: denied", out)

    def test_a_stopped_scan_exits_130(self):
        result = make_result(aborted=True, checks_skipped=["suid"])
        code, _, _, _ = self.run_cli("--output", str(self.out), result=result)
        self.assertEqual(code, 130)

    def test_a_stopped_scan_with_check_errors_still_exits_130(self):
        result = make_result(aborted=True, errors={"cron": "boom"})
        code, _, _, _ = self.run_cli("--output", str(self.out), result=result)
        self.assertEqual(code, 130)

    def test_findings_alone_do_not_change_the_exit_code(self):
        # RootWard reports findings; it is not a pass/fail gate
        code, out, _, _ = self.run_cli("--output", str(self.out))
        self.assertEqual(code, 0)
        self.assertIn("SUID binary: /usr/bin/x", out)


class DryRunTests(CliTestCase):
    def test_a_dry_run_lists_checks_and_writes_nothing(self):
        result = make_result(dry_run=True, checks_run=[], checks_planned=["cron", "suid"])
        code, out, _, run_scan = self.run_cli("--dry-run", "--output", str(self.out),
                                              result=result)
        self.assertEqual(code, 0)
        self.assertIn("Dry run: no system checks were performed.", out)
        self.assertIn("cron", out)
        run_scan.assert_called_once_with(selected=None, dry_run=True)
        self.assertFalse(self.out.exists())  # not even the folder is created
        self.assertNotIn("JSON report saved", out)


class ReportFileTests(CliTestCase):
    def test_a_real_scan_saves_a_report_and_says_where(self):
        code, out, _, _ = self.run_cli("--output", str(self.out))
        self.assertEqual(code, 0)
        files = self.reports()
        self.assertEqual(len(files), 1)
        self.assertIn(f"JSON report saved to {files[0]}", out)

    @unittest.skipUnless(os.name == "posix", "file modes are POSIX only")
    def test_the_report_is_private_to_its_owner(self):
        self.run_cli("--output", str(self.out))
        self.assertEqual(self.reports()[0].stat().st_mode & 0o777, 0o600)

    def test_no_report_writes_nothing(self):
        code, out, _, _ = self.run_cli("--no-report", "--output", str(self.out))
        self.assertEqual(code, 0)
        self.assertFalse(self.out.exists())
        self.assertNotIn("JSON report saved", out)

    def test_a_report_that_cannot_be_saved_does_not_hide_the_results(self):
        code, out, err, _ = self.run_cli("--output", str(self.out),
                                         report_error=PermissionError("read-only folder"))
        self.assertEqual(code, 1)
        self.assertIn("SUID binary: /usr/bin/x", out)  # the scan results were still shown
        self.assertIn("could not save report", err)
        self.assertIn("read-only folder", err)

    def test_a_stopped_scan_keeps_exit_130_when_the_report_cannot_be_saved(self):
        result = make_result(aborted=True, checks_skipped=["suid"])
        code, _, err, _ = self.run_cli("--output", str(self.out), result=result,
                                       report_error=PermissionError("read-only folder"))
        self.assertEqual(code, 130)
        self.assertIn("could not save report", err)

    def test_an_output_path_that_is_a_file_is_reported_not_raised(self):
        blocker = Path(self._tmp.name) / "a-file"
        blocker.write_text("x", encoding="utf-8")
        code, out, err, _ = self.run_cli("--output", str(blocker))
        self.assertEqual(code, 1)
        self.assertIn("could not save report", err)
        self.assertIn("SUID binary: /usr/bin/x", out)


class KillSwitchWiringTests(CliTestCase):
    def test_ctrl_c_during_the_scan_requests_an_abort_instead_of_raising(self):
        seen = {}

        def scan_that_gets_interrupted(selected=None, dry_run=False):
            signal.raise_signal(signal.SIGINT)  # what the terminal sends on Ctrl+C
            seen["abort"] = ethics.should_abort()
            return make_result(aborted=True, checks_skipped=["suid"])

        out, err = io.StringIO(), io.StringIO()
        with mock.patch("rootward.cli.run_scan", side_effect=scan_that_gets_interrupted), \
                mock.patch("builtins.input", return_value="I AUTHORIZE"), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--output", str(self.out)])
        self.assertTrue(seen["abort"])
        self.assertEqual(code, 130)
        self.assertEqual(len(self.reports()), 1)  # the partial results are still saved

    def test_the_original_signal_handlers_are_restored_afterwards(self):
        before = signal.getsignal(signal.SIGINT)
        self.run_cli("--output", str(self.out))
        self.assertIs(signal.getsignal(signal.SIGINT), before)

    def test_a_left_over_abort_does_not_leak_into_the_next_run(self):
        ethics.request_abort()
        seen = {}

        def scan(selected=None, dry_run=False):
            seen["abort"] = ethics.should_abort()
            return make_result()

        with mock.patch("rootward.cli.run_scan", side_effect=scan), \
                mock.patch("builtins.input", return_value="I AUTHORIZE"), \
                contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--no-report"])
        self.assertFalse(seen["abort"])


if __name__ == "__main__":
    unittest.main()
