import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from rootward import report
from rootward.models import Finding, Severity
from rootward.scanner import ScanResult
from rootward.scoring import apply_scoring, summarize

FIXED_TIME = datetime(2026, 11, 23, 14, 30, 5, tzinfo=timezone.utc)


def make_finding(severity=Severity.HIGH, path="/usr/bin/x", note=""):
    finding = Finding("suid", f"SUID binary: {path}", path, severity,
                      "it can be abused", "chmod u-s it", {"suid"})
    finding.escalation_note = note
    return finding


def make_result(**overrides):
    result = ScanResult(checks_run=["suid", "cron"], started_at=100.0, finished_at=101.5)
    for key, value in overrides.items():
        setattr(result, key, value)
    return result


def scored(findings):
    findings = apply_scoring(findings)
    return findings, summarize(findings)


def render(result, findings, summary, width=140):
    buffer = io.StringIO()
    console = report.Console(file=buffer, width=width, force_terminal=False)
    report.print_report(result, findings, summary, console=console)
    return buffer.getvalue()


class CleanLabelTests(unittest.TestCase):
    def test_slashes_spaces_and_leading_dots_are_removed(self):
        self.assertEqual(report._clean_label("../etc/my host", "h"), "etc-my-host")

    def test_only_dots_falls_back(self):
        self.assertEqual(report._clean_label("..", "host"), "host")

    def test_normal_hostname_is_unchanged(self):
        self.assertEqual(report._clean_label("kali-vm.local", "host"), "kali-vm.local")


class JsonReportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()  # never write into the real output/
        self.addCleanup(self._tmp.cleanup)
        self.out = Path(self._tmp.name) / "output"

    def write(self, result=None, findings=None, **kwargs):
        findings, summary = scored(findings if findings is not None else [make_finding()])
        return report.write_json_report(result or make_result(), findings, summary,
                                        "127.0.0.1", out_dir=self.out, now=FIXED_TIME, **kwargs)

    def test_file_is_created_in_the_output_dir_with_host_and_timestamp(self):
        with mock.patch.object(report, "_hostname", return_value="kali-vm"):
            path = self.write()
        self.assertEqual(path.parent, self.out)
        self.assertEqual(path.name, "rootward-kali-vm-20261123-143005.json")

    def test_content_is_valid_json_with_every_key(self):
        data = json.loads(self.write().read_text(encoding="utf-8"))
        self.assertEqual(set(data), {
            "tool", "version", "generated_at", "hostname", "scope", "checks_run",
            "checks_skipped", "errors", "aborted", "duration_seconds", "summary", "findings"})
        self.assertEqual(data["tool"], "RootWard")
        self.assertEqual(data["scope"], "127.0.0.1")
        self.assertEqual(data["checks_run"], ["suid", "cron"])
        self.assertEqual(data["duration_seconds"], 1.5)
        self.assertEqual(data["generated_at"], FIXED_TIME.isoformat())

    def test_findings_match_to_dict_and_keep_their_order(self):
        findings, summary = scored([make_finding(Severity.LOW, "/a"),
                                    make_finding(Severity.CRITICAL, "/b")])
        path = report.write_json_report(make_result(), findings, summary, "127.0.0.1",
                                        out_dir=self.out, now=FIXED_TIME)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["findings"], [f.to_dict() for f in findings])
        self.assertEqual([f["severity"] for f in data["findings"]], ["CRITICAL", "LOW"])
        self.assertEqual(data["summary"]["total"], 2)

    def test_partial_result_from_the_kill_switch_is_marked_aborted(self):
        result = make_result(aborted=True, checks_skipped=["capabilities"],
                             errors={"cron": "permission denied: x"})
        data = json.loads(self.write(result).read_text(encoding="utf-8"))
        self.assertTrue(data["aborted"])
        self.assertEqual(data["checks_skipped"], ["capabilities"])
        self.assertEqual(data["errors"], {"cron": "permission denied: x"})

    def test_no_findings_still_writes_a_report(self):
        data = json.loads(self.write(findings=[]).read_text(encoding="utf-8"))
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["summary"]["total"], 0)

    def test_a_dangerous_hostname_cannot_escape_the_output_dir(self):
        with mock.patch.object(report, "_hostname", return_value="../../evil host"):
            path = self.write()
        self.assertEqual(path.parent, self.out)
        self.assertNotIn("..", path.name)
        self.assertNotIn(" ", path.name)

    def test_an_existing_report_is_never_overwritten(self):
        first, second = self.write(), self.write()
        self.assertNotEqual(first, second)
        self.assertEqual(second.name, first.stem + "-2.json")
        self.assertTrue(first.exists() and second.exists())

    def test_dry_run_writes_nothing_and_returns_none(self):
        findings, summary = scored([])
        result = make_result(dry_run=True, checks_planned=["cron"])
        path = report.write_json_report(result, findings, summary, "127.0.0.1",
                                        out_dir=self.out, now=FIXED_TIME)
        self.assertIsNone(path)
        self.assertFalse(self.out.exists())

    def test_an_output_path_that_is_a_file_raises_oserror(self):
        blocker = Path(self._tmp.name) / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        findings, summary = scored([make_finding()])
        with self.assertRaises(OSError):
            report.write_json_report(make_result(), findings, summary, "127.0.0.1",
                                     out_dir=blocker, now=FIXED_TIME)

    def test_missing_output_dir_is_created(self):
        self.assertFalse(self.out.exists())
        self.write()
        self.assertTrue(self.out.is_dir())


@unittest.skipIf(report.Console is None, "rich is not installed")
class PrintReportTests(unittest.TestCase):
    def test_table_shows_every_severity_and_the_summary(self):
        findings, summary = scored([make_finding(sev, f"/p/{sev.name}") for sev in Severity])
        text = render(make_result(), findings, summary)
        for sev in Severity:
            self.assertIn(sev.name, text)
        self.assertIn("Risk: CRITICAL", text)
        self.assertIn("findings: 5", text)
        self.assertIn("Scan finished in 1.50s.", text)

    def test_wide_terminal_uses_the_table(self):
        findings, summary = scored([make_finding()])
        text = render(make_result(), findings, summary, width=report.WIDE_LAYOUT_MIN_WIDTH)
        self.assertIn("Severity", text)  # table header

    def test_narrow_terminal_lists_findings_instead_of_a_table(self):
        findings, summary = scored([make_finding(Severity.CRITICAL, "/usr/bin/x", "Chain: y")])
        text = render(make_result(), findings, summary, width=report.WIDE_LAYOUT_MIN_WIDTH - 1)
        self.assertNotIn("Severity", text)
        self.assertIn("[CRITICAL] SUID binary: /usr/bin/x (suid)", text)
        self.assertIn("  Path: /usr/bin/x", text)
        self.assertIn("  Risk correlation: Chain: y", text)

    def test_narrow_listing_does_not_repeat_the_path_in_a_column(self):
        findings, summary = scored([make_finding(path="/opt/a/long/path/tool")])
        text = render(make_result(), findings, summary, width=80)
        # once in the title, once on the Path line, once inside the explanation text at most
        self.assertLessEqual(text.count("/opt/a/long/path/tool"), 3)
        self.assertLess(len(text.splitlines()), 20)

    def test_worst_finding_is_listed_first(self):
        findings, summary = scored([make_finding(Severity.LOW, "/low-file"),
                                    make_finding(Severity.CRITICAL, "/crit-file")])
        text = render(make_result(), findings, summary)
        self.assertLess(text.index("/crit-file"), text.index("/low-file"))

    def test_square_brackets_in_a_path_are_printed_literally(self):
        findings, summary = scored([make_finding(path="PATH[0] = /tmp/bin")])
        self.assertIn("PATH[0] = /tmp/bin", render(make_result(), findings, summary))

    def test_escalation_note_is_shown(self):
        findings, summary = scored([make_finding(note="Chain: writable path")])
        self.assertIn("Risk correlation: Chain: writable path",
                      render(make_result(), findings, summary))

    def test_empty_findings_do_not_crash(self):
        findings, summary = scored([])
        text = render(make_result(), findings, summary)
        self.assertIn("findings: 0", text)
        self.assertIn("Risk: INFO", text)

    def test_check_errors_and_kill_switch_are_reported(self):
        result = make_result(aborted=True, errors={"sudo_rules": "unknown check id"})
        findings, summary = scored([])
        text = render(result, findings, summary)
        self.assertIn("sudo_rules: unknown check id", text)
        self.assertIn("stopped by the kill switch", text)
        self.assertNotIn("Scan finished", text)

    def test_dry_run_lists_planned_checks_only(self):
        result = make_result(dry_run=True, checks_planned=["cron", "suid"])
        text = render(result, [], summarize([]))
        self.assertIn("Dry run: no system checks were performed.", text)
        self.assertIn("Planned checks: cron, suid", text)
        self.assertNotIn("Risk:", text)


class PlainFallbackTests(unittest.TestCase):
    def run_plain(self, result, findings, summary):
        buffer = io.StringIO()
        with mock.patch.object(report, "Console", None), \
                mock.patch("sys.stdout", buffer):
            report.print_report(result, findings, summary)
        return buffer.getvalue()

    def test_plain_text_is_used_when_rich_is_missing(self):
        findings, summary = scored([make_finding(Severity.CRITICAL, "/bin/x", "Chain: y")])
        text = self.run_plain(make_result(), findings, summary)
        self.assertIn("[CRITICAL] SUID binary: /bin/x (suid)", text)
        self.assertIn("Risk correlation: Chain: y", text)
        self.assertIn("Scan finished in 1.50s.", text)

    def test_plain_dry_run(self):
        result = make_result(dry_run=True, checks_planned=["cron"])
        text = self.run_plain(result, [], summarize([]))
        self.assertIn("Planned checks: cron", text)


if __name__ == "__main__":
    unittest.main()
