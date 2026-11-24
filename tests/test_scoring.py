import unittest

from rootward import scoring
from rootward.models import Finding, Severity
from rootward.scoring import (KNOWN_TAGS, apply_scoring, risk_score, summarize,
                              validate_tags)


def make(path="/x", tags=(), severity=Severity.LOW, check_id="test"):
    return Finding(check_id, f"finding {path}", path, severity, "explanation",
                   "remediation", set(tags))


class TagRuleTests(unittest.TestCase):
    def test_root_cron_job_running_a_writable_script_is_critical(self):
        finding = make(tags={"cron", "root-owned", "script-writable"}, severity=Severity.MEDIUM)
        apply_scoring([finding])
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_suid_root_binary_that_anyone_can_write_is_critical(self):
        finding = make(tags={"suid", "root-owned", "world-writable"})
        apply_scoring([finding])
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_passwordless_sudo_with_a_wildcard_is_critical(self):
        finding = make(tags={"sudo-nopasswd", "sudo-wildcard"}, severity=Severity.MEDIUM)
        apply_scoring([finding])
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_capability_binary_a_user_can_modify_is_high(self):
        finding = make(tags={"capability", "writable-by-user"})
        apply_scoring([finding])
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_incomplete_combinations_are_not_escalated(self):
        incomplete = [{"cron", "root-owned"}, {"suid", "root-owned"}, {"sudo-nopasswd"},
                      {"sudo-wildcard"}, {"capability"}, {"cron", "script-writable"}]
        for tags in incomplete:
            with self.subTest(tags=sorted(tags)):
                finding = make(tags=tags, severity=Severity.MEDIUM)
                apply_scoring([finding])
                self.assertEqual(finding.severity, Severity.MEDIUM)
                self.assertEqual(finding.escalation_note, "")

    def test_the_reason_for_an_escalation_is_recorded(self):
        finding = make(tags={"cron", "root-owned", "script-writable"})
        apply_scoring([finding])
        self.assertIn("Root cron job", finding.escalation_note)

    def test_severity_is_never_lowered(self):
        finding = make(tags={"capability", "writable-by-user"}, severity=Severity.CRITICAL)
        apply_scoring([finding])
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.escalation_note, "")


class PathChainTests(unittest.TestCase):
    def test_writable_directory_holding_a_suid_binary_makes_both_critical(self):
        directory = make("/opt/bin", {"path-writable"}, Severity.HIGH, "path_perms")
        binary = make("/opt/bin/tool", {"suid"}, Severity.MEDIUM, "suid")
        apply_scoring([directory, binary])
        self.assertEqual(directory.severity, Severity.CRITICAL)
        self.assertEqual(binary.severity, Severity.CRITICAL)
        self.assertIn("Chain", directory.escalation_note)
        self.assertIn("suid", directory.escalation_note)
        self.assertIn("path_perms", binary.escalation_note)

    def test_writable_file_that_sudo_runs_is_a_chain(self):
        script = make("/opt/run.sh", {"writable-by-user"}, Severity.LOW, "cron")
        rule = make("/opt/run.sh", {"sudo-nopasswd"}, Severity.MEDIUM, "sudo_rules")
        apply_scoring([script, rule])
        self.assertEqual(script.severity, Severity.CRITICAL)
        self.assertEqual(rule.severity, Severity.CRITICAL)

    def test_one_finding_does_not_chain_with_itself(self):
        finding = make("/opt/x", {"suid", "world-writable"}, Severity.LOW)
        apply_scoring([finding])
        self.assertEqual(finding.severity, Severity.LOW)

    def test_a_directory_with_a_similar_name_is_not_covered(self):
        directory = make("/opt/bin", {"path-writable"}, Severity.HIGH)
        other = make("/opt/binary/tool", {"suid"}, Severity.MEDIUM)
        apply_scoring([directory, other])
        self.assertEqual(directory.severity, Severity.HIGH)
        self.assertEqual(other.severity, Severity.MEDIUM)

    def test_a_trailing_slash_on_the_directory_still_covers_its_contents(self):
        directory = make("/opt/bin/", {"path-writable"}, Severity.HIGH)
        binary = make("/opt/bin/tool", {"suid"}, Severity.MEDIUM)
        apply_scoring([directory, binary])
        self.assertEqual(binary.severity, Severity.CRITICAL)

    def test_without_a_writable_tag_nothing_chains(self):
        directory = make("/opt/bin", set(), Severity.MEDIUM)
        binary = make("/opt/bin/tool", {"suid"}, Severity.MEDIUM)
        apply_scoring([directory, binary])
        self.assertEqual(directory.severity, Severity.MEDIUM)
        self.assertEqual(binary.severity, Severity.MEDIUM)

    def test_without_a_privileged_tag_nothing_chains(self):
        directory = make("/opt/bin", {"path-writable"}, Severity.HIGH)
        plain = make("/opt/bin/tool", {"sgid"}, Severity.MEDIUM)
        apply_scoring([directory, plain])
        self.assertEqual(directory.severity, Severity.HIGH)
        self.assertEqual(plain.severity, Severity.MEDIUM)


class OrderAndSummaryTests(unittest.TestCase):
    def test_findings_are_sorted_worst_first_then_by_path(self):
        low = make("/z", severity=Severity.LOW)
        crit_b = make("/b", severity=Severity.CRITICAL)
        crit_a = make("/a", severity=Severity.CRITICAL)
        high = make("/m", severity=Severity.HIGH)
        result = apply_scoring([low, crit_b, high, crit_a])
        self.assertEqual([f.path for f in result], ["/a", "/b", "/m", "/z"])

    def test_risk_score_is_the_sum_of_severity_weights(self):
        findings = [make(severity=Severity.LOW), make(severity=Severity.MEDIUM),
                    make(severity=Severity.HIGH)]
        self.assertEqual(risk_score(findings), 5 + 15 + 35)

    def test_info_findings_add_nothing_to_the_score(self):
        self.assertEqual(risk_score([make(severity=Severity.INFO)]), 0)

    def test_risk_score_is_capped_at_100(self):
        findings = [make(severity=Severity.CRITICAL), make(severity=Severity.CRITICAL)]
        self.assertEqual(risk_score(findings), 100)

    def test_no_findings_scores_zero_and_rates_info(self):
        summary = summarize([])
        self.assertEqual(summary["risk_score"], 0)
        self.assertEqual(summary["overall_rating"], "INFO")
        self.assertEqual(summary["total"], 0)

    def test_summary_counts_findings_per_severity_and_rates_by_the_worst(self):
        findings = [make(severity=Severity.HIGH), make(severity=Severity.HIGH),
                    make(severity=Severity.LOW)]
        summary = summarize(findings)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["counts"]["HIGH"], 2)
        self.assertEqual(summary["counts"]["LOW"], 1)
        self.assertEqual(summary["counts"]["CRITICAL"], 0)
        self.assertEqual(summary["overall_rating"], "HIGH")


class TagVocabularyTests(unittest.TestCase):
    def test_unknown_tags_are_reported_with_their_check(self):
        findings = [make(tags={"suid", "typo-tag"}, check_id="suid")]
        self.assertEqual(validate_tags(findings), [("suid", "typo-tag")])

    def test_known_tags_give_no_report(self):
        self.assertEqual(validate_tags([make(tags={"suid", "root-owned"})]), [])

    def test_every_agreed_tag_is_known(self):
        agreed = {"suid", "sgid", "root-owned", "world-writable", "writable-by-user", "cron",
                  "script-writable", "sudo-nopasswd", "sudo-wildcard", "capability",
                  "path-writable"}
        self.assertLessEqual(agreed, KNOWN_TAGS)

    def test_chain_tags_are_part_of_the_known_vocabulary(self):
        self.assertLessEqual(scoring.WRITABLE_TAGS | scoring.PRIVILEGED_EXEC_TAGS, KNOWN_TAGS)


if __name__ == "__main__":
    unittest.main()
