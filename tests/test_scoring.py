import unittest

from rootward.models import Finding, Severity
from rootward.scoring import apply_scoring, validate_tags


def _f(check_id, path, severity, tags):
    return Finding(check_id, "t", path, severity, "e", "r", set(tags))


class CapabilityChainTests(unittest.TestCase):
    def test_writable_dir_holding_capability_binary_chains_to_critical(self):
        cap = _f("capabilities", "/opt/tools/python3", Severity.HIGH, {"capability"})
        directory = _f("path_perms", "/opt/tools", Severity.MEDIUM,
                       {"path-writable", "writable-by-user"})
        apply_scoring([cap, directory])
        self.assertEqual(cap.severity, Severity.CRITICAL)
        self.assertEqual(directory.severity, Severity.CRITICAL)
        self.assertIn("Chain", cap.escalation_note)

    def test_capability_in_unrelated_dir_is_not_escalated(self):
        cap = _f("capabilities", "/usr/bin/python3", Severity.HIGH, {"capability"})
        directory = _f("path_perms", "/opt/tools", Severity.MEDIUM,
                       {"path-writable", "writable-by-user"})
        apply_scoring([cap, directory])
        self.assertEqual(cap.severity, Severity.HIGH)

    def test_writable_capability_binary_hits_tag_rule(self):
        cap = _f("capabilities", "/opt/x", Severity.MEDIUM, {"capability", "writable-by-user"})
        apply_scoring([cap])
        self.assertEqual(cap.severity, Severity.HIGH)

    def test_known_tags_are_accepted(self):
        self.assertEqual(validate_tags([_f("c", "/x", Severity.LOW, {"capability"})]), [])


if __name__ == "__main__":
    unittest.main()