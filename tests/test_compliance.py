from __future__ import annotations

import unittest

from scanner.compliance import PolicyError, load_policy, parse_policy
from scanner.models import Finding


def finding(rule_id: str, severity: str = "high") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="fixture",
        severity=severity,
        category="pipeline",
        file="ci.yml",
        line=1,
        message="fixture",
    )


class BundledPolicyTests(unittest.TestCase):
    def test_baseline_loads(self) -> None:
        policy = load_policy()

        self.assertEqual(policy.name, "CloudGuard CI/CD Baseline")
        self.assertEqual(policy.fail_on, "high")
        self.assertGreaterEqual(len(policy.controls), 8)
        rules = [rule for control in policy.controls for rule in control.rules]
        self.assertIn("CG-SEC-*", rules)
        self.assertIn("CG-PIPE-001", rules)

    def test_wildcard_control_matches_all_secret_rules(self) -> None:
        policy = load_policy()
        controls = policy.evaluate([finding("CG-SEC-001", "critical")])
        secret_control = next(control for control in controls if control.id == "CG-CI-007")

        self.assertEqual(secret_control.status, "fail")
        self.assertEqual(secret_control.matched_findings, ["CG-SEC-001"])

    def test_unmatched_controls_pass(self) -> None:
        policy = load_policy()
        controls = policy.evaluate([finding("CG-PIPE-001")])

        self.assertEqual(next(control for control in controls if control.id == "CG-CI-001").status, "fail")
        self.assertEqual(next(control for control in controls if control.id == "CG-CI-008").status, "pass")

    def test_ignore_list_present(self) -> None:
        policy = load_policy()
        self.assertIn("tests/fixtures/**", policy.ignore)

    def test_vulnerable_rule_maps_to_control(self) -> None:
        policy = load_policy()
        controls = policy.evaluate([finding("CG-VULN-004")])
        control = next(control for control in controls if control.id == "CG-CI-009")

        self.assertEqual(control.status, "fail")


class ValidationTests(unittest.TestCase):
    def test_missing_policy_table_rejected(self) -> None:
        with self.assertRaisesRegex(PolicyError, "\\[policy\\] table"):
            parse_policy({"controls": []})

    def test_empty_controls_rejected(self) -> None:
        with self.assertRaisesRegex(PolicyError, "at least one"):
            parse_policy({"policy": {"name": "x", "version": "1.0.0"}, "controls": []})

    def test_duplicate_control_id_rejected(self) -> None:
        control = {
            "id": "CG-CI-001",
            "title": "one",
            "severity": "high",
            "rules": ["CG-PIPE-001"],
        }
        document = {
            "policy": {"name": "x", "version": "1.0.0"},
            "controls": [control, dict(control)],
        }
        with self.assertRaisesRegex(PolicyError, "declared twice"):
            parse_policy(document)

    def test_invalid_severity_rejected(self) -> None:
        document = {
            "policy": {"name": "x", "version": "1.0.0", "fail_on": "severe"},
            "controls": [
                {"id": "CG-CI-001", "title": "one", "severity": "high", "rules": ["CG-PIPE-001"]},
            ],
        }
        with self.assertRaisesRegex(PolicyError, "fail_on"):
            parse_policy(document)

    def test_missing_policy_file_reports_path(self) -> None:
        with self.assertRaisesRegex(PolicyError, "policy file not readable"):
            load_policy("configs/policies/does-not-exist.toml")


if __name__ == "__main__":
    unittest.main()
