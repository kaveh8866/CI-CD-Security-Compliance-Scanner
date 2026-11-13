from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scanner.compliance import load_policy, parse_policy
from scanner.engine import scan_path

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "configs" / "samples"

PERMISSIVE_POLICY = parse_policy(
    {
        "policy": {"name": "test", "version": "1.0.0", "fail_on": "critical"},
        "controls": [
            {"id": "CG-CI-001", "title": "pins", "severity": "high", "rules": ["CG-PIPE-001"]},
            {"id": "CG-CI-007", "title": "secrets", "severity": "critical", "rules": ["CG-SEC-*"]},
        ],
    }
)


class SampleScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = scan_path(SAMPLES, policy=load_policy(), policy_path=None)

    def test_pipeline_findings_present(self) -> None:
        rule_ids = {finding.rule_id for finding in self.report.findings}

        self.assertIn("CG-PIPE-001", rule_ids)
        self.assertIn("CG-PIPE-002", rule_ids)
        self.assertIn("CG-PIPE-021", rule_ids)

    def test_dependency_findings_present(self) -> None:
        rule_ids = {finding.rule_id for finding in self.report.findings}

        self.assertIn("CG-DEP-001", rule_ids)
        self.assertIn("CG-VULN-001", rule_ids)
        self.assertIn("CG-VULN-004", rule_ids)

    def test_secret_findings_present_and_redacted(self) -> None:
        secrets = [finding for finding in self.report.findings if finding.category == "secret"]

        self.assertTrue(secrets)
        for finding in secrets:
            self.assertTrue(finding.evidence.startswith("sha256:"))
            self.assertNotIn("Zk8Qm2Lp7Rt4Vb9Nx", json.dumps(finding.to_dict()))

    def test_policy_fails_and_exit_code_is_one(self) -> None:
        self.assertGreater(len(self.report.failed_controls()), 0)
        self.assertEqual(self.report.exit_code("high"), 1)
        self.assertEqual(self.report.exit_code("critical"), 1)

    def test_report_serialises(self) -> None:
        payload = self.report.to_dict()

        self.assertGreater(payload["controls_failed"], 0)
        self.assertEqual(sum(payload["summary"].values()), len(payload["findings"]))
        self.assertTrue(all("rule_id" in item for item in payload["findings"]))
        json.dumps(payload)

    def test_files_were_scanned(self) -> None:
        self.assertGreater(self.report.files_scanned, 0)
        self.assertEqual(self.report.errors, [])


class WalkBehaviourTests(unittest.TestCase):
    def test_missing_target_rejected(self) -> None:
        with self.assertRaises(FileNotFoundError):
            scan_path(Path(tempfile.gettempdir()) / "definitely-not-a-dir-xyz", policy=PERMISSIVE_POLICY)

    def test_ignored_paths_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('password = "Zk8Qm2Lp7Rt4Vb9Nx"\n', encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "leak.py").write_text('password = "Qz7Wm3Np9Rt5Vb2X"\n', encoding="utf-8")

            report = scan_path(root, policy=PERMISSIVE_POLICY)
            files = {finding.file for finding in report.findings}

            self.assertIn("app.py", files)
            self.assertFalse(any("node_modules" in path for path in files))

    def test_policy_ignore_glob(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fixtures").mkdir()
            (root / "fixtures" / "bad.py").write_text('password = "Zk8Qm2Lp7Rt4Vb9Nx"\n', encoding="utf-8")

            policy = parse_policy(
                {
                    "policy": {"name": "ignore", "version": "1.0.0", "ignore": ["fixtures/**"]},
                    "controls": [{"id": "CG-CI-007", "title": "secrets", "severity": "critical", "rules": ["CG-SEC-*"]}],
                }
            )
            report = scan_path(root, policy=policy)

            self.assertEqual(report.findings, [])
            self.assertEqual(report.files_scanned, 0)

    def test_binary_files_are_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")

            report = scan_path(root, policy=PERMISSIVE_POLICY)

            self.assertEqual(report.files_scanned, 0)
            self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()
