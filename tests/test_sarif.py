from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scanner.models import Finding, Report
from scanner.sarif import SARIF_VERSION, to_sarif

REPO_ROOT = Path(__file__).resolve().parents[1]


def finding(rule_id: str, severity: str, line: int = 7, evidence: str = "sha256:abcdef123456") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Example rule",
        severity=severity,
        category="pipeline",
        file=".github/workflows/ci.yml",
        line=line,
        message="Something unsafe happened; value redacted.",
        remediation="Fix it.",
        evidence=evidence,
    )


def report(findings: list[Finding]) -> Report:
    return Report(
        target="/scan",
        policy_name="CloudGuard CI/CD Baseline",
        policy_version="1.0.0",
        generated_at="2026-11-13T00:00:00Z",
        files_scanned=3,
        findings=findings,
        controls=[],
    )


class SarifShapeTests(unittest.TestCase):
    def test_top_level_contract(self) -> None:
        log = to_sarif(report([finding("CG-PIPE-001", "high")]))

        self.assertEqual(log["version"], SARIF_VERSION)
        self.assertTrue(log["$schema"].startswith("https://json.schemastore.org/sarif-2.1.0"))
        self.assertEqual(len(log["runs"]), 1)
        self.assertEqual(log["runs"][0]["tool"]["driver"]["name"], "cloudguard-scanner")
        self.assertEqual(log["runs"][0]["invocations"][0]["executionSuccessful"], True)

    def test_severity_to_level_mapping(self) -> None:
        log = to_sarif(
            report(
                [
                    finding("CG-SEC-001", "critical"),
                    finding("CG-PIPE-001", "high"),
                    finding("CG-DEP-001", "medium"),
                    finding("CG-PIPE-007", "low"),
                ]
            )
        )
        levels = [result["level"] for result in log["runs"][0]["results"]]

        self.assertEqual(levels, ["error", "error", "warning", "note"])

    def test_rules_are_deduplicated_and_indices_match(self) -> None:
        log = to_sarif(
            report(
                [
                    finding("CG-PIPE-001", "high", line=1),
                    finding("CG-PIPE-001", "high", line=2),
                    finding("CG-SEC-010", "high", line=3),
                ]
            )
        )
        run = log["runs"][0]

        self.assertEqual([rule["id"] for rule in run["tool"]["driver"]["rules"]], ["CG-PIPE-001", "CG-SEC-010"])
        for result in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"], result["ruleId"])

    def test_location_and_fingerprint(self) -> None:
        log = to_sarif(report([finding("CG-PIPE-001", "high", line=12)]))
        result = log["runs"][0]["results"][0]

        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], ".github/workflows/ci.yml")
        self.assertEqual(location["region"]["startLine"], 12)
        self.assertEqual(result["partialFingerprints"]["cloudguardFinding/v1"], "sha256:abcdef123456")

    def test_report_without_findings(self) -> None:
        log = to_sarif(report([]))
        run = log["runs"][0]

        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])


class SarifRedactionTests(unittest.TestCase):
    def test_no_credential_value_in_serialised_log(self) -> None:
        value = "Zk8Qm2Lp7Rt4Vb9Nx"
        findings = [
            Finding(
                rule_id="CG-SEC-010",
                title="Hard-coded credential assignment",
                severity="high",
                category="secret",
                file="app.py",
                line=4,
                message="Assignment carries a high-entropy literal (sha256:deadbeef1234); value redacted.",
                remediation="Move it to a secret store.",
                evidence="sha256:deadbeef1234",
            )
        ]
        serialised = json.dumps(to_sarif(report(findings)))

        self.assertNotIn(value, serialised)
        self.assertIn("sha256:deadbeef1234", serialised)


class CliSarifTests(unittest.TestCase):
    def test_cli_writes_sarif_and_fails_the_gate(self) -> None:
        env = dict(os.environ, PYTHONPATH=str(REPO_ROOT / "src"))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.sarif"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "scanner",
                    "scan",
                    str(REPO_ROOT / "configs" / "samples"),
                    "--format",
                    "sarif",
                    "--output",
                    str(target),
                ],
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("report", result.stdout)
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertGreaterEqual(len(payload["runs"][0]["results"]), 5)
            self.assertTrue(all("ruleId" in item for item in payload["runs"][0]["results"]))


if __name__ == "__main__":
    unittest.main()
