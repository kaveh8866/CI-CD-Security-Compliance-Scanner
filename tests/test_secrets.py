"""Secret-detection tests.

Credential-shaped fixtures are assembled from fragments so this test file itself
never contains a value that a real secret scanner would (correctly) flag.
"""

from __future__ import annotations

import unittest

from scanner.secrets import entropy, fingerprint, is_scannable_text, scan_text


def aws_key() -> str:
    return "AKIA" + "Q7Z3M8N2P5R9T4V6"


def github_token() -> str:
    return "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


class SignatureTests(unittest.TestCase):
    def test_aws_key_is_critical_and_redacted(self) -> None:
        key = aws_key()
        findings = scan_text("deploy.sh", f"export AWS_KEY={key}\n")

        self.assertEqual([finding.rule_id for finding in findings], ["CG-SEC-001"])
        finding = findings[0]
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.line, 1)
        self.assertNotIn(key, finding.message)
        self.assertNotIn(key, finding.evidence)
        self.assertTrue(finding.evidence.startswith("sha256:"))

    def test_github_token_detected(self) -> None:
        token = github_token()
        findings = scan_text(".github/workflows/ci.yml", f"token: {token}")

        self.assertIn("CG-SEC-002", [finding.rule_id for finding in findings])
        self.assertNotIn(token, str([finding.to_dict() for finding in findings]))

    def test_private_key_block_detected(self) -> None:
        header = "-----BEGIN RSA " + "PRIVATE KEY-----"
        findings = scan_text("id_deploy.txt", f"{header}\nMIIE...\n")

        self.assertIn("CG-SEC-007", [finding.rule_id for finding in findings])

    def test_generic_high_entropy_assignment_detected(self) -> None:
        findings = scan_text("app.py", 'password = "Zk8Qm2Lp7Rt4Vb9Nx"\n')

        self.assertEqual([finding.rule_id for finding in findings], ["CG-SEC-010"])
        self.assertEqual(findings[0].severity, "high")

    def test_placeholders_are_ignored(self) -> None:
        text = (
            'password = "${DB_PASSWORD}"\n'
            'api_key = "your_api_key_here"\n'
            'client_secret = "changeme"\n'
            'auth_token: "${{ secrets.TOKEN }}"\n'
        )
        self.assertEqual(scan_text("README.md", text), [])

    def test_underscore_prefixed_assignments_detected(self) -> None:
        text = 'SERVICE_PASSWORD=xR4tY7uP2aS9dF6g\ndb_password = "Kp8Lm2Nq7Rs4Tv9W"\n'
        findings = scan_text("config.env", text)

        self.assertEqual([finding.rule_id for finding in findings], ["CG-SEC-010", "CG-SEC-010"])

    def test_keyword_inside_larger_identifier_is_not_a_match(self) -> None:
        self.assertEqual(scan_text("notes.txt", 'mypasswordcontext = "Zk8Qm2Lp7Rt4Vb9Nx"'), [])

    def test_specific_rule_wins_over_generic(self) -> None:
        findings = scan_text("ci.yml", f'api_key: "{aws_key()}"\n')
        rule_ids = [finding.rule_id for finding in findings]

        self.assertIn("CG-SEC-001", rule_ids)
        self.assertNotIn("CG-SEC-010", rule_ids)

    def test_low_entropy_literal_is_not_flagged(self) -> None:
        self.assertEqual(scan_text("notes.md", 'password = "aaaaaaaaaaaaaaaa"'), [])


class HelperTests(unittest.TestCase):
    def test_entropy_separates_random_from_repeated(self) -> None:
        self.assertGreater(entropy("Zk8Qm2Lp7Rt4Vb9Nx"), 3.0)
        self.assertLess(entropy("aaaaaaaaaaaaaaaa"), 0.5)

    def test_fingerprint_is_stable_and_short(self) -> None:
        self.assertEqual(fingerprint("abc"), fingerprint("abc"))
        self.assertNotEqual(fingerprint("abc"), fingerprint("abd"))
        self.assertRegex(fingerprint("abc"), r"^sha256:[0-9a-f]{12}$")

    def test_binary_and_image_files_are_skipped(self) -> None:
        self.assertFalse(is_scannable_text("logo.png", b"\x89PNG"))
        self.assertFalse(is_scannable_text("blob.bin", b"text\x00binary"))
        self.assertTrue(is_scannable_text("Dockerfile", b"FROM python:3.12-slim"))
        self.assertTrue(is_scannable_text(".github/workflows/ci.yml", b"name: ci"))


if __name__ == "__main__":
    unittest.main()
