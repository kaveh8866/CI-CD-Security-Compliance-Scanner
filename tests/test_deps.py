from __future__ import annotations

import unittest

from scanner.deps import load_advisories, scan_manifest, version_less_than, version_tuple


class VersionTests(unittest.TestCase):
    def test_version_ordering(self) -> None:
        self.assertTrue(version_less_than("2.28.0", "2.31.0"))
        self.assertFalse(version_less_than("2.31.0", "2.31.0"))
        self.assertTrue(version_less_than("5.3", "5.4"))
        self.assertFalse(version_less_than("10.0.0", "9.9.9"))

    def test_padding(self) -> None:
        self.assertEqual(version_tuple("2.0"), (2, 0))
        self.assertTrue(version_less_than("2.0", "2.0.1"))


class RequirementsTests(unittest.TestCase):
    def test_vulnerable_pin_flagged(self) -> None:
        findings = scan_manifest("requirements.txt", "requests==2.28.0\n")
        rule_ids = [finding.rule_id for finding in findings]

        self.assertIn("CG-VULN-001", rule_ids)
        finding = next(item for item in findings if item.rule_id == "CG-VULN-001")
        self.assertEqual(finding.severity, "high")
        self.assertIn("2.31.0", finding.message)

    def test_multiple_cves_and_unpinned_package(self) -> None:
        text = "requests==2.28.0\nurllib3==2.0.6\npyyaml==5.3.1\nflask\n"
        rule_ids = [finding.rule_id for finding in scan_manifest("requirements.txt", text)]

        self.assertIn("CG-VULN-001", rule_ids)
        self.assertIn("CG-VULN-002", rule_ids)
        self.assertIn("CG-VULN-003", rule_ids)
        self.assertIn("CG-DEP-001", rule_ids)

    def test_fixed_pins_are_clean(self) -> None:
        text = "requests==2.32.3\npyyaml==6.0.2\nflask==3.0.3\n"
        self.assertEqual(scan_manifest("requirements.txt", text), [])

    def test_comments_and_options_ignored(self) -> None:
        text = "# a comment\n-r base.txt\n\nrequests==2.32.3  # pinned\n"
        self.assertEqual(scan_manifest("requirements.txt", text), [])

    def test_prefixed_requirements_file_is_scanned(self) -> None:
        findings = scan_manifest("requirements-dev.txt", "flask\n")
        self.assertEqual([finding.rule_id for finding in findings], ["CG-DEP-001"])


class PackageJsonTests(unittest.TestCase):
    def test_vulnerable_and_wildcard_dependencies(self) -> None:
        text = (
            '{"dependencies": {"lodash": "4.17.15", "minimist": "1.2.0"},'
            ' "devDependencies": {"left-pad": "*"}}'
        )
        rule_ids = {finding.rule_id for finding in scan_manifest("package.json", text)}

        self.assertTrue({"CG-VULN-004", "CG-VULN-005", "CG-DEP-003"} <= rule_ids)

    def test_exact_safe_versions_clean(self) -> None:
        text = '{"dependencies": {"lodash": "4.17.21", "minimist": "1.2.8"}}'
        self.assertEqual(scan_manifest("package.json", text), [])

    def test_invalid_json_reported(self) -> None:
        findings = scan_manifest("package.json", "{not json")
        self.assertEqual([finding.rule_id for finding in findings], ["CG-DEP-002"])

    def test_caret_range_uses_lower_bound(self) -> None:
        findings = scan_manifest("package.json", '{"dependencies": {"lodash": "^4.17.15"}}')
        self.assertIn("CG-VULN-004", [finding.rule_id for finding in findings])


class CatalogueTests(unittest.TestCase):
    def test_catalogue_loads_bundled_entries(self) -> None:
        advisories = load_advisories()

        self.assertGreaterEqual(len(advisories), 5)
        self.assertEqual({entry["ecosystem"] for entry in advisories}, {"pypi", "npm"})
        for advisory in advisories:
            self.assertTrue(advisory["below"])
            self.assertTrue(advisory["rule_id"].startswith("CG-VULN-"))


if __name__ == "__main__":
    unittest.main()
