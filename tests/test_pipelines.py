from __future__ import annotations

import unittest

from scanner.pipelines import is_github_workflow, is_gitlab_pipeline, scan_pipeline

PINNED = "a" * 40


def workflow(steps: str, trigger: str = "pull_request", permissions: str = "read-all") -> str:
    return (
        "name: sample\n"
        f"on: {trigger}\n"
        f"permissions: {permissions}\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"{steps}"
    )


class GithubWorkflowTests(unittest.TestCase):
    def test_pinned_action_passes(self) -> None:
        text = workflow(f"      - uses: actions/checkout@{PINNED}\n")
        self.assertEqual(scan_pipeline(".github/workflows/ci.yml", text), [])

    def test_tag_reference_is_flagged(self) -> None:
        text = workflow("      - uses: actions/checkout@v4\n")
        findings = scan_pipeline(".github/workflows/ci.yml", text)

        self.assertEqual([finding.rule_id for finding in findings], ["CG-PIPE-001"])
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].line, 8)

    def test_pull_request_target_flagged(self) -> None:
        text = workflow(f"      - uses: actions/checkout@{PINNED}\n", trigger="pull_request_target")
        rule_ids = [finding.rule_id for finding in scan_pipeline(".github/workflows/ci.yml", text)]

        self.assertIn("CG-PIPE-002", rule_ids)

    def test_secret_echo_flagged(self) -> None:
        text = workflow('      - run: echo "${{ secrets.DEPLOY_TOKEN }}"\n')
        rule_ids = [finding.rule_id for finding in scan_pipeline(".github/workflows/ci.yml", text)]

        self.assertIn("CG-PIPE-003", rule_ids)

    def test_event_context_injection_flagged(self) -> None:
        text = workflow('      - run: echo "${{ github.event.pull_request.title }}"\n')
        rule_ids = [finding.rule_id for finding in scan_pipeline(".github/workflows/ci.yml", text)]

        self.assertIn("CG-PIPE-004", rule_ids)

    def test_curl_pipe_flagged(self) -> None:
        text = workflow("      - run: curl -fsSL https://example.com/i.sh | bash\n")
        rule_ids = [finding.rule_id for finding in scan_pipeline(".github/workflows/ci.yml", text)]

        self.assertIn("CG-PIPE-005", rule_ids)

    def test_write_all_permissions_flagged(self) -> None:
        text = workflow(f"      - uses: actions/checkout@{PINNED}\n", permissions="write-all")
        rule_ids = [finding.rule_id for finding in scan_pipeline(".github/workflows/ci.yml", text)]

        self.assertIn("CG-PIPE-006", rule_ids)

    def test_invalid_yaml_reported_once(self) -> None:
        findings = scan_pipeline(".github/workflows/broken.yml", "name: [unclosed\n")

        self.assertEqual([finding.rule_id for finding in findings], ["CG-PIPE-010"])

    def test_sample_fixture_triggers_many_rules(self) -> None:
        from pathlib import Path

        sample = Path(__file__).resolve().parents[1] / "configs" / "samples" / "workflows" / "github-actions-insecure.yml"
        findings = scan_pipeline("configs/samples/workflows/github-actions-insecure.yml", sample.read_text(encoding="utf-8"))
        rule_ids = {finding.rule_id for finding in findings}

        self.assertTrue({"CG-PIPE-001", "CG-PIPE-002", "CG-PIPE-003", "CG-PIPE-004", "CG-PIPE-005", "CG-PIPE-006"} <= rule_ids)


class GitlabPipelineTests(unittest.TestCase):
    def test_floating_image_and_token_echo_flagged(self) -> None:
        text = (
            "image: python:latest\n"
            "build:\n"
            "  script:\n"
            '    - echo "$CI_JOB_TOKEN"\n'
            "    - curl -sSf https://example.com/get.sh | sh\n"
        )
        findings = scan_pipeline(".gitlab-ci.yml", text)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertEqual(rule_ids, {"CG-PIPE-020", "CG-PIPE-021", "CG-PIPE-022"})

    def test_digest_pinned_image_passes(self) -> None:
        text = "image: python@sha256:" + "b" * 64 + "\nbuild:\n  script:\n    - echo ok\n"
        self.assertEqual(scan_pipeline(".gitlab-ci.yml", text), [])


class DispatchTests(unittest.TestCase):
    def test_path_classification(self) -> None:
        self.assertTrue(is_github_workflow(".github/workflows/ci.yml"))
        self.assertTrue(is_github_workflow("configs/samples/workflows/ci.yml"))
        self.assertFalse(is_github_workflow("src/app.py"))
        self.assertTrue(is_gitlab_pipeline("configs/samples/gitlab/.gitlab-ci.yml"))
        self.assertFalse(is_gitlab_pipeline("configs/samples/workflows/ci.yml"))

    def test_unrelated_yaml_is_ignored(self) -> None:
        self.assertEqual(scan_pipeline("k8s/deployment.yml", "replicas: 2\n"), [])


if __name__ == "__main__":
    unittest.main()
