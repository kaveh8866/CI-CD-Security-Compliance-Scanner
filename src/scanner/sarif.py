"""SARIF 2.1.0 export.

SARIF is what GitHub code scanning, GitLab SAST and most CI dashboards consume.
The mapping is deliberately conservative:

* `critical`/`high` → `error` (fails a code-scanning gate)
* `medium`         → `warning`
* `low`/`info`     → `note`

Results carry the same value-free message as the JSON report, a physical
location, and a stable fingerprint built from the finding's evidence digest, so
an alert survives re-scans and line shifts without ever containing the secret.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import __version__
from .models import Finding, Report

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _fingerprint(finding: Finding) -> str:
    if finding.evidence.startswith("sha256:"):
        return finding.evidence
    payload = f"{finding.rule_id}:{finding.file}:{finding.line}:{finding.message}"
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _rule(finding: Finding, level: str) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.remediation or finding.title},
        "defaultConfiguration": {"level": level},
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "tags": ["security", "ci-cd", finding.category],
        },
    }


def to_sarif(report: Report) -> dict[str, Any]:
    """Render one report as a SARIF log with a single run."""

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        level = _LEVEL[finding.severity]
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule(finding, level))

        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": level,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": max(finding.line, 1)},
                        }
                    }
                ],
                "partialFingerprints": {"cloudguardFinding/v1": _fingerprint(finding)},
                "properties": {
                    "severity": finding.severity,
                    "category": finding.category,
                    "remediation": finding.remediation,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloudguard-scanner",
                        "informationUri": "https://github.com/kaveh8866/CI-CD-Security-Compliance-Scanner",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "target": report.target,
                            "policy": report.policy_name,
                            "policyVersion": report.policy_version,
                            "filesScanned": report.files_scanned,
                            "controlsFailed": len(report.failed_controls()),
                        },
                    }
                ],
                "properties": {
                    "summary": report.summary,
                    "generatedAt": report.generated_at,
                },
            }
        ],
    }
