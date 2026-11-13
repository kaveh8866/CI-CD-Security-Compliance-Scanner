"""Value-free data model shared by every scanner module.

Findings never carry the secret they describe: evidence is a short SHA-256
fingerprint, so a report can be logged, archived or attached to a ticket without
becoming a second copy of the leak.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES: tuple[str, ...] = tuple(SEVERITY_ORDER)
CATEGORIES: tuple[str, ...] = ("secret", "pipeline", "dependency")


@dataclass(frozen=True)
class Finding:
    """One policy violation, anchored to a file and line."""

    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    message: str
    remediation: str = ""
    evidence: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity}")
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category: {self.category}")

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def sort_key(self) -> tuple[int, str, int, str]:
        return (-self.rank, self.file, self.line, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class ControlResult:
    """Outcome of one compliance control from the policy file."""

    id: str
    title: str
    severity: str
    description: str
    remediation: str
    status: str
    matched_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "status": self.status,
            "matched_findings": self.matched_findings,
        }


@dataclass
class Report:
    target: str
    policy_name: str
    policy_version: str
    generated_at: str
    files_scanned: int
    findings: list[Finding]
    controls: list[ControlResult]
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def exit_code(self, fail_on: str = "high") -> int:
        threshold = SEVERITY_ORDER[fail_on]
        return 1 if any(finding.rank >= threshold for finding in self.findings) else 0

    def failed_controls(self) -> list[ControlResult]:
        return [control for control in self.controls if control.status == "fail"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "policy": {"name": self.policy_name, "version": self.policy_version},
            "generated_at": self.generated_at,
            "files_scanned": self.files_scanned,
            "summary": self.summary,
            "controls": [control.to_dict() for control in self.controls],
            "controls_failed": len(self.failed_controls()),
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
