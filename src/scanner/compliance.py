"""Compliance policy loading and control evaluation.

A policy is a small TOML document: a header with the failing threshold and an
array of controls. Each control names the rule ids it governs, so the same
finding set can be judged by a strict baseline in CI and a relaxed one for a
legacy repository without changing the code.

Parsing uses `tomllib` from the standard library; validation is explicit and
every error names the offending key, because a silently ignored policy is worse
than a broken one.
"""

from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import ControlResult, Finding, SEVERITIES, SEVERITY_ORDER


def default_policy_path() -> Path:
    """Locate the bundled policy in a checkout and inside the container image."""

    package = Path(__file__).resolve()
    candidates = [
        package.parents[1] / "configs" / "policies" / "compliance.toml",
        package.parents[2] / "configs" / "policies" / "compliance.toml",
        Path("/etc/scanner/policies/compliance.toml"),
        Path("/app/configs/policies/compliance.toml"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


class PolicyError(ValueError):
    """Raised when a policy document is missing or structurally invalid."""


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    severity: str
    description: str
    remediation: str
    rules: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    name: str
    version: str
    fail_on: str
    controls: tuple[Control, ...]
    ignore: tuple[str, ...] = field(default_factory=tuple)
    source: str = ""

    def applies_to(self, rule_id: str) -> bool:
        return any(fnmatch.fnmatchcase(rule_id, pattern) for control in self.controls for pattern in control.rules)

    def evaluate(self, findings: list[Finding]) -> list[ControlResult]:
        results: list[ControlResult] = []
        for control in self.controls:
            matched = [
                finding.rule_id
                for finding in findings
                if any(fnmatch.fnmatchcase(finding.rule_id, pattern) for pattern in control.rules)
            ]
            results.append(
                ControlResult(
                    id=control.id,
                    title=control.title,
                    severity=control.severity,
                    description=control.description,
                    remediation=control.remediation,
                    status="fail" if matched else "pass",
                    matched_findings=sorted(set(matched)),
                )
            )
        return results

    def threshold(self) -> int:
        return SEVERITY_ORDER[self.fail_on]


def _require(table: dict, key: str, kind: type, where: str):
    value = table.get(key)
    if not isinstance(value, kind):
        raise PolicyError(f"{where}.{key} must be a {kind.__name__}.")
    return value


def parse_policy(document: dict, source: str = "<memory>") -> Policy:
    header = document.get("policy")
    if not isinstance(header, dict):
        raise PolicyError(f"{source}: missing [policy] table.")

    name = _require(header, "name", str, "[policy]")
    version = _require(header, "version", str, "[policy]")
    fail_on = header.get("fail_on", "high")
    if fail_on not in SEVERITIES:
        raise PolicyError(f"[policy].fail_on must be one of {', '.join(SEVERITIES)}.")

    raw_controls = document.get("controls")
    if not isinstance(raw_controls, list) or not raw_controls:
        raise PolicyError(f"{source}: at least one [[controls]] entry is required.")

    controls: list[Control] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_controls, start=1):
        where = f"[[controls]]#{index}"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be a table.")

        control_id = _require(raw, "id", str, where)
        if control_id in seen_ids:
            raise PolicyError(f"{where}.id '{control_id}' is declared twice.")
        seen_ids.add(control_id)

        severity = _require(raw, "severity", str, where)
        if severity not in SEVERITIES:
            raise PolicyError(f"{where}.severity must be one of {', '.join(SEVERITIES)}.")

        rules = _require(raw, "rules", list, where)
        if not rules or not all(isinstance(rule, str) and rule for rule in rules):
            raise PolicyError(f"{where}.rules must be a non-empty list of rule ids.")

        controls.append(
            Control(
                id=control_id,
                title=_require(raw, "title", str, where),
                severity=severity,
                description=str(raw.get("description", "")),
                remediation=str(raw.get("remediation", "")),
                rules=tuple(rules),
            )
        )

    raw_ignore = header.get("ignore", [])
    if not isinstance(raw_ignore, list) or not all(isinstance(entry, str) for entry in raw_ignore):
        raise PolicyError("[policy].ignore must be a list of glob strings.")

    return Policy(
        name=name,
        version=version,
        fail_on=fail_on,
        controls=tuple(controls),
        ignore=tuple(raw_ignore),
        source=source,
    )


def load_policy(path: str | Path | None = None) -> Policy:
    override = os.environ.get("SCANNER_POLICY_FILE")
    target = Path(path) if path else Path(override) if override else default_policy_path()
    try:
        raw = target.read_bytes()
    except OSError as error:
        raise PolicyError(f"policy file not readable: {target} ({error.strerror})") from error

    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise PolicyError(f"{target}: invalid TOML ({error})") from error

    return parse_policy(document, source=str(target))
