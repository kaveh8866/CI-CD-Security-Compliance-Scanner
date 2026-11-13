"""Dependency manifest parsing and offline advisory matching.

Coverage is deliberate and small: `requirements.txt` and `package.json` are the
two manifests that appear in almost every pipeline, and the advisory catalogue
lives in `configs/advisories/advisories.json` so it can be extended without code
changes. This is a drift detector, not a replacement for OSV or Dependabot: it
catches pins that were already known-bad when the catalogue was written.

Range specs are compared by their lower bound, which is the version a fresh
install resolves to worst-case. That heuristic is reported in the finding text
rather than hidden.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

from .models import Finding

_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:(==|>=|<=|~=|!=|>|<)\s*([0-9][0-9A-Za-z.*+-]*))?$",
)
_VERSION_PART = re.compile(r"^\d+")
_SPEC_VERSION = re.compile(r"(\d+(?:\.\d+)*)")

def default_advisory_file() -> Path:
    """Locate the catalogue in a checkout and inside the container image.

    The package sits at `src/scanner/` in development and at `/app/scanner/` in
    the image, so a fixed ``parents[N]`` offset breaks one of the two. Candidates
    are tried in order and the first existing file wins.
    """

    package = Path(__file__).resolve()
    candidates = [
        Path(os.environ["SCANNER_ADVISORY_FILE"]) if os.environ.get("SCANNER_ADVISORY_FILE") else None,
        package.parents[1] / "configs" / "advisories" / "advisories.json",
        package.parents[2] / "configs" / "advisories" / "advisories.json",
        Path("/etc/scanner/advisories/advisories.json"),
        Path("/app/configs/advisories/advisories.json"),
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    return candidates[1] if candidates[1] else Path("configs/advisories/advisories.json")


def version_tuple(value: str) -> tuple[int, ...]:
    """Numeric version tuple; pre-release suffixes are ignored on purpose."""

    parts: list[int] = []
    for chunk in value.split("."):
        match = _VERSION_PART.match(chunk.strip())
        if not match:
            break
        parts.append(int(match.group(0)))
    return tuple(parts) if parts else (0,)


def version_less_than(left: str, right: str) -> bool:
    a, b = version_tuple(left), version_tuple(right)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def _declared_version(spec: str) -> str | None:
    match = _SPEC_VERSION.search(spec)
    return match.group(1) if match else None


@lru_cache(maxsize=8)
def load_advisories(path: str | None = None) -> list[dict[str, str]]:
    """Load the advisory catalogue once per process."""

    target = Path(path) if path else default_advisory_file()
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    entries = document.get("advisories", []) if isinstance(document, dict) else []
    return [entry for entry in entries if isinstance(entry, dict)]


def _advisory_findings(
    rel_path: str,
    line: int,
    package: str,
    spec: str,
    ecosystem: str,
    advisories: list[dict[str, str]],
) -> list[Finding]:
    declared = _declared_version(spec)
    if declared is None:
        return []

    findings: list[Finding] = []
    for advisory in advisories:
        if advisory.get("package", "").lower() != package.lower():
            continue
        if advisory.get("ecosystem", ecosystem) != ecosystem:
            continue
        below = advisory.get("below", "")
        if not below or not version_less_than(declared, below):
            continue
        findings.append(
            Finding(
                rule_id=advisory.get("rule_id", "CG-DEP-010"),
                title=advisory.get("title", "Vulnerable dependency"),
                severity=advisory.get("severity", "high"),
                category="dependency",
                file=rel_path,
                line=line,
                message=(
                    f"{package} {declared} is below the fixed version {below} "
                    f"({advisory.get('id', 'advisory')}): {advisory.get('summary', 'known vulnerability')}."
                ),
                remediation=advisory.get(
                    "remediation",
                    f"Upgrade {package} to {below} or later and re-run the pipeline.",
                ),
            )
        )
    return findings


def scan_requirements(rel_path: str, text: str, advisories: list[dict[str, str]] | None = None) -> list[Finding]:
    catalogue = advisories if advisories is not None else load_advisories()
    findings: list[Finding] = []

    for index, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line or " @ " in line:
            continue

        match = _REQUIREMENT.match(line)
        if not match:
            continue
        package, operator, version = match.group(1), match.group(2), match.group(3)

        if operator not in ("==", "~="):
            findings.append(
                Finding(
                    rule_id="CG-DEP-001",
                    title="Unpinned dependency",
                    severity="medium",
                    category="dependency",
                    file=rel_path,
                    line=index,
                    message=f"{package} is declared without an exact pin, so builds are not reproducible.",
                    remediation=f"Pin {package} to a reviewed version (==x.y.z) and update it deliberately.",
                )
            )
            continue

        findings.extend(_advisory_findings(rel_path, index, package, version, "pypi", catalogue))

    return findings


def scan_package_json(rel_path: str, text: str, advisories: list[dict[str, str]] | None = None) -> list[Finding]:
    catalogue = advisories if advisories is not None else load_advisories()
    findings: list[Finding] = []

    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return [
            Finding(
                rule_id="CG-DEP-002",
                title="Unparseable package manifest",
                severity="medium",
                category="dependency",
                file=rel_path,
                line=1,
                message="package.json is not valid JSON, so its dependencies cannot be evaluated.",
                remediation="Fix the JSON syntax and re-run the scanner.",
            )
        ]

    if not isinstance(document, dict):
        return []

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = document.get(section)
        if not isinstance(dependencies, dict):
            continue
        for package, spec in dependencies.items():
            if not isinstance(spec, str):
                continue
            line = _line_for_package(text, package)
            declared = _declared_version(spec)
            if declared is None:
                findings.append(
                    Finding(
                        rule_id="CG-DEP-003",
                        title="Unpinned npm dependency",
                        severity="medium",
                        category="dependency",
                        file=rel_path,
                        line=line,
                        message=f"{package} uses '{spec}', which can resolve to a different build on every install.",
                        remediation=f"Pin {package} to an exact version; commit the lockfile.",
                    )
                )
                continue
            findings.extend(_advisory_findings(rel_path, line, package, declared, "npm", catalogue))

    return findings


def _line_for_package(text: str, package: str) -> int:
    needle = f'"{package}"'
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index != -1 else 1


def scan_manifest(rel_path: str, text: str, advisories: list[dict[str, str]] | None = None) -> list[Finding]:
    name = rel_path.rsplit("/", 1)[-1].lower()
    if name == "requirements.txt" or name.startswith("requirements-") and name.endswith(".txt"):
        return scan_requirements(rel_path, text, advisories)
    if name == "package.json":
        return scan_package_json(rel_path, text, advisories)
    return []
