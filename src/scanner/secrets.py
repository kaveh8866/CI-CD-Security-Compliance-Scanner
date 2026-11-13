"""Exposed-credential detection.

Two layers:

* **Signature rules** for credentials with a recognisable shape (cloud access
  keys, forge tokens, PEM blocks). These are high confidence and critical.
* **A generic assignment rule** for ``password = "..."``-style constants, gated
  by Shannon entropy and a placeholder allowlist so documentation and example
  files do not drown the report.

Matched values never leave this module: every finding carries a truncated
SHA-256 fingerprint instead, which is enough to correlate two reports without
being enough to use the credential.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

from .models import Finding

# Placeholder vocabulary that marks a value as documentation rather than a
# credential. Lower-cased substring checks.
PLACEHOLDER_HINTS: tuple[str, ...] = (
    "example",
    "placeholder",
    "changeme",
    "change-me",
    "your_",
    "your-",
    "redacted",
    "dummy",
    "not-real",
    "notreal",
    "replace",
    "xxxx",
    "****",
    "todo",
)

_SIGNATURE_RULES: tuple[tuple[str, str, str, re.Pattern[str], str], ...] = (
    (
        "CG-SEC-001",
        "AWS access key id",
        "critical",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Revoke the key in IAM, issue a new one, and reference it through a secret store.",
    ),
    (
        "CG-SEC-002",
        "GitHub token",
        "critical",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        "Revoke the token in GitHub settings and pass it via an encrypted CI secret.",
    ),
    (
        "CG-SEC-003",
        "GitLab personal access token",
        "critical",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        "Revoke the token in GitLab and move it to a masked CI/CD variable.",
    ),
    (
        "CG-SEC-004",
        "Slack token",
        "critical",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        "Revoke the app token in Slack and inject it at runtime from a secret manager.",
    ),
    (
        "CG-SEC-005",
        "Stripe secret key",
        "critical",
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        "Roll the key in the Stripe dashboard and load it from a secret store.",
    ),
    (
        "CG-SEC-006",
        "Google API key",
        "high",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Restrict or rotate the API key in Google Cloud and inject it from a secret.",
    ),
    (
        "CG-SEC-007",
        "Private key block",
        "critical",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "Remove the key from the repository, rotate it, and use a runtime secret mount.",
    ),
)

_GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|"
    r"auth[_-]?token|password|passwd|pwd|private[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"'#,;]{12,})"
)

_TEXT_EXTENSIONS: tuple[str, ...] = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".tf", ".tfvars",
    ".md", ".txt", ".properties", ".xml", ".gradle", ".ps1", ".dockerfile", ".lock", ".example",
)

_BINARY_EXTENSIONS: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".tar", ".whl",
    ".so", ".dylib", ".dll", ".exe", ".class", ".pyc", ".ico", ".woff", ".woff2",
)


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""

    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def fingerprint(value: str) -> str:
    """Stable, non-reversible identifier for a matched value."""

    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def looks_placeholder(value: str) -> bool:
    lowered = value.lower()
    if "$" in value or "{{" in value or "<" in value:
        return True
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def is_scannable_text(rel_path: str, data: bytes) -> bool:
    lower = rel_path.lower()
    if lower.endswith(_BINARY_EXTENSIONS):
        return False
    if b"\x00" in data[:8192]:
        return False
    if lower.rsplit("/", 1)[-1].startswith("dockerfile"):
        return True
    return lower.endswith(_TEXT_EXTENSIONS) or "." not in lower.rsplit("/", 1)[-1]


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def scan_text(rel_path: str, text: str) -> list[Finding]:
    """Return every credential finding in one text blob."""

    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []

    for rule_id, title, severity, pattern, remediation in _SIGNATURE_RULES:
        for match in pattern.finditer(text):
            claimed.append(match.span())
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    category="secret",
                    file=rel_path,
                    line=_line_of(text, match.start()),
                    message=f"{title} found in tracked content; value redacted ({fingerprint(match.group(0))}).",
                    remediation=remediation,
                    evidence=fingerprint(match.group(0)),
                )
            )

    for match in _GENERIC_ASSIGNMENT.finditer(text):
        start, end = match.span(2)
        if any(start < claimed_end and end > claimed_start for claimed_start, claimed_end in claimed):
            continue
        value = match.group(2)
        if looks_placeholder(value) or entropy(value) < 3.0:
            continue
        findings.append(
            Finding(
                rule_id="CG-SEC-010",
                title="Hard-coded credential assignment",
                severity="high",
                category="secret",
                file=rel_path,
                line=_line_of(text, match.start()),
                message=(
                    f"Assignment to '{match.group(1)}' carries a high-entropy literal "
                    f"({fingerprint(value)}); value redacted."
                ),
                remediation="Move the value into a CI secret and reference it by name at runtime.",
                evidence=fingerprint(value),
            )
        )

    return findings
