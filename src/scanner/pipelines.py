"""CI/CD pipeline definition analysis.

GitHub Actions workflows are parsed with PyYAML for structural checks (trigger
events, permissions) and scanned line-by-line for the constructs that are
cheapest to get wrong: unpinned actions, secrets interpolated into shell,
script injection through event context, and `curl | bash`.

GitLab CI has a smaller, equally useful set: floating images, remote scripts
piped into a shell, and job tokens echoed to logs.
"""

from __future__ import annotations

import re

import yaml

from .models import Finding

_SHA_REF = re.compile(r"^[0-9a-f]{40}$")
_USES_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*[\"']?([^\s\"'#]+)", re.MULTILINE)
_RUN_BLOCK = re.compile(r"^\s*(?:-\s*)?run:\s*(.*)$", re.MULTILINE)
_SHELL_PIPE = re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b")
_EVENT_CONTEXT = re.compile(r"\$\{\{\s*github\.event\.[^}]*\}\}")
_SECRET_IN_SHELL = re.compile(r"\$\{\{\s*secrets\.[^}]+\}\}")
_GITLAB_IMAGE = re.compile(r"^\s*image:\s*[\"']?([^\s\"'#]+)", re.MULTILINE)
_GITLAB_JOB_TOKEN = re.compile(r"\$\{?CI_JOB_TOKEN\}?")
_GITLAB_SCRIPT_INJECTION = re.compile(r"\$\{?CI_COMMIT_(?:MESSAGE|TITLE|DESCRIPTION)\}?")

_ALLOWED_EVENTS = {"push", "pull_request", "workflow_dispatch", "schedule", "release", "merge_group"}


def is_github_workflow(rel_path: str) -> bool:
    """True for workflow files, including fixtures outside `.github/workflows`.

    Real workflows always live under `.github/workflows/`. Samples kept in
    `configs/samples/workflows/` are recognised by the same directory name so a
    demo can be scanned without copying it into a repository layout.
    """

    lower = rel_path.lower()
    if not lower.endswith((".yml", ".yaml")):
        return False
    return "workflows/" in f"/{lower}"


def is_gitlab_pipeline(rel_path: str) -> bool:
    return rel_path.lower().rsplit("/", 1)[-1] in {".gitlab-ci.yml", ".gitlab-ci.yaml"}


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    rel_path: str,
    line: int,
    message: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category="pipeline",
        file=rel_path,
        line=line,
        message=message,
        remediation=remediation,
    )


def _workflow_events(document: object) -> set[str]:
    """Normalise the YAML 1.1 `on` key (parsed as boolean True) to event names."""

    if not isinstance(document, dict):
        return set()

    raw = document.get("on", document.get(True))  # noqa: FBT003 - YAML 1.1 quirk
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(entry) for entry in raw}
    if isinstance(raw, dict):
        return {str(key) for key in raw}
    return set()


def scan_github_workflow(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []

    document: object
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        findings.append(
            _finding(
                "CG-PIPE-010",
                "Unparseable workflow",
                "medium",
                rel_path,
                (mark.line + 1) if mark else 1,
                "The workflow is not valid YAML, so its policy cannot be evaluated.",
                "Fix the YAML syntax and re-run the scanner.",
            )
        )
        document = None

    events = _workflow_events(document)

    for match in _USES_LINE.finditer(text):
        reference = match.group(1)
        if reference.startswith(("./", "docker://")):
            continue
        _, _, ref = reference.partition("@")
        if _SHA_REF.match(ref):
            continue
        findings.append(
            _finding(
                "CG-PIPE-001",
                "Unpinned third-party action",
                "high",
                rel_path,
                _line_of(text, match.start()),
                f"Action '{reference}' is referenced by tag or branch, not a commit SHA.",
                "Pin the action to a full 40-character commit SHA; refresh it deliberately.",
            )
        )

    if "pull_request_target" in events:
        checkout_head = re.search(
            r"(?s)uses:\s*actions/checkout[^\n]*\n(?:.*?\n){0,12}?.*?github\.event\.pull_request\.head",
            text,
        )
        findings.append(
            _finding(
                "CG-PIPE-002",
                "pull_request_target with untrusted checkout",
                "critical",
                rel_path,
                _line_of(text, text.index("pull_request_target")),
                "The privileged pull_request_target trigger is combined with a checkout of PR head code."
                if checkout_head
                else "The privileged pull_request_target trigger runs with repository secrets available.",
                "Run untrusted code under 'pull_request'; keep pull_request_target for label-only workflows.",
            )
        )

    for match in _SECRET_IN_SHELL.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        if not re.search(r"\b(?:echo|printf|cat|printenv)\b", text[line_start : match.start()]):
            continue
        findings.append(
            _finding(
                "CG-PIPE-003",
                "Secret interpolated into shell output",
                "high",
                rel_path,
                _line_of(text, match.start()),
                f"{match.group(0)} is expanded into a shell command that can print it.",
                "Pass secrets as environment variables and never echo them; mask them in logs.",
            )
        )

    for match in _EVENT_CONTEXT.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.start())
        segment = text[line_start : line_end if line_end != -1 else len(text)]
        if not _RUN_BLOCK.search(segment) and "run:" not in segment:
            continue
        findings.append(
            _finding(
                "CG-PIPE-004",
                "Script injection through event context",
                "critical",
                rel_path,
                _line_of(text, match.start()),
                f"Untrusted event data ({match.group(0)}) is interpolated directly into a run step.",
                "Move the value into an environment variable and reference it as \"$VAR\".",
            )
        )

    for match in _SHELL_PIPE.finditer(text):
        findings.append(
            _finding(
                "CG-PIPE-005",
                "Remote script piped into a shell",
                "medium",
                rel_path,
                _line_of(text, match.start()),
                "A network download is executed by a shell without integrity verification.",
                "Download, verify a checksum or signature, then execute the pinned artefact.",
            )
        )

    permissions = document.get("permissions") if isinstance(document, dict) else None
    if isinstance(permissions, str) and permissions.strip() == "write-all":
        findings.append(
            _finding(
                "CG-PIPE-006",
                "Workflow grants write-all permissions",
                "medium",
                rel_path,
                _line_of(text, text.index("write-all")),
                "The workflow token can write every scope, so any injected step inherits that power.",
                "Declare the minimal permissions per job, starting from 'contents: read'.",
            )
        )

    unknown_events = events - _ALLOWED_EVENTS
    if unknown_events:
        findings.append(
            _finding(
                "CG-PIPE-007",
                "Unreviewed workflow trigger",
                "low",
                rel_path,
                _line_of(text, text.index("on:") if "on:" in text else 0),
                f"Trigger(s) outside the approved baseline: {', '.join(sorted(unknown_events))}.",
                "Confirm the trigger is required; document the threat model for privileged events.",
            )
        )

    return findings


def scan_gitlab_pipeline(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []

    for match in _GITLAB_IMAGE.finditer(text):
        image = match.group(1)
        if image.startswith("$") or "@sha256:" in image:
            continue
        tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
        if tag in ("", "latest"):
            findings.append(
                _finding(
                    "CG-PIPE-020",
                    "Floating container image",
                    "medium",
                    rel_path,
                    _line_of(text, match.start()),
                    f"Image '{image}' is not pinned to an immutable digest.",
                    "Pin the image by digest (@sha256:…) so a rebuild cannot introduce a new base.",
                )
            )

    for match in _SHELL_PIPE.finditer(text):
        findings.append(
            _finding(
                "CG-PIPE-021",
                "Remote script piped into a shell",
                "medium",
                rel_path,
                _line_of(text, match.start()),
                "A network download is executed by a shell without integrity verification.",
                "Verify a checksum or signature before executing downloaded scripts.",
            )
        )

    for match in _GITLAB_JOB_TOKEN.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.start())
        segment = text[line_start : line_end if line_end != -1 else len(text)]
        if "echo" not in segment.lower() and "printf" not in segment.lower():
            continue
        findings.append(
            _finding(
                "CG-PIPE-022",
                "CI job token printed",
                "high",
                rel_path,
                _line_of(text, match.start()),
                "CI_JOB_TOKEN is echoed, exposing it to anyone who can read job logs.",
                "Remove the echo and mark the variable masked in the project settings.",
            )
        )

    for match in _GITLAB_SCRIPT_INJECTION.finditer(text):
        findings.append(
            _finding(
                "CG-PIPE-023",
                "Commit metadata interpolated into a script",
                "medium",
                rel_path,
                _line_of(text, match.start()),
                f"Untrusted commit metadata ({match.group(0)}) is expanded into a shell command.",
                "Quote the value or read it from a file instead of interpolating it into script lines.",
            )
        )

    return findings


def scan_pipeline(rel_path: str, text: str) -> list[Finding]:
    """Dispatch to the matching pipeline analyser, if any."""

    if is_github_workflow(rel_path):
        return scan_github_workflow(rel_path, text)
    if is_gitlab_pipeline(rel_path):
        return scan_gitlab_pipeline(rel_path, text)
    return []
