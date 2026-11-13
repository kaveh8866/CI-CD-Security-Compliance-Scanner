"""Scan orchestration: walk a target, dispatch per file type, fold the report.

The walker is intentionally boring: no symlink following, a hard file ceiling, a
per-file byte ceiling, and an explicit exclusion list. A scanner that can be
pointed at a repository must never surprise an operator by reading objects of
unbounded size or escaping the requested tree.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from . import compliance, deps, pipelines, secrets
from .models import Finding, Report, utc_now

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 5_000

EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".terraform",
        "dist",
        "build",
        "target",
        ".cloudguard",
        "data",
    }
)


def discover(target: Path, max_files: int = MAX_FILES) -> tuple[list[Path], list[str]]:
    """Return regular files under *target*, plus non-fatal walk errors."""

    files: list[Path] = []
    errors: list[str] = []

    for root, dirnames, filenames in os.walk(target, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in EXCLUDED_DIRS)
        for name in sorted(filenames):
            path = Path(root) / name
            if path.is_symlink():
                continue
            files.append(path)
            if len(files) >= max_files:
                errors.append(f"file limit reached ({max_files}); remaining files were not scanned")
                return files, errors

    return files, errors


def _ignored(rel_path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(rel_path, pattern) for pattern in patterns)


def scan_path(
    target: str | Path,
    policy: compliance.Policy | None = None,
    policy_path: str | Path | None = None,
    advisories: list[dict[str, str]] | None = None,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> Report:
    """Scan one directory tree and build a report."""

    active_policy = policy or compliance.load_policy(policy_path)
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"not a directory: {root}")

    files, errors = discover(root)
    catalogue = advisories if advisories is not None else deps.load_advisories()
    findings: list[Finding] = []
    scanned = 0

    for path in files:
        rel_path = path.relative_to(root).as_posix()
        if _ignored(rel_path, active_policy.ignore):
            continue

        try:
            data = path.read_bytes()
        except OSError:
            errors.append(f"{rel_path}: unreadable")
            continue
        if len(data) > max_file_bytes:
            errors.append(f"{rel_path}: exceeds {max_file_bytes} bytes")
            continue
        if not secrets.is_scannable_text(rel_path, data):
            continue

        scanned += 1
        text = data.decode("utf-8", "replace")

        findings.extend(secrets.scan_text(rel_path, text))
        findings.extend(pipelines.scan_pipeline(rel_path, text))
        findings.extend(deps.scan_manifest(rel_path, text, catalogue))

    unique: dict[tuple[str, str, int, str], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.file, finding.line, finding.message), finding)

    ordered = sorted(unique.values(), key=Finding.sort_key)
    controls = active_policy.evaluate(ordered)

    return Report(
        target=str(root),
        policy_name=active_policy.name,
        policy_version=active_policy.version,
        generated_at=utc_now(),
        files_scanned=scanned,
        findings=ordered,
        controls=controls,
        errors=errors,
    )
