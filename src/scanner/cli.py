"""Operator CLI: scan a tree, print a report, exit non-zero when policy fails."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, compliance
from .engine import scan_path
from .models import SEVERITIES

_SEVERITY_TAG = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _render(report) -> str:
    lines: list[str] = []
    lines.append(f"policy   {report.policy_name} v{report.policy_version}")
    lines.append(f"target   {report.target}")
    lines.append(f"files    {report.files_scanned} scanned")
    summary = report.summary
    lines.append(
        "findings "
        + ", ".join(f"{severity}={count}" for severity, count in summary.items() if count)
        + ("" if any(summary.values()) else "none")
    )
    failed = report.failed_controls()
    lines.append(f"controls {len(report.controls) - len(failed)}/{len(report.controls)} passing")

    if report.findings:
        lines.append("")
        width = max(len(finding.rule_id) for finding in report.findings)
        for finding in report.findings:
            lines.append(
                f"{_SEVERITY_TAG[finding.severity]}  {finding.rule_id:<{width}}  "
                f"{finding.file}:{finding.line}  {finding.message}"
            )

    lines.append("")
    for control in report.controls:
        mark = "PASS" if control.status == "pass" else "FAIL"
        lines.append(f"{mark}  {control.id}  {control.title} [{control.severity}]")

    if report.errors:
        lines.append("")
        for error in report.errors:
            lines.append(f"note  {error}")

    return "\n".join(lines)


def _command_scan(args: argparse.Namespace) -> int:
    try:
        policy = compliance.load_policy(args.policy)
        report = scan_path(args.path, policy=policy)
    except (FileNotFoundError, NotADirectoryError, compliance.PolicyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render(report))

    exit_code = report.exit_code(args.fail_on or policy.fail_on)
    if exit_code:
        print(
            f"\npolicy failure: findings at or above '{args.fail_on or policy.fail_on}'",
            file=sys.stderr,
        )
    return exit_code


def _command_validate(args: argparse.Namespace) -> int:
    try:
        policy = compliance.load_policy(args.policy)
    except compliance.PolicyError as error:
        print(f"invalid: {error}", file=sys.stderr)
        return 1

    print(f"valid   {policy.name} v{policy.version} ({len(policy.controls)} controls, fail_on={policy.fail_on})")
    for control in policy.controls:
        print(f"  {control.id:<12} {control.severity:<8} {control.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="CloudGuard CI/CD security and compliance scanner",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser("scan", help="scan a directory tree")
    scan.add_argument("path", help="directory to scan")
    scan.add_argument("--policy", default=None, help="policy TOML (default: bundled baseline)")
    scan.add_argument("--json", action="store_true", help="emit the machine-readable report")
    scan.add_argument("--fail-on", choices=SEVERITIES, default=None, help="override the policy threshold")
    scan.set_defaults(func=_command_scan)

    validate = subcommands.add_parser("validate-policy", help="parse and validate a policy file")
    validate.add_argument("policy", help="policy TOML to validate")
    validate.set_defaults(func=_command_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
