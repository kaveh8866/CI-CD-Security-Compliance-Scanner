#!/usr/bin/env bash
# =============================================================================
# CI/CD Security & Compliance Scanner — smoke contract
# =============================================================================
# Runs against a live service (BASE_URL) and the local CLI. Every assertion is
# value-free: the suite proves that reports redact credentials, not that a
# particular secret was found.
#
#   BASE_URL=http://127.0.0.1:8300 bash tests/smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8300}"

# The CLI needs Python 3.11+ (tomllib). Prefer an explicitly provided
# interpreter, then whichever candidate on PATH actually satisfies that.
pick_python() {
  for candidate in ${PYTHON:-} python python3 py; do
    if "$candidate" -c 'import sys, tomllib; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

PYTHON="$(pick_python)" || { echo "python 3.11+ is required to run the smoke suite" >&2; exit 2; }

PYTHONPATH="$ROOT/src" "$PYTHON" - "$BASE_URL" "$ROOT" <<'PY'
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

base_url, root = sys.argv[1].rstrip("/"), sys.argv[2]
passed = 0
failed: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed.append(label)
        print(f"  FAIL  {label}{(' — ' + detail) if detail else ''}")


def request(path: str, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


print("== service contract ==")
status, health = request("/healthz")
check("healthz returns 200", status == 200, str(status))
check("healthz reports ok", health.get("status") == "ok", str(health))
check("healthz exposes policy version", health.get("policy_version") == "1.0.0", str(health.get("policy_version")))
check("healthz advertises >= 10 controls", int(health.get("controls", 0)) >= 10, str(health.get("controls")))

status, policy = request("/policy")
check("policy endpoint returns 200", status == 200, str(status))
check("policy gate is high", policy.get("fail_on") == "high", str(policy.get("fail_on")))
check("policy exposes control CG-CI-007", any(c["id"] == "CG-CI-007" for c in policy.get("controls", [])))

print("== scan contract ==")
status, report = request("/scan", {"path": "/scan"})
check("scan returns 200", status == 200, str(status))
check("scan reports findings", len(report.get("findings", [])) >= 5, str(len(report.get("findings", []))))
check("scan exit_code is 1", report.get("exit_code") == 1, str(report.get("exit_code")))
check("scan fails controls", report.get("controls_failed", 0) > 0, str(report.get("controls_failed")))
rule_ids = {finding["rule_id"] for finding in report.get("findings", [])}
check("unpinned action detected", "CG-PIPE-001" in rule_ids, str(sorted(rule_ids)))
check("insecure trigger detected", "CG-PIPE-002" in rule_ids)
check("vulnerable dependency detected", "CG-VULN-001" in rule_ids)
check("hard-coded credential detected", "CG-SEC-010" in rule_ids)
check("no dependency feed error", report.get("errors") == [], str(report.get("errors")))

serialised = json.dumps(report)
check("report contains no credential value", "Zk8Qm2Lp7Rt4Vb9Nx" not in serialised and "xR4tY7uP2aS9dF6g" not in serialised)
check("evidence is a fingerprint", all(
    finding.get("evidence", "").startswith("sha256:") or not finding.get("evidence")
    for finding in report.get("findings", [])
))

print("== boundary contract ==")
status, body = request("/scan", {"path": "/etc"})
check("path outside roots forbidden", status == 403, f"{status} {body}")
status, _ = request("/scan", {"path": "/scan", "fail_on": "severe"})
check("invalid threshold rejected", status == 400, str(status))
status, _ = request("/nope")
check("unknown route is 404", status == 404, str(status))

print("== CLI contract ==")
env = dict(os.environ, PYTHONPATH=os.path.join(root, "src"))
policy = os.path.join(root, "configs", "policies", "compliance.toml")

validate = subprocess.run(
    [sys.executable, "-m", "scanner", "validate-policy", policy],
    env=env, capture_output=True, text=True,
)
check("validate-policy succeeds", validate.returncode == 0, validate.stderr.strip())

scan = subprocess.run(
    [sys.executable, "-m", "scanner", "scan", os.path.join(root, "configs", "samples")],
    env=env, capture_output=True, text=True,
)
check("CLI scan gates on findings", scan.returncode == 1, f"rc={scan.returncode}")
check("CLI output names a control", "CG-CI-007" in scan.stdout)

clean_dir = os.path.join(root, "configs", "schema")
clean = subprocess.run(
    [sys.executable, "-m", "scanner", "scan", clean_dir],
    env=env, capture_output=True, text=True,
)
check("CLI scan passes clean input", clean.returncode == 0, f"rc={clean.returncode}")

print("== SARIF contract ==")
import tempfile

with tempfile.TemporaryDirectory() as tmp:
    sarif_path = os.path.join(tmp, "report.sarif")
    sarif = subprocess.run(
        [sys.executable, "-m", "scanner", "scan", os.path.join(root, "configs", "samples"),
         "--format", "sarif", "--output", sarif_path],
        env=env, capture_output=True, text=True,
    )
    check("CLI emits SARIF and gates", sarif.returncode == 1, f"rc={sarif.returncode}")
    try:
        payload = json.loads(open(sarif_path, encoding="utf-8").read())
    except (OSError, json.JSONDecodeError):
        payload = {}
    check("SARIF version is 2.1.0", payload.get("version") == "2.1.0", str(payload.get("version")))
    results = payload.get("runs", [{}])[0].get("results", [])
    check("SARIF carries findings", len(results) >= 5, str(len(results)))
    check("SARIF is value-free", "Zk8Qm2Lp7Rt4Vb9Nx" not in json.dumps(payload))

print(f"\n{passed} passed, {len(failed)} failed")
if failed:
    print("failed: " + ", ".join(failed), file=sys.stderr)
    sys.exit(1)
PY
