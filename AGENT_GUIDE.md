# Agent Guide — CI/CD Security & Compliance Scanner

An execution playbook for AI coding agents (Cursor, Claude Code, Windsurf, Codex)
working on this repository. It assumes no prior context: every command is the
one that was actually run to verify the stage it belongs to, and every expected
output is the output that command produced.

**Scope:** build, run, scan, test and inspect the scanner. Cloud provisioning is
documented in `terraform/` and deployed only in a dedicated deployment stage.

---

## 0. Non-negotiables

These hold for every action, including exploratory ones.

1. **Never print, log or commit a credential.** Reports already redact values as
   `sha256:<12 hex>`; do not "helpfully" print a raw match while debugging.
2. **Never add a real secret to a fixture, test, doc or `.env.example`.** The
   sample credentials in `configs/samples/leaky.env.example` are fake by design.
3. **Keep the Git boundary intact.** `.env`, `terraform.tfvars`, state, `*.pem`,
   `*.db` and scan reports are gitignored. Verify with `git check-ignore -v`,
   never by eye.
4. **Do not authenticate the scanner API to the internet.** It has no auth by
   design and is meant for loopback or an SSH tunnel.
5. **`tofu apply` and `tofu destroy` are deployment-stage actions.** Do not run
   them while working on code or docs; they need an explicit operator request.
6. **Certification scope is OCI-only.** The container and IaC are cloud-agnostic
   (AWS/GCP mappings are documented), but final production verification and
   testing certification are performed strictly on Oracle Cloud Infrastructure
   using trial credits. AWS and GCP are ports, not certified targets. As of
   Stage 3 no cloud deployment has run yet, so no live target is claimed.

---

## 1. Repository map

| Path | What it is |
| --- | --- |
| `src/scanner/models.py` | value-free `Finding`/`Report`/`ControlResult` dataclasses |
| `src/scanner/secrets.py` | signature rules + entropy-gated assignment detection |
| `src/scanner/pipelines.py` | GitHub Actions and GitLab CI analysis (PyYAML) |
| `src/scanner/deps.py` | `requirements.txt` / `package.json` + advisory catalogue |
| `src/scanner/compliance.py` | TOML policy parsing, control evaluation |
| `src/scanner/engine.py` | directory walk, per-file dispatch, aggregation |
| `src/scanner/api.py` | `/healthz`, `/policy`, `POST /scan` |
| `src/scanner/cli.py` | `scan`, `validate-policy` |
| `configs/policies/compliance.toml` | baseline policy: 10 controls, `fail_on = high` |
| `configs/advisories/advisories.json` | offline advisory catalogue (pypi + npm) |
| `configs/samples/` | intentionally insecure fixtures — safe to scan, never fix them |
| `tests/` | 74 unit tests and a 29-assertion smoke contract |
| `terraform/` | OCI network + compute modules; validated, not applied |
| `docker/docker-compose.yml` | hardened runtime composition (service `scanner`) |

Ports: **8300** (API, loopback by default). Container: `cg-scanner`.
Image: `cloudguard/scanner:local`. Runtime: Python 3.11+ (image ships 3.12),
PyYAML 6.0.2 — the only dependency.

---

## 2. Prerequisites check (run before anything else)

```bash
docker --version                 # 24+
docker compose version           # v2+
python --version                 # 3.11+ (tomllib); 3.12 inside the image
python -c 'import yaml; print(yaml.__version__)'   # only needed for host CLI
```

On Windows, use Git Bash and prefix Docker mounts with
`MSYS_NO_PATHCONV=1` if a bind-mount path is rewritten. On Linux/macOS the
commands below work unchanged.

OpenTofu is **not** on `PATH` in this workspace; use the project binary:

```bash
TOFU=/c/Users/Kaveh/Desktop/CloudGuard/.cloudguard/tools/tofu/tofu.exe
"$TOFU" version     # OpenTofu v1.13.9
```

---

## 3. Fast path — scanner running in under two minutes

```bash
cd projects/07-cicd-security-compliance-scanner

cp -n .env.example .env          # placeholders; .env is gitignored
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps    # wait for (healthy)
curl -s http://127.0.0.1:8300/healthz
```

Expected `healthz` body:

```json
{"status":"ok","service":"cicd-security-scanner","version":"0.1.0",
 "policy":"CloudGuard CI/CD Baseline","policy_version":"1.0.0","controls":10,
 "roots":["/scan","/etc/scanner"]}
```

If `curl` fails, read the first useful error instead of retrying:

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs --tail 50 scanner
```

---

## 4. Run a scan

The compose stack mounts `configs/` at `/scan` read-only, which is why the
fixtures are immediately scannable.

### 4.1 Over HTTP

```bash
curl -s -X POST http://127.0.0.1:8300/scan \
  -H 'Content-Type: application/json' \
  -d '{"path":"/scan"}'
```

Add `"fail_on":"critical"` to tighten the gate for one request. The response is
the full report plus `exit_code` (`0` pass, `1` gate failure).

### 4.2 Over the CLI, without Docker

```bash
python -m pip install -r src/requirements.txt
PYTHONPATH=src python -m scanner scan configs/samples
PYTHONPATH=src python -m scanner scan configs/samples --json > /tmp/report.json
PYTHONPATH=src python -m scanner scan configs/schema        # clean tree → exit 0
```

Exit codes: `0` no finding at/above the threshold, `1` policy failure,
`2` bad path or invalid policy.

### 4.3 Inside the container

```bash
docker exec cg-scanner python -m scanner scan /scan
docker exec cg-scanner python -m scanner validate-policy /etc/scanner/policies/compliance.toml
```

### 4.4 Structured output: JSON and SARIF

```bash
# JSON report on disk (the command prints a one-line summary and exits 1)
PYTHONPATH=src python -m scanner scan configs/samples --format json --output /tmp/report.json

# SARIF 2.1.0 for GitHub code scanning / GitLab SAST
PYTHONPATH=src python -m scanner scan configs/samples --format sarif --output /tmp/report.sarif

docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/configs:/scan:ro" -v "$PWD/docs/stage-4-evidence:/reports" \
  cloudguard/scanner:local scan /scan --format sarif --output /reports/report.sarif
```

SARIF mapping: `critical`/`high` → `error`, `medium` → `warning`, `low`/`info` →
`note`. Each result carries a physical location, a rule index into the driver's
rule list, and `partialFingerprints["cloudguardFinding/v1"]` as a `sha256:` digest,
so alerts survive re-scans without carrying a credential.

### 4.5 Expected result for the bundled fixtures

| Metric | Value |
| --- | --- |
| Files scanned | 10 |
| Findings | 21 (4 critical, 9 high, 7 medium, 1 low) |
| Controls failing | 9 of 10 |
| Latency | ~115 ms |
| Peak RSS | ~25 MiB |
| Exit code | 1 |

If those numbers move, the fixtures or rules changed — investigate before
updating any doc that quotes them.

---

## 5. Read the report

Findings are sorted by severity, then file, then line. Each one has:

| Field | Meaning |
| --- | --- |
| `rule_id` | stable rule identifier (`CG-PIPE-001`, `CG-SEC-010`, `CG-VULN-001`) |
| `severity` | `info` → `low` → `medium` → `high` → `critical` |
| `category` | `secret`, `pipeline` or `dependency` |
| `file`, `line` | location in the scanned tree |
| `message` | what is wrong, with any matched value replaced by a fingerprint |
| `remediation` | the concrete fix |
| `evidence` | `sha256:<12 hex>` fingerprint — **never the credential** |

Controls mirror the policy and show `pass`/`fail` plus the rule ids that matched.

Useful queries with the standard library (no `jq` dependency):

```bash
# findings at or above high
curl -s -X POST http://127.0.0.1:8300/scan -H 'Content-Type: application/json' \
  -d '{"path":"/scan"}' \
| python -c 'import json,sys; r=json.load(sys.stdin); [print(f["severity"], f["rule_id"], f["file"], f["line"]) for f in r["findings"] if f["severity"] in ("high","critical")]'

# failed controls only
curl -s -X POST http://127.0.0.1:8300/scan -H 'Content-Type: application/json' \
  -d '{"path":"/scan"}' \
| python -c 'import json,sys; r=json.load(sys.stdin); [print(c["id"], c["title"], c["matched_findings"]) for c in r["controls"] if c["status"]=="fail"]'

# severity summary
curl -s -X POST http://127.0.0.1:8300/scan -H 'Content-Type: application/json' \
  -d '{"path":"/scan"}' | python -c 'import json,sys; print(json.load(sys.stdin)["summary"])'
```

Scan a real checkout by adding a read-only mount and keeping the allowlist
honest. Do **not** widen `SCANNER_ALLOWED_ROOTS` to `/`:

```bash
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/configs:/etc/scanner:ro" \
  -v "/absolute/path/to/repo:/scan:ro" \
  -e SCANNER_ALLOWED_ROOTS=/scan:/etc/scanner \
  cloudguard/scanner:local scan /scan
```

---

## 6. Audit logs

There is no separate audit file by design: the report *is* the record, and the
service writes one structured JSON line per request to stdout. The container
logging driver rotates it (`json-file`, 5 MB × 2).

```bash
# live stream
docker compose --env-file .env -f docker/docker-compose.yml logs -f scanner

# scan events from the last 30 minutes (no findings, no values)
docker logs --since 30m cg-scanner 2>&1 | grep '"event":"scan"'

# every HTTP request line
docker logs --since 1h cg-scanner 2>&1 | grep '"event":"http"' | tail -20

# prove no credential value leaked into the log
docker logs cg-scanner 2>&1 | grep -c 'Zk8Qm2Lp7Rt4Vb9Nx\|xR4tY7uP2aS9dF6g'   # must print 0
```

A scan log line looks like:

```json
{"event":"scan","target":"/scan","files":10,"findings":20,
 "critical":4,"high":8,"controls_failed":9}
```

The target path is logged; file contents, messages and matched values are not.
If you need durable history, ship stdout to your log stack — do not add a file
writer to the container, which runs with a read-only root filesystem.

---

## 7. Policy work

```bash
# validate before scanning
PYTHONPATH=src python -m scanner validate-policy configs/policies/compliance.toml

# after editing, always re-validate and re-scan
PYTHONPATH=src python -m scanner validate-policy configs/policies/compliance.toml
PYTHONPATH=src python -m scanner scan configs/samples --json > /tmp/after.json
```

Rules for edits:

- `CG-CI-*` ids are stable API; add new controls, do not renumber.
- Wildcards are allowed in `rules` (`CG-SEC-*`), exact ids are preferred.
- `fail_on` moves the gate, it never hides findings: everything is still reported.
- `ignore` takes repo-relative POSIX globs; do not ignore `configs/samples/**` in
  the baseline policy — those fixtures are the demo.
- A control with a typo'd rule id silently passes. After adding a control, run a
  scan that should fail it and confirm the status flips.

Adding a dependency advisory (no code change):

```json
{
  "id": "CVE-0000-00000",
  "rule_id": "CG-VULN-006",
  "package": "example-package",
  "ecosystem": "pypi",
  "below": "2.0.0",
  "severity": "high",
  "title": "Short title",
  "summary": "What the flaw allows.",
  "remediation": "Upgrade to 2.0.0 or later."
}
```

Then add `CG-VULN-006` coverage to control `CG-CI-009` only if the wildcard
`CG-VULN-*` does not already cover it — it does today.

---

## 8. Verification suite

Run both before any commit that changes engine behaviour:

```bash
# 74 unit tests
PYTHONPATH=src python -m unittest discover -s tests

# 29 assertions against the running container
BASE_URL=http://127.0.0.1:8300 bash tests/smoke.sh
```

The smoke suite selects a Python 3.11+ interpreter itself; if none is found it
exits `2` rather than running the CLI tests on an interpreter without `tomllib`.

Stage 2 infrastructure checks (no cloud resources created):

```bash
cd terraform
"$TOFU" fmt -recursive -check        # silent on success
"$TOFU" validate                      # Success! The configuration is valid.
"$TOFU" plan                          # Plan: 6 to add, 0 to change, 0 to destroy
```

---

## 9. CI integration (how this scanner is meant to be used)

GitHub Actions — the scanner runs as a container and reads the checkout
read-only. Pin the checkout action to a commit SHA, not a tag (rule
`CG-PIPE-001` applies to this workflow too):

```yaml
name: security-scan
on: pull_request

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<40-character-commit-sha>
      - run: docker build -t cloudguard/scanner:ci .
      - run: |
          docker run --rm --read-only --cap-drop ALL \
            --security-opt no-new-privileges \
            -v "$PWD:/scan:ro" \
            cloudguard/scanner:ci scan /scan --fail-on high
```

GitLab CI:

```yaml
security-scan:
  stage: test
  image: docker:27
  services: [docker:27-dind]
  script:
    - docker build -t cloudguard/scanner:ci .
    - docker run --rm -v "$CI_PROJECT_DIR:/scan:ro" cloudguard/scanner:ci scan /scan
```

The job fails on a finding at/above the threshold, so the gate is the exit code,
not log parsing.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError: tomllib` | interpreter is Python 3.10 or older | use Python 3.11+, or run the CLI inside the container |
| `ModuleNotFoundError: scanner` | `PYTHONPATH` unset | `PYTHONPATH=src python -m scanner …` |
| `403 path is outside the configured scan roots` | target not under `/scan` or `/etc/scanner` | mount the repo at `/scan` (read-only) rather than widening the allowlist |
| `400 body must be 1..65536 bytes` | empty or oversized request body | send `{"path":"/scan"}` with `Content-Type: application/json` |
| `healthz` connection refused | container starting or port collision | `docker compose … ps`, then logs; publish a different host port in `.env` |
| `docker exec` prints nothing after a heredoc | missing `-i` | `docker exec -i cg-scanner python -` |
| dependency findings missing | advisory file resolved empty | `docker exec cg-scanner python -c 'from scanner.deps import default_advisory_file; print(default_advisory_file())'` must point at an existing file |
| `tofu validate` reports provider type mismatch | a module lacks `required_providers` | declare `oracle/oci` in the module's `versions.tf` |
| A1 plan/applies fail with capacity | regional A1 exhaustion | pin another AD in tfvars; do not change the free-tier shape |

---

## 11. Change discipline

1. Change one concern at a time; keep the diff reviewable.
2. Run the unit suite (and the smoke suite when the API or container is touched).
3. Re-run `tofu fmt -recursive -check` and `tofu validate` for IaC changes.
4. Verify the Git boundary: `git status --porcelain`, `git check-ignore -v .env`.
5. Update `README.md` and the relevant `docs/stage-*-verification.txt` with what
   actually ran; label anything unrun as unrun.
6. Commit semantically, e.g.
   `fix(scanner): handle CRLF manifests without dropping pins`.
7. Never add an attribution footer unless the repository asks for one.

---

## 12. Certification scope (read before claiming anything)

- Container, CLI and IaC are **cloud-agnostic** with AWS and GCP mappings
  documented in `terraform/README.md`.
- **Final production verification and testing certification are performed
  strictly on Oracle Cloud Infrastructure (OCI) using trial credits.** AWS and
  GCP are supported ports, never certified targets.
- Stage 4 status: local stack verified (74 unit + 29 smoke assertions, JSON and
  SARIF output, gate enforcement, value-free audit logs) and OCI IaC validated
  (`tofu validate`, plan 6 to add). No cloud deployment has executed yet, so do
  not describe the stack as live, publicly reachable or cloud-verified until the
  deployment stage records that evidence.
- What is already proven: the engine's behaviour, the container's runtime
  posture, the Git boundary and the OCI resource graph. What is not: anything
  that requires a running host in the cloud.
