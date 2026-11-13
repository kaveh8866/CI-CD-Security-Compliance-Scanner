# CI/CD Security & Compliance Scanner

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![PyYAML](https://img.shields.io/badge/deps-PyYAML%206.0.2-informational)
![Docker](https://img.shields.io/badge/Docker-read--only%20%2B%20cap__drop%20ALL-2496ED?logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/unit-74%20passing-brightgreen)
![Smoke](https://img.shields.io/badge/smoke-29%2F29%20passing-brightgreen)
![Stage](https://img.shields.io/badge/stage-7%20%C2%B7%20audited%20%26%20documented-blue)
![Security](https://img.shields.io/badge/zero--leak%20audit-passing-brightgreen)
![OpenTofu](https://img.shields.io/badge/IaC-OpenTofu%201.13%20validated-844FBA)

A containerized scanning engine that inspects CI/CD pipeline definitions, flags
known-vulnerable dependency pins, catches credentials committed to a repository,
and turns all of it into a compliance verdict a pipeline can gate on.

It is deliberately small: one service, one TOML policy, one JSON advisory
catalogue, about 1,200 lines of Python, and a report format that never contains
the secret it found.

**Stage 7 status:** security-audited and documentation-complete. The repository
contains no tracked secret, database or audit log; `.env`, `terraform.tfvars`,
state, reports and keys are ignored by 96 verified rules. The scanner passes 74
unit tests and 29 smoke assertions, was verified live on OCI trial credits, and
was then fully torn down — no live billable resource remains. This README covers
policy configuration, local scans, report interpretation, cloud portability and
cross-cloud cost, with a full audit transcript in `docs/stage-7-verification.txt`.

---

## 📋 Overview

| | |
| --- | --- |
| **Problem** | Pipeline definitions are code nobody reviews for privilege, and a leaked token in a workflow is a production incident waiting for a clone |
| **Approach** | Static analysis of workflow YAML, dependency manifests and file content, evaluated against a declarative policy that produces a pass/fail gate |
| **Coverage today** | GitHub Actions, GitLab CI, `requirements.txt`, `package.json`, credential signatures, policy evaluation |
| **Output** | Value-free JSON (CLI and HTTP), SARIF 2.1.0 for code scanning, per-control PASS/FAIL and severity counts |
| **Footprint** | 181 MB image, 19 MiB idle RSS, 128 MiB / 0.25 CPU cap, single container |

## ✨ Features

- **Pipeline SAST** for GitHub Actions and GitLab CI: tag-pinned actions,
  `pull_request_target` + untrusted checkout, expression injection, `curl | bash`,
  `write-all` tokens, mutable container images.
- **Secret detection without secret propagation**: signature rules plus
  entropy-gated assignment matching, with `sha256:<12 hex>` evidence instead of
  the value in every report and log.
- **Dependency risk**: unpinned requirements/npm specs and known-vulnerable
  versions from an offline advisory catalogue.
- **Declarative compliance**: ten controls in one TOML policy, wildcard rule
  mapping, per-control PASS/FAIL, configurable gate threshold.
- **CI-native output**: human table, value-free JSON, and SARIF 2.1.0 with stable
  fingerprints for code scanning; exit `1` at or above `fail_on`.
- **Hardened by construction**: read-only rootfs, `cap_drop: ALL`,
  `no-new-privileges`, non-root, 128 MiB / 0.25 CPU, read-only workspace mount.
- **Portable delivery**: one image, one Compose file, OpenTofu IaC with AWS and
  GCP mappings (OCI is the certified target).

### How a scan flows

```
[CI/CD Pipeline / PRs] --> (Webhook / Trigger) --> [Security & Compliance Scanner Engine] --> [Policy Evaluation & SAST / Secrets Check] --> (OCI Compute Instance)

       │                          │                              │                                    │
       │ pull_request             │ POST /scan                   │ walk trees, parse YAML,            │ systemd + Docker
       │ merge request            │ 64 KiB body, path allowlist  │ match advisories, evaluate policy  │ read-only rootfs
       ▼                          ▼                              ▼                                    ▼
  checkout pinned to SHA      /scan + /etc/scanner roots      findings + 10 controls           JSON / SARIF + exit code
                                                                                                        │
                                                                                                        ▼
                                                                                     [CI Gate: exit 1 at/above fail_on]
```

---

## 📚 Documentation

| Document | Audience | Contents |
| --- | --- | --- |
| [`AGENT_GUIDE.md`](AGENT_GUIDE.md) | AI coding agents (Cursor, Claude Code, Windsurf) | bootstrap, scan, report and audit-log inspection, policy work, tests, CI wiring, troubleshooting |
| [`MANUAL_PREREQS.md`](MANUAL_PREREQS.md) | human operator | OCI credentials, SSH keys, `.env`, policy choices, repository hooks, pre-deployment checklist, teardown |
| [`docker/README.md`](docker/README.md) | whoever runs the container | flag-by-flag hardening rationale |
| [`terraform/README.md`](terraform/README.md) | whoever provisions the host | resource graph, ingress contract, AWS/GCP porting tables |
| [`docs/stage-7-verification.txt`](docs/stage-7-verification.txt) | reviewer / auditor | zero-leak audit commands and results, documentation sign-off |

---

## 🚀 Quick start

Requirements: Docker 24+ with Compose v2 and a free loopback port `8300`.

```bash
cp -n .env.example .env
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps     # wait for (healthy)
curl -s http://127.0.0.1:8300/healthz
```

The stack mounts `configs/` read-only at `/scan`, so the bundled insecure
fixtures are scannable immediately:

```bash
curl -s -X POST http://127.0.0.1:8300/scan \
  -H 'Content-Type: application/json' \
  -d '{"path":"/scan"}' | python -m json.tool | head -40
```

### Run the scanner without Docker

The CLI needs Python 3.11+ and PyYAML (the only runtime dependency):

```bash
python -m pip install -r src/requirements.txt
PYTHONPATH=src python -m scanner scan configs/samples
# prints a table, exits 1 because the fixtures are insecure by design
```

Against a real checkout, with JSON output for a CI job:

```bash
# JSON for a CI job
PYTHONPATH=src python -m scanner scan /path/to/repo --format json --output report.json

# SARIF 2.1.0 for GitHub code scanning / GitLab SAST
PYTHONPATH=src python -m scanner scan /path/to/repo --format sarif --output report.sarif
```

Validate a policy edit before it reaches the pipeline:

```bash
PYTHONPATH=src python -m scanner validate-policy configs/policies/compliance.toml
```

---

## ☁️ Infrastructure (OpenTofu, OCI)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # gitignored: tenancy, CIDRs, public key
tofu init && tofu fmt -recursive -check && tofu validate && tofu plan
# Plan: 6 to add, 0 to change, 0 to destroy
```

| Resource | Purpose |
| --- | --- |
| `oci_core_vcn` `10.7.0.0/16` | isolated network, disjoint from every other CloudGuard project |
| `oci_core_internet_gateway` + route table | egress for OS updates and image pulls |
| `oci_core_security_list` | ingress **22** and **8300 only**, each from one operator CIDR |
| `oci_core_subnet` `10.7.1.0/24` | public subnet with the instance VNIC |
| `oci_core_instance` | requested `A1.Flex` 1 OCPU / 6 GB (ARM); deployed `E2.1.Micro` 1 OCPU / 1 GB in AD-3 because A1 capacity was unavailable — Ubuntu 24.04, 50 GB boot |

`scanner_allowed_cidr` is refused if set to `0.0.0.0/0` — in both the root and
the module variable definitions. There is no 80/443 rule: this host serves no web
UI. The zero-exposure path is an SSH tunnel with the container bound to loopback.

Outputs expose `instance_public_ip`, `instance_private_ip`, `scanner_url`,
`ingress_exposure` and copy-paste connection strings. Cloud-init installs Docker
and hardens the daemon and SSH; it deliberately carries **no credential** —
user-data is readable on the host.

**Deployed in Stage 5, destroyed in Stage 6.** Six resources existed at
`130.162.211.255`. A credential-free archive is copied to `~/scanner` (the
instance does not clone: the repository has never been pushed), the runtime
`.env` is written on the host, and the stack starts with:

```bash
ssh ubuntu@<instance_public_ip>
cd ~/scanner
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps   # cg-scanner (healthy)
```

The container binds `0.0.0.0:8300` **inside the host** so the security-list rule
can reach it; the list admits only the operator `/32`, and
`scanner_allowed_cidr` refuses `0.0.0.0/0`. The zero-exposure path (SSH tunnel
with the loopback default) still works and needs no cloud change. State and
`terraform.tfvars` remain local and gitignored.

Tear down the same way; `plan -destroy` reports 6 to destroy, and the provider
check should return only `TERMINATED` records:

```bash
docker compose --env-file .env -f docker/docker-compose.yml down
ssh ubuntu@<ip> 'cd ~/scanner && docker compose --env-file .env -f docker/docker-compose.yml down'
cd terraform && tofu plan -destroy && tofu destroy -auto-approve && tofu state list
```

---

## 🌐 Cloud-Agnostic Portability

> The IaC uses OpenTofu and supports cloud deployments on **AWS, GCP and OCI**.
> However, **final production verification and testing certification were
> performed strictly on Oracle Cloud Infrastructure (OCI) using trial credits.**
> AWS and GCP are documented ports, not certified targets.

The module boundary is provider-neutral (`network` → `subnet_id`; `compute` →
`public_ip`), and the application contract is identical everywhere: the same
image, `/scan` mounted read-only, the policy at `/etc/scanner`, health on 8300,
and a gate expressed as a process exit code.

| Concept | OCI (certified) | AWS | GCP |
| --- | --- | --- | --- |
| Network | VCN `10.7.0.0/16` | VPC | VPC network |
| Subnet | public subnet `10.7.1.0/24` | public subnet + route table | subnetwork + routes |
| Egress gateway | internet gateway + route table | internet gateway | implicit default route |
| Firewall | security list (22/8300, one `/32`) | security group | VPC firewall rules |
| Compute | `oci_core_instance` | `aws_instance` | `google_compute_instance` |
| Bootstrapping | `metadata.user_data` (cloud-init) | `user_data` | `metadata_startup_script` |
| Admin access | SSH key in metadata | key pair / SSM | OS Login / IAP |

### Migration tips

- **AWS:** map the security list to a security group with the same two ingress
  rules (22 and 8300 from one operator CIDR) and keep the 50 GB gp3 boot volume.
  Use `t3.micro` (2 burst vCPU / 1 GiB), `user_data` for cloud-init, and prefer
  SSM Session Manager over a public SSH rule. The container and policy files need
  no change; only provider resources and the `subnet_id`/`public_ip` wiring move.
- **GCP:** create a custom VPC with a `10.7.1.0/24` subnetwork and two ingress
  firewall rules, then an `e2-micro` with `metadata_startup_script` and an
  `access_config` block for the ephemeral public IP. Use OS Login instead of
  metadata SSH keys. Keep the instance's service account minimal — the scanner
  needs no Google API access.
- **Any target:** keep the container's read-only mounts, 128 MiB cap and
  unauthenticated-API-isolation rule (one CIDR, no `0.0.0.0/0`), and re-run the
  live drill (`/healthz`, `/scan`, gate, logs) before claiming certification.
  Recompute the cost table below if you leave the free tier.

---

## 🔌 API

| Route | Method | Purpose |
| --- | --- | --- |
| `/healthz` | GET | Liveness, version, policy name and control count |
| `/policy` | GET | Effective gate threshold, ignore globs and controls |
| `/scan` | POST | `{"path": "/scan", "fail_on": "high"}` → full report |

The API is loopback-only by default, accepts no uploads, caps bodies at 64 KiB,
and refuses any target outside `SCANNER_ALLOWED_ROOTS` (default
`/scan:/etc/scanner`). It writes no files: reports go to the response and a
structured stdout log line.

```bash
curl -s -X POST http://127.0.0.1:8300/scan \
  -H 'Content-Type: application/json' \
  -d '{"path":"/scan","fail_on":"critical"}'
```

---

## 🧭 Policy model

`configs/policies/compliance.toml` carries the gate and ten controls:

```toml
[policy]
name = "CloudGuard CI/CD Baseline"
version = "1.0.0"
fail_on = "high"

[[controls]]
id = "CG-CI-001"
title = "Third-party actions are pinned to commit SHAs"
severity = "high"
rules = ["CG-PIPE-001"]
```

A control **fails** when any finding matches one of its rule patterns
(`CG-SEC-*` is a wildcard). Every finding is reported even when no control
covers it, so an incomplete policy never hides evidence. `ignore` accepts
repo-relative globs such as `tests/fixtures/**`.

### Configuring compliance policies

1. Edit `configs/policies/compliance.toml`: set `fail_on` (`info` … `critical`),
   add or retitle controls, and map each control to one or more rule IDs.
2. Add ignore globs for generated or vendored trees; keep `tests/fixtures/**`
   ignored in real repositories so sample secrets never gate a build.
3. Validate before use — malformed TOML, unknown severities or a control with no
   rules are rejected with a non-zero exit:

```bash
PYTHONPATH=src python -m scanner validate-policy configs/policies/compliance.toml
```

4. Point the runtime at the file with `SCANNER_POLICY_FILE` (default
   `/etc/scanner/policies/compliance.toml`), or override the threshold per
   request/job with `fail_on` / `--fail-on`.

### Running a local pipeline scan

```bash
# whole repository, human-readable table, gate at the policy default
PYTHONPATH=src python -m scanner scan /path/to/repo

# in CI: JSON plus an explicit threshold
PYTHONPATH=src python -m scanner scan . --format json --output report.json --fail-on high

# container, read-only workspace, same policy
MSYS_NO_PATHCONV=1 docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges -v "$PWD:/scan:ro" \
  cloudguard/scanner:local scan /scan --fail-on high
```

The process exit code is the gate: `0` below the threshold, `1` at or above it,
`2` for usage/policy errors. A CI job should fail on anything non-zero.

### Reading a vulnerability report

```json
{
  "files_scanned": 10,
  "summary": {"critical": 4, "high": 9, "medium": 7, "low": 1, "info": 0},
  "controls_failed": 9,
  "exit_code": 1,
  "findings": [
    {
      "rule_id": "CG-VULN-001",
      "category": "dependency",
      "severity": "critical",
      "path": "samples/requirements-insecure.txt",
      "line": 1,
      "message": "requests 2.28.0 is below the fixed 2.31.0",
      "evidence": "sha256:4f1c9a2b7d30"
    }
  ]
}
```

- `summary` and `controls_failed` answer "can this merge?" without reading every
  finding; `exit_code` mirrors the CLI gate.
- Each finding carries `rule_id`, `severity`, file/line, a message that never
  includes the matched value, and a `sha256` fingerprint for deduplication.
- `category` separates `secret`, `pipeline` and `dependency`; a control may span
  several rules, and `CG-CI-007` covers every `CG-SEC-*` finding at `critical`.
- SARIF consumers should map `error` → critical/high, `warning` → medium and
  `note` → low/info; `partialFingerprints["cloudguardFinding/v1"]` keeps alerts
  stable across re-scans.

### Rule catalogue

| Rule | Severity | Detects |
| --- | --- | --- |
| `CG-PIPE-001` | high | Action referenced by tag or branch instead of a commit SHA |
| `CG-PIPE-002` | critical | `pull_request_target` combined with untrusted checkout |
| `CG-PIPE-003` | high | `${{ secrets.* }}` expanded into a shell command that prints |
| `CG-PIPE-004` | critical | `${{ github.event.* }}` interpolated into `run:` (script injection) |
| `CG-PIPE-005` | medium | `curl … \| bash` in a workflow |
| `CG-PIPE-006` | medium | `permissions: write-all` |
| `CG-PIPE-007` | low | Trigger outside the reviewed baseline |
| `CG-PIPE-010` | medium | Workflow is not valid YAML |
| `CG-PIPE-020` | medium | GitLab image without a digest (`:latest` or no tag) |
| `CG-PIPE-021` | medium | `curl … \| sh` in GitLab CI |
| `CG-PIPE-022` | high | `CI_JOB_TOKEN` echoed to job logs |
| `CG-PIPE-023` | medium | Commit metadata interpolated into a script |
| `CG-SEC-001…007` | critical / high | AWS key, GitHub/GitLab/Slack/Stripe/Google tokens, PEM block |
| `CG-SEC-010` | high | High-entropy literal assigned to a credential-like name |
| `CG-DEP-001` | medium | Unpinned Python requirement |
| `CG-DEP-002` | medium | Unparseable `package.json` |
| `CG-DEP-003` | medium | Unpinned npm dependency (`*`, `latest`, range-only) |
| `CG-VULN-001…005` | high / critical | Known-vulnerable versions from the offline catalogue |

**Zero-leak by design:** findings carry `sha256:<12 hex>` fingerprints, not
values. Entropy-gated assignment detection skips placeholders, `$VAR` and
`${{ secrets.* }}` references, so a repository full of documentation does not
produce noise.

---

## 📁 Layout

```
.
├── Dockerfile                     runtime image, non-root uid 10001
├── docker/
│   ├── docker-compose.yml         hardening, limits, log rotation
│   └── README.md                  flag-by-flag rationale
├── src/
│   ├── requirements.txt           PyYAML only
│   └── scanner/
│       ├── models.py              value-free finding/report model
│       ├── secrets.py             signature + entropy detection
│       ├── pipelines.py           GitHub Actions / GitLab CI analysis
│       ├── deps.py                manifest parsing + advisory matching
│       ├── compliance.py          TOML policy + control evaluation
│       ├── engine.py              walker, dispatch, aggregation
│       ├── api.py                 /healthz, /policy, /scan
│       ├── cli.py                 scan, validate-policy
│       └── __main__.py            serve by default, CLI with args
├── configs/
│   ├── policies/compliance.toml   baseline policy
│   ├── advisories/                offline advisory catalogue
│   ├── samples/                   intentionally insecure fixtures
│   └── schema/                    policy and report JSON Schemas
├── terraform/                     OCI VCN + subnet + security list + free-tier host, modules/
├── tests/                         74 unit tests + smoke.sh (29 assertions)
└── docs/                          stage evidence transcripts
```

---

## 🔒 Runtime posture

Verified against the running container, not just declared:

| Control | Observed |
| --- | --- |
| Root filesystem | `ReadonlyRootfs=true`; writes to `/app` fail with `Read-only file system` |
| Capabilities | `CapDrop=["ALL"]` — none retained |
| Privilege escalation | `no-new-privileges:true` |
| User | `10001:10001`, no login shell, no home directory |
| Process ceiling | `PidsLimit=128` |
| Memory / CPU | 128 MiB / 0.25 CPU; idle usage 19.19 MiB, single scan peak 24.5 MiB |
| Logs | `json-file`, `max-size=5m`, `max-file=2` |
| Workspace mount | `/scan` and `/etc/scanner` read-only |

Scanning the 10-file fixture set: **21 findings** (4 critical, 9 high, 7 medium,
1 low), **9 of 10 controls failing**, **114.6 ms**, in 24.5 MiB of memory.

---

## ✅ Verification (Stages 1–7)

| Check | Result |
| --- | --- |
| Unit suite | **74/74** passing (`PYTHONPATH=src python -m unittest discover -s tests`) |
| Smoke contract | **29/29** assertions against the running container |
| SARIF export | 2.1.0 log, 19 rules, 21 results, `error`/`warning`/`note` levels, sha256 fingerprints |
| Gate behaviour | exit `1` at `high` and `critical`; exit `0` on a clean tree |
| Audit trail | structured scan events on stdout, retained across a container restart, zero credential values |
| Policy validation | `validate-policy` accepts the baseline, rejects five malformed variants |
| Path boundary | `/scan` allowed; project root, `/etc` and traversal attempts → `403` |
| Redaction | No fixture credential value appears in any report or container log |
| Container posture | read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, non-root, limits as declared — re-read from the live host with `docker inspect` |
| Live health (OCI) | `http://130.162.211.255:8300/healthz` → `ok`, 10 controls (Stage 5; host destroyed in Stage 6) |
| Live scan parity | 21 findings (4/9/7/1), 2 secrets, 12 pipeline, 7 dependency, 9/10 controls failing — identical to local |
| Live gate | remote CLI `--fail-on high` → exit `1`; clean schema tree → exit `0` |
| Live SARIF | 2.1.0, 19 rules, 21 results, 13 `error` / 7 `warning` / 1 `note` |
| Live audit trail | structured scan events, zero credential values, retained across restart |
| IaC formatting | `tofu fmt -recursive -check` clean |
| IaC validation | `tofu validate` → `Success! The configuration is valid.` |
| OCI plan | **6 to add, 0 to change, 0 to destroy** against the real tenancy (nothing applied) |
| Documentation | `AGENT_GUIDE.md` and `MANUAL_PREREQS.md` present, fences balanced, every referenced path exists |
| Zero-leak audit | 0 tracked secrets, databases or logs; 96 ignore rules active; 0 sanitizer exposures |

The live rows were measured in Stage 5; the host was destroyed in Stage 6, so they
no longer reproduce against a running endpoint. Teardown evidence (stacks down,
6 destroyed, provider check) is in `docs/stage-6-verification.txt`.

Reproduce the local checks:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
BASE_URL=http://127.0.0.1:8300 bash tests/smoke.sh
```

Transcript: `docs/stage-1-verification.txt` (local), `docs/stage-5-verification.txt`
(live), `docs/stage-6-verification.txt` (teardown), `docs/stage-7-verification.txt`
(audit and documentation sign-off).

---

## 💰 Cross-Cloud Cost & Benchmark Estimation

Basis: the tested footprint is **1 vCPU (capped at 0.25), 1 GiB RAM, 50 GB disk
and negligible egress** (a scan response is ~11 KB JSON / ~34 KB SARIF). Prices
are public on-demand list prices for Linux, November 2026, 730 h/month, excluding
tax, backups and support; free-tier allowances are applied where stated.

| Cloud / entitlement | Compute | Block storage (50 GB) | Egress (100 GB/mo) | Estimated month |
| --- | --- | --- | --- | --- |
| **OCI Always Free** — deployed shape | `VM.Standard.E2.1.Micro` (1 OCPU / 1 GB) — **$0** | included in 200 GB block volume — **$0** | included in 10 TB/mo — **$0** | **$0** |
| **OCI trial credits** (beyond free) | billed to trial credits | billed to trial credits | billed to trial credits | **$0 cash** |
| **AWS** `eu-central-1` | `t3.micro` 2 burst vCPU / 1 GiB — $0.012/h ≈ **$8.76** | gp3 $0.0952/GB-mo ≈ **$4.76** | first 100 GB free — **$0** (1 TB → ≈ $83.16) | **≈ $13.52** (1 TB: ≈ $96.68) |
| **GCP** `us-central1` | `e2-micro` 2 shared vCPU / 1 GiB — $0.008376/h ≈ **$6.12** (free-tier eligible) | pd-standard $0.04/GB-mo ≈ **$2.00** (30 GB free) | $0.12/GB ≈ **$12.00** | **≈ $20.12** on-demand; **≈ $12.68** with free-tier compute |

Why OCI is the certified target: the free tier covers the entire tested
footprint, and the trial credits absorbed the Stage 5 verification. AWS and GCP
can run the same container but cost more once egress is billed — GCP's $0.12/GB
is the largest single line item at this size.

| Benchmark (measured) | Result |
| --- | --- |
| Image size | 181 MB |
| Idle RSS | 19.19 MiB |
| Peak RSS during scan | 24.5 MiB |
| Scan time, 10 files / 21 findings | 54 ms on the OCI micro, 114.6 ms locally |
| CPU / memory cap | 0.25 vCPU / 128 MiB (fits the smallest free shape) |
| Egress per scan | ~11 KB JSON, ~34 KB SARIF |

---

## 🔐 Zero-Leak Security Audit

Audited 2026-11-13 against the full working tree (66 tracked files, 67 paths scanned) and the Git index:

| Check | Result |
| --- | --- |
| Tracked databases / SQLite / audit logs | **0** (`*.db`, `*.sqlite*`, `*.log`, `audit.log` ignored) |
| Tracked private keys / certificates | **0** (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_*` ignored) |
| Tracked runtime env files | **0** — only `.env.example` and the intentionally leaky fixture `samples/leaky.env.example` |
| Tracked Terraform state / variables | **0** — `*.tfstate*`, `*.tfvars` ignored; `terraform.tfvars.example` tracked |
| Ignore rules verified with `git check-ignore` | `.env`, `.env.local`, `terraform.tfvars`, `terraform.tfstate`, `reports/`, `data/vault.db`, `logs/`, `key.pem` → all ignored |
| Local runtime `.env` | present on disk, ignored, never staged |
| Report contents | findings carry `sha256:<12 hex>` evidence; fixture credential values appear in no report or log |
| CloudGuard sanitizer | 67 files scanned, 0 exposed findings, 1 expected block |

Commands and raw output: `docs/stage-7-verification.txt`.

---

## ⚠️ Honest limits

- **Static analysis, not execution.** A workflow that builds its own scanner
  evasion is out of scope; the rules catch known-bad constructs, not intent.
- **The advisory catalogue is offline and small** (5 entries, pypi + npm). It is
  a baseline, not a substitute for OSV, Dependabot or Trivy.
- **Range specs are compared by their declared lower bound.** `^4.17.15` is
  reported because a fresh install may resolve below the fix; a lockfile at
  `4.17.21` is not consulted yet.
- **The API has no authentication.** It is loopback-only and intended to sit
  behind an SSH tunnel or private network; do not publish port 8300.
- **There is no live host right now.** Stage 5 was verified and then torn down;
  redeploying repeats the capacity risk — A1.Flex was unavailable in all three
  ADs and the AMD free-tier micro was the fallback.
- **The deployed API had no authentication.** Exposure was controlled only by the
  OCI security list (one operator `/32` on 8300), not by the application. Any
  redeployment must keep that narrow rule; `scanner_allowed_cidr` refuses
  `0.0.0.0/0`.
- **That deployment was a single host with no TLS, no load balancer and no
  backups** — a trial-credit verification target, not a production topology.
  Zero-resource was verified through the OCI API, not an invoice read.
- **Python 3.11+ is required** (`tomllib`); the image ships 3.12.

---

## 🗺️ Roadmap

| Stage | Scope | Status |
| --- | --- | --- |
| 1 | Scaffold, engine, policy, hardened container, verification | ✅ complete |
| 2 | OpenTofu OCI network + compute, validated plan (6 to add) | ✅ complete |
| 3 | Agent guide and operator prerequisites | ✅ complete |
| 4 | Local stack, policy loading, JSON/SARIF reports, gate and audit-log verification | ✅ complete |
| 5 | Cloud deployment on OCI trial credits, live scan and gate verification | ✅ complete |
| 6 | Teardown, zero-resource verification, state cleanup | ✅ complete |
| 7 | Security audit, README hardening, cross-cloud cost model | ✅ complete |
| 8 | Release tag, public repository, CloudGuard certification | ⬜ |
