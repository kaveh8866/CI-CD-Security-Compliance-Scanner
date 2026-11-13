# CI/CD Security & Compliance Scanner

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![PyYAML](https://img.shields.io/badge/deps-PyYAML%206.0.2-informational)
![Docker](https://img.shields.io/badge/Docker-read--only%20%2B%20cap__drop%20ALL-2496ED?logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/unit-65%20passing-brightgreen)
![Smoke](https://img.shields.io/badge/smoke-25%2F25%20passing-brightgreen)
![Stage](https://img.shields.io/badge/stage-2%20%C2%B7%20IaC-blue)
![OpenTofu](https://img.shields.io/badge/IaC-OpenTofu%201.13%20validated-844FBA)

A containerized scanning engine that inspects CI/CD pipeline definitions, flags
known-vulnerable dependency pins, catches credentials committed to a repository,
and turns all of it into a compliance verdict a pipeline can gate on.

It is deliberately small: one service, one TOML policy, one JSON advisory
catalogue, about 1,200 lines of Python, and a report format that never contains
the secret it found.

**Stage 2 status:** the scanner runs locally, and the OCI infrastructure that
hosts it is written in OpenTofu: VCN, internet gateway, public subnet, a
22/8300-only security list and an Always Free A1.Flex instance. `tofu validate`
passes and a real plan reports **6 to add**; nothing has been applied yet, so no
cloud resource exists or bills today.

---

## 📋 Overview

| | |
| --- | --- |
| **Problem** | Pipeline definitions are code nobody reviews for privilege, and a leaked token in a workflow is a production incident waiting for a clone |
| **Approach** | Static analysis of workflow YAML, dependency manifests and file content, evaluated against a declarative policy that produces a pass/fail gate |
| **Coverage today** | GitHub Actions, GitLab CI, `requirements.txt`, `package.json`, credential signatures, policy evaluation |
| **Output** | Value-free JSON (CLI and HTTP) with per-control PASS/FAIL and severity counts |
| **Footprint** | 181 MB image, 19 MiB idle RSS, 128 MiB / 0.25 CPU cap, single container |

### How a scan flows

```
[ Repository / Pipeline Definitions ]
                │
        ( scan request: path or CI job )
                ▼
[ Scanner API :8300 / CLI ]
                │
                ▼
[ Secret · Pipeline · Dependency Analysis ]
                │
                ▼
[ Policy Engine : TOML controls ]
                │
        ( value-free JSON report )
                ▼
[ CI Gate : exit 1 at/above fail_on ] ──► [ Scorecard / Ticket / Webhook ]
```

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
PYTHONPATH=src python -m scanner scan /path/to/repo --json > report.json
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
| `oci_core_instance` `VM.Standard.A1.Flex` | 1 OCPU / 6 GB, Ubuntu 24.04 ARM, 50 GB boot |

`scanner_allowed_cidr` is refused if set to `0.0.0.0/0` — in both the root and
the module variable definitions. There is no 80/443 rule: this host serves no web
UI. The zero-exposure path is an SSH tunnel with the container bound to loopback.

Outputs expose `instance_public_ip`, `instance_private_ip`, `scanner_url`,
`ingress_exposure` and copy-paste connection strings. Cloud-init installs Docker
and hardens the daemon and SSH; it deliberately carries **no credential** —
user-data is readable on the host.

**Portability:** the module boundary (`network` → `subnet_id`; `compute` →
`public_ip`) is provider-neutral. AWS and GCP mappings are documented in
`terraform/README.md` and in comments: VCN→VPC/network, security list→security
group/firewall, `oci_core_instance`→`aws_instance`/`google_compute_instance`,
`user_data`→`user_data`/`metadata_startup_script`. OCI is the validated target;
AWS and GCP are ports, not tested here.

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
├── terraform/                     OCI VCN + subnet + security list + A1.Flex host, modules/
├── tests/                         65 unit tests + smoke.sh (25 assertions)
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

Scanning the 10-file fixture set: **20 findings** (4 critical, 8 high, 7 medium,
1 low), **9 of 10 controls failing**, **114.6 ms**, in 24.5 MiB of memory.

---

## ✅ Verification (Stage 1)

| Check | Result |
| --- | --- |
| Unit suite | **65/65** passing (`PYTHONPATH=src python -m unittest discover -s tests`) |
| Smoke contract | **25/25** assertions against the running container |
| Policy validation | `validate-policy` accepts the baseline, rejects five malformed variants |
| Path boundary | `/scan` allowed; project root, `/etc` and traversal attempts → `403` |
| Redaction | No fixture credential value appears in any report or container log |
| Container posture | read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, non-root, limits as declared |
| IaC formatting | `tofu fmt -recursive -check` clean |
| IaC validation | `tofu validate` → `Success! The configuration is valid.` |
| OCI plan | **6 to add, 0 to change, 0 to destroy** against the real tenancy (nothing applied) |

Reproduce:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
BASE_URL=http://127.0.0.1:8300 bash tests/smoke.sh
```

Transcript: `docs/stage-1-verification.txt`.

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
- **Not yet cloud-deployed.** The OCI plan is validated but not applied, so
  there is no live host or public IP to point at yet. Deployment is a later stage.
- **Python 3.11+ is required** (`tomllib`); the image ships 3.12.

---

## 🗺️ Roadmap

| Stage | Scope | Status |
| --- | --- | --- |
| 1 | Scaffold, engine, policy, hardened container, verification | ✅ complete |
| 2 | OpenTofu OCI network + compute, validated plan (6 to add) | ✅ complete |
| 3 | Agent guide, operator prerequisites, policy authoring playbook | ⬜ |
| 4 | Real-corpus benchmark, SARIF export, webhook notifications | ⬜ |
| 5 | Cloud deployment verification with trial credits | ⬜ |
| 6 | Teardown and zero-cost proof | ⬜ |
| 7 | Security audit, README hardening, cross-cloud cost model | ⬜ |
| 8 | Release tag, public repository, CloudGuard certification | ⬜ |
