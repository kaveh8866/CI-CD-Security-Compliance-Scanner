# Manual Prerequisites — CI/CD Security & Compliance Scanner

A checklist for the human operator before running any deployment script. Work
top to bottom: each phase ends with a verification command whose expected output
is stated, so "done" never means "looks done".

**What you end up with:** a scanner host on OCI, reachable over SSH, running the
hardened scanner container, with a compliance policy you chose and a CI hook that
fails a pipeline when the policy fails.

**Certification scope:** the container and IaC are cloud-agnostic (AWS and GCP
mappings are documented in `terraform/README.md`), but **final production
verification and testing certification are performed strictly on Oracle Cloud
Infrastructure (OCI) using trial credits**. AWS and GCP are ports, not certified
targets. As of Stage 3, no cloud deployment has executed; this document prepares
it, it does not claim it happened.

---

## Phase 0 — Decisions to make first

| Decision | Default | Why it matters |
| --- | --- | --- |
| Region | `eu-frankfurt-1` | A1 capacity differs per region and AD; changing it later means a new VCN |
| Compartment | your project compartment | scopes everything Terraform creates; never reuse an unrelated compartment |
| Scanner gate | `fail_on = high` | how strict CI becomes on day one |
| Public API access | **none** (SSH tunnel) | the API has no authentication; loopback + tunnel is the safe default |
| Notification channel | none yet | webhook fields exist in `.env`; wiring is a later stage |

Cost envelope: one `VM.Standard.A1.Flex` (1 OCPU / 6 GB), one 50 GB boot volume,
one VCN. Inside OCI Always Free / trial credits this is **$0**. Set a budget alert
in the OCI console before applying anything.

---

## Phase 1 — Workstation tools

| Tool | Minimum | Verify |
| --- | --- | --- |
| Git | 2.30 | `git --version` |
| Docker Engine or Desktop | 24 with Compose v2 | `docker compose version` |
| Python (host CLI only) | 3.11 (for `tomllib`) | `python --version` |
| OpenTofu | 1.6 (workspace ships 1.13.9) | `"$TOFU" version` |
| SSH client | any OpenSSH | `ssh -V` |
| curl | any | `curl --version` |

OpenTofu is not on `PATH` in this workspace:

```bash
TOFU=/c/Users/Kaveh/Desktop/CloudGuard/.cloudguard/tools/tofu/tofu.exe
"$TOFU" version     # OpenTofu v1.13.9
```

- [ ] All five commands succeed.

Windows notes: use Git Bash. Docker bind mounts may need
`MSYS_NO_PATHCONV=1`. Native Windows binaries do not share `/tmp` with Git Bash —
use project-relative paths for temporary files.

---

## Phase 2 — OCI account, credentials and SSH key

### 2.1 Account prerequisites

- [ ] OCI tenancy with Always Free eligibility (or active trial credits).
- [ ] A compartment for this project; note its OCID.
- [ ] A budget alert at a low threshold (e.g. $1) to catch accidental paid
      resources. The stack is free-tier by design, but alerts are cheap insurance.
- [ ] A1.Flex capacity available in your target AD. If AD-1 reports
      "Out of host capacity", pin AD-2/AD-3 with `availability_domain`.

### 2.2 API signing key (what Terraform authenticates with)

1. OCI Console → Identity & Security → Users → your user → **API keys** →
   Add API key → *Generate API key pair* (or paste your own public key).
2. Download the private key **once**; it cannot be downloaded again.
3. Store it outside every repository, e.g. `~/.oci/oci_api_key.pem`, mode `0600`.
4. Create `~/.oci/config`:

```ini
[DEFAULT]
user=ocid1.user.oc1..your-user-placeholder
fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99
tenancy=ocid1.tenancy.oc1..your-tenancy-placeholder
region=eu-frankfurt-1
key_file=~/.oci/oci_api_key.pem
```

- [ ] `ls -l ~/.oci/oci_api_key.pem` shows `600`.
- [ ] `~/.oci/config` is outside this repository (it must never be tracked).
- [ ] You know the tenancy OCID and compartment OCID (copy from the console).

Terraform reads this profile via `config_file_profile = "DEFAULT"`. Inline
`user_ocid` / `fingerprint` / `private_key_path` variables exist for CI runners
that materialise a key at runtime; prefer the profile locally.

### 2.3 SSH key pair

```bash
ssh-keygen -t ed25519 -C "cloudguard-scanner" -f ~/.ssh/id_ed25519
chmod 600 ~/.ssh/id_ed25519
```

- [ ] Public key exists: `cat ~/.ssh/id_ed25519.pub` (starts `ssh-ed25519 `).
- [ ] Private key stays in `~/.ssh`, never in `terraform/`.

Only the **public** key goes into `terraform.tfvars`. The variable validation
rejects anything that is not an OpenSSH public key, which is the guard against
pasting a private key by mistake.

### 2.4 Operator egress address

```bash
curl -s https://ifconfig.me
```

- [ ] Note the address; it becomes `ssh_allowed_cidr` and likely
      `scanner_allowed_cidr` as `/32`.
- [ ] If your ISP changes your address often, plan for a VPN or bastion instead
      of editing security lists weekly.

---

## Phase 3 — Clone and secure runtime configuration

```bash
git clone https://github.com/kaveh8866/CI-CD-Security-Compliance-Scanner.git
cd CI-CD-Security-Compliance-Scanner
cp -n .env.example .env
chmod 600 .env
```

Verify the boundary before you type anything into `.env`:

- [ ] `git check-ignore -v .env` prints the matching rule.
- [ ] `git status --porcelain` does not list `.env`.

`.env` keys you may touch:

| Key | Default | Guidance |
| --- | --- | --- |
| `SCANNER_BIND_ADDRESS` | `127.0.0.1` | keep loopback unless using an SSH tunnel from the host |
| `SCANNER_HOST_PORT` | `8300` | host-side port; keep 8300 so docs and smoke match |
| `SCANNER_FAIL_ON` | `high` | CI gate severity |
| `SCANNER_WORKSPACE` | `../configs` | host path mounted read-only at `/scan` |
| `SLACK_WEBHOOK_URL` | mock URL | treat as a secret; paste the real one only into `.env` on the host |
| `ALERT_EMAIL` | `security@example.com` | plain address, not a credential |

Rules:

- [ ] No credential, webhook URL or token is pasted into a tracked file.
- [ ] `.env` lives only on your machine and (later) on the host, mode `600`.
- [ ] The scanner API has **no authentication**. Do not expose 8300 publicly;
      use `ssh -L 8300:127.0.0.1:8300 ubuntu@<host>` or a private network.

Local sanity check before touching cloud:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps   # (healthy)
curl -s http://127.0.0.1:8300/healthz
```

- [ ] `healthz` returns `{"status":"ok", ... "controls":10 ...}`.

---

## Phase 4 — Configure the compliance policy

Policy file: `configs/policies/compliance.toml`. Read it before deploying; you
are about to gate pipelines on it.

| Control | What it enforces | Default severity |
| --- | --- | --- |
| `CG-CI-001` | actions pinned to commit SHAs | high |
| `CG-CI-002` | privileged workflow triggers constrained | high |
| `CG-CI-003` | secrets never printed / event injection blocked | high |
| `CG-CI-004` | no unverified remote scripts | medium |
| `CG-CI-005` | container images pinned by digest | medium |
| `CG-CI-006` | least-privilege workflow tokens | medium |
| `CG-CI-007` | no hard-coded credentials | critical |
| `CG-CI-008` | dependencies pinned | medium |
| `CG-CI-009` | no known-vulnerable versions | high |
| `CG-CI-010` | pipeline definitions parse | medium |

Decisions to record in the repository (and in your change ticket):

- [ ] `fail_on`: `high` is a reasonable day-one gate. `critical` lets high-severity
      supply-chain findings through; `medium` will fail most repositories.
- [ ] `ignore`: keep `tests/fixtures/**` and `data/**`. Do **not** ignore
      `configs/samples/**` — those fixtures are the demo and the smoke suite.
- [ ] Any control you disable: write down the reason. A silently disabled control
      is indistinguishable from a passing one.

Validate and test the gate:

```bash
PYTHONPATH=src python -m scanner validate-policy configs/policies/compliance.toml
PYTHONPATH=src python -m scanner scan configs/samples            # expect exit 1
PYTHONPATH=src python -m scanner scan configs/schema             # expect exit 0
PYTHONPATH=src python -m scanner scan configs/samples \
  --format sarif --output /tmp/report.sarif                      # SARIF 2.1.0 for CI
```

- [ ] `validate-policy` prints 10 controls.
- [ ] The sample scan exits `1`; the schema-only scan exits `0`.
- [ ] You have run at least one scan against a repository of your own
      (`--fail-on high`) and read the findings.

---

## Phase 5 — Define target repository hooks

Two supported integration modes. Pick one per repository; both fail the job on
the scanner's exit code.

### 5.1 Container mode (no Python on the runner)

GitHub Actions — `.github/workflows/security-scan.yml`:

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

GitLab CI — `.gitlab-ci.yml`:

```yaml
security-scan:
  stage: test
  image: docker:27
  services: [docker:27-dind]
  script:
    - docker build -t cloudguard/scanner:ci .
    - docker run --rm -v "$CI_PROJECT_DIR:/scan:ro" cloudguard/scanner:ci scan /scan
```

- [ ] Workflow file uses a commit SHA for `actions/checkout`, not a tag —
      otherwise the scanner (correctly) flags your own pipeline.
- [ ] The scanner sees the repository read-only; never mount a directory that
      contains production credentials.

### 5.2 Service mode (scanner host reachable)

```bash
curl -s -X POST http://127.0.0.1:8300/scan \
  -H 'Content-Type: application/json' \
  -d '{"path":"/scan"}' | python -m json.tool
```

For a remote host, tunnel first:

```bash
ssh -N -L 8300:127.0.0.1:8300 ubuntu@<host>
```

- [ ] `SCANNER_ALLOWED_ROOTS` contains only the checkout and policy paths.
- [ ] The CI runner reaches the API over the tunnel or a private network, not the
      public internet.

### 5.3 Optional pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: cloudguard-scanner
        name: CloudGuard CI/CD scanner
        entry: bash -c 'PYTHONPATH=src python -m scanner scan . --fail-on high'
        language: system
        pass_filenames: false
```

- [ ] Hook runs on a repository where Python 3.11+ and `PyYAML` are available, or
      skip it in favour of CI.

---

## Phase 6 — Prepare Terraform inputs

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Fill in, keeping every other value at its default:

| Variable | Where it comes from |
| --- | --- |
| `tenancy_ocid` | OCI console → tenancy details |
| `compartment_ocid` | OCI console → compartment details |
| `region` | your chosen region, e.g. `eu-frankfurt-1` |
| `config_file_profile` | `DEFAULT` (matches `~/.oci/config`) |
| `ssh_public_key` | contents of `~/.ssh/id_ed25519.pub` (public only) |
| `ssh_allowed_cidr` | your egress address `/32` from Phase 2.4 |
| `scanner_allowed_cidr` | your egress address `/32`, or a VPN range |
| `availability_domain` | pin AD-2 if A1 capacity is scarce in AD-1 |

Safety checks:

- [ ] `git check-ignore -v terraform/terraform.tfvars` matches.
- [ ] `scanner_allowed_cidr` is **not** `0.0.0.0/0` (validation refuses it).
- [ ] No private key, API key or `.env` value is in the file.
- [ ] `ssh_public_key` starts with `ssh-ed25519 ` or `ssh-rsa `.

Then:

```bash
"$TOFU" init
"$TOFU" fmt -recursive -check
"$TOFU" validate
"$TOFU" plan
```

- [ ] `validate` prints `Success! The configuration is valid.`
- [ ] `plan` prints **Plan: 6 to add, 0 to change, 0 to destroy**.
- [ ] The plan's ingress is exactly `22/tcp` and `8300/tcp`, both from your CIDRs.

`tofu apply` is a deployment-stage action. Do not run it until Phase 8 is
approved.

---

## Phase 7 — Pre-deployment checklist (all boxes required)

- [ ] OCI budget alert configured; compartment confirmed.
- [ ] API signing key mode `600`, profile works, tenancy/compartment OCIDs copied.
- [ ] SSH key pair exists; public key pasted into tfvars; private key untouched.
- [ ] `.env` present locally, mode `600`, gitignored, no real secret in any
      tracked file.
- [ ] Policy reviewed; `fail_on` chosen; `validate-policy` passes.
- [ ] Local stack healthy and `smoke.sh` reports 29/29.
- [ ] `tofu validate` passes and `plan` is exactly 6 to add.
- [ ] Ingress sources are your CIDRs only; no `0.0.0.0/0`.
- [ ] You accept that `tofu destroy` later removes the VCN, subnet, security
      list, gateway, route table and instance — and that it is only run on your
      explicit request.

---

## Phase 8 — Deployment-day sequence (operator + agent)

1. `tofu apply` and capture outputs (`instance_public_ip`, `instance_id`,
   `scanner_url`, `ingress_exposure`).
2. `ssh ubuntu@<public-ip>`, then `cloud-init status --wait` — expect `done`.
3. Verify Docker: `docker --version && docker compose version`.
4. Clone the repository on the host and create `.env` **on the host**; set
   `SCANNER_BIND_ADDRESS=0.0.0.0` only if you accept the restricted ingress rule,
   otherwise keep loopback and tunnel.
5. `docker compose --env-file .env -f docker/docker-compose.yml up -d --build`.
6. `curl -s http://127.0.0.1:8300/healthz` — expect `{"status":"ok",...}`.
7. Run the live drill: scan the bundled fixtures, confirm 21 findings and a
   failing gate, then scan a clean tree and confirm exit `0`.
8. Record the evidence (IPs, timings, counts, log excerpts with values removed)
   in `docs/` and commit it.

Never paste a token, webhook URL or key into a command that is captured in a
transcript.

---

## Phase 9 — Teardown (only on explicit request)

`tofu destroy` is destructive: it deletes the instance and every network
resource in this stack. Only run it when the operator asks for that action, then:

```bash
"$TOFU" plan -destroy
"$TOFU" destroy
"$TOFU" state list          # must be empty
```

Confirm provider-side that the instance is `TERMINATED` and the VCN returns
`404 NotAuthorizedOrNotFound` before removing any local state file.

---

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `tofu plan` asks for variables | `terraform.tfvars` missing or misnamed | create it in `terraform/`, not the repo root |
| `401 NotAuthenticated` from OCI | profile/key/fingerprint mismatch | re-check `~/.oci/config`; do not paste the key into chat |
| `Out of host capacity` on apply | A1 capacity in that AD | set `availability_domain` to another AD; keep the free shape |
| `healthz` refused on the host | container bound to loopback | keep loopback + SSH tunnel, or change bind intentionally |
| `403 path is outside the configured scan roots` | target not mounted at `/scan` | mount read-only; do not widen `SCANNER_ALLOWED_ROOTS` |
| Scanner flags your own workflow | action referenced by tag | pin to a commit SHA |
| `ModuleNotFoundError: tomllib` locally | Python 3.10 | use Python 3.11+ or the container CLI |

---

## Certification scope

- The container image, CLI and Terraform modules are cloud-agnostic, with AWS
  and GCP mappings documented in `terraform/README.md` and inline comments.
- **Final production verification and testing certification are performed
  strictly on Oracle Cloud Infrastructure using trial credits.** AWS and GCP are
  supported ports, not certified targets.
- No deployment is claimed as complete until Phase 8 has actually run and its
  evidence is committed. A passing `tofu plan` proves the configuration, not the
  host, the network path or the container.
