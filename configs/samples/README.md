# Intentional fixtures — do not "fix" these

Every file in this directory is **deliberately insecure test data**. The scanner
needs known-bad inputs to prove detection, redaction, policy evaluation and the
gate, so the pins below must stay vulnerable.

| File | Why it is insecure |
| --- | --- |
| `requirements-insecure.txt` | `requests==2.28.0`, `urllib3==2.0.6`, `pyyaml==5.3.1` sit below their fixed versions, plus an unpinned `flask` |
| `node/package.json` | `lodash@4.17.15`, `minimist@1.2.0` are vulnerable, `left-pad: "*"` is unpinned |
| `workflows/github-actions-insecure.yml` | `pull_request_target` with an untrusted checkout, expression injection into `run:`, tag-pinned actions, `curl \| bash`, `write-all` |
| `gitlab/.gitlab-ci.yml` | floating image, `curl \| sh`, `CI_JOB_TOKEN` echoed |
| `leaky.env.example` | fake high-entropy credentials used to exercise `CG-SEC-010` |

These files are **never installed or executed**. They are consumed only by
`tests/test_engine.py`, `tests/smoke.sh` and manual demos, and every finding is
reported with a `sha256` fingerprint rather than the value.

## Dependency bots

GitHub's dependency graph parses these manifests, so Dependabot raises alerts
against the fake pins. That noise is expected and accepted:

- **Automated security fixes are disabled** for this repository, so no bot PR
  rewrites the fixtures (a merged bump in November 2026 removed `CG-VULN-001`
  and broke CI; it was reverted).
- **Open alerts are dismissed as `not_used`** with a link to this file. They may
  reappear if the fixture manifests change.
- Do not merge a dependency-update PR that touches this directory. If a fixture
  needs a new advisory, add a *new* deliberately vulnerable pin and extend
  `configs/advisories/advisories.json` and the tests.
