# Configuration layout

```
configs/
├── advisories/advisories.json        offline vulnerability catalogue (pypi + npm)
├── policies/compliance.toml          baseline policy: 10 controls, fail_on = high
├── samples/                          intentionally insecure fixtures (never a real secret)
│   ├── workflows/github-actions-insecure.yml
│   ├── gitlab/.gitlab-ci.yml
│   ├── node/package.json
│   ├── requirements-insecure.txt
│   └── leaky.env.example
└── schema/
    ├── policy.schema.json            policy document contract
    └── finding.schema.json           report contract (evidence = sha256 fingerprint)
```

## Policy model

`[policy]` carries the metadata and the CI gate (`fail_on`), plus `ignore`, a
list of repo-relative POSIX globs. Each `[[controls]]` entry groups rule ids:

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

A control **fails** when at least one finding matches one of its rule patterns;
`CG-SEC-*` is a wildcard. Every finding is still reported even when no control
covers it, so a policy edit never hides evidence.

## Samples are fixtures, not advice

The files under `samples/` are deliberately broken: unpinned actions, a
`pull_request_target` checkout, `curl | bash`, floating images, outdated pins
and fake high-entropy credentials. They exist so the demo and the test suite
have something deterministic to flag. The credentials are fake and match no
provider format.

## Advisories

`advisories.json` is an offline catalogue, not a feed. `below` is the first
fixed version; versions are compared by their declared lower bound, which is
reported in the finding text so the heuristic is visible. Replace or extend the
catalogue from an OSV/GHSA export and bump its `updated` field.
