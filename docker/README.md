# Container layout and runtime posture

The scanner's runtime files live here; the `Dockerfile` sits at the repository
root on purpose.

| Path | Role |
| --- | --- |
| `../Dockerfile` | Single-stage runtime image, non-root uid `10001`, no compiler or package cache |
| `docker-compose.yml` | Hardened service definition for a 1 OCPU / 1 GB instance |
| `../.dockerignore` | Keeps the build context to `src/` + `configs/` |

**Why the Dockerfile is at the root:** the build context is the repository, and
CloudGuard's project profiler and portability audit both look for `Dockerfile`
at the project root. Compose therefore builds with `context: ..` and
`dockerfile: Dockerfile`. Everything that describes *how* the container runs —
compose, resource caps, read-only mounts — stays in this directory.

## Run it

```bash
cp -n ../.env.example ../.env
docker compose --env-file ../.env -f docker-compose.yml up -d --build
docker compose --env-file ../.env -f docker-compose.yml ps    # (healthy)
curl -s http://127.0.0.1:8300/healthz
```

Scan the bundled samples:

```bash
curl -s -X POST http://127.0.0.1:8300/scan \
  -H 'Content-Type: application/json' \
  -d '{"path":"/scan"}' | python -m json.tool | head -40
```

## Hardening flags, and why each one is there

| Flag | Effect |
| --- | --- |
| `read_only: true` | Reports go to stdout, so the container never needs a writable rootfs. Nothing an attacker writes survives a restart. |
| `cap_drop: ALL` | The service binds 8300, well above the privileged range, so it needs no capability. |
| `security_opt: no-new-privileges:true` | A setuid binary inside the image cannot elevate even if one appears. |
| `user: "10001:10001"` | Matches the image user; no runtime path can silently become root. |
| `pids_limit: 128` | Caps fork/thread bombs reachable through a hostile repository. |
| `mem_limit: 128m`, `cpus: 0.25` | Ten times the observed idle footprint; leaves headroom for a burst scan. |
| `tmpfs /tmp:16m` | Ephemeral scratch, never persisted to the host. |
| `../configs:/etc/scanner:ro` | Policy and advisories are input, not state. |
| `${SCANNER_WORKSPACE}:/scan:ro` | The scanner reads code and must never be able to modify the tree it inspects. |
| json-file `max-size: 5m`, `max-file: 2` | Bounded log growth on a small boot volume. |

The API is loopback-only by default. On an instance, bind it to the private
interface and leave 8300 out of the public security list entirely.
