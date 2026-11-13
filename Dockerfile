# syntax=docker/dockerfile:1.7
# =============================================================================
# CI/CD Security & Compliance Scanner — runtime image
# =============================================================================
# One stage on purpose: the runtime needs PyYAML and nothing else, so there is
# no toolchain worth a builder stage. The resulting image carries no compiler,
# no package manager cache and no root process.
#
# Build context is the repository root:
#
#   docker build -t cloudguard/scanner:local .
#
# The container is expected to run with:
#   --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="CloudGuard CI/CD Security & Compliance Scanner" \
      org.opencontainers.image.description="Pipeline, dependency and secret scanning with policy evaluation" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/kaveh8866/CI-CD-Security-Compliance-Scanner"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app \
    SCANNER_PORT=8300 \
    SCANNER_POLICY_FILE=/etc/scanner/policies/compliance.toml

# Fixed uid/gid so a bind-mounted workspace has predictable ownership.
RUN groupadd --gid 10001 scanner \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin scanner

WORKDIR /app

# Dependency layer first: source edits do not re-resolve PyYAML.
COPY src/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --no-compile -r requirements.txt

COPY src/scanner ./scanner
COPY configs ./configs

RUN mkdir -p /scan /etc/scanner \
 && cp -R configs/. /etc/scanner/ \
 && chown -R 10001:10001 /etc/scanner

USER 10001:10001

EXPOSE 8300

HEALTHCHECK --interval=20s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8300/healthz', timeout=2)"]

STOPSIGNAL SIGTERM

ENTRYPOINT ["python", "-m", "scanner"]
