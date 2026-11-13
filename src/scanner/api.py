"""Minimal HTTP surface: one health probe and one scan endpoint.

The API is read-only with respect to the filesystem: it never writes reports to
disk, accepts no uploads, refuses paths outside configured roots, caps request
bodies, and answers with the same value-free JSON the CLI emits. Reports are
written to stdout as structured log lines, which the container runtime rotates.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, compliance
from .engine import scan_path
from .models import SEVERITIES

MAX_BODY_BYTES = 64 * 1024
DEFAULT_PORT = 8300


def _allowed_roots() -> list[Path]:
    raw = os.environ.get("SCANNER_ALLOWED_ROOTS", "/scan:/etc/scanner")
    roots = []
    for entry in raw.split(":"):
        entry = entry.strip()
        if not entry:
            continue
        try:
            roots.append(Path(entry).resolve())
        except OSError:
            continue
    return roots or [Path("/scan").resolve()]


def _inside(root: Path, target: Path) -> bool:
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False


def _log(event: str, **fields: object) -> None:
    record = {"event": event, **fields}
    print(json.dumps(record, separators=(",", ":")), flush=True)


class ScannerHandler(BaseHTTPRequestHandler):
    server_version = f"cloudguard-scanner/{__version__}"
    sys_version = ""

    policy: compliance.Policy
    allowed_roots: list[Path]

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        _log("http", method=self.command, peer=self.client_address[0], detail=format % args)

    # --- helpers -----------------------------------------------------------
    def _send(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._send(status, {"error": message, "status": status.value})

    # --- routes ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        if self.path == "/healthz":
            self._send(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "cicd-security-scanner",
                    "version": __version__,
                    "policy": self.policy.name,
                    "policy_version": self.policy.version,
                    "controls": len(self.policy.controls),
                    "roots": [str(root) for root in self.allowed_roots],
                },
            )
            return
        if self.path == "/policy":
            self._send(
                HTTPStatus.OK,
                {
                    "name": self.policy.name,
                    "version": self.policy.version,
                    "fail_on": self.policy.fail_on,
                    "ignore": list(self.policy.ignore),
                    "controls": [
                        {
                            "id": control.id,
                            "title": control.title,
                            "severity": control.severity,
                            "rules": list(control.rules),
                        }
                        for control in self.policy.controls
                    ],
                },
            )
            return
        self._error(HTTPStatus.NOT_FOUND, "unknown route")

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        if self.path != "/scan":
            self._error(HTTPStatus.NOT_FOUND, "unknown route")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._error(HTTPStatus.BAD_REQUEST, f"body must be 1..{MAX_BODY_BYTES} bytes")
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._error(HTTPStatus.BAD_REQUEST, "body must be JSON")
            return
        if not isinstance(payload, dict):
            self._error(HTTPStatus.BAD_REQUEST, "body must be a JSON object")
            return

        raw_path = payload.get("path", str(self.allowed_roots[0]))
        if not isinstance(raw_path, str) or not raw_path.strip():
            self._error(HTTPStatus.BAD_REQUEST, "path must be a non-empty string")
            return

        target = Path(raw_path).expanduser()
        try:
            target = target.resolve()
        except OSError:
            self._error(HTTPStatus.BAD_REQUEST, "path cannot be resolved")
            return

        if not any(_inside(root, target) for root in self.allowed_roots):
            self._error(HTTPStatus.FORBIDDEN, "path is outside the configured scan roots")
            return
        if not target.is_dir():
            self._error(HTTPStatus.NOT_FOUND, "path is not a directory")
            return

        threshold = payload.get("fail_on", self.policy.fail_on)
        if threshold not in SEVERITIES:
            self._error(HTTPStatus.BAD_REQUEST, f"fail_on must be one of {', '.join(SEVERITIES)}")
            return

        try:
            report = scan_path(target, policy=self.policy)
        except (OSError, compliance.PolicyError) as error:
            _log("scan_error", detail=type(error).__name__)
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "scan failed")
            return

        body = report.to_dict()
        body["exit_code"] = report.exit_code(threshold)
        _log(
            "scan",
            target=str(target),
            files=report.files_scanned,
            findings=len(report.findings),
            critical=report.summary["critical"],
            high=report.summary["high"],
            controls_failed=len(report.failed_controls()),
        )
        self._send(HTTPStatus.OK, body)


def create_server(host: str, port: int, policy: compliance.Policy | None = None) -> ThreadingHTTPServer:
    ScannerHandler.policy = policy or compliance.load_policy(os.environ.get("SCANNER_POLICY_FILE"))
    ScannerHandler.allowed_roots = _allowed_roots()
    server = ThreadingHTTPServer((host, port), ScannerHandler)
    server.daemon_threads = True
    return server


def serve() -> int:
    host = os.environ.get("SCANNER_HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("SCANNER_PORT", str(DEFAULT_PORT)))
    except ValueError:
        print("fatal: SCANNER_PORT must be an integer", file=sys.stderr)
        return 2
    policy_path = os.environ.get("SCANNER_POLICY_FILE")

    try:
        policy = compliance.load_policy(policy_path)
    except compliance.PolicyError as error:
        print(f"fatal: {error}", file=sys.stderr)
        return 2

    server = create_server(host, port, policy)

    def shutdown(signum: int, _frame: object) -> None:
        _log("shutdown", signal=signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    _log("start", host=host, port=port, policy=policy.name, version=__version__)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0
