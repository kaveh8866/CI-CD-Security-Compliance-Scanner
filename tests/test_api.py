from __future__ import annotations

import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from scanner.api import create_server
from scanner.compliance import load_policy

REPO_ROOT = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_policy(REPO_ROOT / "configs" / "policies" / "compliance.toml")
        cls.env = mock.patch.dict(
            os.environ,
            {"SCANNER_ALLOWED_ROOTS": f"{REPO_ROOT / 'configs'}"},
            clear=False,
        )
        cls.env.start()
        cls.server = create_server("127.0.0.1", 0, cls.policy)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.env.stop()

    def request(self, path: str, payload: dict | bytes | None = None) -> tuple[int, dict]:
        data = None
        headers = {}
        if isinstance(payload, dict):
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(payload, bytes):
            data = payload
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(f"{self.base}{path}", data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_healthz(self) -> None:
        status, body = self.request("/healthz")

        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["policy"], "CloudGuard CI/CD Baseline")
        self.assertGreaterEqual(body["controls"], 8)

    def test_policy_endpoint(self) -> None:
        status, body = self.request("/policy")

        self.assertEqual(status, 200)
        self.assertEqual(body["fail_on"], "high")
        self.assertTrue(any(control["id"] == "CG-CI-007" for control in body["controls"]))

    def test_scan_reports_findings(self) -> None:
        status, body = self.request("/scan", {"path": str(REPO_ROOT / "configs" / "samples")})

        self.assertEqual(status, 200)
        self.assertGreater(len(body["findings"]), 5)
        self.assertEqual(body["exit_code"], 1)
        self.assertGreater(body["controls_failed"], 0)

    def test_scan_redacts_secret_values(self) -> None:
        _, body = self.request("/scan", {"path": str(REPO_ROOT / "configs" / "samples")})
        serialised = json.dumps(body)

        self.assertNotIn("Zk8Qm2Lp7Rt4Vb9Nx", serialised)
        self.assertNotIn("xR4tY7uP2aS9dF6g", serialised)

    def test_path_outside_roots_forbidden(self) -> None:
        status, body = self.request("/scan", {"path": str(REPO_ROOT)})

        self.assertEqual(status, 403)
        self.assertIn("outside", body["error"])

    def test_traversal_is_forbidden(self) -> None:
        status, body = self.request("/scan", {"path": str(REPO_ROOT / "configs" / ".." / "..")})

        self.assertEqual(status, 403)
        self.assertIn("outside", body["error"])

    def test_unknown_route(self) -> None:
        status, body = self.request("/nope")

        self.assertEqual(status, 404)
        self.assertIn("unknown", body["error"])

    def test_malformed_body_rejected(self) -> None:
        status, body = self.request("/scan", b"{not json")

        self.assertEqual(status, 400)
        self.assertIn("JSON", body["error"])

    def test_invalid_threshold_rejected(self) -> None:
        status, body = self.request("/scan", {"path": str(REPO_ROOT / "configs"), "fail_on": "severe"})

        self.assertEqual(status, 400)
        self.assertIn("fail_on", body["error"])

    def test_missing_body_rejected(self) -> None:
        request = urllib.request.Request(f"{self.base}/scan", data=b"", method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10):
                self.fail("expected HTTP 400")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 400)


if __name__ == "__main__":
    unittest.main()
