"""Tests for active loopback interception and request mutation."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aegify.harness.proxy import ProxyVerificationExecutor, ProxyVerificationPlan
from aegify.harness.proxy_runner import _apply_mutations, _execute_cases

PINNED_IMAGE = f"example.invalid/proxy@sha256:{'e' * 64}"


def _plan(**overrides: object) -> ProxyVerificationPlan:
    payload: dict[str, object] = {
        "version": 1,
        "name": "proxy-smoke",
        "image": PINNED_IMAGE,
        "service_command": ["python3", "-m", "http.server", "8080"],
        "base_url": "http://127.0.0.1:8080",
        "cases": [
            {
                "id": "mutate",
                "method": "POST",
                "path": "/orders?mode=normal",
                "headers": {"Content-Type": "application/json"},
                "body": '{"role":"user"}',
                "mutations": [
                    {"kind": "json-set", "name": "role", "value": '"admin"'},
                    {"kind": "query-set", "name": "debug", "value": "true"},
                ],
                "expected_status": [403],
            }
        ],
    }
    payload.update(overrides)
    return ProxyVerificationPlan.model_validate(payload)


def test_proxy_plan_rejects_external_targets_and_sensitive_headers():
    with pytest.raises(ValueError, match="loopback"):
        _plan(base_url="https://example.com")
    with pytest.raises(ValueError, match="pinned"):
        _plan(image="example.invalid/proxy:latest")
    with pytest.raises(ValueError, match="sensitive"):
        _plan(
            cases=[
                {
                    "id": "secret",
                    "method": "GET",
                    "path": "/",
                    "headers": {"Authorization": "Bearer not-retained"},
                    "mutations": [{"kind": "query-set", "name": "x", "value": "1"}],
                }
            ]
        )
    with pytest.raises(ValueError, match="1-50"):
        _plan(cases=[{"id": "none", "method": "GET", "path": "/", "mutations": []}])


def test_proxy_dry_run_stages_runner_with_no_container_network(tmp_path: Path):
    (tmp_path / "index.html").write_text("owned\n")

    report = ProxyVerificationExecutor("docker").plan(_plan(), tmp_path)

    command = report.docker_commands[0]
    assert report.status == "planned"
    assert command[command.index("--network") :][:2] == ["--network", "none"]
    assert command[-3:] == [
        "python3",
        ".aegify-runtime/proxy_runner.py",
        ".aegify-runtime/proxy-plan.json",
    ]


def test_mutation_metadata_never_retains_values_or_bodies():
    case = _plan().cases[0].model_dump(mode="json")

    method, path, _, body, evidence = _apply_mutations(case)

    assert method == "POST"
    assert path == "/orders?mode=normal&debug=true"
    assert json.loads(body) == {"role": "admin"}
    assert evidence == [
        {"kind": "json-set", "name": "role"},
        {"kind": "query-set", "name": "debug"},
    ]
    assert "admin" not in str(evidence)
    assert "true" not in str(evidence)


def test_live_proxy_intercepts_mutates_and_emits_redacted_evidence():
    received: list[dict[str, object]] = []

    class OwnedHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            received.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "probe": self.headers.get("X-Aegify-Probe"),
                    "body": json.loads(body),
                }
            )
            self.send_response(403)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    try:
        target = ThreadingHTTPServer(("127.0.0.1", 0), OwnedHandler)
    except PermissionError:
        pytest.skip("sandbox policy forbids loopback bind; run outside the sandbox")
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    port = int(target.server_address[1])
    case = _plan().cases[0].model_dump(mode="json")
    case["mutations"].append(
        {
            "kind": "header-set",
            "name": "X-Aegify-Probe",
            "value": "owned-value",
            "match": "",
            "replacement": "",
        }
    )
    try:
        records = _execute_cases(
            f"http://127.0.0.1:{port}",
            [case],
            timeout=5,
            response_limit=4096,
        )
    finally:
        target.shutdown()
        target.server_close()
        thread.join(timeout=5)

    assert received == [
        {
            "method": "POST",
            "path": "/orders?mode=normal&debug=true",
            "probe": "owned-value",
            "body": {"role": "admin"},
        }
    ]
    assert len(records) == 1
    assert records[0]["passed"] is True
    assert records[0]["status_code"] == 403
    assert records[0]["path"] == "/orders"
    assert len(records[0]["query_sha256"]) == 64
    assert len(records[0]["request_body_sha256"]) == 64
    assert "admin" not in str(records[0])
    assert "owned-value" not in str(records[0])
    assert "debug=true" not in str(records[0])
