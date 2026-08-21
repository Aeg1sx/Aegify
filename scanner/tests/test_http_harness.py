"""Tests for loopback-only isolated HTTP verification contracts."""

from pathlib import Path

import pytest

from aegify.harness.http import HttpVerificationExecutor, HttpVerificationPlan
from aegify.harness.http_runner import _request

PINNED_IMAGE = f"example.invalid/http@sha256:{'c' * 64}"


def _plan(**overrides: object) -> HttpVerificationPlan:
    payload: dict[str, object] = {
        "version": 1,
        "name": "http-smoke",
        "image": PINNED_IMAGE,
        "service_command": ["python3", "-m", "http.server", "8080"],
        "base_url": "http://127.0.0.1:8080",
        "cases": [{"id": "root", "method": "GET", "path": "/", "expected_status": [200]}],
    }
    payload.update(overrides)
    return HttpVerificationPlan.model_validate(payload)


def test_http_plan_is_loopback_only_digest_pinned_and_secret_free():
    with pytest.raises(ValueError, match="loopback"):
        _plan(base_url="https://example.com")
    with pytest.raises(ValueError, match="pinned"):
        _plan(image="example.invalid/http:latest")
    with pytest.raises(ValueError, match="secrets"):
        _plan(service_command=["python3", "--token=secret"])
    with pytest.raises(ValueError, match="relative"):
        _plan(cases=[{"id": "external", "path": "https://example.com/"}])


def test_http_dry_run_stages_runner_and_keeps_container_network_disabled(
    tmp_path: Path,
):
    (tmp_path / "index.html").write_text("ok\n")

    report = HttpVerificationExecutor("docker").plan(_plan(), tmp_path)

    command = report.docker_commands[0]
    assert report.status == "planned"
    assert command[command.index("--network") :][:2] == ["--network", "none"]
    assert command[-3:] == [
        "python3",
        ".aegify-runtime/http_runner.py",
        ".aegify-runtime/http-plan.json",
    ]


def test_http_runner_retains_only_bounded_hash_evidence():
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        @staticmethod
        def read(limit: int) -> bytes:
            return b"owned fixture secret"[:limit]

    class Opener:
        @staticmethod
        def open(request: object, timeout: int) -> Response:
            return Response()

    evidence = _request(
        Opener(),
        "http://127.0.0.1:8080",
        {"id": "root", "method": "GET", "path": "/", "expected_status": [200]},
        5,
        4096,
    )

    assert evidence["passed"]
    assert len(evidence["response_sha256"]) == 64
    assert "owned fixture" not in str(evidence)
