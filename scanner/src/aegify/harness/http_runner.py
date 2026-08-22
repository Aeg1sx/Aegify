"""Standard-library loopback HTTP runner copied into an isolated workspace."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def _validated_service_command(plan: dict[str, Any]) -> list[str]:
    """Revalidate the staged argv against the plan's explicit allowlist."""
    raw_command = plan.get("service_command")
    raw_policy = plan.get("policy")
    if not isinstance(raw_command, list) or not raw_command:
        raise ValueError("service_command must be a non-empty argv list")
    if not isinstance(raw_policy, dict):
        raise ValueError("verification policy is required")
    raw_allowed = raw_policy.get("allowed_commands")
    if not isinstance(raw_allowed, list) or not raw_allowed:
        raise ValueError("allowed_commands must be a non-empty list")
    if any(not isinstance(value, str) or "\x00" in value for value in raw_command):
        raise ValueError("service_command must contain NUL-free strings")
    allowed = {value for value in raw_allowed if isinstance(value, str)}
    if raw_command[0] not in allowed:
        raise ValueError(f"service command {raw_command[0]!r} is not allowlisted")
    return list(raw_command)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _wait_for_port(base_url: str, timeout: int) -> None:
    parsed = urlsplit(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"loopback service did not listen on {host}:{port}")


def _request(  # type: ignore[no-untyped-def]
    opener, base_url: str, case: dict[str, Any], timeout: int, limit: int
):
    started = time.monotonic()
    request = urllib.request.Request(
        base_url + str(case["path"]),
        method=str(case["method"]),
    )
    status = 0
    error = ""
    body = b""
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        body = exc.read(limit + 1)
    except (OSError, urllib.error.URLError) as exc:
        error = str(exc)[:500]
    truncated = len(body) > limit
    retained = body[:limit]
    expected = [int(value) for value in case["expected_status"]]
    return {
        "id": str(case["id"]),
        "method": str(case["method"]),
        "path": str(case["path"]),
        "status_code": status or None,
        "expected_status": expected,
        "duration_ms": (time.monotonic() - started) * 1000,
        "passed": not error and status in expected,
        "response_sha256": hashlib.sha256(retained).hexdigest(),
        "response_truncated": truncated,
        "error": error,
    }


def main() -> int:
    plan_path = Path(sys.argv[1])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    service_command = _validated_service_command(plan)
    service = subprocess.Popen(
        service_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    cases: list[dict[str, Any]] = []
    run_error = ""
    try:
        _wait_for_port(str(plan["base_url"]), int(plan["startup_timeout_seconds"]))
        opener = urllib.request.build_opener(_NoRedirect())
        for case in plan["cases"]:
            cases.append(
                _request(
                    opener,
                    str(plan["base_url"]),
                    case,
                    int(plan["request_timeout_seconds"]),
                    int(plan["max_response_bytes"]),
                )
            )
    except (OSError, TimeoutError, ValueError) as exc:
        run_error = str(exc)[:500]
    finally:
        service.terminate()
        try:
            service.wait(timeout=5)
        except subprocess.TimeoutExpired:
            service.kill()
            service.wait(timeout=5)

    evidence = {
        "contract_version": 1,
        "producer": "aegify-http-harness",
        "cases": cases,
        "error": run_error,
    }
    output = plan_path.with_name("http-evidence.json")
    output.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if not run_error and cases and all(case["passed"] for case in cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
