"""Tests for loopback-only Playwright verification planning."""

from pathlib import Path

import pytest

from aegify.harness.browser import BrowserVerificationExecutor, BrowserVerificationPlan
from aegify.harness.browser_runner import _validated_service_command

PINNED_IMAGE = f"example.invalid/browser@sha256:{'d' * 64}"


def _plan(**overrides: object) -> BrowserVerificationPlan:
    payload: dict[str, object] = {
        "version": 1,
        "name": "browser-smoke",
        "image": PINNED_IMAGE,
        "service_command": ["python3", "-m", "http.server", "8080"],
        "base_url": "http://127.0.0.1:8080",
        "scenarios": [
            {
                "id": "orders",
                "actions": [
                    {"action": "navigate", "path": "/orders"},
                    {"action": "wait_for_selector", "selector": "main"},
                    {"action": "click", "selector": "a[data-order-id]"},
                ],
            }
        ],
    }
    payload.update(overrides)
    return BrowserVerificationPlan.model_validate(payload)


def test_browser_plan_rejects_external_navigation_and_arbitrary_action():
    with pytest.raises(ValueError, match="loopback"):
        _plan(base_url="https://example.com")
    with pytest.raises(ValueError, match="loopback-relative"):
        _plan(
            scenarios=[
                {
                    "id": "external",
                    "actions": [{"action": "navigate", "path": "https://example.com/"}],
                }
            ]
        )
    with pytest.raises(ValueError, match="Input should be"):
        _plan(
            scenarios=[
                {
                    "id": "script",
                    "actions": [{"action": "evaluate", "selector": "alert(1)"}],
                }
            ]
        )


def test_browser_runner_revalidates_staged_service_command():
    staged = _plan().model_dump(mode="json")
    assert _validated_service_command(staged) == staged["service_command"]
    staged["service_command"] = ["unapproved-server"]
    with pytest.raises(ValueError, match="not allowlisted"):
        _validated_service_command(staged)


def test_browser_plan_stages_playwright_runner_with_no_container_network(
    tmp_path: Path,
):
    (tmp_path / "index.html").write_text("<main>owned</main>\n")

    report = BrowserVerificationExecutor("docker").plan(_plan(), tmp_path)

    command = report.docker_commands[0]
    assert report.status == "planned"
    assert command[command.index("--network") :][:2] == ["--network", "none"]
    assert command[-3:] == [
        "python3",
        ".aegify-runtime/browser_runner.py",
        ".aegify-runtime/browser-plan.json",
    ]
