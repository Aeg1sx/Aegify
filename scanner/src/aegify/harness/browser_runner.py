"""Playwright runner copied into a no-network verification container."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]


def _wait_for_port(base_url: str, timeout: int) -> None:
    parsed = urlsplit(base_url)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(
                (parsed.hostname or "127.0.0.1", parsed.port or 80),
                timeout=0.5,
            ):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("loopback browser target did not become ready")


def _local_url(url: str, origin: tuple[str, int]) -> bool:
    parsed = urlsplit(url)
    return (
        parsed.scheme == "http"
        and parsed.hostname == origin[0]
        and (parsed.port or 80) == origin[1]
    )


def main() -> int:
    plan_path = Path(sys.argv[1])
    plan: dict[str, Any] = json.loads(plan_path.read_text(encoding="utf-8"))
    base_url = str(plan["base_url"])
    parsed = urlsplit(base_url)
    origin = (parsed.hostname or "127.0.0.1", parsed.port or 80)
    service = subprocess.Popen(
        [str(value) for value in plan["service_command"]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    observations: list[dict[str, Any]] = []
    failures: list[str] = []
    try:
        _wait_for_port(base_url, int(plan["startup_timeout_seconds"]))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            started: dict[int, float] = {}

            def route_request(route: Any) -> None:
                if _local_url(str(route.request.url), origin):
                    route.continue_()
                else:
                    route.abort("blockedbyclient")

            def on_request(request: Any) -> None:
                started[id(request)] = time.monotonic()

            def on_response(response: Any) -> None:
                request = response.request
                url = urlsplit(str(request.url))
                observations.append(
                    {
                        "id": f"browser-{len(observations)}",
                        "method": str(request.method),
                        "path": url.path or "/",
                        "status_code": int(response.status),
                        "duration_ms": (
                            time.monotonic() - started.pop(id(request), time.monotonic())
                        )
                        * 1000,
                        "passed": True,
                    }
                )

            page.route("**/*", route_request)
            page.on("request", on_request)
            page.on("response", on_response)
            for scenario in plan["scenarios"]:
                try:
                    for action in scenario["actions"]:
                        timeout = int(action["timeout_seconds"]) * 1000
                        if action["action"] == "navigate":
                            page.goto(
                                base_url + str(action["path"]),
                                wait_until="domcontentloaded",
                                timeout=timeout,
                            )
                        elif action["action"] == "click":
                            page.locator(str(action["selector"])).click(timeout=timeout)
                        else:
                            page.locator(str(action["selector"])).wait_for(timeout=timeout)
                except Exception as error:  # Playwright exposes several runtime error types.
                    failures.append(f"{scenario['id']}: {str(error)[:500]}")
            context.close()
            browser.close()
    except (OSError, TimeoutError, ValueError) as error:
        failures.append(str(error)[:500])
    finally:
        service.terminate()
        try:
            service.wait(timeout=5)
        except subprocess.TimeoutExpired:
            service.kill()
            service.wait(timeout=5)

    evidence = {
        "contract_version": 1,
        "producer": "aegify-browser-harness",
        "requests": observations,
        "failures": failures,
    }
    plan_path.with_name("browser-evidence.json").write_text(
        json.dumps(evidence, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0 if observations and not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
