"""Standard-library loopback intercepting proxy copied into an isolated run."""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_CASE_HEADER = "X-Aegify-Proxy-Case"
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _set_header(headers: dict[str, str], name: str, value: str) -> None:
    _delete_header(headers, name)
    headers[name] = value


def _delete_header(headers: dict[str, str], name: str) -> None:
    lowered = name.lower()
    for existing in list(headers):
        if existing.lower() == lowered:
            del headers[existing]


def _json_parent(document: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    parts = path.split(".")
    current = document
    for part in parts[:-1]:
        value = current.get(part)
        if not isinstance(value, dict):
            value = {}
            current[part] = value
        current = value
    return current, parts[-1]


def _apply_mutations(
    case: dict[str, Any],
) -> tuple[str, str, dict[str, str], bytes, list[dict[str, str]]]:
    method = str(case["method"]).upper()
    path = str(case["path"])
    headers = {str(key): str(value) for key, value in dict(case["headers"]).items()}
    body = str(case.get("body") or "").encode("utf-8")
    evidence: list[dict[str, str]] = []

    for raw_mutation in case["mutations"]:
        mutation = dict(raw_mutation)
        kind = str(mutation["kind"])
        name = str(mutation.get("name") or "")
        value = str(mutation.get("value") or "")
        if kind == "method":
            method = value.upper()
        elif kind == "path-replace":
            parsed = urlsplit(path)
            mutated_path = parsed.path.replace(
                str(mutation.get("match") or ""),
                str(mutation.get("replacement") or ""),
                1,
            )
            path = urlunsplit(("", "", mutated_path, parsed.query, ""))
        elif kind in {"query-set", "query-delete"}:
            parsed = urlsplit(path)
            pairs = [
                (key, item)
                for key, item in parse_qsl(parsed.query, keep_blank_values=True)
                if key != name
            ]
            if kind == "query-set":
                pairs.append((name, value))
            path = urlunsplit(("", "", parsed.path, urlencode(pairs), ""))
        elif kind == "header-set":
            _set_header(headers, name, value)
        elif kind == "header-delete":
            _delete_header(headers, name)
        elif kind == "body-replace":
            body = value.encode("utf-8")
        elif kind in {"json-set", "json-delete"}:
            raw_document = json.loads(body.decode("utf-8") or "{}")
            if not isinstance(raw_document, dict):
                raise ValueError("JSON mutation requires an object body")
            parent, key = _json_parent(raw_document, name)
            if kind == "json-set":
                try:
                    parent[key] = json.loads(value)
                except json.JSONDecodeError:
                    parent[key] = value
            else:
                parent.pop(key, None)
            body = json.dumps(raw_document, separators=(",", ":"), sort_keys=True).encode("utf-8")
            _set_header(headers, "Content-Type", "application/json")
        mutation_evidence = {"kind": kind}
        if name:
            mutation_evidence["name"] = name
        evidence.append(mutation_evidence)

    parsed = urlsplit(path)
    if not parsed.path.startswith("/") or parsed.scheme or parsed.netloc:
        raise ValueError("mutation escaped the loopback-relative path boundary")
    if ".." in Path(parsed.path).parts:
        raise ValueError("mutation produced parent traversal")
    return method, path, headers, body, evidence


class _ProxyState:
    def __init__(
        self,
        base_url: str,
        cases: list[dict[str, Any]],
        timeout: int,
        response_limit: int,
    ) -> None:
        self.base_url = base_url
        self.target = urlsplit(base_url)
        self.cases = {str(case["id"]): case for case in cases}
        self.timeout = timeout
        self.response_limit = response_limit
        self.records: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    def record(self, case_id: str, record: dict[str, Any]) -> None:
        with self.lock:
            self.records[case_id] = record


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AegifyProxy/1"
    state: _ProxyState

    def do_GET(self) -> None:
        self._intercept()

    def do_HEAD(self) -> None:
        self._intercept()

    def do_OPTIONS(self) -> None:
        self._intercept()

    def do_POST(self) -> None:
        self._intercept()

    def do_PUT(self) -> None:
        self._intercept()

    def do_PATCH(self) -> None:
        self._intercept()

    def do_DELETE(self) -> None:
        self._intercept()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _intercept(self) -> None:
        started = time.monotonic()
        case_id = self.headers.get(_CASE_HEADER, "")
        case = self.state.cases.get(case_id)
        original = urlsplit(self.path)
        original_path = original.path or "/"
        record: dict[str, Any] = {
            "id": case_id,
            "original_method": self.command,
            "original_path": original_path,
            "method": self.command,
            "path": original_path,
            "status_code": None,
            "expected_status": [],
            "duration_ms": 0.0,
            "passed": False,
            "mutations": [],
            "query_sha256": _sha256((original.query or "").encode("utf-8")),
            "request_body_sha256": _sha256(b""),
            "request_body_bytes": 0,
            "response_sha256": _sha256(b""),
            "response_truncated": False,
            "error": "",
        }
        try:
            if case is None:
                raise ValueError("missing or unknown internal proxy case id")
            target = original if original.scheme else urlsplit(self.state.base_url + self.path)
            if (
                target.scheme != "http"
                or target.hostname not in _LOOPBACK
                or target.hostname != self.state.target.hostname
                or (target.port or 80) != (self.state.target.port or 80)
            ):
                raise ValueError("proxy target escaped the configured loopback origin")
            content_length = int(self.headers.get("Content-Length", "0") or 0)
            if content_length < 0 or content_length > 1_000_000:
                raise ValueError("proxied request body exceeds 1,000,000 bytes")
            if content_length:
                self.rfile.read(content_length)

            method, path, headers, body, mutations = _apply_mutations(case)
            parsed_path = urlsplit(path)
            record.update(
                {
                    "method": method,
                    "path": parsed_path.path or "/",
                    "expected_status": [int(value) for value in case["expected_status"]],
                    "mutations": mutations,
                    "query_sha256": _sha256(parsed_path.query.encode("utf-8")),
                    "request_body_sha256": _sha256(body),
                    "request_body_bytes": len(body),
                }
            )
            outgoing_headers = {
                name: value
                for name, value in headers.items()
                if name.lower() not in _HOP_BY_HOP and name.lower() != _CASE_HEADER.lower()
            }
            outgoing_headers["Host"] = self.state.target.netloc
            outgoing_headers["Connection"] = "close"
            if body:
                outgoing_headers["Content-Length"] = str(len(body))
            else:
                _delete_header(outgoing_headers, "Content-Length")

            connection = http.client.HTTPConnection(
                self.state.target.hostname,
                self.state.target.port or 80,
                timeout=self.state.timeout,
            )
            try:
                connection.request(
                    method,
                    urlunsplit(("", "", parsed_path.path, parsed_path.query, "")),
                    body=body or None,
                    headers=outgoing_headers,
                )
                response = connection.getresponse()
                response_body = response.read(self.state.response_limit + 1)
                status = int(response.status)
            finally:
                connection.close()
            truncated = len(response_body) > self.state.response_limit
            retained = response_body[: self.state.response_limit]
            record.update(
                {
                    "status_code": status,
                    "response_sha256": _sha256(retained),
                    "response_truncated": truncated,
                    "passed": status in record["expected_status"],
                }
            )
            self.send_response(status)
            self.send_header("Content-Length", str(len(retained)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(retained)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            record["error"] = str(error)[:500]
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        finally:
            record["duration_ms"] = (time.monotonic() - started) * 1000
            self.state.record(case_id, record)


def _handler_for(state: _ProxyState) -> type[_ProxyHandler]:
    class Handler(_ProxyHandler):
        pass

    Handler.state = state
    return Handler


def _execute_cases(
    base_url: str,
    cases: list[dict[str, Any]],
    timeout: int,
    response_limit: int,
) -> list[dict[str, Any]]:
    state = _ProxyState(base_url, cases, timeout, response_limit)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proxy_host, proxy_port = server.server_address[:2]
    try:
        for case in cases:
            case_id = str(case["id"])
            connection = http.client.HTTPConnection(
                str(proxy_host), int(proxy_port), timeout=timeout
            )
            headers = {
                str(name): str(value) for name, value in dict(case.get("headers") or {}).items()
            }
            headers[_CASE_HEADER] = case_id
            body = str(case.get("body") or "").encode("utf-8")
            try:
                connection.request(
                    str(case["method"]),
                    base_url + str(case["path"]),
                    body=body or None,
                    headers=headers,
                )
                response = connection.getresponse()
                response.read(response_limit + 1)
            except OSError as error:
                state.record(
                    case_id,
                    {
                        "id": case_id,
                        "method": str(case["method"]),
                        "path": urlsplit(str(case["path"])).path,
                        "status_code": None,
                        "duration_ms": 0.0,
                        "passed": False,
                        "error": str(error)[:500],
                    },
                )
            finally:
                connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return [state.records[str(case["id"])] for case in cases]


def main() -> int:
    plan_path = Path(sys.argv[1])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    service = subprocess.Popen(
        [str(value) for value in plan["service_command"]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    records: list[dict[str, Any]] = []
    run_error = ""
    try:
        _wait_for_port(str(plan["base_url"]), int(plan["startup_timeout_seconds"]))
        records = _execute_cases(
            str(plan["base_url"]),
            [dict(case) for case in plan["cases"]],
            int(plan["request_timeout_seconds"]),
            int(plan["max_response_bytes"]),
        )
    except (OSError, TimeoutError, ValueError) as error:
        run_error = str(error)[:500]
    finally:
        service.terminate()
        try:
            service.wait(timeout=5)
        except subprocess.TimeoutExpired:
            service.kill()
            service.wait(timeout=5)

    evidence = {
        "contract_version": 1,
        "producer": "aegify-proxy-harness",
        "cases": records,
        "error": run_error,
    }
    output = plan_path.with_name("proxy-evidence.json")
    output.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if not run_error and records and all(record.get("passed") for record in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
