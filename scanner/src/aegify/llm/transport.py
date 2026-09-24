"""Bound SDK success and error bodies before decoding or error construction."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import NoReturn

import httpx2

from aegify.llm.budget import MAX_PROMPT_BYTES

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
BODY_DEADLINE_SECONDS = 60.0
IO_TIMEOUT_SECONDS = 10.0


@dataclass
class HttpObservation:
    started: float = field(default_factory=time.monotonic)
    request_digest: str = ""
    response_digest: str = ""
    http_status: int | None = None
    requests: int = 0
    error_code: str = ""
    response_bytes: int = 0

    def fail(self, code: str) -> NoReturn:
        self.error_code = code
        raise httpx2.TransportError(code)

    def check_deadline(self) -> None:
        if time.monotonic() - self.started > BODY_DEADLINE_SECONDS:
            self.fail("body_deadline_exceeded")


observation: ContextVar[HttpObservation | None] = ContextVar("aegify_model_http", default=None)


class _BoundedStream(httpx2.SyncByteStream):
    def __init__(self, stream: httpx2.SyncByteStream, current: HttpObservation) -> None:
        self.stream = stream
        self.current = current

    def __iter__(self) -> Iterator[bytes]:
        digest = hashlib.sha256()
        try:
            for chunk in self.stream:
                self.current.check_deadline()
                self.current.response_bytes += len(chunk)
                if self.current.response_bytes > MAX_RESPONSE_BYTES:
                    self.current.fail("response_too_large")
                digest.update(chunk)
                yield chunk
            self.current.check_deadline()
            self.current.response_digest = "sha256:" + digest.hexdigest()
        finally:
            self.stream.close()

    def close(self) -> None:
        self.stream.close()


def guard_request(request: httpx2.Request) -> None:
    current = observation.get()
    if current is None:
        raise httpx2.TransportError("unreserved_model_request")
    current.check_deadline()
    if current.requests:
        current.fail("automatic_replay_rejected")
    if len(request.content) > MAX_PROMPT_BYTES:
        current.fail("prompt_too_large")
    current.request_digest = "sha256:" + hashlib.sha256(request.content).hexdigest()
    current.requests += 1


def guard_response(response: httpx2.Response) -> None:
    current = observation.get()
    if current is None:
        raise httpx2.TransportError("unreserved_model_response")
    current.check_deadline()
    if not 100 <= response.status_code <= 599:
        current.fail("invalid_http_status")
    current.http_status = response.status_code
    if 300 <= response.status_code < 400:
        current.fail("redirect_rejected")
    # Ask for identity encoding and reject a server that ignores it. The bound
    # then applies before decompression, including SDK APIStatusError bodies.
    if response.headers.get("content-encoding", "identity").strip().lower() not in {"", "identity"}:
        current.fail("encoded_response_rejected")
    length = response.headers.get("content-length")
    if length is not None and (
        not length.isascii()
        or not length.isdigit()
        or len(length) > 9
        or int(length) > MAX_RESPONSE_BYTES
    ):
        current.fail("response_too_large")
    if (
        200 <= response.status_code < 300
        and response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        current.fail("unsupported_content_type")
    if not isinstance(response.stream, httpx2.SyncByteStream):
        current.fail("unsupported_response_stream")
    if response.is_stream_consumed:
        # Injected transports may return an already buffered response. Real
        # network responses use the guarded stream below before body reads.
        current.response_bytes = len(response.content)
        if current.response_bytes > MAX_RESPONSE_BYTES:
            current.fail("response_too_large")
        current.response_digest = "sha256:" + hashlib.sha256(response.content).hexdigest()
        return
    response.stream = _BoundedStream(response.stream, current)


def guarded_http_client(transport: httpx2.BaseTransport | None = None) -> httpx2.Client:
    # No retry/redirect layer exists in this client. The SDK also receives an
    # explicit zero-retry policy. Event hooks run before httpx/SDK read bodies.
    return httpx2.Client(
        transport=transport,
        follow_redirects=False,
        trust_env=transport is None,
        timeout=httpx2.Timeout(IO_TIMEOUT_SECONDS, connect=5.0),
        headers={"Accept-Encoding": "identity"},
        event_hooks={"request": [guard_request], "response": [guard_response]},
    )
