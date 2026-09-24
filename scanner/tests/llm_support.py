"""Owned scripted responses through the installed SDK; never opens a socket."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from types import TracebackType
from typing import Any

import httpx2
import pytest

from aegify.llm.budget import TokenBudget
from aegify.llm.client import LLMClient
from aegify.llm.transport import guarded_http_client


def message(text: str = '{"verdict":"needs_review"}', **changes: Any) -> dict[str, Any]:
    return {
        "id": "msg_owned_fixture",
        "type": "message",
        "role": "assistant",
        "model": "fixture-model-version",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 12, "output_tokens": 7},
        "content": [{"type": "text", "text": text}],
        **changes,
    }


class RecordedStream(httpx2.SyncByteStream):
    def __init__(
        self,
        body: bytes,
        *,
        fault: BaseException | None = None,
        on_read: Callable[[], None] | None = None,
    ) -> None:
        self.body = body
        self.fault = fault
        self.on_read = on_read
        self.reads = 0
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        for index in range(0, len(self.body), 16_384):
            if self.on_read:
                self.on_read()
            self.reads += 1
            yield self.body[index : index + 16_384]
        if self.fault is not None:
            raise self.fault

    def close(self) -> None:
        self.closed = True


class ScriptedProvider:
    def __init__(
        self,
        body: dict[str, Any] | bytes | None = None,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        handler: Callable[[httpx2.Request], httpx2.Response] | None = None,
        fault: BaseException | None = None,
        on_read: Callable[[], None] | None = None,
        buffered: bool = False,
    ) -> None:
        self.body = body if body is not None else message()
        self.status = status
        self.headers = {"content-type": "application/json", **(headers or {})}
        self.handler = handler
        self.fault = fault
        self.on_read = on_read
        self.buffered = buffered
        self.requests: list[httpx2.Request] = []
        self.streams: list[RecordedStream] = []
        self.clients: list[LLMClient] = []
        self.http_clients: list[httpx2.Client] = []
        self.transport = httpx2.MockTransport(self.dispatch)

    def dispatch(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self.handler:
            return self.handler(request)
        raw = self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()
        if self.buffered:
            return httpx2.Response(self.status, content=raw, headers=self.headers)
        stream = RecordedStream(raw, fault=self.fault, on_read=self.on_read)
        self.streams.append(stream)
        return httpx2.Response(self.status, stream=stream, headers=self.headers)

    def client(self, budget: TokenBudget | None = None) -> LLMClient:
        client = LLMClient(
            api_key="synthetic-unused-key",
            model="fixture-model",
            budget=budget,
            transport=self.transport,
        )
        self.clients.append(client)
        return client

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def local_client(_transport: httpx2.BaseTransport | None = None) -> httpx2.Client:
            client = guarded_http_client(self.transport)
            self.http_clients.append(client)
            return client

        monkeypatch.setattr("aegify.llm.client.guarded_http_client", local_client)

    def __enter__(self) -> ScriptedProvider:
        return self

    def __exit__(
        self,
        _type: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        for client in self.clients:
            client.close()
