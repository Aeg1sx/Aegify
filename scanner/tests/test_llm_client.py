from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import anthropic
import httpx2
import pytest

from aegify.llm.budget import MAX_PROMPT_BYTES, TokenBudget
from aegify.llm.transport import MAX_RESPONSE_BYTES, observation
from tests.llm_support import ScriptedProvider, message


def test_actual_sdk_normal_completion_binds_digests_and_native_usage() -> None:
    envelope = message(
        usage={
            "input_tokens": 12,
            "output_tokens": 7,
            "cache_creation_input_tokens": 4,
            "cache_read_input_tokens": 9,
            "cache_creation": {"ephemeral_5m_input_tokens": 4},
        }
    )
    with ScriptedProvider(envelope) as provider:
        client = provider.client()
        assert client.query("system", "prompt") == {"verdict": "needs_review"}
        assert len(provider.requests) == 1
        request = provider.requests[0]
        assert request.method == "POST" and request.url.path == "/v1/messages"
        assert request.headers["accept-encoding"] == "identity"
        payload = json.loads(request.content)
        assert payload["model"] == "fixture-model"
        assert payload["messages"] == [{"role": "user", "content": "prompt"}]
        usage = client.budget.get_token_usage()
        assert usage.reported_tokens == 32
        assert usage.total_cost_usd is None and usage.cost_status == "unavailable"
        assert usage.usage_status == "reported" and usage.reserved_tokens == 0
        receipt = usage.calls[0]
        assert receipt.state == "completed" and receipt.http_status == 200
        assert (
            receipt.model == "fixture-model" and receipt.response_model == "fixture-model-version"
        )
        assert receipt.response_id == "msg_owned_fixture" and receipt.stop_reason == "end_turn"
        assert receipt.request_digest == "sha256:" + hashlib.sha256(request.content).hexdigest()
        assert receipt.prompt_bytes == len(request.content)
        assert (
            receipt.response_digest
            == "sha256:" + hashlib.sha256(provider.streams[0].body).hexdigest()
        )
        assert provider.streams[0].closed


def test_hidden_reasoning_and_source_do_not_enter_receipts_or_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    envelope = message(
        content=[
            {"type": "thinking", "thinking": "private fixture reasoning"},
            {"type": "text", "text": '{"reasoning":'},
            {"type": "redacted_thinking", "data": "opaque fixture reasoning"},
            {"type": "text", "text": '"sk-ant-abcdefghijklmnopqrstuvwxyz"}'},
        ]
    )
    caplog.set_level(logging.DEBUG)
    with ScriptedProvider(envelope) as provider:
        client = provider.client()
        assert client.query("system", "token=super-secret source-marker") == {
            "reasoning": "[REDACTED_API_KEY]"
        }
        assert "super-secret" not in provider.requests[0].content.decode()
        assert "[REDACTED]" in provider.requests[0].content.decode()
        retained = client.budget.get_token_usage().model_dump_json() + caplog.text
        for private in ("super-secret", "private fixture", "opaque fixture", "source-marker"):
            assert private not in retained
        assert "cost=unknown" in caplog.text


@pytest.mark.parametrize(
    "stop", ["max_tokens", "refusal", "tool_use", "pause_turn", None, "new_reason"]
)
def test_nonnormal_completion_is_not_a_review_but_retains_usage(stop: Any) -> None:
    with ScriptedProvider(message(stop_reason=stop)) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        usage = client.budget.get_token_usage()
        assert usage.reported_tokens == 19 and usage.reserved_tokens == 0
        assert usage.calls[0].state == "rejected" and usage.last_error_code == "incomplete_response"
        assert usage.total_cost_usd is None


@pytest.mark.parametrize(
    "text",
    [
        '```json\n{"ok":true}\n```',
        'prose {"ok":true}',
        '{"ok":true} trailing',
        '{"ok":true,"ok":false}',
        '{"number":NaN}',
        '{"number":Infinity}',
        '{"number":1e309}',
        '{"unfinished":',
        "null",
        "true",
    ],
)
def test_review_requires_one_complete_unambiguous_json_document(text: str) -> None:
    with ScriptedProvider(message(text)) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        assert client.budget.get_token_usage().last_error_code == "invalid_review_json"


@pytest.mark.parametrize(
    "content",
    [
        [],
        "text",
        [None],
        [{"type": "tool_use", "name": "not_executed"}],
        [{"type": "text", "text": 3}],
        [{"type": "thinking", "thinking": "only hidden"}],
    ],
)
def test_unusable_content_abstains(content: Any) -> None:
    with ScriptedProvider(message(content=content)) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        assert client.budget.get_token_usage().calls[0].state == "rejected"


@pytest.mark.parametrize(
    "body",
    [
        b'{"usage":{},"usage":{"input_tokens":0,"output_tokens":0}}',
        b'{"usage":{"input_tokens":1e309}}',
        b"[]",
        b"\xff",
        b'{"partial":',
    ],
)
def test_outer_envelope_must_be_strict_json(body: bytes) -> None:
    with ScriptedProvider(body) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        usage = client.budget.get_token_usage()
        assert usage.usage_status == "unknown" and usage.reserved_tokens > 0
        assert usage.last_error_code == "invalid_response"


@pytest.mark.parametrize(
    "key,value", [("type", "error"), ("role", "user"), ("model", None), ("id", "")]
)
def test_missing_or_invalid_response_identity_does_not_pass(key: str, value: Any) -> None:
    with ScriptedProvider(message(**{key: value})) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        assert client.budget.get_token_usage().last_error_code == "invalid_response"


@pytest.mark.parametrize(
    "native,status,count",
    [
        (None, "unknown", 0),
        ({}, "unknown", 0),
        ({"input_tokens": -1, "output_tokens": 7}, "partial", 7),
        ({"input_tokens": True, "output_tokens": "7"}, "unknown", 0),
        ({"input_tokens": 10**13, "output_tokens": 0}, "partial", 0),
        ({"input_tokens": 12, "output_tokens": 7, "cache_read_input_tokens": -4}, "partial", 19),
    ],
)
def test_malformed_usage_keeps_reservation_and_never_invents_free_call(
    native: Any,
    status: str,
    count: int,
) -> None:
    with ScriptedProvider(message(usage=native)) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is not None
        usage = client.budget.get_token_usage()
        assert usage.usage_status == status and usage.reported_tokens == count
        assert usage.calls_with_unknown_usage == 1 and usage.reserved_tokens > 0
        assert usage.calls[0].state == "completed"
        assert usage.total_cost_usd is None and usage.last_error_code == "usage_unavailable"


@pytest.mark.parametrize("status", [429, 500, 503])
def test_sdk_errors_do_not_retry_or_log_error_body(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with ScriptedProvider({"error": "private-provider-body"}, status=status) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        assert len(provider.requests) == 1
        usage = client.budget.get_token_usage()
        assert usage.calls[0].http_status == status
        assert usage.total_cost_usd is None and usage.reserved_tokens > 0
        assert provider.streams[0].closed and "private-provider-body" not in caplog.text


@pytest.mark.parametrize("status", [200, 503])
@pytest.mark.parametrize("buffered", [False, True])
def test_success_and_sdk_error_bodies_share_size_bound(status: int, buffered: bool) -> None:
    with ScriptedProvider(
        b" " * (MAX_RESPONSE_BYTES + 1),
        status=status,
        headers={"content-length": "1"},
        buffered=buffered,
    ) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        usage = client.budget.get_token_usage()
        assert usage.last_error_code == "response_too_large"
        assert usage.calls[0].response_digest == ""
        assert usage.reserved_tokens > 0 and len(provider.requests) == 1
        if not buffered:
            assert provider.streams[0].closed


@pytest.mark.parametrize(
    "status,headers,error",
    [
        (302, {"location": "https://unused.example.test/"}, "redirect_rejected"),
        (200, {"content-encoding": "gzip"}, "encoded_response_rejected"),
        (503, {"content-encoding": "br"}, "encoded_response_rejected"),
        (200, {"content-length": "99999999999"}, "response_too_large"),
        (503, {"content-length": "-1"}, "response_too_large"),
        (200, {"content-type": "text/html"}, "unsupported_content_type"),
    ],
)
def test_unsafe_headers_stop_before_body_read(
    status: int, headers: dict[str, str], error: str
) -> None:
    with ScriptedProvider(status=status, headers=headers) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        assert client.budget.get_token_usage().last_error_code == error
        assert provider.streams[0].reads == 0 and provider.streams[0].closed
        assert len(provider.requests) == 1


def test_mid_body_timeout_keeps_unknown_reservation() -> None:
    with ScriptedProvider(fault=httpx2.ReadTimeout("private-error-content")) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        usage = client.budget.get_token_usage()
        assert usage.last_error_code == "transport_timeout" and usage.calls[0].response_digest == ""
        assert usage.usage_status == "unknown" and usage.reserved_tokens > 0
        assert provider.streams[0].closed


def test_body_deadline_is_observed_between_reads() -> None:
    def age_call() -> None:
        current = observation.get()
        assert current is not None
        current.started -= 61

    with ScriptedProvider(on_read=age_call) as provider:
        client = provider.client()
        assert client.query("system", "prompt") is None
        assert client.budget.get_token_usage().last_error_code == "body_deadline_exceeded"
        assert provider.streams[0].closed


def test_interrupt_settles_in_finally_without_replaying() -> None:
    with ScriptedProvider(fault=KeyboardInterrupt()) as provider:
        client = provider.client()
        with pytest.raises(KeyboardInterrupt):
            client.query("system", "prompt")
        usage = client.budget.get_token_usage()
        assert usage.calls_started == 1 and usage.calls[0].state == "unknown"
        assert usage.last_error_code == "interrupted" and usage.reserved_tokens > 0
        assert observation.get() is None and provider.streams[0].closed


def test_batched_response_cannot_silently_drop_malformed_items() -> None:
    with ScriptedProvider(message('[{"idx":0},null,"bad"]')) as provider:
        client = provider.client()
        assert client.query_batch("system", "prompt") == []
        assert client.budget.get_token_usage().last_error_code == "invalid_review_json"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"phase": "unknown"},
        {"max_tokens": True},
        {"max_tokens": -1},
        {"max_tokens": 32_769},
        {"user_prompt": "\ud800"},
        {"user_prompt": "한" * 100_000},
        {"user_prompt": "x" * MAX_PROMPT_BYTES},
    ],
)
def test_invalid_or_oversized_requests_never_reach_sdk(kwargs: dict[str, Any]) -> None:
    with ScriptedProvider() as provider:
        client = provider.client()
        assert client.query(**{"system": "system", "user_prompt": "prompt", **kwargs}) is None
        usage = client.budget.get_token_usage()
        assert not provider.requests and usage.calls_started == 0
        assert usage.calls_rejected_before_dispatch == 1 and usage.total_cost_usd == 0


def test_reservation_and_call_cap_block_further_requests() -> None:
    with ScriptedProvider(message(usage=None)) as provider:
        client = provider.client(TokenBudget(total_budget=4200))
        assert client.query("system", "prompt") is not None
        assert client.query("system", "prompt") is None
        assert len(provider.requests) == 1
    with ScriptedProvider(message(usage={"input_tokens": 0, "output_tokens": 0})) as provider:
        client = provider.client(TokenBudget(total_budget=100_000, max_calls=1))
        assert client.query("system", "prompt") is not None
        assert client.query("system", "prompt") is None
        assert (
            len(provider.requests) == 1 and client.budget.get_token_usage().total_cost_usd is None
        )


def test_underlying_sdk_cannot_be_called_without_reservation() -> None:
    with ScriptedProvider() as provider:
        client = provider.client()
        with pytest.raises(anthropic.APIConnectionError):
            client.client.messages.create(
                model="fixture-model",
                max_tokens=1,
                messages=[{"role": "user", "content": "fixture"}],
            )
        assert not provider.requests
