from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from aegify.llm.client import LLMClient


class _Messages:
    def __init__(self, text: str = '{"verdict":"needs_review"}') -> None:
        self.kwargs: dict[str, Any] = {}
        self.text = text

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self.kwargs = kwargs
        return SimpleNamespace(
            usage=SimpleNamespace(input_tokens=12, output_tokens=7),
            content=[
                SimpleNamespace(type="thinking", thinking="bounded"),
                SimpleNamespace(type="text", text=self.text),
            ],
        )


def test_anthropic_v1_messages_contract_and_latest_default_model() -> None:
    client = LLMClient(api_key="fixture")
    messages = _Messages()
    client.client = SimpleNamespace(messages=messages)  # type: ignore[assignment]

    result = client.query("system", "prompt")

    assert result == {"verdict": "needs_review"}
    assert messages.kwargs["model"] == "claude-opus-5"
    assert messages.kwargs["messages"] == [{"role": "user", "content": "prompt"}]
    assert client.budget.input_tokens_used == 12
    assert client.budget.output_tokens_used == 7


def test_client_redacts_model_input_and_structured_output() -> None:
    client = LLMClient(api_key="fixture")
    messages = _Messages('{"reasoning":"sk-ant-abcdefghijklmnopqrstuvwxyz"}')
    client.client = SimpleNamespace(messages=messages)  # type: ignore[assignment]

    result = client.query("system", "token=super-secret")

    assert messages.kwargs["messages"][0]["content"] == "token=[REDACTED]"
    assert result == {"reasoning": "[REDACTED_API_KEY]"}


def test_batch_filters_non_object_items_and_unclosed_fences_do_not_crash() -> None:
    client = LLMClient(api_key="fixture")
    messages = _Messages('[{"verdict":"needs_review"}, null, "bad"]')
    client.client = SimpleNamespace(messages=messages)  # type: ignore[assignment]
    assert client.query_batch("system", "prompt") == [{"verdict": "needs_review"}]
    assert LLMClient._extract_json("```json\nnot-json") is None
