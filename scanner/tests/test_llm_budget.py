from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import Any

import pytest
from pydantic import ValidationError

from aegify.config import LLMConfig
from aegify.llm.budget import (
    MAX_OUTPUT_TOKENS_REQUESTED,
    MAX_PROMPT_BYTES,
    MAX_TOTAL_PROMPT_BYTES,
    TokenBudget,
)
from aegify.models import ModelCallReceipt, TokenUsage


def reserve(budget: TokenBudget, **changes: Any) -> str | None:
    return budget.reserve(
        "verification",
        **{
            "estimated_input": 40,
            "max_output": 60,
            "prompt_bytes": 160,
            "model": "fixture-model",
            "request_digest": "sha256:" + "a" * 64,
            **changes,
        },
    )


def test_concurrent_admission_and_exactly_once_settlement() -> None:
    budget = TokenBudget(total_budget=100)
    barrier = Barrier(8)

    def attempt(_index: int) -> str | None:
        barrier.wait()
        return reserve(budget)

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = [call for call in pool.map(attempt, range(8)) if call]
    assert len(admitted) == 1 and budget.remaining == 0
    budget.settle(admitted[0], usage={}, usage_complete=False, state="unknown")
    assert budget.remaining == 0 and budget.get_token_usage().reserved_tokens == 100
    with pytest.raises(ValueError, match="already settled"):
        budget.settle(admitted[0], usage={}, usage_complete=False, state="unknown")
    assert budget.get_token_usage().calls_rejected_before_dispatch == 7


@pytest.mark.parametrize(
    "usage,complete",
    [
        ({"input_tokens": -1, "output_tokens": 5}, True),
        ({"input_tokens": True, "output_tokens": 5}, True),
        ({"input_tokens": 1.5, "output_tokens": 5}, True),
        ({"input_tokens": 10**13, "output_tokens": 5}, True),
        ({"input_tokens": 1, "reasoning_tokens": 5}, False),
        ({"input_tokens": 1}, True),
    ],
)
def test_invalid_settlement_cannot_release_reservation(usage: Any, complete: bool) -> None:
    budget = TokenBudget(total_budget=100)
    call = reserve(budget)
    assert call is not None
    before = budget.get_token_usage().model_dump()
    with pytest.raises(ValueError):
        budget.settle(call, usage=usage, usage_complete=complete, state="completed")
    assert budget.get_token_usage().model_dump() == before


def test_incomplete_report_retains_unresolved_part_and_snapshots_are_independent() -> None:
    budget = TokenBudget(total_budget=200)
    call = reserve(budget)
    assert call
    budget.settle(call, usage={"input_tokens": 20}, usage_complete=False, state="completed")
    snapshot = budget.get_token_usage()
    assert snapshot.reported_tokens == 20 and snapshot.reserved_tokens == 80
    assert snapshot.usage_status == "partial" and budget.remaining == 100
    snapshot.calls[0].reported_usage["input_tokens"] = 999
    assert budget.get_token_usage().calls[0].reported_usage["input_tokens"] == 20


def test_native_cache_counters_count_once_and_underestimated_usage_blocks_next_call() -> None:
    budget = TokenBudget(total_budget=100)
    call = reserve(budget)
    assert call
    budget.settle(
        call,
        usage={
            "input_tokens": 10,
            "output_tokens": 20,
            "cache_read_input_tokens": 30,
            "cache_creation_input_tokens": 100,
        },
        usage_complete=True,
        state="completed",
    )
    assert budget.total_used == 160 and budget.remaining == 0
    assert reserve(budget) is None
    assert budget.get_token_usage().reserved_tokens == 0


def test_reported_zero_followed_by_unknown_remains_partial_and_unknown_cost() -> None:
    budget = TokenBudget(total_budget=200)
    first = reserve(budget)
    assert first
    budget.settle(
        first, usage={"input_tokens": 0, "output_tokens": 0}, usage_complete=True, state="completed"
    )
    assert reserve(budget)
    usage = budget.get_token_usage()
    assert usage.usage_status == "partial" and usage.calls_with_unknown_usage == 1
    assert usage.total_cost_usd is None


@pytest.mark.parametrize("cap", ["prompt", "output", "calls"])
def test_hard_caps_apply_even_when_provider_reports_zero(cap: str) -> None:
    budget = TokenBudget(total_budget=10_000_000, max_calls=25)
    kwargs = {"estimated_input": 0, "max_output": 1, "prompt_bytes": 1}
    count = 25
    if cap == "prompt":
        kwargs["prompt_bytes"] = MAX_PROMPT_BYTES
        count = MAX_TOTAL_PROMPT_BYTES // MAX_PROMPT_BYTES
    elif cap == "output":
        kwargs["max_output"] = 32_768
        count = MAX_OUTPUT_TOKENS_REQUESTED // 32_768
    for _ in range(count):
        call = reserve(budget, **kwargs)
        assert call
        budget.settle(
            call,
            usage={"input_tokens": 0, "output_tokens": 0},
            usage_complete=True,
            state="completed",
        )
    assert reserve(budget, **kwargs) is None
    assert budget.get_token_usage().calls_started == count


@pytest.mark.parametrize(
    "payload",
    [
        {"input_tokens": -1},
        {"output_tokens": True},
        {"input_tokens": "2"},
        {"total_cost_usd": float("nan")},
        {"total_cost_usd": float("inf")},
        {"total_cost_usd": True},
        {"total_cost_usd": -1},
        {"total_cost_usd": 0.0, "cost_status": "unavailable"},
        {"calls_started": 1, "cost_status": "not_used"},
        {"reserved_tokens": 1, "cost_status": "not_used"},
    ],
)
def test_import_cannot_claim_invalid_counters_or_free_unknown_calls(
    payload: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        TokenUsage.model_validate(payload)


def test_legacy_costs_remain_labeled_estimates_and_zero_is_not_paid_call_evidence() -> None:
    old = TokenUsage(input_tokens=12, output_tokens=7, total_cost_usd=0.003)
    assert old.usage_status == "legacy" and old.cost_status == "legacy_estimate"
    assert old.total_cost_usd == 0.003
    zero = TokenUsage(input_tokens=12, total_cost_usd=0)
    assert zero.cost_status == "unavailable" and zero.total_cost_usd is None
    assert TokenUsage.model_validate_json(old.model_dump_json()) == old
    assert TokenUsage.model_validate_json(zero.model_dump_json()) == zero
    unused = TokenUsage()
    assert unused.total_cost_usd == 0 and unused.cost_status == "not_used"
    assert TokenUsage(total_cost_usd=None).cost_status == "unavailable"
    legacy_budget = TokenBudget(100)
    legacy_budget.record_usage("verification", 21, 7)
    assert legacy_budget.get_token_usage().usage_status == "legacy"
    assert legacy_budget.estimated_cost_usd is None


@pytest.mark.parametrize(
    "changes",
    [
        {"reported_usage": {"input_tokens": True}},
        {"reported_usage": {"input_tokens": -1}},
        {"reported_usage": {"input_tokens": 10**13}},
        {"reported_usage": {"unknown_counter": 1}},
        {"usage_status": "reported", "reported_usage": {"input_tokens": 1}},
        {"usage_status": "unknown", "reported_usage": {"input_tokens": 1}},
        {"usage_status": "partial", "reported_usage": {}},
        {"request_digest": "unbound"},
        {"requested_output_tokens": True},
    ],
)
def test_receipts_reject_malformed_imports(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ModelCallReceipt.model_validate(
            {
                "id": "fixture-call",
                "model": "fixture-model",
                "phase": "verification",
                "state": "completed",
                "estimated_input_tokens": 1,
                "requested_output_tokens": 10,
                "prompt_bytes": 4,
                "request_digest": "sha256:" + "a" * 64,
                **changes,
            }
        )


@pytest.mark.parametrize(
    "limits",
    [
        {"token_budget": -1},
        {"token_budget": True},
        {"max_calls": 251},
        {"max_calls": 0},
        {"batch_size": 0},
        {"max_retries": 3},
        {"verify_threshold": float("nan")},
    ],
)
def test_configuration_enforces_bounded_calls_and_zero_retry(limits: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        LLMConfig.model_validate(limits)
