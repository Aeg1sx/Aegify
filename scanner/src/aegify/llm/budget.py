"""Reserve model work before dispatch and preserve uncertainty after interruption."""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from typing import Literal, get_args

from aegify.models import NATIVE_TOKEN_COUNTERS, ModelCallPhase, ModelCallReceipt, TokenUsage

logger = logging.getLogger(__name__)
Phase = ModelCallPhase
PHASES = frozenset(get_args(Phase))
TOKEN_COUNTERS = NATIVE_TOKEN_COUNTERS
MAX_PROMPT_BYTES = 262_144
MAX_TOTAL_PROMPT_BYTES = 4_000_000
MAX_OUTPUT_TOKENS_REQUESTED = 655_360
MAX_COUNTER = 1_000_000_000_000


def valid_counter(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_COUNTER


@dataclass
class BudgetAllocation:
    verification: int
    remediation: int
    additional_search: int


@dataclass
class TokenBudget:
    """Estimated token admission plus hard call/prompt/output-request caps.

    Token estimates and provider counters cannot enforce an invoice limit.
    Unknown calls keep their reservation; they never replenish the budget.
    """

    total_budget: int
    max_calls: int = 100
    input_tokens_used: int = field(default=0, init=False)
    output_tokens_used: int = field(default=0, init=False)
    allocation: BudgetAllocation = field(init=False)
    _cache_creation: int = field(default=0, init=False)
    _cache_read: int = field(default=0, init=False)
    _unknown_reservations: int = field(default=0, init=False)
    _prompt_bytes: int = field(default=0, init=False)
    _output_requested: int = field(default=0, init=False)
    _rejected: int = field(default=0, init=False)
    _last_error: str = field(default="", init=False)
    _legacy_usage: bool = field(default=False, init=False)
    _calls: list[ModelCallReceipt] = field(default_factory=list, init=False)
    _pending: dict[str, tuple[int, int]] = field(default_factory=dict, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.total_budget) is not int or not 0 <= self.total_budget <= 10_000_000:
            raise ValueError("token budget must be an integer from 0 to 10000000")
        if type(self.max_calls) is not int or not 1 <= self.max_calls <= 250:
            raise ValueError("model call limit must be an integer from 1 to 250")
        self.allocation = BudgetAllocation(
            verification=int(self.total_budget * 0.6),
            remediation=int(self.total_budget * 0.3),
            additional_search=int(self.total_budget * 0.1),
        )

    @property
    def total_used(self) -> int:
        return (
            self.input_tokens_used
            + self.output_tokens_used
            + self._cache_creation
            + self._cache_read
        )

    @property
    def reserved(self) -> int:
        return self._unknown_reservations + sum(amount for _, amount in self._pending.values())

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.total_budget - self.total_used - self.reserved)

    @property
    def estimated_cost_usd(self) -> float | None:
        # A model name and token count do not establish a tariff, cache price,
        # service tier, gateway markup or paid-call outcome.
        return None if self._calls or self._legacy_usage else 0.0

    def can_spend(self, phase: str, estimated_tokens: int) -> bool:
        with self._lock:
            return (
                phase in PHASES
                and type(estimated_tokens) is int
                and estimated_tokens >= 0
                and estimated_tokens <= self.remaining
                and len(self._calls) < self.max_calls
            )

    def reject(self, code: str) -> None:
        with self._lock:
            self._rejected += 1
            self._last_error = code

    def reserve(
        self,
        phase: Phase,
        *,
        estimated_input: int,
        max_output: int,
        prompt_bytes: int,
        model: str,
        request_digest: str,
    ) -> str | None:
        with self._lock:
            if (
                not valid_counter(estimated_input)
                or type(max_output) is not int
                or not 1 <= max_output <= 32_768
                or type(prompt_bytes) is not int
                or not 0 < prompt_bytes <= MAX_PROMPT_BYTES
            ):
                self.reject("invalid_request_limits")
                return None
            amount = estimated_input + max_output
            if (
                not self.can_spend(phase, amount)
                or self._prompt_bytes + prompt_bytes > MAX_TOTAL_PROMPT_BYTES
                or self._output_requested + max_output > MAX_OUTPUT_TOKENS_REQUESTED
            ):
                self.reject("budget_exhausted")
                return None
            call_id = str(uuid.uuid4())
            receipt = ModelCallReceipt(
                id=call_id,
                model=model,
                phase=phase,
                estimated_input_tokens=estimated_input,
                requested_output_tokens=max_output,
                prompt_bytes=prompt_bytes,
                request_digest=request_digest,
            )
            self._pending[call_id] = (len(self._calls), amount)
            self._calls.append(receipt)
            self._prompt_bytes += prompt_bytes
            self._output_requested += max_output
            logger.info("Model call reserved: id=%s phase=%s", call_id, phase)
            return call_id

    def settle(
        self,
        call_id: str,
        *,
        usage: dict[str, int],
        usage_complete: bool,
        state: Literal["completed", "rejected", "unknown"],
        error_code: str = "",
        response_digest: str = "",
        request_digest: str = "",
        response_model: str = "",
        response_id: str = "",
        stop_reason: str = "",
        http_status: int | None = None,
        elapsed_ms: int = 0,
    ) -> None:
        with self._lock:
            if call_id not in self._pending:
                raise ValueError("model reservation is absent or already settled")
            if any(
                key not in TOKEN_COUNTERS or not valid_counter(value)
                for key, value in usage.items()
            ):
                raise ValueError("invalid native usage counter")
            if usage_complete and not {"input_tokens", "output_tokens"} <= usage.keys():
                raise ValueError("complete usage needs both input and output counters")
            index, amount = self._pending[call_id]
            previous = self._calls[index]
            # Construct before mutating accounting so validation failure cannot
            # release a reservation or leave a half-published receipt.
            receipt = ModelCallReceipt(
                **{
                    **previous.model_dump(),
                    "state": state,
                    "usage_status": "reported"
                    if usage_complete
                    else "partial"
                    if usage
                    else "unknown",
                    "reported_usage": dict(usage),
                    "error_code": error_code,
                    "request_digest": request_digest or previous.request_digest,
                    "response_digest": response_digest,
                    "response_model": response_model,
                    "response_id": response_id,
                    "stop_reason": stop_reason,
                    "http_status": http_status,
                    "elapsed_ms": elapsed_ms,
                }
            )
            del self._pending[call_id]
            self.input_tokens_used += usage.get("input_tokens", 0)
            self.output_tokens_used += usage.get("output_tokens", 0)
            self._cache_creation += usage.get("cache_creation_input_tokens", 0)
            self._cache_read += usage.get("cache_read_input_tokens", 0)
            if not usage_complete:
                self._unknown_reservations += max(0, amount - sum(usage.values()))
            self._calls[index] = receipt
            if error_code:
                self._last_error = error_code
            logger.info(
                "Model call finished: id=%s state=%s usage=%s error=%s cost=unknown",
                call_id,
                state,
                receipt.usage_status,
                error_code or "none",
            )

    def record_usage(self, phase: str, input_tokens: int, output_tokens: int) -> None:
        """Compatibility for caller-supplied counters; provenance remains legacy."""
        if (
            phase not in PHASES
            or not valid_counter(input_tokens)
            or not valid_counter(output_tokens)
        ):
            raise ValueError("invalid caller-supplied usage")
        with self._lock:
            self.input_tokens_used += input_tokens
            self.output_tokens_used += output_tokens
            self._legacy_usage = True

    def get_token_usage(self) -> TokenUsage:
        with self._lock:
            unknown = sum(call.usage_status != "reported" for call in self._calls)
            status: Literal["not_used", "reported", "partial", "unknown", "legacy"]
            if not self._calls:
                status = "legacy" if self._legacy_usage else "not_used"
            elif unknown or self._legacy_usage:
                known = any(call.reported_usage for call in self._calls) or self._legacy_usage
                status = "partial" if known else "unknown"
            else:
                status = "reported"
            return TokenUsage(
                input_tokens=self.input_tokens_used,
                output_tokens=self.output_tokens_used,
                cache_creation_input_tokens=self._cache_creation,
                cache_read_input_tokens=self._cache_read,
                total_cost_usd=self.estimated_cost_usd,
                cost_status="not_used" if status == "not_used" else "unavailable",
                usage_status=status,
                calls_started=len(self._calls),
                calls_rejected_before_dispatch=self._rejected,
                calls_with_unknown_usage=unknown,
                reserved_tokens=self.reserved,
                prompt_bytes=self._prompt_bytes,
                output_tokens_requested=self._output_requested,
                last_error_code=self._last_error,
                calls=[call.model_copy(deep=True) for call in self._calls],
            )

    def restore_usage(self, usage: TokenUsage) -> None:
        """Restore settled native receipts into a fresh budget without replenishing it."""
        with self._lock:
            if self._calls or self.total_used or self._legacy_usage or self._pending:
                raise ValueError("usage restoration requires an unused budget")
            if (
                usage.usage_status == "legacy"
                or len(usage.calls) > self.max_calls
                or len({call.id for call in usage.calls}) != len(usage.calls)
                or any(call.state == "dispatched" for call in usage.calls)
            ):
                raise ValueError("usage restoration requires bounded settled native receipts")
            candidate = TokenBudget(self.total_budget, self.max_calls)
            candidate._calls = [call.model_copy(deep=True) for call in usage.calls]
            for call in usage.calls:
                counters = call.reported_usage
                candidate.input_tokens_used += counters.get("input_tokens", 0)
                candidate.output_tokens_used += counters.get("output_tokens", 0)
                candidate._cache_creation += counters.get("cache_creation_input_tokens", 0)
                candidate._cache_read += counters.get("cache_read_input_tokens", 0)
                candidate._prompt_bytes += call.prompt_bytes
                candidate._output_requested += call.requested_output_tokens
                if call.usage_status != "reported":
                    candidate._unknown_reservations += max(
                        0,
                        call.estimated_input_tokens
                        + call.requested_output_tokens
                        - sum(counters.values()),
                    )
            candidate._rejected = usage.calls_rejected_before_dispatch
            candidate._last_error = usage.last_error_code
            if candidate.get_token_usage() != usage:
                raise ValueError("usage snapshot disagrees with native receipts")
            for name in (
                "input_tokens_used",
                "output_tokens_used",
                "_cache_creation",
                "_cache_read",
                "_unknown_reservations",
                "_prompt_bytes",
                "_output_requested",
                "_rejected",
                "_last_error",
                "_calls",
            ):
                setattr(self, name, getattr(candidate, name))
