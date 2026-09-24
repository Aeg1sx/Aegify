"""Strict Anthropic review responses with bounded, explicit call accounting."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from collections.abc import Mapping
from typing import Any, Literal, cast

import anthropic
import httpx2

from aegify.llm.budget import (
    MAX_PROMPT_BYTES,
    PHASES,
    TOKEN_COUNTERS,
    Phase,
    TokenBudget,
    valid_counter,
)
from aegify.llm.tools import redact_sensitive
from aegify.llm.transport import (
    IO_TIMEOUT_SECONDS,
    HttpObservation,
    guarded_http_client,
    observation,
)

logger = logging.getLogger(__name__)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def strict_json(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )


def _label(value: object, limit: int = 256) -> str:
    return str(redact_sensitive(value))[:limit] if isinstance(value, str) else ""


def _usage(value: object) -> tuple[dict[str, int], bool]:
    if not isinstance(value, Mapping):
        return {}, False
    counters = {key: value[key] for key in TOKEN_COUNTERS if valid_counter(value.get(key))}
    complete = all(valid_counter(value.get(key)) for key in ("input_tokens", "output_tokens"))
    complete = complete and all(
        value.get(key) is None or valid_counter(value[key]) for key in TOKEN_COUNTERS[2:]
    )
    return counters, complete


class LLMClient:
    """One reserved SDK request per call; no provider output executes as a tool."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-5",
        budget: TokenBudget | None = None,
        base_url: str | None = None,
        *,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        if not isinstance(model, str) or not 0 < len(model) <= 256:
            raise ValueError("model must be a nonempty name of at most 256 characters")
        # Aegify's --verbose must not turn SDK request bodies into CI logs.
        # Our own fixed-schema call events remain available at INFO/DEBUG.
        for name in ("anthropic", "anthropic._base_client", "httpx2", "httpcore", "httpcore2"):
            logging.getLogger(name).setLevel(logging.WARNING)
        self.client = anthropic.Anthropic(
            api_key=api_key,
            base_url=base_url,
            max_retries=0,
            timeout=httpx2.Timeout(IO_TIMEOUT_SECONDS, connect=5.0),
            http_client=guarded_http_client(transport),
        )
        self.model = model
        self.budget = budget or TokenBudget(total_budget=100_000)

    def close(self) -> None:
        self.client.close()

    def query(
        self,
        system: str,
        user_prompt: str,
        phase: str = "verification",
        max_tokens: int = 4096,
        *,
        require_batch: bool = False,
    ) -> dict[str, Any] | list[Any] | None:
        if (
            not isinstance(phase, str)
            or phase not in PHASES
            or type(max_tokens) is not int
            or not 1 <= max_tokens <= 32_768
        ):
            self.budget.reject("invalid_request_limits")
            return None
        if not isinstance(system, str) or not isinstance(user_prompt, str):
            self.budget.reject("invalid_prompt")
            return None
        # Reject instead of silently truncating a structured evidence snapshot.
        if len(system) + len(user_prompt) > MAX_PROMPT_BYTES:
            self.budget.reject("prompt_too_large")
            return None
        safe_system, safe_prompt = str(redact_sensitive(system)), str(redact_sensitive(user_prompt))
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": safe_system,
            "messages": [{"role": "user", "content": safe_prompt}],
        }
        try:
            request_bytes = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except UnicodeError:
            self.budget.reject("invalid_prompt")
            return None
        if len(request_bytes) > MAX_PROMPT_BYTES:
            self.budget.reject("prompt_too_large")
            return None
        call_id = self.budget.reserve(
            cast(Phase, phase),
            estimated_input=(len(request_bytes) + 3) // 4,
            max_output=max_tokens,
            prompt_bytes=len(request_bytes),
            model=_label(self.model),
            request_digest="sha256:" + hashlib.sha256(request_bytes).hexdigest(),
        )
        if call_id is None:
            return None
        current = HttpObservation()
        context_token = observation.set(current)
        usage: dict[str, int] = {}
        complete = False
        state: Literal["completed", "rejected", "unknown"] = "unknown"
        error_code = "interrupted"
        response_model = response_id = stop_reason = ""
        try:
            with self.client.messages.with_streaming_response.create(
                model=self.model,
                max_tokens=max_tokens,
                system=safe_system,
                messages=[{"role": "user", "content": safe_prompt}],
            ) as raw:
                body = b"".join(raw.iter_bytes())
            state = "rejected"
            data = strict_json(body.decode("utf-8"))
            if not isinstance(data, dict):
                error_code = "invalid_response"
                return None
            usage, complete = _usage(data.get("usage"))
            response_model, response_id = _label(data.get("model")), _label(data.get("id"))
            stop_reason = _label(data.get("stop_reason"), 80)
            if (
                data.get("type") != "message"
                or data.get("role") != "assistant"
                or not response_model
                or not response_id
            ):
                error_code = "invalid_response"
                return None
            if data.get("stop_reason") != "end_turn":
                error_code = "incomplete_response"
                return None
            content = data.get("content")
            if not isinstance(content, list) or not 1 <= len(content) <= 64:
                error_code = "invalid_content"
                return None
            parts: list[str] = []
            for block in content:
                if not isinstance(block, dict):
                    error_code = "invalid_content"
                    return None
                if block.get("type") in {"thinking", "redacted_thinking"}:
                    continue
                if block.get("type") != "text" or not isinstance(block.get("text"), str):
                    error_code = "unsupported_content"
                    return None
                parts.append(block["text"])
            text = "".join(parts)
            if len(text.encode("utf-8")) > 1_048_576:
                error_code = "model_text_too_large"
                return None
            parsed = self._extract_json(text)
            if parsed is None or (
                require_batch
                and isinstance(parsed, list)
                and any(not isinstance(item, dict) for item in parsed)
            ):
                error_code = "invalid_review_json"
                return None
            # A valid narrative with unavailable usage remains usable evidence,
            # but its reservation and unknown billing state remain visible.
            state, error_code = "completed", "" if complete else "usage_unavailable"
            safe = redact_sensitive(parsed)
            return safe if isinstance(safe, (dict, list)) else None
        except anthropic.APITimeoutError, httpx2.TimeoutException:
            error_code = current.error_code or "transport_timeout"
            return None
        except anthropic.APIStatusError, anthropic.APIConnectionError, httpx2.TransportError:
            error_code = current.error_code or "provider_transport_error"
            return None
        except ValueError, TypeError, RecursionError, UnicodeError:
            error_code = current.error_code or "invalid_response"
            return None
        except Exception:
            # Exception text may include provider bodies, prompts or credentials.
            error_code = current.error_code or "provider_client_error"
            return None
        finally:
            observation.reset(context_token)
            self.budget.settle(
                call_id,
                usage=usage,
                usage_complete=complete,
                state=state,
                error_code=error_code,
                request_digest=current.request_digest,
                response_digest=current.response_digest,
                response_model=response_model,
                response_id=response_id,
                stop_reason=stop_reason,
                http_status=current.http_status,
                elapsed_ms=max(0, int((time.monotonic() - current.started) * 1000)),
            )
            if error_code:
                logger.warning("Model review unavailable or incomplete: %s", error_code)

    def query_batch(
        self,
        system: str,
        user_prompt: str,
        phase: str = "verification",
        max_tokens: int = 8192,
    ) -> list[dict[str, Any]]:
        result = self.query(system, user_prompt, phase, max_tokens, require_batch=True)
        if result is None:
            return []
        if isinstance(result, list):
            return cast(list[dict[str, Any]], result)
        return [result]

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | list[Any] | None:
        """Require one complete JSON document; prose/fences are not evidence."""
        try:
            value = strict_json(text)
            return value if isinstance(value, (dict, list)) else None
        except ValueError, RecursionError:
            return None
