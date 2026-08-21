"""Anthropic API client wrapper for CodeGuard."""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from codeguard.llm.budget import TokenBudget

logger = logging.getLogger(__name__)


class LLMClient:
    """Wrapper around the Anthropic API with budget management."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-4-6",
        budget: TokenBudget | None = None,
        base_url: str | None = None,
    ) -> None:
        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        self.client = anthropic.Anthropic(**client_kwargs)
        self.model = model
        self.budget = budget or TokenBudget(total_budget=100_000)

    def query(
        self,
        system: str,
        user_prompt: str,
        phase: str = "verification",
        max_tokens: int = 4096,
    ) -> dict[str, Any] | list[Any] | None:
        """Send a query to the LLM and return parsed JSON response."""
        # Estimate tokens (rough: 4 chars ≈ 1 token)
        estimated_input = (len(system) + len(user_prompt)) // 4
        estimated_total = estimated_input + max_tokens

        if not self.budget.can_spend(phase, estimated_total):
            logger.warning("Skipping LLM call: budget exceeded for phase '%s'", phase)
            return None

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user_prompt}],
            )

            # Record actual usage
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            self.budget.record_usage(phase, input_tokens, output_tokens)

            # Extract text response
            text = ""
            for block in response.content:
                if block.type == "text":
                    text = block.text
                    break

            if not text:
                return None

            # Parse JSON from response
            return self._extract_json(text)

        except anthropic.APIError as e:
            logger.error("Anthropic API error: %s", e)
            return None

    def query_batch(
        self,
        system: str,
        user_prompt: str,
        phase: str = "verification",
        max_tokens: int = 8192,
    ) -> list[dict[str, Any]]:
        """Send a batch query and return parsed JSON array response."""
        result = self.query(system, user_prompt, phase, max_tokens)
        if result is None:
            return []
        if isinstance(result, list):
            return result
        return [result]

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | list[Any] | None:
        """Extract JSON from LLM response text."""
        # Try direct parse
        try:
            return LLMClient._validated_json(json.loads(text))
        except json.JSONDecodeError:
            pass

        # Try extracting from code block
        for marker in ("```json", "```"):
            if marker in text:
                start = text.index(marker) + len(marker)
                end = text.index("```", start)
                try:
                    return LLMClient._validated_json(json.loads(text[start:end].strip()))
                except (json.JSONDecodeError, ValueError):
                    pass

        # Try finding JSON object/array in text
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = text.find(start_char)
            end = text.rfind(end_char)
            if start != -1 and end > start:
                try:
                    return LLMClient._validated_json(json.loads(text[start : end + 1]))
                except json.JSONDecodeError:
                    pass

        logger.warning("Failed to extract JSON from LLM response")
        return None

    @staticmethod
    def _validated_json(value: Any) -> dict[str, Any] | list[Any] | None:
        if isinstance(value, (dict, list)):
            return value
        return None
