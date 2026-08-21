"""Token budget manager for LLM API calls."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Approximate pricing per 1M tokens (Claude Opus 4.6)
INPUT_COST_PER_1M = 15.0  # $15 per 1M input tokens
OUTPUT_COST_PER_1M = 75.0  # $75 per 1M output tokens


@dataclass
class BudgetAllocation:
    """Budget allocation for different analysis phases."""

    verification: int  # 60% default
    remediation: int  # 30% default
    additional_search: int  # 10% default


@dataclass
class TokenBudget:
    """Manages token budget for LLM operations."""

    total_budget: int
    input_tokens_used: int = 0
    output_tokens_used: int = 0
    allocation: BudgetAllocation = field(init=False)

    # Phase usage tracking
    verification_used: int = 0
    remediation_used: int = 0
    additional_used: int = 0

    def __post_init__(self) -> None:
        self.allocation = BudgetAllocation(
            verification=int(self.total_budget * 0.6),
            remediation=int(self.total_budget * 0.3),
            additional_search=int(self.total_budget * 0.1),
        )

    @property
    def total_used(self) -> int:
        return self.input_tokens_used + self.output_tokens_used

    @property
    def remaining(self) -> int:
        return max(0, self.total_budget - self.total_used)

    @property
    def estimated_cost_usd(self) -> float:
        input_cost = (self.input_tokens_used / 1_000_000) * INPUT_COST_PER_1M
        output_cost = (self.output_tokens_used / 1_000_000) * OUTPUT_COST_PER_1M
        return round(input_cost + output_cost, 4)

    def can_spend(self, phase: str, estimated_tokens: int) -> bool:
        """Check if there's budget for the estimated token usage."""
        if self.total_used + estimated_tokens > self.total_budget:
            logger.warning(
                "Budget exceeded: %d used of %d, need %d more",
                self.total_used,
                self.total_budget,
                estimated_tokens,
            )
            return False

        phase_budget = getattr(self.allocation, phase, 0)
        phase_used = getattr(self, f"{phase}_used", 0)
        if phase_used + estimated_tokens > phase_budget:
            logger.warning(
                "Phase '%s' budget exceeded: %d used of %d",
                phase,
                phase_used,
                phase_budget,
            )
            # Allow using other phases' remaining budget
            return self.remaining >= estimated_tokens

        return True

    def record_usage(self, phase: str, input_tokens: int, output_tokens: int) -> None:
        """Record token usage for a phase."""
        self.input_tokens_used += input_tokens
        self.output_tokens_used += output_tokens
        total = input_tokens + output_tokens

        match phase:
            case "verification":
                self.verification_used += total
            case "remediation":
                self.remediation_used += total
            case "additional_search":
                self.additional_used += total

        logger.debug(
            "Token usage: phase=%s, input=%d, output=%d, total_used=%d/%d, cost=$%.4f",
            phase,
            input_tokens,
            output_tokens,
            self.total_used,
            self.total_budget,
            self.estimated_cost_usd,
        )
