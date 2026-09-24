"""One usage/cost vocabulary for CLI and generated CI reports."""

from aegify.models import TokenUsage


def has_model_activity(usage: TokenUsage) -> bool:
    return usage.cost_status != "not_used" or usage.calls_rejected_before_dispatch > 0


def format_token_usage(usage: TokenUsage) -> str:
    if usage.cost_status == "legacy_estimate" and usage.total_cost_usd is not None:
        cost = f"Legacy estimate: ${usage.total_cost_usd:.4f} (unverified)"
    elif usage.cost_status == "not_used":
        cost = "Cost: no model call"
    else:
        cost = "Cost: unknown (check provider billing)"
    calls = str(usage.calls_started) if usage.usage_status != "legacy" else "not recorded"
    parts = [
        f"AI calls: {calls}",
        f"Reported tokens: {usage.reported_tokens:,} ({usage.usage_status})",
    ]
    if usage.calls_with_unknown_usage:
        parts.append(f"Usage incomplete: {usage.calls_with_unknown_usage} calls")
    if usage.reserved_tokens:
        parts.append(f"Unresolved token reservation: {usage.reserved_tokens:,}")
    if usage.calls_rejected_before_dispatch:
        parts.append(f"Not dispatched: {usage.calls_rejected_before_dispatch}")
    return " | ".join([*parts, cost])
