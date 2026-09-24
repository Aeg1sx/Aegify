"""Bind ordinary scanner review output without changing deterministic facts."""

from __future__ import annotations

import math
from typing import Any

from aegify.models import AIReview, AIReviewVerdict, Finding


def bind_batch(results: list[dict[str, Any]], count: int) -> dict[int, dict[str, Any]] | None:
    bound: dict[int, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            return None
        indices = [result[key] for key in ("idx", "finding_index") if key in result]
        if not indices or any(
            type(index) is not int or not 0 <= index < count for index in indices
        ):
            return None
        index = indices[0]
        if any(other != index for other in indices) or index in bound:
            return None
        bound[index] = result
    return bound


def _text(value: object, limit: int = 4000) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _evidence(value: object) -> list[str] | None:
    if (
        not isinstance(value, list)
        or len(value) > 20
        or any(not isinstance(item, str) for item in value)
    ):
        return None
    return [item[:2000] for item in value]


def review_from_result(result: dict[str, Any]) -> AIReview:
    verdicts = {
        "TRUE_POSITIVE": AIReviewVerdict.LIKELY_TRUE_POSITIVE,
        "LIKELY_TRUE_POSITIVE": AIReviewVerdict.LIKELY_TRUE_POSITIVE,
        "FALSE_POSITIVE": AIReviewVerdict.LIKELY_FALSE_POSITIVE,
        "LIKELY_FALSE_POSITIVE": AIReviewVerdict.LIKELY_FALSE_POSITIVE,
        "NEEDS_REVIEW": AIReviewVerdict.NEEDS_REVIEW,
    }
    verdict = verdicts.get(str(result.get("verdict", "")).upper())
    confidence = result.get("confidence")
    evidence = [
        _evidence(result.get(key, []))
        for key in ("evidence_for", "evidence_against", "evidence_gaps")
    ]
    reasoning = result.get("reasoning")
    if (
        verdict is None
        or not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0 <= confidence <= 1
        or not math.isfinite(confidence)
        or not isinstance(reasoning, str)
        or not reasoning.strip()
        or any(items is None for items in evidence)
    ):
        return AIReview(evidence_gaps=["Model review fields were missing, invalid or ambiguous."])
    return AIReview(
        verdict=verdict,
        confidence=confidence,
        reasoning=_text(reasoning),
        evidence_for=evidence[0] or [],
        evidence_against=evidence[1] or [],
        evidence_gaps=evidence[2] or [],
        remediation_summary=_text(result.get("remediation")),
    )


def save_review(finding: Finding, review: AIReview, model: str = "") -> None:
    review.model = model
    finding.ai_review = review
    finding.llm_analysis = review.model_dump_json()


def save_batch(findings: list[Finding], results: list[dict[str, Any]], model: str) -> None:
    bound = bind_batch(results, len(findings))
    for index, finding in enumerate(findings):
        if bound is None:
            review = AIReview(
                evidence_gaps=["The returned batch had invalid or repeated finding indices."]
            )
        elif index not in bound:
            review = AIReview(
                evidence_gaps=["No valid model review was returned for this finding."]
            )
        else:
            review = review_from_result(bound[index])
        save_review(finding, review, model)


def save_remediation(finding: Finding, result: dict[str, Any], model: str) -> None:
    explanation = _text(result.get("explanation"))
    code = _text(result.get("fixed_code"), 16_000)
    steps = _evidence(result.get("recommendations", []))
    review = finding.ai_review or AIReview(
        evidence_gaps=["A model finding verdict is unavailable."]
    )
    if steps is None or not (explanation or code or steps):
        review.evidence_gaps = [
            *review.evidence_gaps,
            "No valid remediation suggestion was returned.",
        ][:20]
    else:
        review.remediation_summary = explanation
        review.fixed_code = code
        review.remediation_steps = steps
    save_review(finding, review, model)
