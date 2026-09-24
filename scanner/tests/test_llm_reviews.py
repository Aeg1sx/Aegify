from __future__ import annotations

import json
from typing import Any

import pytest

from aegify.llm.pr_verifier import PRVerifier
from aegify.llm.review_result import review_from_result, save_remediation
from aegify.llm.verifier import LLMVerifier
from aegify.models import AIReview, AIReviewVerdict, Finding, Severity
from tests.llm_support import ScriptedProvider, message


def finding(**changes: Any) -> Finding:
    return Finding(
        **{
            "rule_id": "FIXTURE-001",
            "rule_name": "Owned review fixture",
            "severity": Severity.LOW,
            "confidence": 0.4,
            "file_path": "fixture.py",
            "line_start": 1,
            "line_end": 1,
            "remediation": "Scanner-authored guidance",
            **changes,
        }
    )


def verdict(**changes: Any) -> dict[str, Any]:
    return {
        "idx": 0,
        "verdict": "LIKELY_FALSE_POSITIVE",
        "confidence": 0.9,
        "reasoning": "A defense is present in the supplied fixture",
        **changes,
    }


@pytest.mark.parametrize("verifier_type", [LLMVerifier, PRVerifier])
@pytest.mark.parametrize(
    "indices",
    [
        {},
        {"idx": -1},
        {"idx": True},
        {"idx": "0"},
        {"idx": 2},
        {"idx": 0, "finding_index": 1},
        {"duplicate": True},
    ],
)
def test_invalid_batch_binding_abstains_without_changing_scanner_facts(
    verifier_type: type[LLMVerifier] | type[PRVerifier],
    indices: dict[str, Any],
) -> None:
    response = verdict()
    del response["idx"]
    response.update(indices)
    results = [response]
    if "duplicate" in indices:
        results = [verdict(), verdict()]
    candidates = [finding(), finding()]
    before = [item.model_dump(exclude={"ai_review", "llm_analysis"}) for item in candidates]
    with ScriptedProvider(message(json.dumps(results))) as provider:
        verifier = verifier_type(api_key="synthetic-unused-key")
        verifier.client.close()
        verifier.client = provider.client(verifier.budget)
        if isinstance(verifier, PRVerifier):
            assert verifier.verify_all(candidates, []) == candidates
        else:
            assert verifier.verify_and_remediate(candidates) == candidates
        assert verifier.get_token_usage().calls_started == 1
    for item, original in zip(candidates, before, strict=True):
        assert item.model_dump(exclude={"ai_review", "llm_analysis"}) == original
        assert item.ai_review and item.ai_review.verdict == AIReviewVerdict.NEEDS_REVIEW
        assert item.ai_review.evidence_gaps


@pytest.mark.parametrize("verifier_type", [LLMVerifier, PRVerifier])
def test_partial_batch_covers_only_its_index_and_retains_missing_review_gap(
    verifier_type: type[LLMVerifier] | type[PRVerifier],
) -> None:
    candidates = [finding(), finding()]
    with ScriptedProvider(message(json.dumps([verdict(idx=1)]))) as provider:
        verifier = verifier_type(api_key="synthetic-unused-key")
        verifier.client.close()
        verifier.client = provider.client(verifier.budget)
        if isinstance(verifier, PRVerifier):
            verifier.verify_all(candidates, [])
        else:
            verifier.verify_and_remediate(candidates)
    assert candidates[0].ai_review and candidates[0].ai_review.evidence_gaps
    assert candidates[1].ai_review
    assert candidates[1].ai_review.verdict == AIReviewVerdict.LIKELY_FALSE_POSITIVE
    assert (
        candidates[1].confidence == 0.4 and candidates[1].remediation == "Scanner-authored guidance"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"confidence": True},
        {"confidence": float("nan")},
        {"confidence": float("inf")},
        {"confidence": 10**500},
        {"confidence": "0.8"},
        {"confidence": None},
        {"reasoning": " "},
        {"reasoning": {}},
        {"evidence_for": "not a list"},
        {"evidence_gaps": [None]},
        {"verdict": "CONFIRMED"},
    ],
)
def test_invalid_review_fields_abstain(changes: dict[str, Any]) -> None:
    review = review_from_result(verdict(**changes))
    assert review.verdict == AIReviewVerdict.NEEDS_REVIEW and review.evidence_gaps


@pytest.mark.parametrize("verifier_type", [LLMVerifier, PRVerifier])
def test_model_remediation_is_separate_from_deterministic_guidance(
    verifier_type: type[LLMVerifier] | type[PRVerifier],
) -> None:
    candidate = finding(
        severity=Severity.HIGH,
        ai_review=AIReview(
            verdict=AIReviewVerdict.LIKELY_TRUE_POSITIVE,
            reasoning="Static fixture suggestion",
        ),
    )
    original = candidate.model_dump(exclude={"ai_review", "llm_analysis"})
    suggestion = {
        "explanation": "Proposed safer API",
        "fixed_code": "safe(value)",
        "recommendations": ["Review the change"],
    }
    with ScriptedProvider(message(json.dumps(suggestion))) as provider:
        verifier = verifier_type(api_key="synthetic-unused-key")
        verifier.client.close()
        verifier.client = provider.client(verifier.budget)
        verifier._generate_remediations([candidate])
    assert candidate.model_dump(exclude={"ai_review", "llm_analysis"}) == original
    assert candidate.ai_review and candidate.ai_review.fixed_code == "safe(value)"
    assert candidate.ai_review.remediation_summary == "Proposed safer API"
    assert json.loads(candidate.llm_analysis or "{}")["remediation_steps"] == ["Review the change"]


def test_malformed_remediation_does_not_fabricate_guidance_or_drop_existing_review() -> None:
    candidate = finding(ai_review=AIReview(reasoning="Existing review"))
    save_remediation(
        candidate, {"explanation": {"unsafe": "object"}, "recommendations": [None]}, "fixture"
    )
    assert candidate.ai_review and candidate.ai_review.reasoning == "Existing review"
    assert candidate.ai_review.evidence_gaps
    assert candidate.remediation == "Scanner-authored guidance"
