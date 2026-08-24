"""LLM-based vulnerability verification and remediation."""

from __future__ import annotations

import logging
import math
from typing import Any

from aegify.llm.budget import TokenBudget
from aegify.llm.client import LLMClient
from aegify.llm.prompts import (
    BATCH_VERIFICATION_PROMPT,
    BATCH_VERIFICATION_SYSTEM,
    REMEDIATION_PROMPT,
    REMEDIATION_SYSTEM,
    format_finding_for_batch,
)
from aegify.models import AIReview, AIReviewVerdict, Finding, Severity, TokenUsage

logger = logging.getLogger(__name__)


class LLMVerifier:
    """Uses LLM to verify findings and generate remediation suggestions."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-5",
        token_budget: int = 100_000,
        verify_threshold: float = 0.7,
        batch_size: int = 5,
        base_url: str | None = None,
    ) -> None:
        self.budget = TokenBudget(total_budget=token_budget)
        self.client = LLMClient(
            api_key=api_key,
            model=model,
            budget=self.budget,
            base_url=base_url,
        )
        self.verify_threshold = verify_threshold
        self.batch_size = batch_size

    def verify_and_remediate(self, findings: list[Finding]) -> list[Finding]:
        """Run LLM verification and remediation on findings.

        Strategy:
        1. Filter findings that need LLM verification (below confidence threshold)
        2. Batch verify in groups
        3. Generate remediation for confirmed findings
        """
        if not findings:
            return findings

        # Split into findings that need verification vs already high confidence
        needs_verification: list[Finding] = []
        auto_confirmed: list[Finding] = []

        for finding in findings:
            if finding.confidence < self.verify_threshold:
                needs_verification.append(finding)
            else:
                auto_confirmed.append(finding)

        logger.info(
            "LLM verification: %d need verification, %d auto-confirmed",
            len(needs_verification),
            len(auto_confirmed),
        )

        # Batch verify
        self._batch_verify(needs_verification)

        # Suggestions never remove or mutate the workflow state of a finding.
        self._generate_remediations(findings)

        return findings

    def _batch_verify(self, findings: list[Finding]) -> list[Finding]:
        """Verify findings in batches using LLM."""
        reviewed: list[Finding] = []

        for i in range(0, len(findings), self.batch_size):
            batch = findings[i : i + self.batch_size]

            if not self.budget.can_spend("verification", len(batch) * 1000):
                logger.warning("Budget exhausted, skipping remaining verification")
                # Keep remaining findings as-is (no LLM verdict)
                reviewed.extend(findings[i:])
                break

            findings_dicts = [f.model_dump() for f in batch]
            findings_block = "\n".join(
                format_finding_for_batch(j, fd) for j, fd in enumerate(findings_dicts)
            )

            prompt = BATCH_VERIFICATION_PROMPT.format(
                count=len(batch), findings_block=findings_block
            )

            results = self.client.query_batch(
                BATCH_VERIFICATION_SYSTEM, prompt, phase="verification"
            )

            for result in results:
                idx = result.get("finding_index", 0)
                if idx >= len(batch):
                    continue
                finding = batch[idx]
                finding.ai_review = self._review_from_result(result)
                finding.llm_analysis = finding.ai_review.model_dump_json()
                reviewed.append(finding)

        return reviewed

    def _generate_remediations(self, findings: list[Finding]) -> None:
        """Generate remediation suggestions for critical/high findings."""
        for finding in findings:
            if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue
            if (
                finding.ai_review
                and finding.ai_review.verdict == AIReviewVerdict.LIKELY_FALSE_POSITIVE
            ):
                continue

            if not self.budget.can_spend("remediation", 2000):
                logger.warning("Budget exhausted, skipping remediation generation")
                break

            prompt = REMEDIATION_PROMPT.format(
                rule_id=finding.rule_id,
                rule_name=finding.rule_name,
                severity=finding.severity.value,
                cwe_id=getattr(finding, "cwe_id", "N/A"),
                file_path=finding.file_path,
                line_start=finding.line_start,
                language=self._detect_language(finding.file_path),
                code_snippet=finding.code_snippet,
                message=finding.message,
            )

            result = self.client.query(
                REMEDIATION_SYSTEM, prompt, phase="remediation", max_tokens=2048
            )

            if isinstance(result, dict):
                finding.remediation = self._format_remediation(result)

    def get_token_usage(self) -> TokenUsage:
        """Get current token usage statistics."""
        return TokenUsage(
            input_tokens=self.budget.input_tokens_used,
            output_tokens=self.budget.output_tokens_used,
            total_cost_usd=self.budget.estimated_cost_usd,
        )

    @staticmethod
    def _format_remediation(result: dict[str, Any]) -> str:
        """Format LLM remediation result into readable text."""
        parts: list[str] = []

        if explanation := result.get("explanation"):
            parts.append(f"**Vulnerability**: {explanation}")

        if fixed_code := result.get("fixed_code"):
            parts.append(f"\n**Fix**:\n```\n{fixed_code}\n```")

        if recommendations := result.get("recommendations"):
            parts.append("\n**Recommendations**:")
            for rec in recommendations:
                parts.append(f"- {rec}")

        return "\n".join(parts) if parts else ""

    @staticmethod
    def _review_from_result(result: dict[str, Any]) -> AIReview:
        verdicts = {
            "TRUE_POSITIVE": AIReviewVerdict.LIKELY_TRUE_POSITIVE,
            "LIKELY_TRUE_POSITIVE": AIReviewVerdict.LIKELY_TRUE_POSITIVE,
            "FALSE_POSITIVE": AIReviewVerdict.LIKELY_FALSE_POSITIVE,
            "LIKELY_FALSE_POSITIVE": AIReviewVerdict.LIKELY_FALSE_POSITIVE,
        }
        verdict = verdicts.get(str(result.get("verdict", "")).upper(), AIReviewVerdict.NEEDS_REVIEW)
        confidence = result.get("confidence", 0.0)
        if not isinstance(confidence, (int, float)) or not math.isfinite(confidence):
            confidence = 0.0
        return AIReview(
            verdict=verdict,
            confidence=max(0.0, min(float(confidence), 1.0)),
            reasoning=str(result.get("reasoning", "")),
            evidence_for=[
                str(item) for item in result.get("evidence_for", []) if isinstance(item, str)
            ],
            evidence_against=[
                str(item) for item in result.get("evidence_against", []) if isinstance(item, str)
            ],
            evidence_gaps=[
                str(item) for item in result.get("evidence_gaps", []) if isinstance(item, str)
            ],
        )

    @staticmethod
    def _detect_language(file_path: str) -> str:
        if file_path.endswith(".py"):
            return "python"
        if file_path.endswith((".js", ".jsx")):
            return "javascript"
        if file_path.endswith((".ts", ".tsx")):
            return "typescript"
        if file_path.endswith(".java"):
            return "java"
        if file_path.endswith(".go"):
            return "go"
        return ""
