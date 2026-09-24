"""LLM-based vulnerability verification and remediation."""

from __future__ import annotations

import logging
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
from aegify.llm.review_result import review_from_result, save_batch, save_remediation
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
        max_calls: int = 100,
    ) -> None:
        self.budget = TokenBudget(total_budget=token_budget, max_calls=max_calls)
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
        3. Keep remediation suggestions separate from the scanner's guidance
        """
        if not findings:
            return findings

        # Split into findings that need verification vs already high confidence
        needs_verification: list[Finding] = []
        not_selected: list[Finding] = []

        for finding in findings:
            if finding.confidence < self.verify_threshold:
                needs_verification.append(finding)
            else:
                not_selected.append(finding)

        logger.info(
            "LLM review: %d selected, %d outside the configured confidence threshold",
            len(needs_verification),
            len(not_selected),
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

            save_batch(batch, results, self.client.model)
            reviewed.extend(batch)

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
                save_remediation(finding, result, self.client.model)

    def get_token_usage(self) -> TokenUsage:
        """Get current token usage statistics."""
        return self.budget.get_token_usage()

    @staticmethod
    def _review_from_result(result: dict[str, Any]) -> AIReview:
        return review_from_result(result)

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
