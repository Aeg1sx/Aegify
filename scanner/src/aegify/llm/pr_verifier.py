"""LLM-based PR verification — verifies all findings with token-efficient prompts."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from aegify.llm.budget import TokenBudget
from aegify.llm.client import LLMClient
from aegify.llm.prompts import (
    PR_BATCH_PROMPT,
    PR_VERIFICATION_SYSTEM,
    REMEDIATION_PROMPT,
    REMEDIATION_SYSTEM,
    format_pr_file_context,
    format_pr_finding,
)
from aegify.llm.review_result import review_from_result, save_batch, save_remediation
from aegify.models import AIReview, AIReviewVerdict, FileAST, Finding, Severity, TokenUsage

logger = logging.getLogger(__name__)


class PRVerifier:
    """Verifies all PR findings via LLM with file-grouped, token-efficient prompts."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-opus-5",
        token_budget: int = 100_000,
        batch_size: int = 10,
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
        self.batch_size = batch_size

    def verify_all(
        self,
        findings: list[Finding],
        file_asts: list[FileAST],
    ) -> list[Finding]:
        """Verify ALL findings through LLM — no confidence threshold skip.

        Groups findings by file for shared context, then generates
        remediation suggestions for critical/high findings.
        """
        if not findings:
            return findings

        # Build file_path -> FileAST index
        ast_by_path: dict[str, FileAST] = {a.file_path: a for a in file_asts}

        # Group findings by file path
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)

        reviewed: list[Finding] = []

        for file_path, file_findings in by_file.items():
            # Build shared file context once per file
            ast = ast_by_path.get(file_path)
            file_context = ""
            if ast:
                file_context = format_pr_file_context(file_path, ast.model_dump())

            # Verify in batches per file
            for i in range(0, len(file_findings), self.batch_size):
                batch = file_findings[i : i + self.batch_size]

                if not self.budget.can_spend("verification", len(batch) * 500):
                    logger.warning("Budget exhausted, keeping remaining findings as-is")
                    reviewed.extend(file_findings[i:])
                    break

                reviewed.extend(self._verify_batch(batch, file_context))

        # Generate remediations for critical/high
        self._generate_remediations(findings)

        return findings

    def _verify_batch(
        self,
        batch: list[Finding],
        file_context: str,
    ) -> list[Finding]:
        """Verify a batch of findings sharing the same file context."""
        findings_dicts = [f.model_dump() for f in batch]
        findings_block = "\n".join(format_pr_finding(j, fd) for j, fd in enumerate(findings_dicts))

        prompt = PR_BATCH_PROMPT.format(
            file_context=file_context,
            count=len(batch),
            findings_block=findings_block,
        )

        results = self.client.query_batch(PR_VERIFICATION_SYSTEM, prompt, phase="verification")

        save_batch(batch, results, self.client.model)
        return batch

    def _generate_remediations(self, findings: list[Finding]) -> None:
        """Generate separate remediation suggestions for critical/high findings."""
        for finding in findings:
            if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue
            if (
                finding.ai_review
                and finding.ai_review.verdict == AIReviewVerdict.LIKELY_FALSE_POSITIVE
            ):
                continue
            if finding.ai_review and finding.ai_review.remediation_summary:
                continue

            if not self.budget.can_spend("remediation", 2000):
                logger.warning("Budget exhausted, skipping remaining remediations")
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
        if file_path.endswith((".kt", ".kts")):
            return "kotlin"
        if file_path.endswith(".swift"):
            return "swift"
        if file_path.endswith(".rs"):
            return "rust"
        return ""
