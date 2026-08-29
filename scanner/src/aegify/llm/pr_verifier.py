"""LLM-based PR verification — verifies all findings with token-efficient prompts."""

from __future__ import annotations

import logging
import math
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
    ) -> None:
        self.budget = TokenBudget(total_budget=token_budget)
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
        remediations for critical/high confirmed findings.
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

        reviewed: list[Finding] = []
        result_by_idx: dict[int, dict[str, Any]] = {}
        for r in results:
            idx = r.get("idx", r.get("finding_index", -1))
            if 0 <= idx < len(batch):
                result_by_idx[idx] = r

        for idx, finding in enumerate(batch):
            result = result_by_idx.get(idx)
            if result is None:
                # LLM didn't return a verdict — keep finding as-is
                reviewed.append(finding)
                continue

            finding.ai_review = self._review_from_result(result)
            finding.llm_analysis = finding.ai_review.model_dump_json()
            if result.get("remediation"):
                finding.remediation = str(result["remediation"])
            reviewed.append(finding)

        return reviewed

    def _generate_remediations(self, findings: list[Finding]) -> None:
        """Generate detailed remediations for confirmed critical/high findings."""
        for finding in findings:
            if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue
            if (
                finding.ai_review
                and finding.ai_review.verdict == AIReviewVerdict.LIKELY_FALSE_POSITIVE
            ):
                continue
            if finding.remediation:
                continue  # Already got inline remediation from verification

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
        if file_path.endswith((".kt", ".kts")):
            return "kotlin"
        if file_path.endswith(".swift"):
            return "swift"
        if file_path.endswith(".rs"):
            return "rust"
        return ""
