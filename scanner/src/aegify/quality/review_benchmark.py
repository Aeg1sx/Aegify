"""Replay saved AI SAST reviews against source-bound, separately supplied labels."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aegify.llm.sources import SourceCatalog
from aegify.models import AIReview, AIReviewVerdict, Finding, ScanResult, ScanStatus
from aegify.quality.artifacts import parse_json_object, read_regular_file


class ReviewCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    repository_id: str = Field(min_length=1, max_length=256)
    path: str = Field(min_length=1, max_length=1024)
    source_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    rule_id: str = Field(min_length=1, max_length=256)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    expected: Literal["likely_true_positive", "likely_false_positive", "needs_review"]


class ReviewLabels(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal[1]
    dataset: str = Field(min_length=1, max_length=256)
    cases: list[ReviewCase] = Field(min_length=1, max_length=2000)


def _check_review(review: AIReview, finding: Finding, sources: SourceCatalog) -> str:
    if review.trace.stop_reason != "final_review" or review.trace.model_calls < 1:
        return "unfinished_review"
    if review.trace.source_manifest != sources.manifest_digest:
        return "source_manifest_mismatch"
    issued: dict[str, list[tuple[Any, Any]]] = {}
    for span in review.tools_used:
        if span.request_id in issued:
            return "ambiguous_tool_record"
        records: list[tuple[Any, Any]] = []
        if span.ok and span.tool == "source_read":
            records = [(span.evidence.get("citation"), span.evidence.get("content"))]
        elif span.ok and span.tool == "source_search":
            matches = span.evidence.get("matches")
            if isinstance(matches, list):
                records = [
                    (m.get("citation"), m.get("content")) for m in matches if isinstance(m, dict)
                ]
        issued[span.request_id] = records
    for citation in review.citations:
        identity = citation.model_dump(exclude={"request_id"})
        if not sources.valid_citation(identity):
            return "unsupported_citation"
        source = sources.files[(citation.repository_id, citation.path)]
        excerpt = "\n".join(source.lines[citation.line_start - 1 : citation.line_end])
        if (identity, excerpt) not in issued.get(citation.request_id, []):
            return "unsupported_citation"
    if review.verdict == AIReviewVerdict.NEEDS_REVIEW:
        return "" if any(gap.strip() for gap in review.evidence_gaps) else "missing_evidence_gap"
    if not sources.covers_finding(finding, review.citations):
        return "incomplete_source_range"
    support = (
        review.evidence_for
        if review.verdict == AIReviewVerdict.LIKELY_TRUE_POSITIVE
        else review.evidence_against
    )
    return (
        ""
        if review.reasoning.strip() and any(fact.strip() for fact in support)
        else "missing_rationale"
    )


def evaluate_reviews(scan_file: Path, label_file: Path, roots: dict[str, Path]) -> dict[str, Any]:
    scan_bytes = read_regular_file(scan_file, limit=100_000_000)
    labels_bytes = read_regular_file(label_file, limit=2_000_000)
    scan = ScanResult.model_validate(parse_json_object(scan_bytes))
    labels = ReviewLabels.model_validate(parse_json_object(labels_bytes))
    sources = SourceCatalog.from_scan(scan, roots)
    indexed: dict[tuple[str, str, str, int, int], list[Finding]] = defaultdict(list)
    for finding in scan.findings:
        location = sources.finding_location(finding)
        if location:
            indexed[
                (
                    location["repository_id"],
                    location["path"],
                    finding.rule_id,
                    finding.line_start,
                    finding.line_end,
                )
            ].append(finding)

    counts: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    seen: set[tuple[str, str, str, int, int]] = set()
    outcomes = []
    for case in labels.cases:
        key = (case.repository_id, case.path, case.rule_id, case.line_start, case.line_end)
        if key in seen or case.line_end < case.line_start:
            raise ValueError("label identities must be unique and line ranges must be ordered")
        seen.add(key)
        entry = sources.files.get((case.repository_id, case.path))
        findings = indexed.get(key, [])
        observed = None
        if (
            not entry
            or entry.source_digest != case.source_digest
            or case.line_end > len(entry.lines)
        ):
            gap = "source_unavailable_or_changed"
        elif len(findings) != 1:
            gap = "ambiguous_finding" if findings else "missing_finding"
        elif (review := findings[0].ai_review) is None:
            gap = "missing_review"
        else:
            gap = _check_review(review, findings[0], sources)
            observed = review.verdict.value
        outcome = "unscored" if gap else ("agree" if observed == case.expected else "disagree")
        counts[outcome] += 1
        if not gap and observed is not None:
            decisions[observed] += 1
        outcomes.append({**case.model_dump(), "observed": observed, "outcome": outcome, "gap": gap})
    return {
        "schema_version": 1,
        "dataset": labels.dataset,
        "label_count": len(seen),
        "agreed": counts["agree"],
        "disagreed": counts["disagree"],
        "unscored": counts["unscored"],
        "agreement_over_all_labels": counts["agree"] / len(seen),
        "observed_verdicts": dict(decisions),
        "complete": not counts["unscored"]
        and scan.status == ScanStatus.COMPLETED
        and not scan.analysis_gaps,
        "scan_status": scan.status.value,
        "analysis_gap_count": len(scan.analysis_gaps),
        "scan_digest": "sha256:" + hashlib.sha256(scan_bytes).hexdigest(),
        "labels_digest": "sha256:" + hashlib.sha256(labels_bytes).hexdigest(),
        "cases": outcomes,
    }
