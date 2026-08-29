"""Ground-truth precision and recall evaluation for Aegify findings."""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

from pydantic import BaseModel, Field

from aegify.models import Finding


class ExpectedFinding(BaseModel):
    rule_id: str
    file_path: str
    line_start: int = Field(ge=0)


class RuleMetrics(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 1.0
    recall: float = 1.0
    f1: float = 1.0


class BenchmarkReport(BaseModel):
    metrics: RuleMetrics
    by_rule: dict[str, RuleMetrics]
    unmatched_actual: list[str]
    unmatched_expected: list[str]


def _path(value: str) -> str:
    return PurePosixPath(value.replace("\\", "/")).as_posix().removeprefix("./")


def _metrics(tp: int, fp: int, fn: int) -> RuleMetrics:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return RuleMetrics(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def evaluate_findings(
    actual: list[Finding], expected: list[ExpectedFinding], *, line_tolerance: int = 3
) -> BenchmarkReport:
    unmatched_expected = set(range(len(expected)))
    actual_matches: dict[int, int] = {}
    for actual_index, finding in enumerate(actual):
        candidates = [
            expected_index
            for expected_index in unmatched_expected
            if expected[expected_index].rule_id == finding.rule_id
            and _path(expected[expected_index].file_path) == _path(finding.file_path)
            and abs(expected[expected_index].line_start - finding.line_start) <= line_tolerance
        ]
        if candidates:
            best = min(
                candidates,
                key=lambda expected_index: abs(
                    expected[expected_index].line_start - finding.line_start
                ),
            )
            unmatched_expected.remove(best)
            actual_matches[actual_index] = best

    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for actual_index, finding in enumerate(actual):
        counts[finding.rule_id][0 if actual_index in actual_matches else 1] += 1
    for expected_index in unmatched_expected:
        counts[expected[expected_index].rule_id][2] += 1

    tp = len(actual_matches)
    fp = len(actual) - tp
    fn = len(unmatched_expected)
    return BenchmarkReport(
        metrics=_metrics(tp, fp, fn),
        by_rule={rule_id: _metrics(*values) for rule_id, values in sorted(counts.items())},
        unmatched_actual=[
            f"{finding.rule_id}:{_path(finding.file_path)}:{finding.line_start}"
            for index, finding in enumerate(actual)
            if index not in actual_matches
        ],
        unmatched_expected=[
            f"{expected[index].rule_id}:{_path(expected[index].file_path)}:"
            f"{expected[index].line_start}"
            for index in sorted(unmatched_expected)
        ],
    )
