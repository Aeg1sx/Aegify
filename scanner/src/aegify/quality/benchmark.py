"""Ground-truth precision and recall evaluation for Aegify findings."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Collection
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegify.models import Finding


class ExpectedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=r"^AEG-[A-Z0-9-]+$")
    file_path: str
    line_start: int = Field(ge=1)

    @field_validator("file_path")
    @classmethod
    def validate_relative_source_path(cls, value: str) -> str:
        normalized = PurePosixPath(value.replace("\\", "/"))
        if not normalized.parts or normalized.is_absolute() or ".." in normalized.parts:
            raise ValueError("file_path must stay inside the benchmark source tree")
        return normalized.as_posix()


class GroundTruthManifest(BaseModel):
    """Versioned, explicit benchmark scope and expected evidence identities."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=1)
    corpus_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    corpus_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    rule_scope: list[str] = Field(min_length=1)
    expected: list[ExpectedFinding] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_scope(self) -> GroundTruthManifest:
        if len(self.rule_scope) != len(set(self.rule_scope)):
            raise ValueError("rule_scope contains duplicate rule IDs")
        scoped = set(self.rule_scope)
        expected_rules = {item.rule_id for item in self.expected}
        outside = expected_rules - scoped
        if outside:
            raise ValueError(
                f"expected findings reference rules outside rule_scope: {sorted(outside)}"
            )
        missing = scoped - expected_rules
        if missing:
            raise ValueError(f"every scoped rule needs a positive control: {sorted(missing)}")
        identities = [
            (item.rule_id, _path(item.file_path), item.line_start) for item in self.expected
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("expected findings contain duplicate evidence identities")
        return self


class RuleMetrics(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 1.0
    recall: float = 1.0
    f1: float = 1.0


class BenchmarkReport(BaseModel):
    schema_version: int = 1
    corpus_id: str = ""
    corpus_version: str = ""
    source_digest: str = ""
    ground_truth_digest: str = ""
    line_tolerance: int = 3
    evaluated_rules: list[str] = Field(default_factory=list)
    metrics: RuleMetrics
    by_rule: dict[str, RuleMetrics]
    unmatched_actual: list[str]
    unmatched_expected: list[str]


def _path(value: str, target_root: Path | None = None) -> str:
    normalized = PurePosixPath(value.replace("\\", "/")).as_posix().removeprefix("./")
    if target_root is None:
        return normalized

    root = target_root.resolve()
    resolved = Path(value).resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return normalized


def digest_source_tree(target: Path) -> str:
    """Hash source paths and bytes so a benchmark report identifies its exact corpus."""
    root = target if target.is_dir() else target.parent
    paths = [target] if target.is_file() else sorted(target.rglob("*"))
    digest = hashlib.sha256()
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"benchmark corpus must not contain symlinks: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        material = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative.encode("utf-8"))
        digest.update(len(material).to_bytes(8, "big"))
        digest.update(material)
    return f"sha256:{digest.hexdigest()}"


def digest_bytes(material: bytes) -> str:
    return f"sha256:{hashlib.sha256(material).hexdigest()}"


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
    actual: list[Finding],
    expected: list[ExpectedFinding],
    *,
    line_tolerance: int = 3,
    target_root: Path | None = None,
    rule_scope: Collection[str] | None = None,
    corpus_id: str = "",
    corpus_version: str = "",
    source_digest: str = "",
    ground_truth_digest: str = "",
) -> BenchmarkReport:
    scoped_rules = set(rule_scope or [])
    scoped_actual = [
        finding for finding in actual if not scoped_rules or finding.rule_id in scoped_rules
    ]
    if scoped_rules and any(item.rule_id not in scoped_rules for item in expected):
        raise ValueError("expected finding is outside the declared rule scope")

    unmatched_expected = set(range(len(expected)))
    actual_matches: dict[int, int] = {}
    for actual_index, finding in enumerate(scoped_actual):
        candidates = [
            expected_index
            for expected_index in unmatched_expected
            if expected[expected_index].rule_id == finding.rule_id
            and _path(expected[expected_index].file_path) == _path(finding.file_path, target_root)
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
    for rule_id in scoped_rules:
        counts[rule_id]
    for actual_index, finding in enumerate(scoped_actual):
        counts[finding.rule_id][0 if actual_index in actual_matches else 1] += 1
    for expected_index in unmatched_expected:
        counts[expected[expected_index].rule_id][2] += 1

    tp = len(actual_matches)
    fp = len(scoped_actual) - tp
    fn = len(unmatched_expected)
    return BenchmarkReport(
        corpus_id=corpus_id,
        corpus_version=corpus_version,
        source_digest=source_digest,
        ground_truth_digest=ground_truth_digest,
        line_tolerance=line_tolerance,
        evaluated_rules=sorted(scoped_rules),
        metrics=_metrics(tp, fp, fn),
        by_rule={rule_id: _metrics(*values) for rule_id, values in sorted(counts.items())},
        unmatched_actual=[
            f"{finding.rule_id}:{_path(finding.file_path, target_root)}:{finding.line_start}"
            for index, finding in enumerate(scoped_actual)
            if index not in actual_matches
        ],
        unmatched_expected=[
            f"{expected[index].rule_id}:{_path(expected[index].file_path)}:"
            f"{expected[index].line_start}"
            for index in sorted(unmatched_expected)
        ],
    )
