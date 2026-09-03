from pathlib import Path

import pytest
from pydantic import ValidationError

from aegify.models import Finding, Severity
from aegify.quality.benchmark import (
    ExpectedFinding,
    GroundTruthManifest,
    digest_source_tree,
    evaluate_findings,
)


def _finding(rule: str, path: str, line: int) -> Finding:
    return Finding(
        rule_id=rule,
        rule_name=rule,
        severity=Severity.HIGH,
        confidence=0.9,
        file_path=path,
        line_start=line,
        line_end=line,
    )


def test_benchmark_reports_precision_recall_and_unmatched_evidence() -> None:
    actual = [_finding("AEG-ONE", "src/a.py", 11), _finding("AEG-EXTRA", "src/b.py", 4)]
    expected = [
        ExpectedFinding(rule_id="AEG-ONE", file_path="src/a.py", line_start=10),
        ExpectedFinding(rule_id="AEG-MISSING", file_path="src/c.py", line_start=8),
    ]
    report = evaluate_findings(actual, expected)
    assert report.metrics.true_positives == 1
    assert report.metrics.false_positives == 1
    assert report.metrics.false_negatives == 1
    assert report.metrics.precision == 0.5
    assert report.metrics.recall == 0.5
    assert report.unmatched_actual == ["AEG-EXTRA:src/b.py:4"]
    assert report.unmatched_expected == ["AEG-MISSING:src/c.py:8"]


def test_versioned_manifest_requires_a_positive_control_for_every_scoped_rule() -> None:
    with pytest.raises(ValidationError, match="positive control"):
        GroundTruthManifest.model_validate(
            {
                "schema_version": 1,
                "corpus_id": "owned-core",
                "corpus_version": "1.0.0",
                "rule_scope": ["AEG-ONE", "AEG-MISSING"],
                "expected": [{"rule_id": "AEG-ONE", "file_path": "unsafe.py", "line_start": 4}],
            }
        )


def test_ground_truth_paths_cannot_escape_the_owned_source_tree() -> None:
    with pytest.raises(ValidationError, match="inside the benchmark source tree"):
        GroundTruthManifest.model_validate(
            {
                "corpus_id": "owned-core",
                "corpus_version": "1.0.0",
                "rule_scope": ["AEG-ONE"],
                "expected": [{"rule_id": "AEG-ONE", "file_path": "../outside.py", "line_start": 1}],
            }
        )


def test_scoped_benchmark_normalizes_paths_and_ignores_out_of_scope_rules(
    tmp_path: Path,
) -> None:
    sources = tmp_path / "sources"
    sources.mkdir()
    source = sources / "unsafe.py"
    source.write_text("dangerous()\n", encoding="utf-8")
    actual = [
        _finding("AEG-ONE", str(source), 1),
        _finding("AEG-OUTSIDE", str(source), 1),
    ]
    expected = [ExpectedFinding(rule_id="AEG-ONE", file_path="unsafe.py", line_start=1)]

    report = evaluate_findings(
        actual,
        expected,
        target_root=sources,
        rule_scope=["AEG-ONE"],
        corpus_id="owned-core",
        corpus_version="1.0.0",
    )

    assert report.metrics.precision == 1.0
    assert report.metrics.recall == 1.0
    assert report.metrics.f1 == 1.0
    assert report.line_tolerance == 3
    assert report.evaluated_rules == ["AEG-ONE"]
    assert report.unmatched_actual == []


def test_source_tree_digest_binds_paths_and_content(tmp_path: Path) -> None:
    source = tmp_path / "fixture.py"
    source.write_text("safe = True\n", encoding="utf-8")
    original = digest_source_tree(tmp_path)

    source.write_text("safe = False\n", encoding="utf-8")

    assert original.startswith("sha256:")
    assert digest_source_tree(tmp_path) != original
