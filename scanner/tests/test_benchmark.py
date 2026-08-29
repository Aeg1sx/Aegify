from aegify.models import Finding, Severity
from aegify.quality.benchmark import ExpectedFinding, evaluate_findings


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
