"""Owned, non-executable cases for external benchmark scoring contracts."""

import csv
import hashlib
import json
import time
from itertools import permutations
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegify.cli import app
from aegify.models import Finding, FindingDisposition, ScanResult, ScanStatus, Severity
from aegify.quality.owasp import (
    BenchmarkCase,
    case_metrics,
    evaluate_cases,
    inventory_python_sources,
    read_labels,
)
from aegify.quality.owasp_runner import run_owasp_python
from aegify.scanner.engine import ScanEngine


def _case(number: int, positive: bool, cwe: int = 89) -> BenchmarkCase:
    return BenchmarkCase(f"BenchmarkTest{number:05}", "sqli", positive, cwe)


def _finding(case: BenchmarkCase, *, blocking: bool = False, cwe: int = 89) -> Finding:
    return Finding(
        rule_id="AEG-SQL-001" if cwe == 89 else "AEG-PATH-001",
        rule_name="Owned scoring fixture",
        severity=Severity.HIGH,
        confidence=0.9,
        cwe_id=cwe,
        file_path=case.file_path,
        line_start=4,
        line_end=4,
        disposition=FindingDisposition.BLOCKING if blocking else FindingDisposition.ADVISORY,
    )


def _scan(cases: list[BenchmarkCase], findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=findings,
        analyzed_files=[case.file_path for case in cases],
        evaluated_rules=["AEG-SQL-001", "AEG-PATH-001"],
    )


def _score(scan: ScanResult, cases: list[BenchmarkCase], root: Path) -> dict:
    return evaluate_cases(
        scan, cases, target_root=root, rule_cwes={"AEG-SQL-001": 89, "AEG-PATH-001": 22}
    )


def test_upstream_csv_literals_are_strict_and_labels_are_sorted() -> None:
    cases = read_labels(
        b"# test name, category, real vulnerability, cwe, version 0.1\n"
        b"BenchmarkTest00002,sqli,false,89\nBenchmarkTest00001,sqli,true,89\n"
    )
    assert [case.name for case in cases] == ["BenchmarkTest00001", "BenchmarkTest00002"]
    assert [case.positive for case in cases] == [True, False]


@pytest.mark.parametrize(
    "material",
    [
        b"",
        b"# no data\n",
        b"../BenchmarkTest00001,sqli,true,89",
        b"BenchmarkTest00001,sqli,False,89",
        b"BenchmarkTest00001,sqli,true,0",
        b"BenchmarkTest00001,sqli,true,89,extra",
        b"BenchmarkTest00001,sqli,true,89\nBenchmarkTest00001,sqli,false,89",
    ],
)
def test_malformed_or_ambiguous_labels_are_rejected(material: bytes) -> None:
    with pytest.raises(ValueError):
        read_labels(material)


def test_case_confusion_matrix_deduplicates_and_separates_blocking(tmp_path: Path) -> None:
    cases = [_case(1, True), _case(2, False), _case(3, True), _case(4, False)]
    findings = [_finding(cases[0]), _finding(cases[0]), _finding(cases[1], blocking=True)]
    report = _score(_scan(cases, findings), cases, tmp_path)
    metrics = report["metrics"]["all_candidates"]
    for key in ("true_positives", "false_positives", "false_negatives", "true_negatives"):
        assert metrics[key] == 1
    assert metrics["precision"] == metrics["recall"] == metrics["accuracy"] == 0.5
    assert metrics["balanced_accuracy"] == 0.5
    assert metrics["mcc"] == 0.0
    assert metrics["precision_wilson_95"][0] < 0.5 < metrics["precision_wilson_95"][1]
    assert report["metrics"]["blocking"]["true_positives"] == 0
    assert report["metrics"]["blocking"]["false_positives"] == 1
    assert report["metrics"]["advisory"]["precision"] == 1
    assert report["cases"][0]["matched_finding_count"] == 2
    assert report["by_rule"]["AEG-SQL-001"]["true_positives"] == 1
    assert report["by_cwe"]["89"]["all_candidates"] == {
        key: value for key, value in metrics.items() if key != "recall_over_all_positive_labels"
    }
    for order in permutations(findings):
        assert _score(_scan(cases, list(order)), list(reversed(cases)), tmp_path) == report


def test_wrong_cwe_foreign_paths_and_unexecuted_rules_never_match(tmp_path: Path) -> None:
    cases = [_case(1, True), _case(2, False)]
    wrong_cwe = _finding(cases[0], cwe=22)
    foreign = _finding(cases[0]).model_copy(
        update={"file_path": str(tmp_path.parent / "foreign" / cases[0].file_path)}
    )
    traversal = _finding(cases[0]).model_copy(update={"file_path": f"../{cases[0].file_path}"})
    unknown = _finding(cases[0]).model_copy(update={"rule_id": "AEG-UNEXECUTED"})
    report = _score(_scan(cases, [wrong_cwe, foreign, traversal, unknown]), cases, tmp_path)
    assert report["unscored_findings"] == {
        "different_cwe": 1,
        "outside_labeled_case": 2,
        "unverified_rule_cwe": 1,
    }
    metrics = report["metrics"]["all_candidates"]
    assert metrics["false_negatives"] == metrics["true_negatives"] == 1
    assert metrics["precision"] is None
    assert metrics["recall"] == 0


def test_missing_files_and_unmapped_cwe_are_abstentions_not_true_negatives(tmp_path: Path) -> None:
    cases = [_case(1, True), _case(2, False, 501), _case(3, True)]
    scan = _scan(cases[:2], [_finding(cases[0])])
    report = _score(scan, cases, tmp_path)
    assert report["unscored_reasons"] == {"file_not_analyzed": 1, "no_executed_cwe_rule": 1}
    assert report["scored_case_fraction"] == 1 / 3
    metrics = report["metrics"]["all_candidates"]
    assert metrics["true_positives"] == 1 and metrics["true_negatives"] == 0
    assert metrics["recall"] == 1 and metrics["recall_over_all_positive_labels"] == 0.5


def test_global_partial_scan_never_earns_a_confusion_matrix(tmp_path: Path) -> None:
    cases = [_case(1, True), _case(2, False)]
    scan = _scan(cases, [_finding(cases[0])])
    scan.add_gap("taint_context_limit", "taint", "Incomplete context exploration")
    report = _score(scan, cases, tmp_path)
    assert report["unscored_reasons"] == {"analysis_incomplete": 2}
    assert report["metrics"]["all_candidates"]["accuracy"] is None
    assert report["cases"][0]["matched_finding_count"] == 1


def test_empty_denominators_and_perfect_negative_accuracy_are_distinct() -> None:
    empty = case_metrics([])
    assert empty["precision"] is empty["recall"] is empty["accuracy"] is None
    negative = case_metrics(["tn"])
    assert negative["accuracy"] == 1
    assert negative["precision"] is negative["recall"] is negative["mcc"] is None


def test_absolute_and_backslash_paths_keep_the_same_case_identity(tmp_path: Path) -> None:
    cases = [_case(1, True)]
    finding = _finding(cases[0]).model_copy(
        update={"file_path": str(tmp_path / cases[0].file_path)}
    )
    scan = _scan(cases, [finding])
    scan.analyzed_files = [cases[0].file_path.replace("/", "\\")]
    assert _score(scan, cases, tmp_path)["metrics"]["all_candidates"]["true_positives"] == 1


def test_case_scoring_is_bounded_for_many_duplicate_observations(tmp_path: Path) -> None:
    cases = [_case(number, number % 2 == 0) for number in range(1, 1001)]
    findings = [_finding(case) for case in cases for _ in range(3)]
    started = time.monotonic()
    report = _score(_scan(cases, findings), cases, tmp_path)
    assert time.monotonic() - started < 2.0
    assert report["metrics"]["all_candidates"]["true_positives"] == 500
    assert report["metrics"]["all_candidates"]["false_positives"] == 500


def _corpus(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "corpus"
    (root / "testcode").mkdir(parents=True)
    for number in (1, 2):
        (root / _case(number, True).file_path).write_text(
            "raise AssertionError('Static benchmark source must never execute')\n"
            "def handler():\n    return 'owned constant'\n"
        )
    labels = root / "expectedresults.csv"
    labels.write_text("BenchmarkTest00001,sqli,true,89\nBenchmarkTest00002,sqli,false,89\n")
    return root, labels


def test_inventory_binds_auxiliary_inputs_and_rejects_links(tmp_path: Path) -> None:
    root, _ = _corpus(tmp_path)
    sources, first = inventory_python_sources(root)
    assert len(sources) == 2
    (root / "openapi.yaml").write_text("openapi: 3.0.1\n")
    assert inventory_python_sources(root)[1] != first
    (root / "linked.py").symlink_to(sources[0])
    with pytest.raises(ValueError, match="symbolic links"):
        inventory_python_sources(root)


def test_real_runner_is_static_and_ignores_corpus_and_environment_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, labels = _corpus(tmp_path)
    (root / ".aegify.yml").write_text("llm:\n  enabled: true\nstorage:\n  backend: postgresql\n")
    monkeypatch.setenv("AEGIFY_LLM__ENABLED", "true")
    monkeypatch.setenv("AEGIFY_RULES__CUSTOM_RULES", str(root / "forbidden-rules.yml"))
    monkeypatch.setenv("AEGIFY_ANTHROPIC_API_KEY", "synthetic-provider-key-must-be-ignored")
    report = run_owasp_python(root, labels)
    assert report["evaluation_complete"] is True
    assert report["metrics"]["all_candidates"]["false_negatives"] == 1
    assert report["metrics"]["all_candidates"]["true_negatives"] == 1
    config = report["provenance"]["config"]
    assert config["llm"]["enabled"] is False
    assert config["rules"]["custom_rules"] is None
    assert config["storage"]["backend"] == "memory"
    assert "synthetic-provider-key" not in json.dumps(report)
    assert report["provenance"]["implementation"]["bundled_rules_digest"].startswith("sha256:")


def test_runner_rejects_source_mutation_during_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, labels = _corpus(tmp_path)

    def mutate(self: ScanEngine, target: Path, files: list[Path]) -> ScanResult:
        files[0].write_text("changed = True\n")
        return ScanResult()

    monkeypatch.setattr(ScanEngine, "scan_files", mutate)
    with pytest.raises(ValueError, match="changed during analysis"):
        run_owasp_python(root, labels)


@pytest.mark.parametrize(
    "status,expected_exit",
    [(ScanStatus.COMPLETED, 1), (ScanStatus.PARTIAL, 3), (ScanStatus.FAILED, 2)],
)
def test_cli_retains_report_and_distinguishes_quality_from_incomplete_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: ScanStatus, expected_exit: int
) -> None:
    root, labels = _corpus(tmp_path)

    def fake_scan(self: ScanEngine, target: Path, files: list[Path]) -> ScanResult:
        scan = ScanResult(
            status=status,
            analyzed_files=[str(path) for path in files],
            evaluated_rules=["AEG-SQL-001"],
        )
        if status != ScanStatus.COMPLETED:
            scan.add_gap("rule_finding_limit", "rules", "Findings omitted")
        return scan

    monkeypatch.setattr(ScanEngine, "scan_files", fake_scan)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        app, ["benchmark-owasp", str(root), "--expected-results", str(labels), "-o", str(output)]
    )
    assert result.exit_code == expected_exit, result.output
    report = json.loads(output.read_text())
    assert report["metrics"]["all_candidates"]["precision"] is None
    assert report["evaluation_complete"] is (status == ScanStatus.COMPLETED)


def test_cli_refuses_an_output_inside_the_corpus(tmp_path: Path) -> None:
    root, labels = _corpus(tmp_path)
    output = root / "report.json"
    result = CliRunner().invoke(
        app, ["benchmark-owasp", str(root), "--expected-results", str(labels), "-o", str(output)]
    )
    assert result.exit_code == 2
    assert not output.exists()


def test_committed_baseline_preserves_all_cases_and_replay_digest() -> None:
    corpus = Path(__file__).resolve().parents[1] / "benchmarks" / "owasp-python-v01"
    report = json.loads((corpus / "results.json").read_text())
    material = (corpus / "cases.csv").read_bytes()
    assert hashlib.sha256(material).hexdigest() == report["baseline"]["case_outcomes_sha256"]
    cases = []
    for row in csv.DictReader(material.decode().splitlines()):
        cases.append(
            {
                "case": row["case"],
                "file_path": row["file_path"],
                "category": row["category"],
                "cwe": int(row["cwe"]),
                "positive": row["positive"] == "true",
                "unscored_reason": row["unscored_reason"] or None,
                "outcomes": {key: row[key] for key in ("all_candidates", "advisory", "blocking")},
                "matched_rules": row["matched_rules"].split("|") if row["matched_rules"] else [],
                "matched_finding_count": int(row["matched_finding_count"]),
            }
        )
    digest = hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":")).encode())
    assert f"sha256:{digest.hexdigest()}" == report["outcomes_digest"]
    assert len(cases) == report["label_cases"] == 1230
    assert sum(case["positive"] for case in cases) == report["positive_labels"]
    for channel in ("all_candidates", "advisory", "blocking"):
        expected = case_metrics(case["outcomes"][channel] for case in cases)
        actual = report["metrics"][channel]
        for key in (
            "true_positives",
            "false_positives",
            "false_negatives",
            "true_negatives",
            "scored_cases",
            "unscored_cases",
        ):
            assert actual[key] == expected[key]
    assert report["evaluation_complete"] is False
    assert all(run["exit_code"] == 3 for run in report["baseline"]["runs"])
