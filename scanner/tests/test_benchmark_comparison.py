"""Saved-result evaluation uses supplied case evidence, not scanner execution."""

import copy
import csv
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegify.cli import app
from aegify.config import AegifyConfig
from aegify.models import Finding, ScanResult, ScanStatus, Severity
from aegify.quality.comparison import CHANNELS, compare_owasp_reports, load_owasp_report
from aegify.quality.owasp import BenchmarkCase, evaluate_cases
from aegify.quality.provenance import json_digest


def _report(
    root: Path, detected: set[int], *, missing: int | None = None, partial: bool = False
) -> dict:
    cases = [
        BenchmarkCase(f"BenchmarkTest{index:05d}", "sqli", index < 2, 89) for index in range(4)
    ]
    findings = [
        Finding(
            rule_id="AEG-DEMO",
            rule_name="Owned observation",
            confidence=0.5,
            severity=Severity.LOW,
            cwe_id=89,
            file_path=cases[index].file_path,
            line_start=1,
            line_end=1,
        )
        for index in sorted(detected)
    ]
    result = ScanResult(
        findings=findings,
        evaluated_rules=["AEG-DEMO"],
        analyzed_files=[case.file_path for index, case in enumerate(cases) if index != missing],
        status=ScanStatus.PARTIAL if partial else ScanStatus.COMPLETED,
    )
    report = evaluate_cases(result, cases, target_root=root, rule_cwes={"AEG-DEMO": 89})
    config = AegifyConfig.model_construct().model_dump(mode="json")
    report["provenance"] = {
        "corpus_digest": "sha256:" + "1" * 64,
        "ground_truth_digest": "sha256:" + "2" * 64,
        "config_digest": json_digest(config),
        "config": {key: value for key, value in config.items() if key != "anthropic_api_key"},
        "workspace_snapshot": "sha256:" + "3" * 64,
        "implementation": {
            "scanner_version": "0.3.0",
            "scanner_code_and_modelpacks_digest": "sha256:" + "4" * 64,
            "bundled_rules_digest": "sha256:" + "5" * 64,
            "rule_definitions_digest": "sha256:" + "6" * 64,
            "parser_fingerprint": "owned-parser",
            "packages": {"owned": "1.0"},
            "python": "3.14.7",
            "system": "test",
            "system_release": "1",
            "machine": "owned",
            "logical_cpus": 1,
        },
        "evaluated_rules": ["AEG-DEMO"],
        "requested_python_files": 4,
        "analyzed_python_files": len(result.analyzed_files),
        "python_parser_execution": "sequential_scan_files",
        "llm_enabled": False,
        "repository_code_executed": False,
    }
    report["evaluation_complete"] = not partial and missing is None
    report["outcomes_digest"] = json_digest(report["cases"])
    report["measurement"] = {"scan_seconds": 1.0}
    return report


def _save(path: Path, report: dict) -> dict:
    path.write_text(json.dumps(report))
    return load_owasp_report(path)


def test_paired_gate_catches_case_swaps_hidden_by_identical_aggregate_metrics(
    tmp_path: Path,
) -> None:
    baseline = _report(tmp_path, {0})
    candidate = _report(tmp_path, {1})
    assert baseline["metrics"] == candidate["metrics"]
    result = compare_owasp_reports(
        _save(tmp_path / "before.json", baseline), _save(tmp_path / "after.json", candidate)
    )
    assert result["exit_code"] == 1
    assert not result["regression_free"]
    channel = result["channels"]["all_candidates"]
    assert channel["improved_cases"] == ["BenchmarkTest00001"]
    assert channel["regressed_cases"] == ["BenchmarkTest00000"]
    assert channel["metric_deltas"]["recall"] == 0


def test_coverage_losses_cannot_be_disguised_by_better_subset_precision(tmp_path: Path) -> None:
    baseline = _save(tmp_path / "before.json", _report(tmp_path, {0, 2}))
    candidate = _save(tmp_path / "after.json", _report(tmp_path, {0, 2}, missing=2))
    result = compare_owasp_reports(baseline, candidate)
    assert result["exit_code"] == 1
    assert result["coverage_lost"] == ["BenchmarkTest00002"]
    channel = result["channels"]["all_candidates"]
    assert channel["jointly_scored_cases"] == 3
    assert channel["metric_deltas"]["precision"] == 0
    reverse = compare_owasp_reports(candidate, baseline)
    assert reverse["exit_code"] == 3
    assert reverse["coverage_gained"] == ["BenchmarkTest00002"]


def test_undefined_joint_metrics_remain_null_for_incomplete_analysis(tmp_path: Path) -> None:
    left = _save(tmp_path / "before.json", _report(tmp_path, {0}, partial=True))
    right = _save(tmp_path / "after.json", _report(tmp_path, {0}, partial=True))
    result = compare_owasp_reports(left, right, require_identical=True)
    assert result["identical_replay"]
    assert result["exit_code"] == 3
    assert result["channels"]["all_candidates"]["metric_deltas"]["precision"] is None


def test_early_partial_and_failed_runs_can_lack_a_workspace_snapshot(tmp_path: Path) -> None:
    report = _report(tmp_path, set(), partial=True)
    report["provenance"]["workspace_snapshot"] = ""
    partial = _save(tmp_path / "partial.json", report)
    assert compare_owasp_reports(partial, partial)["exit_code"] == 3
    report["analysis_status"] = "failed"
    failed = _save(tmp_path / "failed.json", report)
    assert compare_owasp_reports(partial, failed)["exit_code"] == 2
    report = _report(tmp_path, set())
    report["provenance"]["workspace_snapshot"] = ""
    with pytest.raises(ValueError, match="workspace_snapshot"):
        _save(tmp_path / "complete.json", report)


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("llm", "enabled", True),
        ("storage", "backend", "sqlite"),
        ("rules", "custom_rules", "local.yml"),
    ],
)
def test_configuration_and_source_only_claim_must_agree(
    tmp_path: Path, section: str, key: str, value: object
) -> None:
    report = _report(tmp_path, {0})
    report["provenance"]["config"][section][key] = value
    report["provenance"]["config_digest"] = json_digest(
        {**report["provenance"]["config"], "anthropic_api_key": ""}
    )
    with pytest.raises(ValueError, match="source-only"):
        _save(tmp_path / "report.json", report)


@pytest.mark.parametrize(
    "change", ["measurement", "packages", "parser", "off_label", "duplicate_hit", "implementation"]
)
def test_replay_binds_implementation_and_observations_but_not_timings(
    tmp_path: Path, change: str
) -> None:
    before = _report(tmp_path, {0})
    after = copy.deepcopy(before)
    if change == "measurement":
        after["measurement"] = {"scan_seconds": 900, "peak_rss_self_bytes": 200}
    elif change == "packages":
        after["provenance"]["implementation"]["packages"]["owned"] = "2.0"
    elif change == "parser":
        after["provenance"]["implementation"]["parser_fingerprint"] = "new-parser"
    elif change == "off_label":
        after["unscored_findings"] = {"different_cwe": 1}
    elif change == "duplicate_hit":
        after["cases"][0]["matched_finding_count"] += 1
        after["outcomes_digest"] = json_digest(after["cases"])
    else:
        after["provenance"]["implementation"]["scanner_code_and_modelpacks_digest"] = (
            "sha256:" + "7" * 64
        )
    result = compare_owasp_reports(
        _save(tmp_path / "before.json", before),
        _save(tmp_path / "after.json", after),
        require_identical=True,
    )
    assert result["identical_replay"] is (change == "measurement")
    assert result["exit_code"] == (0 if change == "measurement" else 1)


@pytest.mark.parametrize(
    "field", ["corpus_digest", "ground_truth_digest", "config", "label_identity"]
)
def test_comparison_refuses_changed_denominators_or_configuration(
    tmp_path: Path, field: str
) -> None:
    before = _report(tmp_path, {0})
    after = copy.deepcopy(before)
    if field in {"corpus_digest", "ground_truth_digest"}:
        after["provenance"][field] = "sha256:" + "8" * 64
    elif field == "config":
        after["provenance"]["config"]["taint"]["max_contexts"] += 1
        after["provenance"]["config_digest"] = json_digest(
            {**after["provenance"]["config"], "anthropic_api_key": ""}
        )
    else:
        after["cases"][0]["category"] = "changed"
        after["outcomes_digest"] = json_digest(after["cases"])
    with pytest.raises(ValueError, match="not comparable"):
        compare_owasp_reports(
            _save(tmp_path / "before.json", before), _save(tmp_path / "after.json", after)
        )


@pytest.mark.parametrize(
    "tamper",
    [
        "digest",
        "metrics",
        "by_cwe",
        "by_rule",
        "label_count",
        "label_boolean",
        "duplicate_case",
        "path",
        "outcome_label",
        "unscored",
        "health",
        "complete",
        "config_digest",
        "missing_provenance",
        "missing_executed",
        "rule_cwe",
        "finding_count",
        "missing_cases",
        "llm",
        "executed_code",
        "file_counts",
        "unscored_findings",
        "nan",
        "duplicate_key",
    ],
)
def test_saved_report_inconsistencies_are_rejected(tmp_path: Path, tamper: str) -> None:
    report = _report(tmp_path, {0})
    if tamper == "digest":
        report["outcomes_digest"] = "sha256:" + "0" * 64
    elif tamper == "metrics":
        report["metrics"]["all_candidates"]["true_positives"] = 99
    elif tamper == "by_cwe":
        report["by_cwe"]["89"]["all_candidates"]["recall"] = 1
    elif tamper == "by_rule":
        report["by_rule"]["AEG-DEMO"]["precision"] = False
    elif tamper == "label_count":
        report["label_cases"] -= 1
    elif tamper == "label_boolean":
        report["cases"][0]["positive"] = 1
    elif tamper == "duplicate_case":
        report["cases"].append(report["cases"][0])
    elif tamper == "path":
        report["cases"][0]["file_path"] = "../outside.py"
    elif tamper == "outcome_label":
        report["cases"][0]["outcomes"]["all_candidates"] = "fp"
    elif tamper == "unscored":
        report["cases"][0]["unscored_reason"] = "file_not_analyzed"
    elif tamper == "health":
        report["analysis_status"] = "failed"
    elif tamper == "complete":
        report["evaluation_complete"] = False
    elif tamper == "config_digest":
        report["provenance"]["config"]["taint"]["max_contexts"] += 1
    elif tamper == "missing_provenance":
        report["provenance"]["implementation"].pop("packages")
    elif tamper == "missing_executed":
        report["provenance"]["evaluated_rules"] = []
    elif tamper == "rule_cwe":
        report["by_rule"]["AEG-DEMO"]["cwe"] = 22
    elif tamper == "finding_count":
        report["cases"][0]["matched_finding_count"] = 0
    elif tamper == "missing_cases":
        report.pop("cases")
    elif tamper == "llm":
        report["provenance"]["llm_enabled"] = True
    elif tamper == "executed_code":
        report["provenance"]["repository_code_executed"] = True
    elif tamper == "file_counts":
        report["provenance"]["analyzed_python_files"] = 500
    elif tamper == "unscored_findings":
        report["unscored_findings"] = {"different_cwe": -1}
    elif tamper == "nan":
        report["measurement"]["scan_seconds"] = float("nan")
    path = tmp_path / "report.json"
    material = json.dumps(report)
    if tamper == "duplicate_key":
        material = material.replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
        )
    path.write_text(material)
    with pytest.raises(ValueError):
        load_owasp_report(path)


@pytest.mark.parametrize(
    "name,json_name,csv_name",
    [
        ("owasp-python-v01", "results.json", "cases.csv"),
        ("hash-selection-v1", "owasp-results.json", "owasp-cases.csv"),
        ("cookie-options-v1", "owasp-results.json", "owasp-cases.csv"),
    ],
)
def test_committed_baselines_validate_without_rewriting_archived_evidence(
    name: str, json_name: str, csv_name: str
) -> None:
    corpus = Path(__file__).resolve().parents[1] / "benchmarks" / name
    report = load_owasp_report(corpus / json_name, corpus / csv_name)
    assert len(report["cases"]) == 1230
    assert compare_owasp_reports(report, report, require_identical=True)["exit_code"] == 3


def test_cli_writes_changed_case_evidence_and_preserves_exit_codes(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    output = tmp_path / "comparison.json"
    _save(before, _report(tmp_path, {0}))
    _save(after, _report(tmp_path, {0, 1}))
    result = CliRunner().invoke(app, ["compare-owasp", str(before), str(after), "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["channels"]["all_candidates"]["improved_cases"] == [
        "BenchmarkTest00001"
    ]
    result = CliRunner().invoke(
        app, ["compare-owasp", str(before), str(after), "-o", str(output), "--require-identical"]
    )
    assert result.exit_code == 1
    _save(after, _report(tmp_path, {0}, missing=3))
    result = CliRunner().invoke(app, ["compare-owasp", str(after), str(after), "-o", str(output)])
    assert result.exit_code == 3
    material = before.read_bytes()
    result = CliRunner().invoke(app, ["compare-owasp", str(before), str(after), "-o", str(before)])
    assert result.exit_code == 2
    assert before.read_bytes() == material


def test_csv_requires_explicit_companion_and_rejects_conflicting_or_ambiguous_rows(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path, {0})
    cases = tmp_path / "cases.csv"
    with cases.open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "case",
                "file_path",
                "category",
                "cwe",
                "positive",
                "unscored_reason",
                *CHANNELS,
                "matched_rules",
                "matched_finding_count",
            ],
        )
        writer.writeheader()
        for case in report["cases"]:
            writer.writerow(
                {
                    **{
                        key: case[key]
                        for key in (
                            "case",
                            "file_path",
                            "category",
                            "cwe",
                            "unscored_reason",
                            "matched_finding_count",
                        )
                    },
                    "positive": str(case["positive"]).lower(),
                    **case["outcomes"],
                    "matched_rules": "|".join(case["matched_rules"]),
                }
            )
    path = tmp_path / "report.json"
    _save(path, report)
    with pytest.raises(ValueError, match="never both"):
        load_owasp_report(path, cases)
    report.pop("cases")
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="complete case rows"):
        load_owasp_report(path)
    assert len(load_owasp_report(path, cases)["cases"]) == 4
    original = cases.read_text()
    cases.write_text(original.replace("true", "yes", 1))
    with pytest.raises(ValueError, match="malformed"):
        load_owasp_report(path, cases)
    cases.write_text(original.replace("AEG-DEMO", "AEG-DEMO|AEG-TWO;AEG-THREE", 1))
    with pytest.raises(ValueError, match="mixed"):
        load_owasp_report(path, cases)
