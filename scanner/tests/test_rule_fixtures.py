"""Authoring contracts against the real engine and supervised worker process."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from aegify.cli import app
from aegify.quality.rule_fixtures import (
    MAX_FILE_BYTES,
    MAX_RULE_BYTES,
    FixtureReport,
    FixtureWorkerError,
    RuleFixtureSuite,
    _supervise,
    read_input,
    result_digest,
    run_rule_fixtures,
    strict_json,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "rule-fixtures"


def _suite(name: str = "call") -> RuleFixtureSuite:
    return RuleFixtureSuite.model_validate_json((EXAMPLES / f"{name}.fixtures.json").read_text())


def _rule(name: str = "call") -> str:
    return (EXAMPLES / f"{name}.yml").read_text()


def test_real_worker_exact_results_replay_and_environment_independence(monkeypatch):
    first = run_rule_fixtures(_rule(), _suite())
    # An operator's shell must not enable AI, change detection or select remote storage.
    monkeypatch.setenv("AEGIFY_LLM__ENABLED", "true")
    monkeypatch.setenv("AEGIFY_RULES__DISABLED_RULES", '["AEG-CUSTOM-001"]')
    monkeypatch.setenv("AEGIFY_STORAGE__BACKEND", "postgresql")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-secret-not-forwarded")
    second = run_rule_fixtures(_rule(), _suite())
    assert first.exit_code == second.exit_code == 0
    assert first.result_digest == second.result_digest == result_digest(second)
    assert first.metrics is not None
    assert first.metrics.true_positives == 1
    assert first.metrics.false_positives == first.metrics.false_negatives == 0
    assert first.cases[0].actual[0]["file_path"] == "handlers/main.py"
    assert first.cases[0].actual[0]["evidence_state"] == "candidate"
    assert first.cases[0].actual[0]["disposition"] == "advisory"
    assert first.cases[1].metrics is not None
    assert first.cases[1].metrics.precision is first.cases[1].metrics.recall is None
    assert all(case.evaluated_rules == ["AEG-CUSTOM-001"] for case in second.cases)
    assert second.manifest["config"]["llm"]["enabled"] is False
    assert second.manifest["config"]["storage"]["backend"] == "memory"
    assert "synthetic-secret-not-forwarded" not in second.model_dump_json()
    if sys.platform.startswith("linux"):
        assert 0 < second.manifest["memory_limit_bytes"] <= 2 * 1024**3


def test_real_taint_flow_with_constant_and_parameterized_negatives():
    report = run_rule_fixtures(_rule("taint"), _suite("taint"))
    assert report.exit_code == 0
    assert run_rule_fixtures(_rule("taint"), _suite("taint")).result_digest == report.result_digest
    finding = report.cases[0].actual[0]
    assert finding["evidence_state"] == "reachable"
    assert finding["disposition"] == "blocking"
    assert finding["taint_flow"]["source"]["source_type"] == "http_param"
    assert finding["taint_flow"]["sink"]["sink_type"] == "sql_query"
    assert not report.cases[1].actual and not report.cases[2].actual
    cross_file = report.cases[3].actual[0]["taint_flow"]
    assert cross_file["source"]["file_path"] == "handler.py"
    assert cross_file["sink"]["file_path"] == "helper.py"
    assert any(
        step["propagation_type"] == "argument" and step["call_context"]
        for step in cross_file["path"]
    )


def test_direct_json_worker_and_cli_controller_share_timeout_identity(tmp_path):
    reports = []
    request = tmp_path / "request.json"
    for timeout in (30, 30.0):
        request.write_text(
            json.dumps(
                {"rule_yaml": _rule(), "suite": _suite().model_dump(), "timeout_seconds": timeout}
            )
        )
        raw = _supervise(
            [sys.executable, "-I", "-m", "aegify.quality.rule_fixture_worker", str(request)],
            tmp_path,
            30,
        )
        report = FixtureReport.model_validate(strict_json(raw))
        assert report.exit_code == 0
        assert type(report.manifest["wall_timeout_seconds"]) is int
        assert report.result_digest == result_digest(report)
        reports.append(report)
    controller = run_rule_fixtures(_rule(), _suite(), timeout_seconds=30.0)
    assert controller.exit_code == 0
    assert reports[0].result_digest == reports[1].result_digest == controller.result_digest


@pytest.mark.parametrize("timeout", [True, "30", None, 0, 120.1])
def test_direct_worker_rejects_invalid_timeout_before_analysis(tmp_path, timeout):
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {"rule_yaml": _rule(), "suite": _suite().model_dump(), "timeout_seconds": timeout}
        )
    )
    raw = _supervise(
        [sys.executable, "-I", "-m", "aegify.quality.rule_fixture_worker", str(request)],
        tmp_path,
        30,
    )
    report = FixtureReport.model_validate(strict_json(raw))
    assert report.status == "error"
    assert report.issues == ["rule_or_worker_invalid"]
    assert report.cases == []


def test_cross_file_constant_and_unused_source_are_negative_controls():
    suite = _suite("taint")
    cross_file = suite.cases[3].model_dump()
    for identity, handler in [
        (
            "constant",
            "from helper import run_query\ndef handler(request, cursor):\n"
            "    return run_query(cursor, 'SELECT 1')\n",
        ),
        (
            "unused-source",
            "from helper import run_query\ndef handler(request, cursor):\n"
            "    query = request.args.get('query')\n"
            "    return run_query(cursor, 'SELECT 1')\n",
        ),
    ]:
        value = json.loads(json.dumps(cross_file))
        value["id"] = identity
        value["files"][0]["content"] = handler
        value["expected"] = []
        suite.cases.append(type(suite.cases[0]).model_validate(value))
    report = run_rule_fixtures(_rule("taint"), suite)
    assert report.exit_code == 0
    assert report.cases[-2].actual == report.cases[-1].actual == []


def test_sources_in_multiple_files_are_never_imported_or_executed():
    value = _suite().model_dump()
    value["cases"][0]["files"].append(
        {
            "path": "helpers/never_import.py",
            "content": "import package_that_does_not_exist\n"
            "raise RuntimeError('must not execute')\n",
        }
    )
    report = run_rule_fixtures(_rule(), RuleFixtureSuite.model_validate(value))
    assert report.exit_code == 0
    assert report.cases[0].files_scanned == 2


def test_mismatch_counts_unexpected_and_missing_locations_without_line_tolerance():
    suite = _suite()
    suite.cases[0].expected[0].line_start = 1
    suite.cases[1].files[0].content = "def handle(request):\n    return review_target(request)\n"
    report = run_rule_fixtures(_rule(), suite)
    assert report.exit_code == 1
    assert report.metrics is not None
    assert (
        report.metrics.true_positives,
        report.metrics.false_positives,
        report.metrics.false_negatives,
    ) == (0, 2, 1)
    assert report.cases[0].unmatched_actual == ["AEG-CUSTOM-001:handlers/main.py:2"]
    assert report.cases[0].unmatched_expected == ["AEG-CUSTOM-001:handlers/main.py:1"]


@pytest.mark.parametrize("mode", ["no-positive", "one-negative"])
def test_missing_controls_never_give_a_green_suite(mode):
    suite = _suite()
    if mode == "no-positive":
        suite.cases = suite.cases[1:]
    else:
        suite.cases = suite.cases[:2]
    report = run_rule_fixtures(_rule(), suite)
    assert report.exit_code == 3
    assert all(case.status == "passed" for case in report.cases)
    assert report.metrics is None
    assert report.issues


@pytest.mark.parametrize(
    "mode,issue",
    [
        ("parse-error", "syntax_recovery"),
        ("unsupported", "unsupported_source"),
        ("different-language", "rule_not_evaluated"),
        ("cap", "detector_limit_reached"),
    ],
)
def test_analysis_gaps_and_internal_output_caps_are_not_negative_passes(mode, issue):
    value = _suite().model_dump()
    source = value["cases"][1]["files"][0]
    if mode == "parse-error":
        source["content"] = "def broken(\n"
    elif mode == "unsupported":
        source["path"] = "main.rb"
        source["content"] = "def run; end\n"
    elif mode == "different-language":
        source["path"] = "main.js"
        source["content"] = "function run() { return 1; }\n"
    else:
        source["content"] = "def handle(request):\n" + "    review_target(request)\n" * 8
    report = run_rule_fixtures(_rule(), RuleFixtureSuite.model_validate(value))
    assert report.exit_code == 3
    assert report.cases[1].status == "incomplete"
    assert issue in report.cases[1].issues
    assert report.cases[1].metrics is report.metrics is None


@pytest.mark.parametrize(
    "path",
    [
        "../outside.py",
        "/absolute.py",
        "src//main.py",
        "src/./main.py",
        "src/../main.py",
        "src\\main.py",
        ".env",
        "src/.hidden.py",
        "name:main.py",
        "main.py\n",
    ],
)
def test_fixture_paths_cannot_escape_or_alias(path):
    value = _suite().model_dump()
    value["cases"][1]["files"][0]["path"] = path
    with pytest.raises(ValidationError):
        RuleFixtureSuite.model_validate(value)


@pytest.mark.parametrize(
    "mode",
    [
        "duplicate-path",
        "case-collision",
        "directory-collision",
        "large-source",
        "bad-unicode",
        "duplicate-case",
        "unknown-field",
        "wrong-rule",
        "missing-file",
        "missing-line",
        "string-line",
        "boolean-line",
        "duplicate-expected",
        "boolean-version",
    ],
)
def test_fixture_contract_rejects_ambiguous_or_unbounded_inputs(mode):
    value = _suite().model_dump()
    case = value["cases"][0]
    expected = case["expected"][0]
    if mode in {"duplicate-path", "case-collision", "directory-collision"}:
        path = case["files"][0]["path"]
        path = (
            path.upper()
            if mode == "case-collision"
            else path + "/child.py"
            if mode == "directory-collision"
            else path
        )
        case["files"].append({"path": path, "content": "pass\n"})
    elif mode == "large-source":
        case["files"][0]["content"] = "x" * (MAX_FILE_BYTES + 1)
    elif mode == "bad-unicode":
        case["files"][0]["content"] = "\ud800"
    elif mode == "duplicate-case":
        value["cases"].append(case)
    elif mode == "unknown-field":
        case["command"] = "not-an-executable-contract"
    elif mode == "wrong-rule":
        expected["rule_id"] = "AEG-OTHER-001"
    elif mode == "missing-file":
        expected["file_path"] = "absent.py"
    elif mode == "missing-line":
        expected["line_start"] = 100
    elif mode == "string-line":
        expected["line_start"] = "2"
    elif mode == "boolean-line":
        expected["line_start"] = True
    elif mode == "duplicate-expected":
        case["expected"].append(dict(expected))
    else:
        value["schema_version"] = True
    with pytest.raises(ValidationError):
        RuleFixtureSuite.model_validate(value)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'])
def test_json_does_not_silently_replace_keys_or_accept_nonfinite_values(raw):
    with pytest.raises(ValueError):
        strict_json(raw)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate-key",
        "alias",
        "deep",
        "multi-rule",
        "wrong-id",
        "disabled",
        "unsupported-field",
        "bad-taint",
        "empty-taint",
    ],
)
def test_invalid_rule_never_runs_as_a_partial_or_empty_rule_set(mutation):
    rule = _rule()
    if mutation == "duplicate-key":
        rule += "id: AEG-CUSTOM-001\n"
    elif mutation == "alias":
        rule += "notes: &notes [*notes]\n"
    elif mutation == "deep":
        rule += "notes: " + "[" * 45 + "value" + "]" * 45 + "\n"
    elif mutation == "multi-rule":
        rule = yaml.safe_dump({"rules": [yaml.safe_load(rule)] * 2})
    elif mutation == "wrong-id":
        rule = rule.replace("AEG-CUSTOM-001", "AEG-OTHER-001")
    elif mutation == "disabled":
        rule += "enabled: false\n"
    elif mutation == "unsupported-field":
        rule = rule.replace("args_match: request", "future_args: request")
    elif mutation == "bad-taint":
        rule += "taint:\n  sources: [{type: http_param}]\n  sinks: [{type: sql_query}]\n"
    else:
        rule += "taint: {}\n"
    report = run_rule_fixtures(rule, _suite())
    assert report.exit_code == 2
    assert not report.cases
    assert report.manifest["rule_digest"].startswith("sha256:")
    assert report.result_digest == result_digest(report)
    if mutation in {"unsupported-field", "bad-taint", "empty-taint"}:
        assert report.issues == ["invalid_rule"]
        assert report.diagnostics


def test_injected_registry_does_not_load_defaults_or_custom_rules(tmp_path, monkeypatch):
    import aegify.scanner.engine as module
    from aegify.rules.base import RuleRegistry
    from aegify.rules.yaml_rule import load_yaml_rules
    from aegify.worker import worker_config

    def forbidden(*_args):
        raise AssertionError("global registry must not participate in a rule preview")

    monkeypatch.setattr(module, "load_builtin_rules", forbidden)
    monkeypatch.setattr(module, "load_custom_rules", forbidden)
    monkeypatch.setattr(module, "get_registry", forbidden)
    registry = RuleRegistry()
    registry.register(load_yaml_rules(EXAMPLES / "call.yml")[0])
    source = tmp_path / "main.py"
    source.write_text("def handle(request):\n    return review_target(request)\n")
    config = worker_config()
    config.rules.custom_rules = "must-not-load.yml"
    result = module.ScanEngine(config=config, rule_registry=registry).scan_files(tmp_path, [source])
    assert result.evaluated_rules == ["AEG-CUSTOM-001"]
    assert len(result.findings) == 1


def test_supervisor_deadline_and_output_limit_stop_trusted_test_processes(tmp_path):
    started = time.monotonic()
    with pytest.raises(FixtureWorkerError, match="worker_timeout"):
        _supervise([sys.executable, "-I", "-c", "import time; time.sleep(10)"], tmp_path, 0.2)
    assert time.monotonic() - started < 3
    with pytest.raises(FixtureWorkerError, match="worker_output_limit"):
        _supervise(
            [sys.executable, "-I", "-c", "import sys; sys.stdout.write('x' * 5000000)"], tmp_path, 5
        )


def test_controller_reports_timeout_and_rejects_oversized_rule():
    report = run_rule_fixtures(_rule(), _suite(), timeout_seconds=0.01)
    assert report.exit_code == 2 and report.issues == ["worker_timeout"]
    assert run_rule_fixtures("x" * (MAX_RULE_BYTES + 1), _suite()).exit_code == 2


def test_worker_report_with_changed_findings_fails_digest_check(monkeypatch):
    import aegify.quality.rule_fixtures as module

    report = run_rule_fixtures(_rule(), _suite())
    report.cases[0].actual = []
    monkeypatch.setattr(module, "_supervise", lambda *_args: report.model_dump_json().encode())
    invalid = run_rule_fixtures(_rule(), _suite())
    assert invalid.exit_code == 2
    assert invalid.issues == ["worker_report_mismatch"]


def test_regular_input_requirement_rejects_symlinks_and_fifo_without_blocking(tmp_path):
    source = tmp_path / "source"
    source.write_text("{}")
    link = tmp_path / "link"
    link.symlink_to(source)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (link, fifo):
        with pytest.raises((OSError, ValueError)):
            read_input(path, 100)


def test_cli_writes_machine_readable_reports_and_preserves_exit_contract(tmp_path):
    runner = CliRunner()
    path = tmp_path / "fixtures.json"
    output = tmp_path / "result.json"
    suite = _suite()
    for expected_exit in (0, 1, 3, 2):
        if expected_exit == 1:
            suite.cases[0].expected[0].line_start = 1
        elif expected_exit == 3:
            suite.cases = suite.cases[1:]
        path.write_text(suite.model_dump_json() if expected_exit != 2 else '{"bad":')
        result = runner.invoke(
            app,
            [
                "test-rule",
                str(EXAMPLES / "call.yml"),
                "--fixtures",
                str(path),
                "--output-file",
                str(output),
                "--json",
            ],
        )
        assert result.exit_code == expected_exit, result.output
        assert json.loads(result.stdout) == json.loads(output.read_text())
