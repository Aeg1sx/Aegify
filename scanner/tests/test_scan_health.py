"""Scan failures and bounded results must never masquerade as clean scans."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from aegify.cli import _scan_exit_code, app
from aegify.config import AegifyConfig
from aegify.models import Finding, Language, ScanResult, ScanStatus, Severity
from aegify.reporter.github import GitHubReporter, generate_pr_comment
from aegify.reporter.sarif import SARIFReporter
from aegify.scanner.engine import ScanEngine


@pytest.mark.parametrize("status,expected", [(ScanStatus.FAILED, 2), (ScanStatus.PARTIAL, 3)])
@pytest.mark.parametrize("command", ["scan", "scan-pr"])
def test_cli_preserves_unhealthy_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: ScanStatus, expected: int, command: str
) -> None:
    source = tmp_path / "health.py"
    source.write_text("def health():\n    return True\n")
    scan = ScanResult(status=status)
    scan.add_gap("test_interruption", "scan", "Analysis did not finish")
    monkeypatch.setattr(ScanEngine, "scan", lambda *args, **kwargs: scan)
    monkeypatch.setattr(ScanEngine, "scan_files", lambda *args, **kwargs: scan)
    args = [command, str(tmp_path), "--no-llm"]
    if command == "scan-pr":
        args.extend(
            [
                "--changed-files",
                "health.py",
                "--output-file",
                str(tmp_path / "result.sarif"),
                "--comment-file",
                str(tmp_path / "comment.md"),
            ]
        )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == expected, result.output
    assert "No security findings detected" not in result.output
    assert "Analysis health" in result.output
    if command == "scan-pr":
        assert "No Issues Found" not in (tmp_path / "comment.md").read_text()


@pytest.mark.parametrize("status", [ScanStatus.FAILED, ScanStatus.PARTIAL])
def test_reports_preserve_failure_and_partial_diagnostics(status: ScanStatus) -> None:
    result = ScanResult(status=status)
    result.add_gap("test_interruption", "scan", "Analysis did not finish", 7)
    sarif = SARIFReporter().generate(result)["runs"][0]
    assert sarif["invocations"][0]["executionSuccessful"] is False
    assert sarif["properties"]["analysisStatus"] == status.value
    assert sarif["properties"]["analysisGaps"][0]["affected_count"] == 7
    for markdown in (
        GitHubReporter().generate_comment(result),
        generate_pr_comment(result, [], []),
    ):
        assert "coverage is incomplete" in markdown
        assert "No Issues" not in markdown
        assert "No security" not in markdown


def test_partial_benchmark_cannot_pass_even_with_perfect_finding_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "corpus"
    root.mkdir()
    source = root / "health.py"
    source.write_text("value = 1\n")
    manifest = tmp_path / "truth.json"
    manifest.write_text(
        json.dumps(
            {
                "corpus_id": "health-contract",
                "corpus_version": "1.0.0",
                "rule_scope": ["AEG-DEMO"],
                "expected": [{"rule_id": "AEG-DEMO", "file_path": "health.py", "line_start": 1}],
            }
        )
    )
    finding = _finding(source, 1)
    scan = ScanResult(findings=[finding])
    scan.add_gap("taint_limit", "taint", "Analysis reached its bound")
    monkeypatch.setattr(ScanEngine, "scan", lambda *args, **kwargs: scan)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            str(source),
            "--ground-truth",
            str(manifest),
            "--output-file",
            str(output),
        ],
    )
    assert result.exit_code == 3, result.output
    report = json.loads(output.read_text())
    assert report["metrics"]["precision"] == 1.0
    assert report["analysis_status"] == "partial"


def _finding(source: Path, line: int) -> Finding:
    return Finding(
        rule_id="AEG-DEMO",
        rule_name="Synthetic count contract",
        severity=Severity.LOW,
        confidence=0.9,
        file_path=str(source),
        line_start=line,
        line_end=line,
    )


@pytest.mark.parametrize(
    "rule_cap,file_cap,code",
    [
        (2, 0, "rule_finding_limit"),
        (0, 2, "file_finding_limit"),
        (0, 0, None),
    ],
)
def test_output_limits_preserve_omission_count_and_zero_disables_limit(
    tmp_path: Path, rule_cap: int, file_cap: int, code: str | None
) -> None:
    source = tmp_path / "health.py"
    source.write_text("def health():\n    return True\n")
    config = AegifyConfig()
    config.rules.severity_threshold = "low"
    config.scan.max_findings_per_rule = rule_cap
    config.scan.max_findings_per_file = file_cap
    engine = ScanEngine(config=config)
    rule = Mock()
    rule.definition.id = "AEG-DEMO"
    rule.definition.languages = [Language.PYTHON]
    rule.evaluate.return_value = [_finding(source, line) for line in range(1, 6)]
    engine.registry = Mock()
    engine.registry.get_enabled.return_value = [rule]
    engine.registry.get.return_value = None
    result = engine.scan(source)
    if code:
        assert result.status == ScanStatus.PARTIAL
        assert len(result.findings) == 2
        assert [(gap.code, gap.affected_count) for gap in result.analysis_gaps] == [(code, 3)]
    else:
        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 5
        assert not result.analysis_gaps
    assert result.evaluated_rules == ["AEG-DEMO"]


def test_empty_or_unsupported_source_is_not_a_clean_scan(tmp_path: Path) -> None:
    (tmp_path / "app.php").write_text("<?php echo 'health';\n")
    result = ScanEngine().scan(tmp_path)
    assert result.status == ScanStatus.PARTIAL
    assert any(gap.code == "no_source_files" for gap in result.analysis_gaps)
    assert result.unsupported_languages == {"php": 1}
    assert _scan_exit_code(result) == 3


def test_mixed_language_backend_cannot_be_hidden_by_supported_frontend(tmp_path: Path) -> None:
    (tmp_path / "server.php").write_text("<?php echo 'ok';\n")
    (tmp_path / "app.js").write_text("const ready = true;\n")
    result = ScanEngine().scan(tmp_path)
    assert result.files_scanned == 1
    assert result.status == ScanStatus.PARTIAL
    assert result.unsupported_languages == {"php": 1}
    config = AegifyConfig()
    config.scan.exclude.append("*.php")
    scoped = ScanEngine(config).scan(tmp_path)
    assert scoped.status == ScanStatus.COMPLETED
    assert scoped.unsupported_languages == {}


@pytest.mark.parametrize("mode", ["file", "directory", "files", "workspace"])
def test_syntax_recovery_is_partial_in_every_scan_mode(tmp_path: Path, mode: str) -> None:
    source = tmp_path / "broken.py"
    source.write_text("value = 1\ndef broken(:\n    return value\n")
    engine = ScanEngine()
    if mode == "file":
        result = engine.scan(source)
    elif mode == "files":
        result = engine.scan_files(tmp_path, [source])
    elif mode == "workspace":
        manifest = tmp_path / "workspace.yaml"
        manifest.write_text("name: health\nrepositories:\n  - id: app\n    path: .\n")
        result = engine.scan_workspace(manifest)
    else:
        result = engine.scan(tmp_path)
    assert result.status == ScanStatus.PARTIAL
    assert any(gap.code == "syntax_recovery" for gap in result.analysis_gaps)
    assert result.parse_diagnostics[0].line_start == 2


def test_size_limit_and_configured_languages_are_applied(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("value = 1\n")
    (tmp_path / "huge.py").write_text("# " + "x" * 2000)
    (tmp_path / "disabled.js").write_text("const value = 1;\n")
    config = AegifyConfig()
    config.scan.max_file_size_kb = 1
    config.scan.languages = ["python"]
    result = ScanEngine(config).scan(tmp_path)
    assert result.files_scanned == 1
    assert result.status == ScanStatus.PARTIAL
    assert [(gap.code, gap.affected_count) for gap in result.analysis_gaps] == [
        ("source_size_limit", 1)
    ]


def test_supported_but_unreadable_source_is_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    engine = ScanEngine()
    monkeypatch.setattr(engine.ast_parser, "parse_file", lambda *args, **kwargs: None)
    result = engine.scan(source)
    assert result.status == ScanStatus.PARTIAL
    assert any(gap.code == "unreadable_source" for gap in result.analysis_gaps)


def test_configured_taint_bound_propagates_to_scan_health(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def helper(value):\n    return len(value)\ndef route():\n    return helper(input())\n"
    )
    config = AegifyConfig()
    config.taint.max_contexts = 1
    result = ScanEngine(config).scan(source)
    assert result.status == ScanStatus.PARTIAL
    assert any(gap.code == "taint_limit" for gap in result.analysis_gaps)
    assert "global taint hit the 1-context bound" in result.taint_analysis.warnings
    assert result.taint_analysis.contexts_analyzed <= 1
