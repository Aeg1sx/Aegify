from pathlib import Path

from typer.testing import CliRunner

from aegify.cli import _has_blocking_high_findings, app
from aegify.models import (
    Finding,
    FindingDisposition,
    ScanResult,
    ScanStatus,
    Severity,
)

runner = CliRunner()


def _gate_result(disposition: FindingDisposition) -> ScanResult:
    return ScanResult(
        status=ScanStatus.COMPLETED,
        findings=[
            Finding(
                rule_id="TEST-GATE-001",
                rule_name="Gate test",
                severity=Severity.HIGH,
                confidence=0.8,
                disposition=disposition,
                file_path="app.py",
                line_start=1,
                line_end=1,
            )
        ],
    )


def test_ci_gate_ignores_high_advisory_but_blocks_high_evidence() -> None:
    assert _has_blocking_high_findings(_gate_result(FindingDisposition.ADVISORY)) is False
    assert _has_blocking_high_findings(_gate_result(FindingDisposition.BLOCKING)) is True


def test_scan_pr_supports_static_only_mode_without_api_key(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def health():\n    return 'ok'\n", encoding="utf-8")
    sarif = tmp_path / "results.sarif"
    comment = tmp_path / "comment.md"

    result = runner.invoke(
        app,
        [
            "scan-pr",
            str(tmp_path),
            "--changed-files",
            "app.py",
            "--no-llm",
            "--output-file",
            str(sarif),
            "--comment-file",
            str(comment),
        ],
        env={"AEGIFY_ANTHROPIC_API_KEY": ""},
    )

    assert result.exit_code == 0, result.output
    assert sarif.is_file()
    assert comment.is_file()
    assert "LLM: disabled" in result.output


def test_scan_pr_requires_api_key_when_llm_is_enabled(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan-pr", str(tmp_path), "--changed-files", "app.py", "--llm"],
        env={"AEGIFY_ANTHROPIC_API_KEY": ""},
    )

    assert result.exit_code == 2
    assert "AEGIFY_ANTHROPIC_API_KEY" in result.output
