from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aegify.agents.models import SecurityAgentRun
from aegify.cli import app
from aegify.config import AegifyConfig
from aegify.models import Finding, ScanResult, Severity
from aegify.scanner.engine import ScanEngine
from tests.llm_support import ScriptedProvider, message


@pytest.mark.parametrize(
    "command,output",
    [
        ("scan", "json"),
        ("scan", "sarif"),
        ("scan", "github"),
        ("scan", "console"),
        ("scan-pr", "sarif"),
    ],
)
def test_scan_cli_retains_uncertain_accounting_and_original_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    output: str,
) -> None:
    (tmp_path / "app.py").write_text("def greet(name):\n    return name\n")
    config = AegifyConfig(anthropic_api_key="synthetic-unused-key")
    config.scan.max_workers = 1
    monkeypatch.setattr(AegifyConfig, "load", classmethod(lambda *_: config))
    method = "scan_files" if command == "scan-pr" else "scan"
    original_scan = getattr(ScanEngine, method)

    def supplied_candidate(engine: ScanEngine, *args: Any, **kwargs: Any) -> ScanResult:
        result = original_scan(engine, *args, **kwargs)
        result.findings = [
            Finding(
                rule_id="OWNED-FIXTURE",
                rule_name="Owned static candidate",
                severity=Severity.LOW,
                confidence=0.4,
                file_path="app.py",
                line_start=1,
                line_end=1,
                remediation="Scanner-authored guidance",
            )
        ]
        return result

    monkeypatch.setattr(ScanEngine, method, supplied_candidate)
    report, comment = tmp_path / "report.out", tmp_path / "comment.md"
    args = [command, str(tmp_path), "--llm", "--model", "fixture-model"]
    if command == "scan-pr":
        args.extend(["--changed-files", "app.py", "--comment-file", str(comment)])
    elif output != "console":
        args.extend(["--output", output])
    if output != "console":
        args.extend(["--output-file", str(report)])
    with ScriptedProvider({"error": "owned scripted interruption"}, status=503) as provider:
        provider.install(monkeypatch)
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, result.output
        assert len(provider.requests) == 1
        assert provider.http_clients and all(client.is_closed for client in provider.http_clients)
    if output == "json":
        retained = json.loads(report.read_text())
        usage = retained["token_usage"]
        candidate = retained["findings"][0]
        assert candidate["status"] == "new" and candidate["evidence_state"] == "candidate"
        assert candidate["remediation"] == "Scanner-authored guidance"
    elif output == "sarif":
        run = json.loads(report.read_text())["runs"][0]
        usage = run["invocations"][0]["properties"]["tokenUsage"]
        candidate = run["results"][0]["properties"]
        assert candidate["status"] == "new" and candidate["evidenceState"] == "candidate"
        assert candidate["aiReview"]["verdict"] == "needs_review"
    else:
        rendered = result.output if output == "console" else report.read_text()
        assert "Cost: unknown" in rendered and "$0.0000" not in rendered
        return
    assert usage["calls_started"] == 1 and usage["calls_with_unknown_usage"] == 1
    assert usage["total_cost_usd"] is None and usage["reserved_tokens"] > 0
    assert usage["calls"][0]["http_status"] == 503
    if command == "scan-pr":
        assert "Cost: unknown" in comment.read_text() and "findings retained" in result.output
        assert "confirmed findings" not in result.output


@pytest.mark.parametrize(
    "outcome,expected_calls",
    [
        ("completed", 6),
        ("incomplete", 6),
        ("budget", 2),
        ("invalid_narrative", 6),
    ],
)
def test_anthropic_agent_cli_retains_all_role_receipts_and_closes_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    expected_calls: int,
) -> None:
    config = AegifyConfig(anthropic_api_key="synthetic-unused-key")
    if outcome == "budget":
        config.llm.max_calls = 2
    monkeypatch.setattr(AegifyConfig, "load", classmethod(lambda *_: config))
    source, artifact = tmp_path / "scan.json", tmp_path / "agent.json"
    source.write_text(ScanResult(id="owned-empty-scan").model_dump_json())
    narrative = {
        "summary": "Static fixture narrative",
        "claims": [],
        "evidence_gaps": [],
        "recommendations": [],
    }
    if outcome == "invalid_narrative":
        del narrative["claims"]
    envelope = message(
        json.dumps(narrative), stop_reason=("max_tokens" if outcome == "incomplete" else "end_turn")
    )
    with ScriptedProvider(envelope) as provider:
        provider.install(monkeypatch)
        result = CliRunner().invoke(
            app,
            [
                "agent-run",
                str(source),
                "--provider",
                "anthropic-api",
                "--model",
                "fixture-model",
                "--workspace",
                str(tmp_path),
                "--output-file",
                str(artifact),
            ],
        )
        assert result.exit_code == (0 if outcome == "completed" else 3), result.output
        assert len(provider.requests) == expected_calls
        assert provider.http_clients and all(client.is_closed for client in provider.http_clients)
    run = SecurityAgentRun.model_validate_json(artifact.read_text())
    assert run.token_usage and run.token_usage.calls_started == expected_calls
    assert run.token_usage.total_cost_usd is None
    assert run.token_usage.reported_tokens == expected_calls * 19
    roles = [f"agent:{stage.role.value}" for stage in run.stages][:expected_calls]
    assert [call.phase for call in run.token_usage.calls] == roles
    if outcome == "budget":
        assert run.token_usage.calls_rejected_before_dispatch == 4
    elif outcome != "completed":
        code = "incomplete_response" if outcome == "incomplete" else "invalid_response"
        assert all(
            stage.backend_error_code == code and stage.narrative is None for stage in run.stages
        )
    assert run.artifact_digest in result.output
    old_digest = run.artifact_digest
    run.token_usage = None
    assert run.artifact_digest != old_digest
