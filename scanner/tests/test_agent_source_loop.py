"""Owned, inert sources and scripted models; no live providers or reviewed code run."""

from __future__ import annotations

import hashlib
import io
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest
from typer.testing import CliRunner

from aegify.agents.backends import CommandAgentBackend, CommandBackendConfig
from aegify.agents.catalog import AGENT_CATALOG
from aegify.agents.exploration import SOURCE_TOOLS, AgentSourceExplorer, turn_schema
from aegify.agents.models import (
    AgentExplorationLimits,
    AgentRole,
    AgentStageResult,
    AgentStageStatus,
    SecurityAgentRun,
)
from aegify.agents.pipeline import SecurityAgentPipeline
from aegify.cli import app
from aegify.llm.sources import SourceCatalog
from aegify.llm.tools import AnalysisToolContext, default_tool_registry
from aegify.models import AnalyzedSource, EvidenceProvenance, Finding, ScanResult, Severity
from tests.llm_support import ScriptedProvider, message

NARRATIVE = {
    "summary": "The supplied source returns the name. This is a static observation.",
    "claims": [],
    "evidence_gaps": [],
    "recommendations": [],
}


def source_scan(root: Path, repository: str = "service") -> tuple[ScanResult, SourceCatalog]:
    path = root / "src/app.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = b"def greet(name):\n    return name\n"
    path.write_bytes(raw)
    scan = ScanResult(
        analyzed_sources=[
            AnalyzedSource(
                repository_id=repository,
                module_path="src/app.py",
                file_path=str(path),
                language="python",
                source_digest=hashlib.sha256(raw).hexdigest(),
            )
        ],
        findings=[
            Finding(
                id="owned-finding",
                rule_id="OWNED-STATIC",
                rule_name="Owned static review",
                severity=Severity.LOW,
                confidence=0.4,
                file_path=str(path),
                line_start=2,
                line_end=2,
                message="Review source provenance",
                provenance=EvidenceProvenance(repository_id=repository),
            )
        ],
    )
    return scan, SourceCatalog.from_scan(scan, {repository: root})


def requests(*items: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "kind": "tools",
        "requests": [{"name": name, "arguments": args} for name, args in items],
        "narrative": None,
        "citation_ids": [],
    }


def final(citations: list[str]) -> dict[str, Any]:
    return {
        "kind": "final",
        "requests": [],
        "narrative": dict(NARRATIVE),
        "citation_ids": citations,
    }


def read_then_finish(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload["tool_results"]:
        return requests(("source_read", {"repository_id": "service", "path": "src/app.py"}))
    output = payload["tool_results"][0]["output"]
    return final([output["citation"]["citation_id"]] if "citation" in output else [])


class ScriptedBackend:
    provider_name = "openai_api"

    def __init__(
        self, handler: Callable[[dict[str, Any]], dict[str, Any]] = read_then_finish
    ) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def invoke(self, *_args: Any) -> Any:
        raise AssertionError("source review must use iterative turns")

    def invoke_turn(self, _spec: Any, payload: dict[str, Any], _schema: Any) -> dict[str, Any]:
        self.calls.append(payload)
        return self.handler(payload)


def review(
    tmp_path: Path,
    handler: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    limits: AgentExplorationLimits | None = None,
    role: AgentRole = AgentRole.STATIC,
) -> tuple[AgentStageResult, ScriptedBackend]:
    scan, sources = source_scan(tmp_path)
    stage = AgentStageResult(
        role=role,
        agent_code="owned",
        agent_name="Owned",
        summary="facts",
        status=AgentStageStatus.COMPLETED,
        facts={"unaltered": [1, 2]},
    )
    backend = ScriptedBackend(handler)
    AgentSourceExplorer(default_tool_registry(), limits or AgentExplorationLimits()).review(
        backend,
        AGENT_CATALOG[role],
        stage,
        AnalysisToolContext(
            findings={finding.id: finding for finding in scan.findings}, sources=sources
        ),
        "sha256:" + "a" * 64,
    )
    return stage, backend


def test_model_selects_files_then_reads_and_cites_across_all_six_roles(tmp_path: Path) -> None:
    scan, sources = source_scan(tmp_path)
    before = scan.model_dump_json()
    baseline = SecurityAgentPipeline().run(scan)

    def select(payload: dict[str, Any]) -> dict[str, Any]:
        payload["facts"]["model_mutation"] = "must stay detached"
        if payload["round"] == 1:
            return requests(("source_list_files", {"repository_id": "service", "offset": None}))
        if payload["round"] == 2:
            path = payload["tool_results"][0]["output"]["files"][0]["path"]
            return requests(
                ("source_search", {"repository_id": "service", "query": "return"}),
                ("source_read", {"repository_id": "service", "path": path}),
            )
        return final([payload["tool_results"][-1]["output"]["citation"]["citation_id"]])

    backend = ScriptedBackend(select)
    run = SecurityAgentPipeline(backend, source_tools=True).run(scan, sources=sources)
    assert len(backend.calls) == 18
    assert run.status == baseline.status
    assert scan.model_dump_json() == before
    assert [stage.facts for stage in run.stages] == [stage.facts for stage in baseline.stages]
    for stage in run.stages:
        trace = stage.exploration
        assert trace and trace.stop_reason == "final" and not trace.gaps
        assert trace.model_calls == 3 and trace.tool_calls == 3
        assert trace.covered_finding_ids == ["owned-finding"]
        assert trace.source_manifest == sources.manifest_digest
        assert len(trace.citations) == 1
        assert [item.outcome for item in trace.rounds] == ["tools", "tools", "final"]
        assert all(
            item.input_digest.startswith("sha256:") and item.output_digest for item in trace.rounds
        )
        assert trace.prompt_bytes == sum(item.prompt_bytes for item in trace.rounds)
    restored = SecurityAgentRun.model_validate_json(run.model_dump_json())
    assert restored.artifact_digest == run.artifact_digest
    original_digest = run.artifact_digest
    run.stages[0].exploration.rounds[0].output_digest = "sha256:" + "b" * 64  # type: ignore[union-attr]
    assert run.artifact_digest != original_digest


@pytest.mark.parametrize("kind", ["absent", "forged", "unissued"])
def test_unearned_citations_never_finish_source_review(tmp_path: Path, kind: str) -> None:
    _, catalog = source_scan(tmp_path)
    unissued = catalog.read({"repository_id": "service", "path": "src/app.py"})["citation"][
        "citation_id"
    ]
    ids = [] if kind == "absent" else [unissued if kind == "unissued" else "sha256:" + "f" * 64]
    stage, backend = review(tmp_path, lambda _payload: final(ids))
    assert len(backend.calls) == 1
    assert stage.status == AgentStageStatus.PARTIAL
    assert stage.exploration and not stage.exploration.citations
    assert "source_citations_required" in stage.exploration.gaps


@pytest.mark.parametrize(
    "response",
    [
        {"kind": "tools", "requests": [], "narrative": None, "citation_ids": []},
        {**final([]), "unknown": True},
        {**final([]), "narrative": {"summary": "Missing required lists"}},
        {**final([]), "citation_ids": ["same", "same"]},
        {**requests(("source_read", {})), "narrative": NARRATIVE},
        {**final([]), "narrative": {**NARRATIVE, "claims": [42]}},
        {**final([]), "narrative": {**NARRATIVE, "summary": float("nan")}},
        {**final([]), "narrative": {**NARRATIVE, "summary": "\ud800"}},
        requests(("source_read", {"repository_id": "service", "path": "\ud800"})),
        requests(("\ud800", {})),
    ],
)
def test_invalid_turns_stop_without_mutating_facts(
    tmp_path: Path, response: dict[str, Any]
) -> None:
    stage, backend = review(tmp_path, lambda _payload: response)
    assert len(backend.calls) == 1 and stage.narrative is None
    assert stage.exploration and stage.exploration.stop_reason == "invalid_response"
    assert stage.facts == {"unaltered": [1, 2]}


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("shell", {"command": "never executed"}),
        ("harness_plan", {"finding_id": "owned-finding"}),
        ("source_read", {"repository_id": "service", "path": "../private.py"}),
        ("source_read", {"repository_id": "service", "path": "src/app.py", "line_start": True}),
        ("source_read", {"repository_id": "service", "path": "src/app.py", "unknown": None}),
    ],
)
def test_role_and_argument_denials_are_audited(
    tmp_path: Path, name: str, arguments: dict[str, Any]
) -> None:
    def select(payload: dict[str, Any]) -> dict[str, Any]:
        return requests((name, arguments)) if payload["round"] == 1 else final([])

    stage, _backend = review(tmp_path, select)
    assert stage.status == AgentStageStatus.PARTIAL and stage.exploration
    tool = stage.exploration.tools[0]
    assert not tool.ok and not tool.evidence
    assert stage.exploration.tool_calls == 1


@pytest.mark.parametrize(
    "limit,expected,calls",
    [
        ({"max_rounds": 1}, "round_limit", 1),
        ({"max_tool_calls": 0}, "tool_limit", 1),
        ({"max_prompt_bytes": 4096}, "prompt_limit", 0),
    ],
)
def test_budgets_stop_before_further_dispatch(
    tmp_path: Path, limit: dict[str, int], expected: str, calls: int
) -> None:
    stage, backend = review(tmp_path, read_then_finish, limits=AgentExplorationLimits(**limit))
    assert len(backend.calls) == calls and stage.status == AgentStageStatus.PARTIAL
    assert stage.exploration and stage.exploration.stop_reason == expected
    assert stage.exploration.tool_calls == 0


def test_repeat_request_uses_cache_but_consumes_request_budget(tmp_path: Path) -> None:
    def select(payload: dict[str, Any]) -> dict[str, Any]:
        if payload["round"] == 1:
            item = ("source_read", {"repository_id": "service", "path": "src/app.py"})
            return requests(item, item)
        return read_then_finish(payload)

    stage, _backend = review(tmp_path, select, limits=AgentExplorationLimits(max_tool_calls=2))
    assert stage.status == AgentStageStatus.COMPLETED
    assert stage.exploration and stage.exploration.tool_calls == 1
    assert stage.exploration.cached_calls == 1
    first, second = stage.exploration.tools
    assert first.request_id != second.request_id and second.cached
    assert stage.exploration.citations[0].request_id == first.request_id


def test_partial_finding_coverage_is_not_complete_review(tmp_path: Path) -> None:
    def select(payload: dict[str, Any]) -> dict[str, Any]:
        if payload["round"] == 1:
            return requests(
                (
                    "source_read",
                    {
                        "repository_id": "service",
                        "path": "src/app.py",
                        "line_start": 1,
                        "line_end": 1,
                    },
                )
            )
        return read_then_finish(payload)

    stage, _backend = review(tmp_path, select)
    assert stage.status == AgentStageStatus.PARTIAL and stage.exploration
    assert stage.exploration.citations and not stage.exploration.covered_finding_ids
    assert "finding_source_coverage_incomplete" in stage.exploration.gaps


def test_backend_error_does_not_retain_private_content_or_retry(tmp_path: Path) -> None:
    def fail(_payload: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("private provider body and source must not be logged")

    stage, backend = review(tmp_path, fail)
    assert len(backend.calls) == 1 and stage.status == AgentStageStatus.PARTIAL
    assert "private provider body" not in stage.model_dump_json()
    assert stage.exploration and stage.exploration.rounds[0].outcome == "error"


def test_response_size_stops_before_narrative_acceptance(tmp_path: Path) -> None:
    response = {**final([]), "narrative": {**NARRATIVE, "summary": "x" * 2048}}
    stage, backend = review(
        tmp_path, lambda _: response, limits=AgentExplorationLimits(max_response_bytes=1024)
    )
    assert len(backend.calls) == 1 and stage.narrative is None
    assert stage.exploration and stage.exploration.stop_reason == "response_limit"


def test_tool_evidence_limit_retains_receipt_then_stops(tmp_path: Path) -> None:
    scan, _catalog = source_scan(tmp_path)
    raw = "value = '" + "a" * 8000 + "'\n"
    (tmp_path / "src/app.py").write_text(raw)
    scan.analyzed_sources[0].source_digest = hashlib.sha256(raw.encode()).hexdigest()
    catalog = SourceCatalog.from_scan(scan, {"service": tmp_path})
    backend = ScriptedBackend()
    run = SecurityAgentPipeline(
        backend, source_tools=True, source_limits=AgentExplorationLimits(max_evidence_bytes=1024)
    ).run(scan, sources=catalog)
    assert len(backend.calls) == 6
    for stage in run.stages:
        assert stage.exploration and stage.exploration.stop_reason == "evidence_limit"
        assert stage.exploration.tools[0].truncated
        assert stage.exploration.tools[0].evidence == {}
        assert not stage.exploration.citations
    assert "a" * 100 not in run.model_dump_json()


def test_scan_binding_failure_stops_before_model_dispatch(tmp_path: Path) -> None:
    scan, catalog = source_scan(tmp_path)
    scan.analyzed_sources[0].source_digest = "e" * 64
    backend = ScriptedBackend()
    run = SecurityAgentPipeline(backend, source_tools=True).run(scan, sources=catalog)
    assert not backend.calls
    assert all(
        stage.exploration and stage.exploration.stop_reason == "source_unavailable"
        for stage in run.stages
    )


def test_turn_schema_has_strict_nested_tool_union() -> None:
    specs = [spec for spec in default_tool_registry().specs() if spec.name in SOURCE_TOOLS]
    schema = turn_schema(specs)
    assert schema["type"] == "object" and "anyOf" not in schema

    def inspect(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for value in node.values():
                inspect(value)
        elif isinstance(node, list):
            for item in node:
                inspect(item)

    inspect(schema)


@pytest.mark.parametrize("provider", ["openai-api", "anthropic-api"])
@pytest.mark.parametrize("changed", [False, True])
def test_cli_source_review_and_ci_outcome_with_installed_provider_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    changed: bool,
) -> None:
    scan, _sources = source_scan(tmp_path)
    scan.findings = []
    saved, output = tmp_path / "scan.json", tmp_path / "run.json"
    saved.write_text(scan.model_dump_json())
    if changed:
        (tmp_path / "src/app.py").write_text("changed = True\n")
    dispatched: list[dict[str, Any]] = []

    def reply(body: dict[str, Any]) -> dict[str, Any]:
        prompt = body["input"] if provider == "openai-api" else body["messages"][0]["content"]
        payload = json.loads(prompt)["input"]
        dispatched.append(payload)
        return read_then_finish(payload)

    def anthropic(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json=message(json.dumps(reply(json.loads(request.content)))))

    def openai(request: Any, **_kwargs: Any) -> io.BytesIO:
        body = json.loads(request.data)
        assert body["text"]["format"]["name"] == "aegify_agent_turn"
        assert body["text"]["format"]["strict"] and not body["store"]
        return io.BytesIO(
            json.dumps(
                {
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "role": "assistant",
                            "status": "completed",
                            "content": [{"type": "output_text", "text": json.dumps(reply(body))}],
                        }
                    ],
                }
            ).encode()
        )

    class Opener:
        open = staticmethod(openai)

    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: Opener())
    with ScriptedProvider(handler=anthropic) as scripted:
        scripted.install(monkeypatch)
        result = CliRunner().invoke(
            app,
            [
                "agent-run",
                str(saved),
                "--provider",
                provider,
                "--model",
                "fixture-model",
                "--workspace",
                str(tmp_path),
                "--source-tools",
                "--source-root",
                f"service={tmp_path}",
                "--output-file",
                str(output),
            ],
            env={"OPENAI_API_KEY": "fixture-only-key", "ANTHROPIC_API_KEY": "fixture-only-key"},
        )
    assert result.exit_code == (3 if changed else 0), result.output
    retained = SecurityAgentRun.model_validate_json(output.read_text())
    assert retained.status.value == ("partial" if changed else "completed")
    assert len(dispatched) == (0 if changed else 12)
    for stage in retained.stages:
        assert stage.exploration
        assert stage.exploration.stop_reason == ("source_unavailable" if changed else "final")
        assert bool(stage.exploration.citations) is not changed
    if provider == "anthropic-api" and not changed:
        assert retained.token_usage and retained.token_usage.calls_started == 12
    elif provider == "openai-api":
        assert retained.token_usage is None


@pytest.mark.parametrize("kind", ["codex", "claude"])
def test_native_adapter_iterates_owned_subprocess_with_source_broker(
    tmp_path: Path, kind: str
) -> None:
    scan, sources = source_scan(tmp_path)
    executable = tmp_path / "owned-cli"
    executable.write_text(
        f"#!{sys.executable}\nimport sys, json\nfrom pathlib import Path\n"
        "envelope = json.loads(sys.stdin.read().split('INPUT JSON:\\n', 1)[1])\n"
        "payload = envelope['input']\n"
        "assert set(envelope['required_output_schema']['required']) == "
        "{'kind', 'requests', 'narrative', 'citation_ids'}\n"
        f"narrative = {NARRATIVE!r}\n"
        "if not payload['tool_results']:\n"
        "    value = {'kind': 'tools', 'requests': [{'name': 'source_read', 'arguments': "
        "{'repository_id': 'service', 'path': 'src/app.py'}}], "
        "'narrative': None, 'citation_ids': []}\n"
        "else:\n"
        "    citation = payload['tool_results'][0]['output']['citation']['citation_id']\n"
        "    value = {'kind': 'final', 'requests': [], 'narrative': narrative, "
        "'citation_ids': [citation]}\n"
        "if '--output-last-message' in sys.argv:\n"
        "    schema = json.loads(Path(sys.argv[sys.argv.index('--output-schema')+1]).read_text())\n"
        "    assert schema == envelope['required_output_schema']\n"
        "    output = Path(sys.argv[sys.argv.index('--output-last-message')+1])\n"
        "    output.write_text(json.dumps(value))\n"
        "else:\n"
        "    print(json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False, "
        "'stop_reason': 'end_turn', 'result': json.dumps(value)}))\n"
    )
    executable.chmod(0o700)
    backend = CommandAgentBackend(
        CommandBackendConfig(kind=kind, executable=str(executable), inherit_environment=[]),
        tmp_path,
    )
    run = SecurityAgentPipeline(backend, source_tools=True).run(scan, sources=sources)
    assert run.provider.value == ("codex_cli" if kind == "codex" else "claude_code")
    assert all(
        stage.exploration and not stage.exploration.gaps and stage.exploration.model_calls == 2
        for stage in run.stages
    )
    assert run.token_usage is None  # Native usage and live isolation were not established.
