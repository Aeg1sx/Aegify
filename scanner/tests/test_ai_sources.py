"""Source-tool admission and review controls use synthetic local files only."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx2
import pytest
from typer.testing import CliRunner

from aegify.cli import app
from aegify.config import AegifyConfig
from aegify.llm import sources as source_module
from aegify.llm.orchestrator import AISTASTOrchestrator
from aegify.llm.sources import SourceCatalog
from aegify.llm.tools import AnalysisToolContext, ToolRequest, default_tool_registry
from aegify.models import (
    AIReview,
    AIReviewVerdict,
    EvidenceProvenance,
    FileAST,
    Finding,
    ScanResult,
    Severity,
)
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from tests.llm_support import ScriptedProvider, message


def _ast(root: Path, path: str, text: str, repository: str = "service") -> FileAST:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    ast = ASTParser().parse_file(target, repository_id=repository, repository_root=root)
    assert ast is not None
    return ast


def _catalog(root: Path, text: str = "def greet(name):\n    return name\n") -> SourceCatalog:
    return SourceCatalog.capture([_ast(root, "src/app.py", text)], {"service": root})


def _finding() -> Finding:
    return Finding(
        id="review-1",
        rule_id="TEST-REVIEW",
        rule_name="Owned source review",
        file_path="src/app.py",
        line_start=2,
        line_end=2,
        severity=Severity.LOW,
        confidence=0.4,
        message="Inspect this supplied candidate",
        provenance=EvidenceProvenance(repository_id="service", module_path="src/app.py"),
    )


def test_repository_identity_source_digest_symbols_and_immutable_content(tmp_path: Path) -> None:
    left, right = tmp_path / "one", tmp_path / "two"
    one = _ast(left, "src/app.py", "def greet(name):\n    return name\n", "one")
    two = _ast(right, "src/app.py", "def greet(name):\n    return 'other'\n", "two")
    catalog = SourceCatalog.capture([two, one], {"one": left, "two": right})
    assert not catalog.gap_counts
    assert catalog.summary()["repositories"] == ["one", "two"]
    assert catalog.list_files({"repository_id": "one"})["files"][0]["path"] == "src/app.py"
    output = catalog.read({"repository_id": "one", "path": "src/app.py", "line_start": 2})
    assert output["content"] == "    return name"
    assert output["source_digest"] == "sha256:" + one.source_digest
    assert catalog.valid_citation(output["citation"])
    assert not catalog.valid_citation({**output["citation"], "repository_id": "two"})
    assert not catalog.valid_citation({**output["citation"], "line_start": 1})
    symbol = catalog.symbols({"repository_id": "one", "query": "greet"})["symbols"][0]
    assert symbol["line_start"] == 1 and symbol["line_end"] == 2
    assert symbol["symbol_id"].startswith("repo:one:")
    (left / "src/app.py").write_text("modified after snapshot\n")
    assert catalog.read({"repository_id": "one", "path": "src/app.py"})["content"].endswith("name")
    with pytest.raises(TypeError):
        catalog.files[("one", "new.py")] = catalog.files[("one", "src/app.py")]  # type: ignore[index]


@pytest.mark.parametrize(
    "kind", ["changed", "outside", "file_link", "directory_link", "hidden", "fifo"]
)
def test_capture_rejects_unbound_changed_linked_and_special_files(
    tmp_path: Path, kind: str
) -> None:
    root = tmp_path / "repo"
    ast = _ast(root, "src/app.py", "value = 1\n")
    if kind == "changed":
        Path(ast.file_path).write_text("value = 2\n")
    elif kind == "outside":
        ast = _ast(tmp_path / "elsewhere", "app.py", "value = 1\n")
    elif kind == "file_link":
        target = tmp_path / "owned.py"
        target.write_text("value = 1\n")
        Path(ast.file_path).unlink()
        Path(ast.file_path).symlink_to(target)
    elif kind == "directory_link":
        (root / "src").rename(root / "actual")
        (root / "src").symlink_to(root / "actual", target_is_directory=True)
    elif kind == "hidden":
        ast = _ast(root, ".private/config.py", "value = 1\n")
    else:
        Path(ast.file_path).unlink()
        os.mkfifo(ast.file_path)
    start = time.monotonic()
    catalog = SourceCatalog.capture([ast], {"service": root})
    assert not catalog.files and sum(catalog.gap_counts.values()) == 1
    assert time.monotonic() - start < 1
    assert str(tmp_path) not in json.dumps(catalog.summary())


@pytest.mark.parametrize(
    "arguments",
    [
        {"repository_id": "another", "path": "src/app.py"},
        {"repository_id": "service", "path": "../src/app.py"},
        {"repository_id": "service", "path": "/etc/passwd"},
        {"repository_id": "service", "path": "src/app.py", "line_start": True},
        {"repository_id": "service", "path": "src/app.py", "line_start": 0},
        {"repository_id": "service", "path": "src/app.py", "line_start": 4},
        {"repository_id": "service", "path": "src/app.py", "shell": "ignored"},
    ],
)
def test_read_only_tools_deny_unknown_namespaces_paths_and_invalid_arguments(
    tmp_path: Path, arguments: dict[str, Any]
) -> None:
    context = AnalysisToolContext(sources=_catalog(tmp_path))
    result = default_tool_registry().execute(
        ToolRequest(name="source_read", arguments=arguments), context
    )
    assert not result.ok and not result.output


def test_secrets_redacted_before_partial_reads_and_search_without_line_drift(
    tmp_path: Path,
) -> None:
    catalog = _catalog(
        tmp_path,
        'value = """-----BEGIN PRIVATE KEY-----\nsynthetic-key-body\n'
        '-----END PRIVATE KEY-----"""\npassword = "owned-placeholder"\nprint(value)\n',
    )
    output = catalog.read(
        {"repository_id": "service", "path": "src/app.py", "line_start": 2, "line_end": 2}
    )
    assert output["line_start"] == output["line_end"] == 2
    assert output["content"] == "[REDACTED_PRIVATE_KEY]"
    for query in ["synthetic-key-body", "owned-placeholder"]:
        assert not catalog.search({"repository_id": "service", "query": query})["matches"]
    code = catalog.read({"repository_id": "service", "path": "src/app.py", "line_start": 5})
    assert code["content"] == "print(value)"
    assert catalog.valid_citation(code["citation"])


def test_pagination_and_resource_bounds_do_not_silently_drop_search_matches(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path, "value = 'needle'\n" * 450)
    offset: dict[str, Any] = {}
    seen = []
    for _ in range(30):
        page = catalog.search({"repository_id": "service", "query": "needle", **offset})
        seen.extend(item["citation"]["line_start"] for item in page["matches"])
        assert len(page["matches"]) <= 20
        if page["next_cursor"] is None:
            break
        offset = page["next_cursor"]
    assert seen == list(range(1, 451))
    output = catalog.read({"repository_id": "service", "path": "src/app.py", "line_end": 450})
    assert output["truncated"] and output["line_end"] == 200
    literal = catalog.search({"repository_id": "service", "query": ".*"})
    assert not literal["matches"]


def test_capture_bounds_file_count_bytes_and_large_line_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asts = [_ast(tmp_path, f"{index}.py", "value = 1\n") for index in range(4)]
    monkeypatch.setattr(source_module, "MAX_SOURCE_FILES", 2)
    catalog = SourceCatalog.capture(asts, {"service": tmp_path})
    assert len(catalog.files) == 2 and catalog.gap_counts["source_catalog_limit"] == 2
    huge_line = _catalog(tmp_path, "#" + "n" * 20_000 + "\n")
    output = huge_line.read({"repository_id": "service", "path": "src/app.py"})
    assert output["truncated"] and "citation" not in output and output["content"] == ""
    search = huge_line.search({"repository_id": "service", "query": "n"})
    assert search["truncated"] and search["skipped_long_lines"] == 1
    monkeypatch.setattr(source_module, "MAX_FILE_BYTES", 5)
    assert not _catalog(tmp_path).files


def test_iterative_review_follows_search_to_source_and_preserves_executor_citations(
    tmp_path: Path,
) -> None:
    catalog = _catalog(tmp_path)
    observed: list[dict[str, Any]] = []

    def model(_system: str, prompt: str) -> dict[str, Any]:
        context = json.loads(prompt)
        observed.append(context)
        calls = len(observed)
        if calls == 1:
            return {
                "tool_requests": [
                    {
                        "name": "source_symbols",
                        "arguments": {"repository_id": "service", "query": "greet"},
                    }
                ]
            }
        if calls == 2:
            symbol = context["tool_results"][0]["output"]["symbols"][0]
            return {
                "tool_requests": [
                    {
                        "name": "source_read",
                        "arguments": {
                            "repository_id": symbol["repository_id"],
                            "path": symbol["path"],
                            "line_start": symbol["line_start"],
                            "line_end": symbol["line_end"],
                        },
                    }
                ]
            }
        citation = context["tool_results"][-1]["output"]["citation"]["citation_id"]
        return {
            "verdict": "likely_false_positive",
            "confidence": 0.8,
            "citations": [citation],
            "reasoning": "The supplied source returns its argument.",
        }

    finding = _finding()
    before = finding.model_dump_json()
    review = AISTASTOrchestrator().review_finding(finding, model, sources=catalog)
    assert review.verdict is AIReviewVerdict.LIKELY_FALSE_POSITIVE
    assert review.trace.model_calls == 3 and review.trace.tool_calls == 2
    assert review.trace.source_manifest == catalog.manifest_digest
    assert review.citations[0].path == "src/app.py"
    assert review.citations[0].request_id == "tool-2"
    assert all(
        item.input_digest.startswith("sha256:") and item.output_digest.startswith("sha256:")
        for item in review.tools_used
    )
    assert [item.round for item in review.tools_used] == [1, 2]
    assert finding.model_dump_json() == before
    assert AIReview.model_validate_json(review.model_dump_json()).citations == review.citations


@pytest.mark.parametrize("citations", [[], ["made-up-citation"], {"path": "src/app.py"}])
def test_missing_or_fabricated_source_citations_force_abstention(
    tmp_path: Path, citations: Any
) -> None:
    calls = 0

    def model(_system: str, _prompt: str) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {
                "tool_requests": [
                    {
                        "name": "source_read",
                        "arguments": {"repository_id": "service", "path": "src/app.py"},
                    }
                ]
            }
        return {"verdict": "likely_true_positive", "confidence": 1, "citations": citations}

    review = AISTASTOrchestrator().review_finding(_finding(), model, sources=_catalog(tmp_path))
    assert review.verdict is AIReviewVerdict.NEEDS_REVIEW
    assert review.evidence_gaps


@pytest.mark.parametrize("scope", ["other_repository", "other_line"])
def test_valid_but_unrelated_source_citations_cannot_support_a_finding(
    tmp_path: Path, scope: str
) -> None:
    catalog = _catalog(tmp_path)
    finding = _finding()
    if scope == "other_repository":
        finding.provenance.repository_id = "unread-repository"
    calls = 0

    def model(_system: str, prompt: str) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return {
                "tool_requests": [
                    {
                        "name": "source_read",
                        "arguments": {
                            "repository_id": "service",
                            "path": "src/app.py",
                            "line_start": 1,
                            "line_end": 1,
                        },
                    }
                ]
            }
        citation = json.loads(prompt)["tool_results"][0]["output"]["citation"]["citation_id"]
        return {"verdict": "likely_true_positive", "confidence": 1, "citations": [citation]}

    review = AISTASTOrchestrator().review_finding(finding, model, sources=catalog)
    assert review.citations and review.verdict is AIReviewVerdict.NEEDS_REVIEW
    assert any("do not cover" in gap for gap in review.evidence_gaps)


def test_repeated_tool_requests_reuse_evidence_but_consume_budget(tmp_path: Path) -> None:
    def model(_system: str, _prompt: str) -> dict[str, Any]:
        return {
            "tool_requests": [
                {
                    "request_id": "same",
                    "name": "source_read",
                    "arguments": {"repository_id": "service", "path": "src/app.py"},
                }
            ]
        }

    review = AISTASTOrchestrator(max_tool_calls=3, max_rounds=8).review_finding(
        _finding(), model, sources=_catalog(tmp_path)
    )
    assert review.verdict is AIReviewVerdict.NEEDS_REVIEW
    assert review.trace.model_calls == 4 and review.trace.tool_calls == 3
    assert review.trace.cached_calls == 2 and review.trace.stop_reason == "tool_limit"
    assert len({item.request_id for item in review.tools_used}) == 3


def test_prompt_evidence_and_model_response_budgets_fail_closed(tmp_path: Path) -> None:
    def request(_system: str, _prompt: str) -> dict[str, Any]:
        return {
            "tool_requests": [
                {
                    "name": "source_read",
                    "arguments": {"repository_id": "service", "path": "src/app.py"},
                }
            ]
        }

    catalog = _catalog(tmp_path)
    prompt = AISTASTOrchestrator(max_prompt_bytes=1_024).review_finding(
        _finding(), request, sources=catalog
    )
    assert prompt.trace.model_calls == 0 and prompt.trace.stop_reason == "prompt_limit"
    evidence = AISTASTOrchestrator(max_evidence_bytes=256).review_finding(
        _finding(), request, sources=catalog
    )
    assert evidence.tools_used[0].truncated and not evidence.tools_used[0].ok
    assert not evidence.citations and evidence.verdict is AIReviewVerdict.NEEDS_REVIEW
    oversized = AISTASTOrchestrator().review_finding(
        _finding(), lambda *_: {"reasoning": "x" * 70_000}
    )
    assert oversized.trace.stop_reason == "model_error" and oversized.trace.model_calls == 1


def test_engine_attaches_only_scanned_source_and_clears_it_between_runs(tmp_path: Path) -> None:
    _ast(tmp_path, "src/app.py", "def greet(name):\n    return name\n")
    config = AegifyConfig()
    config.llm.enabled = True
    config.storage.backend = "memory"
    config.scan.max_workers = 1
    engine = ScanEngine(config=config, capture_ai_source=True)
    result = engine.scan_files(tmp_path, [tmp_path / "src/app.py"])
    assert result.files_scanned == 1
    assert engine.source_catalog is not None
    assert list(engine.source_catalog.files) == [("local", "src/app.py")]
    engine.scan_files(tmp_path, [])
    assert engine.source_catalog is None


def test_legacy_ai_review_payloads_remain_readable() -> None:
    legacy = AIReview.model_validate(
        {"verdict": "needs_review", "tools_used": [{"tool": "finding_context"}]}
    )
    assert not legacy.citations and legacy.trace.model_calls == 0


def test_workspace_cli_persists_source_evidence_and_usage_in_sarif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "service"
    _ast(repository, "src/app.py", "def greet(name):\n    return name\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: service\n    path: service\n")
    config = AegifyConfig(anthropic_api_key="synthetic-unused-key")
    config.scan.max_workers = 1
    monkeypatch.setattr(AegifyConfig, "load", classmethod(lambda *_: config))
    original_scan = ScanEngine.scan_workspace

    def supplied_candidate(engine: ScanEngine, path: Path) -> ScanResult:
        result = original_scan(engine, path)
        candidate = _finding()
        candidate.remediation = "Scanner-authored remediation"
        result.findings = [candidate]
        return result

    monkeypatch.setattr(ScanEngine, "scan_workspace", supplied_candidate)
    calls = 0

    def query(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        evidence = json.loads(json.loads(request.content)["messages"][0]["content"])
        if calls == 1:
            location = evidence["finding_source"]
            response = {
                "tool_requests": [
                    {
                        "name": "source_read",
                        "arguments": {
                            "repository_id": location["repository_id"],
                            "path": location["path"],
                        },
                    }
                ]
            }
        else:
            citation = evidence["tool_results"][0]["output"]["citation"]["citation_id"]
            response = {
                "verdict": "likely_false_positive",
                "confidence": 0.7,
                "citations": [citation],
                "remediation_summary": "Unaccepted model suggestion",
            }
        return httpx2.Response(
            200,
            json=message(
                json.dumps(response),
                usage={"input_tokens": 21, "output_tokens": 7},
            ),
        )

    report = tmp_path / "result.sarif"
    with ScriptedProvider(handler=query) as provider:
        provider.install(monkeypatch)
        result = CliRunner().invoke(
            app, ["scan-workspace", str(manifest), "--ai-tools", "--output-file", str(report)]
        )
        assert provider.http_clients and all(client.is_closed for client in provider.http_clients)
    assert result.exit_code == 0, result.output
    run = json.loads(report.read_text())["runs"][0]
    properties = run["results"][0]["properties"]
    assert properties["aiReview"]["trace"]["model_calls"] == 2
    assert properties["aiReview"]["citations"][0]["repository_id"] == "service"
    assert properties["remediation"] == "Scanner-authored remediation"
    assert properties["status"] == "new" and properties["evidenceState"] == "candidate"
    usage = run["invocations"][0]["properties"]["tokenUsage"]
    assert usage["input_tokens"] == 42
    assert usage["output_tokens"] == 14
    assert usage["total_cost_usd"] is None and usage["usage_status"] == "reported"
    assert usage["calls_started"] == 2 and len(usage["calls"]) == 2


def test_digest_bound_admission_requires_parser_hash(tmp_path: Path) -> None:
    source = _ast(tmp_path, "main.py", "value = 1\n")
    source.source_digest = ""
    catalog = SourceCatalog.capture([source], {"service": tmp_path})
    assert catalog.gap_counts["unbound_source"] == 1
    assert not catalog.files
    assert catalog.manifest_digest.startswith("sha256:")
