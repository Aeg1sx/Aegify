"""Exercise the public review evaluator with a scripted reviewer and inert source."""

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegify.cli import app
from aegify.llm.orchestrator import AISTASTOrchestrator
from aegify.llm.sources import SourceCatalog
from aegify.models import AnalyzedSource, Language, ScanResult
from tests.test_ai_sources import _finding


@pytest.fixture
def review_inputs(tmp_path: Path):
    root = tmp_path / "checkout"
    path = root / "src/app.py"
    path.parent.mkdir(parents=True)
    material = b"def greet(name):\n    text = str(name)\n    return text\n"
    path.write_bytes(material)
    digest = hashlib.sha256(material).hexdigest()
    finding = _finding().model_copy(update={"line_start": 2, "line_end": 3})
    scan = ScanResult(
        analyzed_sources=[
            AnalyzedSource(
                file_path=str(path),
                repository_id="service",
                module_path="src/app.py",
                source_digest=digest,
                language=Language.PYTHON,
            )
        ],
        findings=[finding],
    )
    sources = SourceCatalog.from_scan(scan, {"service": root})

    def respond(_system, prompt):
        results = json.loads(prompt)["tool_results"]
        if not results:
            return {
                "tool_requests": [
                    {
                        "name": "source_read",
                        "arguments": {
                            "repository_id": "service",
                            "path": "src/app.py",
                            "line_start": line,
                            "line_end": line,
                        },
                    }
                    for line in [3, 2]
                ]
            }
        return {
            "verdict": "likely_false_positive",
            "confidence": 0.85,
            "reasoning": "The function formats a display string.",
            "evidence_against": ["It returns text without modifying application state."],
            "citations": [result["output"]["citation"]["citation_id"] for result in results],
        }

    finding.ai_review = AISTASTOrchestrator().review_finding(finding, respond, sources=sources)
    assert finding.ai_review.verdict == "likely_false_positive"
    scan.findings = [finding]
    artifact, labels = tmp_path / "scan.json", tmp_path / "labels.json"
    artifact.write_text(scan.model_dump_json())
    labels.write_text(
        json.dumps(
            {
                "version": 1,
                "dataset": "owned-string-review",
                "cases": [
                    {
                        "path": "src/app.py",
                        "repository_id": "service",
                        "rule_id": finding.rule_id,
                        "line_start": 2,
                        "line_end": 3,
                        "source_digest": "sha256:" + digest,
                        "expected": "likely_false_positive",
                    }
                ],
            }
        )
    )
    return artifact, labels, root


@pytest.mark.parametrize(
    ("change", "exit_code", "gap"),
    [
        ("none", 0, ""),
        ("wrong_label", 1, ""),
        ("changed_source", 3, "source_unavailable_or_changed"),
        ("missing_review", 3, "missing_review"),
        ("same_location_twice", 3, "ambiguous_finding"),
        ("partial_range", 3, "incomplete_source_range"),
        ("other_request", 3, "unsupported_citation"),
        ("different_manifest", 3, "source_manifest_mismatch"),
        ("tampered_excerpt", 3, "unsupported_citation"),
        ("missing_facts", 3, "missing_rationale"),
        ("stopped_provider", 3, "unfinished_review"),
        ("expected_abstention", 0, ""),
        ("duplicate_label", 2, ""),
        ("partial_scan", 3, ""),
    ],
)
def test_labeled_review_replay(review_inputs, change, exit_code, gap):
    artifact, labels, root = review_inputs
    scan = json.loads(artifact.read_text())
    reference = json.loads(labels.read_text())
    review = scan["findings"][0]["ai_review"]
    if change == "wrong_label":
        reference["cases"][0]["expected"] = "likely_true_positive"
    elif change == "changed_source":
        (root / "src/app.py").write_text("def greet(): pass\n")
    elif change == "missing_review":
        scan["findings"][0]["ai_review"] = None
    elif change == "same_location_twice":
        scan["findings"].append(scan["findings"][0])
    elif change == "partial_range":
        review["citations"].pop()
    elif change == "other_request":
        review["citations"][0]["request_id"] = "unissued"
    elif change == "different_manifest":
        review["trace"]["source_manifest"] = "sha256:" + "a" * 64
    elif change == "tampered_excerpt":
        review["tools_used"][0]["evidence"]["content"] = "different text"
    elif change == "missing_facts":
        review["evidence_against"] = []
    elif change == "stopped_provider":
        review["trace"]["stop_reason"] = "model_error"
    elif change == "expected_abstention":
        review.update(verdict="needs_review", evidence_gaps=["Caller configuration is missing."])
        reference["cases"][0]["expected"] = "needs_review"
    elif change == "duplicate_label":
        reference["cases"].append(reference["cases"][0])
    elif change == "partial_scan":
        scan["status"] = "partial"
    artifact.write_text(json.dumps(scan))
    labels.write_text(json.dumps(reference))
    output = artifact.parent / "score.json"
    result = CliRunner().invoke(
        app,
        [
            "benchmark-reviews",
            str(artifact),
            "--labels",
            str(labels),
            "--source-root",
            f"service={root}",
            "--output-file",
            str(output),
        ],
    )
    assert result.exit_code == exit_code, result.output
    if exit_code == 2:
        assert not output.exists()
    else:
        report = json.loads(output.read_text())
        assert report["label_count"] == 1
        assert report["cases"][0]["gap"] == gap
        assert report["agreed"] + report["disagreed"] + report["unscored"] == 1
