"""Golden tests for bounded CodeQL, Semgrep, and Joern evidence imports."""

import json
from pathlib import Path

from codeguard.adapters import ExternalAnalysisImporter
from codeguard.config import CodeGuardConfig
from codeguard.models import Severity
from codeguard.scanner.engine import ScanEngine
from codeguard.scanner.workspace import AnalysisArtifact, WorkspaceRepository


def _repository(tmp_path: Path) -> WorkspaceRepository:
    root = tmp_path / "service"
    root.mkdir()
    (root / "App.java").write_text("class App { void run() {} }\n")
    return WorkspaceRepository(id="service", path=root)


def test_sarif_import_preserves_codeql_provenance_and_thread_flow(tmp_path: Path):
    repository = _repository(tmp_path)
    sarif = tmp_path / "codeql.sarif"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "semanticVersion": "2.20.0",
                                "rules": [
                                    {
                                        "id": "java/sql-injection",
                                        "name": "SQL injection",
                                        "properties": {
                                            "security-severity": "9.3",
                                            "precision": "very-high",
                                            "tags": ["security", "external/cwe/cwe-089"],
                                        },
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "java/sql-injection",
                                "message": {"text": "tainted query"},
                                "partialFingerprints": {"primaryLocationLineHash": "stable"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "App.java"},
                                            "region": {"startLine": 1, "endLine": 1},
                                        }
                                    }
                                ],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": {
                                                            "physicalLocation": {
                                                                "artifactLocation": {
                                                                    "uri": "App.java"
                                                                },
                                                                "region": {"startLine": 1},
                                                            },
                                                            "message": {"text": "source"},
                                                        }
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
    )
    artifact = AnalysisArtifact(format="sarif", path=sarif)

    bundle = ExternalAnalysisImporter().load(artifact, repository)

    assert len(bundle.findings) == 1
    finding = bundle.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.cwe_id == 89
    assert finding.confidence == 0.98
    assert finding.provenance.producer == "CodeQL"
    assert finding.provenance.fidelity == "sarif-result"
    assert finding.call_chain[0].function == "source"
    assert bundle.relationships[0].fidelity == "sarif-thread-flow"


def test_semgrep_json_rejects_path_escape_and_caps_results(tmp_path: Path):
    repository = _repository(tmp_path)
    output = tmp_path / "semgrep.json"
    output.write_text(
        json.dumps(
            {
                "version": "1.100.0",
                "results": [
                    {
                        "check_id": "java.lang.security.audit",
                        "path": "App.java",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {
                            "severity": "ERROR",
                            "message": "dangerous call",
                            "metadata": {"confidence": "HIGH", "cwe": ["CWE-78"]},
                        },
                    },
                    {
                        "check_id": "escape",
                        "path": "../outside.java",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {"severity": "ERROR"},
                    },
                ],
            }
        )
    )
    artifact = AnalysisArtifact(format="semgrep-json", path=output, max_results=2)

    bundle = ExternalAnalysisImporter().load(artifact, repository)

    assert [finding.rule_id for finding in bundle.findings] == ["java.lang.security.audit"]
    assert bundle.findings[0].cwe_id == 78
    assert bundle.findings[0].provenance.fidelity == "pattern-analysis"
    assert any("outside repository" in warning for warning in bundle.summary.warnings)


def test_joern_jsonl_imports_query_findings_and_graphson_edges(tmp_path: Path):
    repository = _repository(tmp_path)
    output = tmp_path / "joern.jsonl"
    records = [
        {
            "record": "finding",
            "rule_id": "joern.command-injection",
            "severity": "high",
            "file": "App.java",
            "line": 1,
            "message": "source reaches exec",
        },
        {"id": 1, "outE": {"REACHING_DEF": [{"inV": 2}]}},
    ]
    output.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    artifact = AnalysisArtifact(format="joern-jsonl", path=output)

    bundle = ExternalAnalysisImporter().load(artifact, repository)

    assert bundle.findings[0].provenance.fidelity == "cpg-query"
    assert bundle.relationships[0].source == "repo:service:joern:1"
    assert bundle.relationships[0].target == "repo:service:joern:2"
    assert bundle.relationships[0].kind == "reaching_def"
    assert bundle.relationships[0].fidelity == "joern-graphson"


def test_workspace_merges_external_finding_and_cpg_edge_into_program_graph(
    tmp_path: Path,
):
    repository = _repository(tmp_path)
    joern = tmp_path / "joern.jsonl"
    joern.write_text(
        json.dumps(
            {
                "record": "finding",
                "rule_id": "joern.test",
                "severity": "high",
                "file": "App.java",
                "line": 1,
                "message": "external evidence",
            }
        )
        + "\n"
        + json.dumps({"record": "edge", "source": "a", "target": "b", "kind": "ddg"})
        + "\n"
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: service\n"
        f"    path: {repository.path}\n"
        "    analysis_artifacts:\n"
        "      - format: joern-jsonl\n"
        "        path: ./joern.jsonl\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    assert result.status == "completed"
    assert result.external_analysis.findings_imported == 1
    assert any(finding.rule_id == "joern.test" for finding in result.findings)
    assert engine._last_program_graph.has_edge("repo:service:joern:a", "repo:service:joern:b")
    edge_data = engine._last_program_graph.get_edge_data(
        "repo:service:joern:a", "repo:service:joern:b"
    )
    assert any(edge["fidelity"] == "cpg-export" for edge in edge_data.values())
