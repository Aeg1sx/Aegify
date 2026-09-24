"""Tests for the SARIF reporter and evidence interchange contract."""

import shutil
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

import pytest

from aegify.config import AegifyConfig
from aegify.models import (
    Finding,
    FindingDisposition,
    ScanResult,
    Severity,
    TaintFlow,
    TaintPropagation,
    TaintSink,
    TaintSource,
)
from aegify.reporter.sarif import SARIFReporter
from aegify.scanner.engine import ScanEngine

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("../app/[id]/page.tsx", "../app/%5Bid%5D/page.tsx"),
        ("src/a b#c?d%25.py", "src/a%20b%23c%3Fd%2525.py"),
        ("src/한글.py", "src/%ED%95%9C%EA%B8%80.py"),
        ("src/literal%2F.py", "src/literal%252F.py"),
        ("/checkout/src/(group)/a!b'c*d.py", "/checkout/src/%28group%29/a%21b%27c%2Ad.py"),
        ("./src/colon:name.py", "./src/colon%3Aname.py"),
    ],
)
def test_artifact_and_flow_uris_encode_paths_without_changing_evidence(path, expected):
    finding = Finding(
        rule_id="DEMO",
        rule_name="Owned path fixture",
        severity=Severity.LOW,
        confidence=0.5,
        file_path=path,
        line_start=2,
        line_end=2,
        taint_flow=TaintFlow(
            source=TaintSource(variable="value", file_path=path, line=1, source_type="fixture"),
            sink=TaintSink(function="review", file_path=path, line=2, sink_type="fixture"),
            path=[
                TaintPropagation(
                    variable="value", file_path=path, line=2, propagation_type="argument"
                )
            ],
        ),
    )
    fingerprint = finding.fingerprint
    run = SARIFReporter().generate(ScanResult(findings=[finding]))["runs"][0]
    result = run["results"][0]
    artifacts = [
        result["locations"][0]["physicalLocation"]["artifactLocation"],
        result["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"][
            "artifactLocation"
        ],
    ]
    for artifact in artifacts:
        assert artifact == {"uri": expected, "uriBaseId": "%WORKDIR%"}
        assert unquote(artifact["uri"]) == path
        absolute = urlsplit(urljoin(run["originalUriBaseIds"]["%WORKDIR%"]["uri"], artifact["uri"]))
        assert absolute.scheme == "file"
        assert not absolute.query and not absolute.fragment
    assert run["properties"]["artifactPathEncoding"] == "percent-encoded-path-v1"
    assert finding.file_path == path
    assert result["partialFingerprints"]["aegifyFingerprint/v2"] == fingerprint


def test_context_snippet_retains_its_source_offset(tmp_path):
    source = tmp_path / "context.py"
    source.write_text("\n".join(f"line_{i}" for i in range(1, 21)))
    finding = Finding(
        rule_id="AEG-TEST-001",
        rule_name="Context test",
        severity=Severity.LOW,
        confidence=0.5,
        file_path=str(source),
        line_start=10,
        line_end=11,
    )
    ScanEngine(config=AegifyConfig())._enrich_snippets([finding])
    assert finding.code_snippet_start_line == 5
    assert finding.code_snippet.splitlines()[0] == "line_5"
    location = SARIFReporter()._build_result(finding)["locations"][0]["physicalLocation"]
    assert location["region"] == {
        "startLine": 10,
        "endLine": 11,
        "snippet": {"text": "line_10\nline_11"},
    }
    assert location["contextRegion"]["startLine"] == 5
    assert location["contextRegion"]["endLine"] == 16
    assert location["contextRegion"]["snippet"]["text"] == finding.code_snippet


def test_uri_base_preserves_root_and_encodes_working_directory(tmp_path, monkeypatch):
    for directory in [Path(tmp_path.anchor), tmp_path / "build # [id]"]:
        directory.mkdir(exist_ok=True)
        monkeypatch.chdir(directory)
        run = SARIFReporter().generate(ScanResult())["runs"][0]
        base = run["originalUriBaseIds"]["%WORKDIR%"]["uri"]
        assert base.startswith("file:///")
        assert base.endswith("/")
        assert " " not in base and "#" not in base and "[" not in base
        assert urljoin(base, "src/app.py").endswith("/src/app.py")


class TestSARIFReporter:
    @pytest.fixture
    def scan_result(self):
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        engine = ScanEngine(config=config)
        return engine.scan(FIXTURES / "vulnerable_app.py")

    @pytest.fixture
    def reporter(self):
        return SARIFReporter()

    def test_generate_sarif(self, reporter, scan_result):
        sarif = reporter.generate(scan_result)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "Aegify"
        assert len(run["results"]) > 0
        assert run["properties"]["evidenceContractVersion"] == 1
        assert run["properties"]["workspaceSnapshot"].startswith("sha256:")
        assert run["properties"]["taintAnalysis"]["provider"] == ("aegify-taint-v2")
        assert run["properties"]["taintAnalysis"]["iterations"] >= 1
        assert run["properties"]["taintAnalysis"]["context_depth"] == 2
        assert run["properties"]["taintAnalysis"]["contexts_analyzed"] >= 1
        assert "object_return_propagations" in run["properties"]["taintAnalysis"]
        assert "heap_strong_updates" in run["properties"]["taintAnalysis"]
        assert run["properties"]["taintAnalysis"]["library_model_pack"] == "2026.08.1"
        assert run["properties"]["taintAnalysis"]["library_models_loaded"] >= 9
        assert run["properties"]["programGraph"]["enabled"] is True
        assert run["properties"]["programGraph"]["context_balanced_query_available"] is True
        assert run["properties"]["programGraph"]["context_query_default_max_call_depth"] == 32
        assert run["properties"]["programGraph"]["callable_descriptors"] >= 1
        assert "interprocedural_callsites" in run["properties"]["programGraph"]
        assert "interprocedural_call_edges" in run["properties"]["programGraph"]
        assert "interprocedural_return_edges" in run["properties"]["programGraph"]
        assert "overload_calls_resolved" in run["properties"]["programGraph"]
        assert "overload_calls_ambiguous" in run["properties"]["programGraph"]
        assert run["properties"]["semanticAnalysis"]["enabled"] is False
        assert "scip_packages" in run["properties"]["semanticAnalysis"]
        assert "scip_cache_hits" in run["properties"]["semanticAnalysis"]
        assert "jvm_artifacts" in run["properties"]["semanticAnalysis"]
        assert "jvm_dependency_lockfiles" in run["properties"]["semanticAnalysis"]
        assert "jvm_version_catalogs" in run["properties"]["semanticAnalysis"]
        assert "jvm_exact_external_resolutions" in run["properties"]["semanticAnalysis"]
        assert "jvm_unresolved_workspace_dependencies" in run["properties"]["semanticAnalysis"]
        assert "scip_package_version_conflicts" in run["properties"]["semanticAnalysis"]
        assert "jvm_bytecode_invokedynamic_sites" in run["properties"]["semanticAnalysis"]
        assert "jvm_bytecode_lambda_targets" in run["properties"]["semanticAnalysis"]
        assert "jvm_bytecode_unresolved_bootstraps" in run["properties"]["semanticAnalysis"]
        assert run["properties"]["frameworkAnalysis"]["enabled"] is True
        assert "bean_factories" in run["properties"]["frameworkAnalysis"]
        assert "qualified_bindings" in run["properties"]["frameworkAnalysis"]
        assert "conditional_candidates" in run["properties"]["frameworkAnalysis"]
        assert "ambiguous_bindings" in run["properties"]["frameworkAnalysis"]
        assert "cross_repository_di_edges" in run["properties"]["frameworkAnalysis"]
        assert (
            run["invocations"][0]["properties"]["workspaceSnapshot"]
            == scan_result.workspace_snapshot
        )

    def test_sarif_has_rules(self, reporter, scan_result):
        sarif = reporter.generate(scan_result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0

        # Each rule should have required fields
        for rule in rules:
            assert "id" in rule
            assert "name" in rule
            assert "shortDescription" in rule
            for relationship in rule.get("relationships", []):
                assert "guid" not in relationship["target"]

    def test_sarif_results_have_locations(self, reporter, scan_result):
        sarif = reporter.generate(scan_result)
        results = sarif["runs"][0]["results"]

        for result in results:
            assert "ruleId" in result
            assert "level" in result
            assert "message" in result
            assert result["partialFingerprints"]["aegifyFingerprint/v1"]
            assert len(result["locations"]) > 0

            loc = result["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert "region" in loc

            provenance = result["properties"]["provenance"]
            assert provenance["contract_version"] == 1
            assert provenance["producer"].startswith("aegify.")
            assert provenance["rule_digest"].startswith("sha256:")
            assert provenance["evidence_id"].startswith("ev:")
            assert provenance["workspace_snapshot"] == scan_result.workspace_snapshot
            assert result["properties"]["evidenceState"] in {
                "candidate",
                "reachable",
                "observed",
                "impact_proven",
            }
            assert result["properties"]["disposition"] in {"blocking", "advisory"}
            assert result["properties"]["blocksCi"] is (
                result["properties"]["disposition"] == "blocking"
            )

    def test_advisory_result_is_review_note(self, reporter, scan_result):
        finding = scan_result.findings[0]
        finding.disposition = FindingDisposition.ADVISORY

        result = reporter._build_result(finding)

        assert result["level"] == "note"
        assert result["kind"] == "review"
        assert result["properties"]["blocksCi"] is False

    def test_write_sarif(self, reporter, scan_result, tmp_path):
        output = tmp_path / "report.sarif"
        reporter.write(scan_result, output)
        assert output.exists()
        assert output.stat().st_size > 0

    def test_workspace_snapshot_is_path_stable_and_content_sensitive(self, tmp_path):
        source = FIXTURES / "vulnerable_app.py"
        first = tmp_path / "first" / "vulnerable_app.py"
        second = tmp_path / "second" / "vulnerable_app.py"
        first.parent.mkdir()
        second.parent.mkdir()
        shutil.copy2(source, first)
        shutil.copy2(source, second)

        config = AegifyConfig()
        config.llm.enabled = False
        engine = ScanEngine(config=config)
        first_result = engine.scan(first)
        second_result = engine.scan(second)

        assert first_result.workspace_snapshot == second_result.workspace_snapshot
        second.write_text(second.read_text() + "\n# evidence changed\n")
        changed_result = engine.scan(second)
        assert changed_result.workspace_snapshot != first_result.workspace_snapshot

    def test_gateway_configuration_participates_in_workspace_snapshot(self, tmp_path):
        workspace = tmp_path / "workspace"
        shutil.copytree(FIXTURES / "workspace_golden", workspace)
        manifest = workspace / "workspace.yml"

        config = AegifyConfig()
        config.llm.enabled = False
        engine = ScanEngine(config=config)
        first = engine.scan_workspace(manifest)
        gateway = workspace / "gateway" / "application.yml"
        gateway.write_text(gateway.read_text().replace("orders", "orders-v2", 1))
        changed = engine.scan_workspace(manifest)

        assert changed.workspace_snapshot != first.workspace_snapshot
        manifest.write_text(manifest.read_text().replace("id: edge-gateway", "id: renamed-gateway"))
        renamed = engine.scan_workspace(manifest)
        assert renamed.workspace_snapshot != changed.workspace_snapshot
        assert renamed.gateway_routes[0].repository_id == "renamed-gateway"
        assert changed.attack_surface_links
        assert all(
            link.provenance.workspace_snapshot == changed.workspace_snapshot
            and link.provenance.evidence_id.startswith("edge:")
            for link in changed.attack_surface_links
        )
        sarif = SARIFReporter().generate(changed)
        properties = sarif["runs"][0]["properties"]
        assert len(properties["runtimeObservations"]) == 2
        assert all(
            endpoint["runtimeObserved"] and endpoint["runtimeObservationCount"] == 1
            for endpoint in properties["endpoints"]
        )
        assert all(
            set(observation)
            <= {
                "id",
                "kind",
                "method",
                "path",
                "statusCode",
                "durationMs",
                "traceId",
                "spanId",
                "parentSpanId",
                "repositoryId",
                "passed",
                "provenance",
            }
            for observation in properties["runtimeObservations"]
        )
