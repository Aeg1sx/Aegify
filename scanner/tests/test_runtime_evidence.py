"""Tests for redacted HTTP, browser/proxy, and trace evidence adapters."""

import json
from pathlib import Path

from codeguard.config import CodeGuardConfig
from codeguard.ir import ProgramGraphQuery
from codeguard.runtime import RuntimeEvidenceImporter
from codeguard.scanner.engine import ScanEngine
from codeguard.scanner.workspace import RuntimeArtifact, WorkspaceRepository


def _repository(tmp_path: Path) -> WorkspaceRepository:
    root = tmp_path / "service"
    root.mkdir()
    return WorkspaceRepository(id="service", path=root)


def test_browser_har_imports_only_redacted_request_metadata(tmp_path: Path):
    repository = _repository(tmp_path)
    har = tmp_path / "browser.har"
    har.write_text(
        json.dumps(
            {
                "log": {
                    "creator": {"name": "Playwright", "version": "1.55"},
                    "entries": [
                        {
                            "startedDateTime": "2026-08-21T00:00:00Z",
                            "time": 12.5,
                            "request": {
                                "method": "GET",
                                "url": "https://example.test/api/orders/42?token=secret",
                                "headers": [{"name": "Authorization", "value": "Bearer secret"}],
                                "postData": {"text": "sensitive"},
                            },
                            "response": {"status": 200, "content": {"text": "secret"}},
                        }
                    ],
                }
            }
        )
    )
    artifact = RuntimeArtifact(format="browser-har", path=har)

    bundle = RuntimeEvidenceImporter().load(artifact, repository)

    observation = bundle.observations[0]
    assert observation.method == "GET"
    assert observation.path == "/api/orders/42"
    assert observation.status_code == 200
    assert observation.provenance.producer == "Playwright"
    rendered = observation.model_dump_json()
    assert "Bearer secret" not in rendered
    assert "sensitive" not in rendered


def test_active_proxy_evidence_imports_mutated_request_without_values(
    tmp_path: Path,
):
    repository = _repository(tmp_path)
    evidence = tmp_path / "proxy-evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "contract_version": 1,
                "producer": "codeguard-proxy-harness",
                "cases": [
                    {
                        "id": "role-boundary",
                        "original_method": "POST",
                        "original_path": "/api/orders",
                        "method": "POST",
                        "path": "/api/orders",
                        "status_code": 403,
                        "duration_ms": 4.2,
                        "passed": True,
                        "mutations": [
                            {"kind": "json-set", "name": "role"},
                            {"kind": "query-set", "name": "debug"},
                        ],
                        "query_sha256": "a" * 64,
                        "request_body_sha256": "b" * 64,
                        "response_sha256": "c" * 64,
                    }
                ],
            }
        )
    )
    artifact = RuntimeArtifact(format="proxy-evidence-json", path=evidence)

    bundle = RuntimeEvidenceImporter().load(artifact, repository)

    assert len(bundle.observations) == 1
    observation = bundle.observations[0]
    assert observation.kind == "proxy-evidence-json"
    assert observation.method == "POST"
    assert observation.path == "/api/orders"
    assert observation.status_code == 403
    assert observation.passed is True
    assert observation.provenance.fidelity == "proxy-evidence-json"


def test_otel_import_preserves_parent_child_trace_reachability(tmp_path: Path):
    repository = _repository(tmp_path)
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps(
            {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "traceId": "trace-1",
                                        "spanId": "parent",
                                        "name": "gateway",
                                        "attributes": [
                                            {
                                                "key": "http.request.method",
                                                "value": {"stringValue": "GET"},
                                            },
                                            {
                                                "key": "url.path",
                                                "value": {"stringValue": "/api/orders/42"},
                                            },
                                        ],
                                    },
                                    {
                                        "traceId": "trace-1",
                                        "spanId": "child",
                                        "parentSpanId": "parent",
                                        "name": "orders",
                                        "attributes": {
                                            "http.request.method": "GET",
                                            "http.route": "/orders/{id}",
                                            "http.response.status_code": 200,
                                        },
                                    },
                                ]
                            }
                        ]
                    }
                ]
            }
        )
    )
    artifact = RuntimeArtifact(format="otel-json", path=trace)

    bundle = RuntimeEvidenceImporter().load(artifact, repository)

    assert len(bundle.observations) == 2
    assert bundle.relationships[0].source == ("runtime-span:service:trace-1:parent")
    assert bundle.relationships[0].target == "runtime-span:service:trace-1:child"
    assert bundle.relationships[0].fidelity == "runtime-trace"
    assert {
        (relationship.kind, relationship.target)
        for relationship in bundle.relationships
        if relationship.kind == "observed-http"
    } == {
        ("observed-http", f"runtime_observation:{observation.id}")
        for observation in bundle.observations
    }


def test_runtime_gateway_request_marks_backend_endpoint_as_observed(tmp_path: Path):
    backend = tmp_path / "orders"
    gateway = tmp_path / "gateway"
    browser = tmp_path / "web"
    backend.mkdir()
    gateway.mkdir()
    browser.mkdir()
    (backend / "OrderController.java").write_text(
        "@RestController\n"
        '@RequestMapping("/orders")\n'
        "class OrderController {\n"
        '  @GetMapping("/{id}") String get(String id) { return id; }\n'
        "}\n"
    )
    (gateway / "application.yml").write_text(
        "spring:\n"
        "  cloud:\n"
        "    gateway:\n"
        "      routes:\n"
        "        - id: orders\n"
        "          uri: lb://orders\n"
        "          predicates: [Path=/edge/**]\n"
        "          filters: [StripPrefix=1]\n"
    )
    evidence = tmp_path / "http.json"
    evidence.write_text(
        json.dumps(
            {
                "contract_version": 1,
                "producer": "codeguard-http-harness",
                "cases": [
                    {
                        "id": "orders-read",
                        "method": "GET",
                        "path": "/edge/orders/42",
                        "status_code": 200,
                        "duration_ms": 8.0,
                        "passed": True,
                    }
                ],
            }
        )
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: orders\n"
        "    path: ./orders\n"
        "  - id: gateway\n"
        "    path: ./gateway\n"
        "  - id: web\n"
        "    path: ./web\n"
        "    runtime_artifacts:\n"
        "      - format: http-evidence-json\n"
        "        path: ./http.json\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1

    result = ScanEngine(config=config).scan_workspace(manifest)

    endpoint = next(endpoint for endpoint in result.endpoints if endpoint.path == "/orders/{id}")
    assert endpoint.runtime_observed
    assert endpoint.runtime_observation_count == 1
    assert result.runtime_evidence.endpoint_links == 1
    runtime_link = next(
        link for link in result.attack_surface_links if link.source_kind == "runtime_observation"
    )
    assert runtime_link.match_kind == "runtime_gateway_transform"
    assert runtime_link.provenance.analysis_kind == "dynamic-correlation"


def test_trace_parent_path_reaches_runtime_observed_endpoint(tmp_path: Path):
    repository = tmp_path / "orders"
    repository.mkdir()
    (repository / "OrderController.java").write_text(
        "@RestController class OrderController {\n"
        '  @GetMapping("/orders/{id}") String get(String id) { return id; }\n'
        "}\n"
    )
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps(
            {
                "spans": [
                    {
                        "traceId": "trace-1",
                        "spanId": "gateway",
                        "attributes": {
                            "http.request.method": "GET",
                            "url.path": "/edge/orders/42",
                        },
                    },
                    {
                        "traceId": "trace-1",
                        "spanId": "orders",
                        "parentSpanId": "gateway",
                        "attributes": {
                            "http.request.method": "GET",
                            "http.route": "/orders/{id}",
                            "http.response.status_code": 200,
                        },
                    },
                ]
            }
        )
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: orders\n"
        "    path: ./orders\n"
        "    runtime_artifacts:\n"
        "      - format: otel-json\n"
        "        path: ./trace.json\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    child = next(
        observation
        for observation in result.runtime_observations
        if observation.span_id == "orders"
    )
    endpoint = next(endpoint for endpoint in result.endpoints if endpoint.path == "/orders/{id}")
    endpoint_id = (
        f"endpoint:{endpoint.repository_id}:{endpoint.method}:{endpoint.path}:{endpoint.file_path}"
    )
    path = ProgramGraphQuery(engine._last_program_graph).shortest_path(
        "runtime-span:orders:trace-1:gateway",
        endpoint_id,
        {"semantic", "attack-surface"},
    )

    assert path == [
        "runtime-span:orders:trace-1:gateway",
        "runtime-span:orders:trace-1:orders",
        f"runtime_observation:{child.id}",
        endpoint_id,
    ]
