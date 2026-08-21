"""Tests for collision-safe multi-repository identities."""

import shutil
from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.models import TaintSink, TaintSource
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.dataflow import DataflowAnalyzer
from aegify.scanner.engine import ScanEngine
from aegify.scanner.workspace import WorkspaceManifest

GOLDEN_WORKSPACE = Path(__file__).parent / "fixtures" / "workspace_golden"


def test_workspace_manifest_rejects_unknown_fields(tmp_path: Path):
    repository = tmp_path / "repo"
    repository.mkdir()
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        """
version: 1
name: strict-workspace
unexpected: ignored-before
repositories:
  - id: service
    path: ./repo
"""
    )

    with pytest.raises(ValueError, match="unexpected"):
        WorkspaceManifest.load(manifest)


def test_workspace_manifest_resolves_paths_and_symbol_collisions(tmp_path: Path):
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    file_a = repo_a / "service.py"
    file_b = repo_b / "service.py"
    file_a.write_text("def process():\n    return 1\n")
    file_b.write_text("def process():\n    return 2\n")
    manifest_path = tmp_path / "workspace.yml"
    manifest_path.write_text(
        """
        version: 1
        name: collision-test
        repositories:
          - id: repo-a
            path: ./repo-a
          - id: repo-b
            path: ./repo-b
        """
    )

    manifest = WorkspaceManifest.load(manifest_path)
    parser = ASTParser()
    asts = [
        parser.parse_file(
            repository.path / "service.py",
            repository_id=repository.id,
            repository_root=repository.path,
        )
        for repository in manifest.repositories
    ]
    graph = CallGraphBuilder().build([ast for ast in asts if ast is not None])

    process_nodes = [node for node in graph if node.endswith("::process()")]
    assert len(process_nodes) == 2
    assert process_nodes[0] != process_nodes[1]
    assert {graph.nodes[node]["data"].repository_id for node in process_nodes} == {
        "repo-a",
        "repo-b",
    }


def test_workspace_dataflow_resolves_repository_qualified_scope(tmp_path: Path):
    repository = tmp_path / "service"
    repository.mkdir()
    source_file = repository / "app.py"
    source_file.write_text(
        "def entry():\n"
        "    value = input()\n"
        "    helper(value)\n\n"
        "def helper(value):\n"
        "    eval(value)\n"
    )

    ast = ASTParser().parse_file(
        source_file,
        repository_id="service",
        repository_root=repository,
    )
    assert ast is not None
    graph = CallGraphBuilder().build([ast])

    source = TaintSource(
        variable="value",
        file_path=str(source_file),
        line=2,
        source_type="stdin",
        in_function="entry",
    )
    sink = TaintSink(
        function="eval",
        file_path=str(source_file),
        line=6,
        sink_type="code_execution",
        in_function="helper",
    )

    assert DataflowAnalyzer()._can_reach(source, sink, ast, graph)


def test_workspace_scan_correlates_frontend_gateway_and_spring_endpoint(
    tmp_path: Path,
):
    backend = tmp_path / "orders"
    frontend = tmp_path / "web"
    gateway = tmp_path / "gateway"
    backend.mkdir()
    frontend.mkdir()
    gateway.mkdir()
    (backend / "OrderController.java").write_text(
        """
@RestController
@RequestMapping("/orders")
class OrderController {
    @GetMapping("/{id}")
    String getOrder(@PathVariable String id) { return id; }
}
"""
    )
    (frontend / "orders.ts").write_text('fetch("/api/orders/42")\n')
    (gateway / "application.yml").write_text(
        """
spring:
  cloud:
    gateway:
      routes:
        - id: orders
          uri: lb://orders
          predicates:
            - Path=/api/**
          filters:
            - StripPrefix=1
"""
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        """
version: 1
name: commerce
repositories:
  - id: orders
    path: ./orders
  - id: web
    path: ./web
  - id: edge-gateway
    path: ./gateway
"""
    )

    config = AegifyConfig()
    config.scan.max_workers = 1
    result = ScanEngine(config=config).scan_workspace(manifest)

    endpoint = next(ep for ep in result.endpoints if ep.path == "/orders/{id}")
    assert endpoint.repository_id == "orders"
    assert endpoint.called_by_frontend
    assert endpoint.frontend_call_count == 1
    assert endpoint.exposed_via_gateway
    assert endpoint.gateway_route_ids == ["orders"]
    assert result.gateway_routes[0].repository_id == "edge-gateway"
    assert {link.source_kind for link in result.attack_surface_links} == {
        "frontend_call",
        "gateway_route",
    }


def test_golden_workspace_preserves_cross_repo_attack_surface_evidence(
    tmp_path: Path,
):
    workspace = shutil.copytree(GOLDEN_WORKSPACE, tmp_path / "workspace")
    config = AegifyConfig()
    config.scan.max_workers = 2
    config.llm.enabled = False
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(workspace / "workspace.yml")

    endpoints = {(endpoint.method, endpoint.path): endpoint for endpoint in result.endpoints}
    assert set(endpoints) == {
        ("GET", "/orders/{id}"),
        ("POST", "/orders/{id}/cancel"),
    }
    assert all(endpoint.repository_id == "orders" for endpoint in endpoints.values())
    assert all(endpoint.auth_required for endpoint in endpoints.values())
    assert all(endpoint.called_by_frontend for endpoint in endpoints.values())
    assert all(endpoint.exposed_via_gateway for endpoint in endpoints.values())
    assert all(endpoint.gateway_route_ids == ["orders-api"] for endpoint in endpoints.values())

    assert {(call.method, call.path, call.repository_id) for call in result.frontend_calls} == {
        ("GET", "/edge/v1/orders/{dynamic}", "web"),
        ("POST", "/edge/v1/orders/{dynamic}/cancel", "web"),
    }
    assert len(result.gateway_routes) == 1
    route = result.gateway_routes[0]
    assert route.repository_id == "edge-gateway"
    assert route.methods == ["GET", "POST"]
    assert route.filters == ["RewritePath=/edge/v1/(?<segment>.*), /${segment}"]

    assert len(result.attack_surface_links) == 6
    assert {link.source_kind for link in result.attack_surface_links} == {
        "frontend_call",
        "gateway_route",
        "runtime_observation",
    }
    assert {link.endpoint_repository_id for link in result.attack_surface_links} == {"orders"}
    assert {link.match_kind for link in result.attack_surface_links} == {
        "gateway_transform",
        "runtime_gateway_transform",
    }
    assert all(endpoint.runtime_observed for endpoint in endpoints.values())
    assert all(endpoint.runtime_observation_count == 1 for endpoint in endpoints.values())
    assert result.runtime_evidence.endpoint_links == 2
    assert result.semantic_analysis.jvm_module_edges == 1
    assert result.framework_analysis.di_call_edges >= 2

    order_symbols = [
        node
        for node, data in engine._last_call_graph.nodes(data=True)
        if data["data"].repository_id == "orders"
    ]
    assert any(
        node.startswith("repo:orders:api/src/main/kotlin/com/acme/orders/OrderController.kt::")
        for node in order_symbols
    )


def test_identical_routes_in_different_repositories_are_not_deduplicated(
    tmp_path: Path,
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    controller = """
@RestController
class HealthController {
    @GetMapping("/api/resource")
    String resource() { return "ok"; }
}
"""
    (first / "Controller.java").write_text(controller)
    (second / "Controller.java").write_text(controller)
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        """
version: 1
repositories:
  - id: first
    path: ./first
  - id: second
    path: ./second
"""
    )

    result = ScanEngine(config=AegifyConfig()).scan_workspace(manifest)

    matching = [endpoint for endpoint in result.endpoints if endpoint.path == "/api/resource"]
    assert {endpoint.repository_id for endpoint in matching} == {"first", "second"}
