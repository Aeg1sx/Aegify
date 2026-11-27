"""Route declarations carry repository-relative evidence and explicit service ownership."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegify.cli import app
from aegify.config import AegifyConfig
from aegify.models import GatewayInventory
from aegify.scanner import gateway_inventory as inventory
from aegify.scanner.engine import ScanEngine
from aegify.scanner.workspace import WorkspaceRepository


def _workspace(root: Path) -> Path:
    for name in ("edge", "catalog", "accounts"):
        (root / name).mkdir()
    (root / "catalog" / "app.py").write_text('"""Catalog service."""\n')
    (root / "edge" / "application.yml").write_text(
        "spring:\n"
        "  cloud:\n"
        "    gateway:\n"
        "      routes:\n"
        "        - id: old\n"
        "          uri: https://credential-marker@catalog.svc/path?key=query-marker\n"
        "          predicates: [Path=/catalog/**]\n"
        "          filters: [AddRequestHeader=secret-header-marker]\n"
    )
    (root / "edge" / "application-dev.yml").write_text(
        "spring.cloud.gateway.mvc.routes: [{id: mvc, uri: 'lb://catalog.svc'}]\n"
        "---\n"
        "spring.cloud.gateway.server:\n"
        "  webflux.routes:\n"
        "    - {id: modern, uri: 'lb://shared'}\n"
        "  webmvc.routes:\n"
        "    - {id: placeholder, uri: 'lb://${SERVICE_HOST}'}\n"
        "    - {id: undeclared, uri: 'http://accounts'}\n"
    )
    (root / "edge" / "declarative.json").write_text(
        json.dumps(
            {
                "_format_version": "3.0",
                "services": [
                    {
                        "name": "different-from-host",
                        "id": "svc-id",
                        "host": "catalog.svc",
                        "routes": [
                            {
                                "name": "child",
                                "paths": ["/catalog"],
                                "plugins": [
                                    {"name": "key-auth", "config": {"token": "plugin-marker"}}
                                ],
                            }
                        ],
                    },
                    {"name": "balancer", "url": "https://pool.svc/ignored"},
                ],
                "upstreams": [{"name": "pool.svc", "targets": [{"target": "catalog.svc:8443"}]}],
                "routes": [
                    {"name": "by-name", "service": "different-from-host"},
                    {"name": "by-id", "service": {"id": "svc-id"}},
                    {"name": "pool", "service": {"name": "balancer"}},
                    {"name": "missing", "service": "unlisted"},
                    {"name": "no-service"},
                ],
            },
            indent=2,
        )
    )
    (root / "edge" / "kong.yaml").write_text(
        "_format_version: '1.1'\nservices:\n  - name: svc\n"
        "    url: https://accounts.svc/\n    routes:\n      - name: kong-old\n"
    )
    manifest = root / "workspace.yml"
    manifest.write_text(
        "repositories:\n"
        "  - {id: edge, path: edge, gateway_configs: [declarative.json]}\n"
        "  - {id: accounts, path: accounts, service_names: [accounts.svc, shared, pool.svc]}\n"
        "  - {id: catalog, path: catalog, service_names: [CATALOG.SVC., shared]}\n"
    )
    return manifest


def test_workspace_cli_reports_owned_and_unresolved_declarations(tmp_path: Path) -> None:
    manifest = _workspace(tmp_path)
    reports = []
    for fmt in ("json", "sarif"):
        output = tmp_path / ("report." + fmt)
        result = CliRunner().invoke(
            app, ["scan-workspace", str(manifest), "-o", fmt, "-f", str(output)]
        )
        assert result.exit_code == 0, result.output
        raw = output.read_text()
        assert all(
            secret not in raw
            for secret in (
                "credential-marker",
                "query-marker",
                "secret-header-marker",
                "plugin-marker",
            )
        )
        data = json.loads(raw)
        if fmt == "json":
            reports.append(data["gateway_inventory"])
            # New declarations remain isolated from executable reachability and issue counts.
            assert [route["id"] for route in data["gateway_routes"]] == ["old"]
            assert data["findings"] == []
        else:
            reports.append(data["runs"][0]["properties"]["gatewayInventory"])
    assert reports[0] == reports[1]
    report = GatewayInventory.model_validate(reports[0])
    from aegify.agents.models import AgentRole
    from aegify.agents.pipeline import SecurityAgentPipeline
    from aegify.models import ScanResult

    review = SecurityAgentPipeline().run(ScanResult(gateway_inventory=report))
    stages = {s.role: s.facts for s in review.stages}
    ownership = stages[AgentRole.STATIC]["gatewayOwnership"]
    assert (ownership["resolved"], ownership["ambiguous"], ownership["unresolved"]) == (6, 1, 5)
    assert (
        "Some declared gateway routes lack a unique repository owner."
        in stages[AgentRole.SYNTHESIS]["reviewHandoff"]["gaps"]
    )
    assert report.input_status == "processed"
    routes = {route.route_name: route for file in report.files for route in file.routes}
    assert set(routes) == {
        "old",
        "mvc",
        "modern",
        "placeholder",
        "undeclared",
        "child",
        "by-name",
        "by-id",
        "pool",
        "missing",
        "no-service",
        "kong-old",
    }
    for name in ("old", "mvc", "child", "by-name", "by-id"):
        assert routes[name].status == "resolved"
        assert routes[name].repository_ids == ["catalog"]
    assert (routes["old"].document, routes["old"].line) == (1, 5)
    assert (routes["modern"].document, routes["modern"].line) == (2, 5)
    assert routes["modern"].status == "ambiguous"
    assert routes["modern"].repository_ids == ["accounts", "catalog"]
    assert routes["placeholder"].reason == "dynamic_or_unsupported_destination"
    assert routes["undeclared"].reason == "no_manifest_owner"
    assert routes["pool"].reason == "kong_upstream_pool"
    assert routes["missing"].reason == routes["no-service"].reason == "unresolved_service_ref"
    assert routes["kong-old"].repository_ids == ["accounts"]
    assert routes["kong-old"].schema_path == "kong.1.1"
    assert routes["child"].schema_path == "kong.3.0"
    assert all(file.repository_id == "edge" for file in report.files)
    for file in report.files:
        assert (
            file.sha256 == hashlib.sha256((tmp_path / "edge" / file.path).read_bytes()).hexdigest()
        )
        assert not file.diagnostics


def test_inventory_digest_survives_relocation_and_tracks_aliases_and_bytes(tmp_path: Path) -> None:
    before = tmp_path / "before"
    before.mkdir()
    _workspace(before)
    after = tmp_path / "after"
    shutil.copytree(before, after)
    engine = ScanEngine()

    def digest(folder: Path) -> str:
        review = engine.scan_workspace(folder / "workspace.yml").gateway_inventory
        assert review and review.digest
        return review.digest

    original = digest(before)
    assert digest(after) == original
    path = after / "edge" / "kong.yaml"
    path.write_bytes(path.read_bytes() + b"\n")
    changed_bytes = digest(after)
    assert changed_bytes != original
    manifest = after / "workspace.yml"
    manifest.write_text(manifest.read_text().replace("CATALOG.SVC.", "catalog-backup.svc"))
    assert digest(after) != changed_bytes


def test_selection_and_config_only_inputs(tmp_path: Path) -> None:
    config = AegifyConfig()
    config.scan.exclude.append("ignored/**")
    engine = ScanEngine(config=config)
    path = tmp_path / "kong.yml"
    path.write_text("_format_version: '3.0'\nroutes: [{name: one}]\n")
    spring = tmp_path / "bootstrap-prod.yaml"
    spring.write_text("spring.cloud.gateway.routes: [{id: two, uri: 'lb://catalog'}]\n")
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (ignored / "kong.yaml").write_bytes(path.read_bytes())
    unrelated = tmp_path / "application.yml"
    unrelated.write_text("spring.application.name: catalog")
    for result, expected in (
        (engine.scan_files(tmp_path, [path]), {"kong.yml"}),
        (engine.scan(spring), {"bootstrap-prod.yaml"}),
        (engine.scan(tmp_path), {"kong.yml", "bootstrap-prod.yaml"}),
    ):
        assert result.files_scanned == 0
        assert result.gateway_inventory
        assert {item.path for item in result.gateway_inventory.files} == expected
    assert engine.scan_files(tmp_path, [unrelated, ignored / "kong.yaml"]).gateway_inventory is None


def test_explicit_invalid_files_have_sanitized_diagnostics(tmp_path: Path) -> None:
    edge = tmp_path / "edge"
    edge.mkdir()
    external = tmp_path / "external.yml"
    external.write_text("_format_version: '3.0'\nroutes: [{name: external}]")
    (edge / "link.yml").symlink_to(external)
    samples = {
        "alias.yml": "id: &id {}\nvalue: *id",
        "duplicate.yml": "_format_version: '3.0'\nroutes: [{name: ok}]\nroutes: []",
        "late-error.yml": "_format_version: '3.0'\nroutes: [{name: discard}]\n---\n[",
        "custom.yaml": "spring.application.name: catalog",
        "bad.json": "_format_version: 3.0",
        "unknown.yml": "_format_version: future\n",
        "ignored.yml": "_format_version: '3.0'\nroutes: [{name: excluded}]",
    }
    for filename, value in samples.items():
        (edge / filename).write_text(value)
    declared = [*samples, "link.yml", "absent.yml"]
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "id": "edge",
                        "path": "edge",
                        "gateway_configs": declared,
                        "exclude": ["ignored.yml"],
                    }
                ]
            }
        )
    )
    report = ScanEngine().scan_workspace(manifest).gateway_inventory
    assert report
    assert report.input_status == "partial"
    files = {file.path: file for file in report.files}
    assert "ignored.yml" not in files
    assert all(not file.routes and file.diagnostics for file in files.values())
    assert files["unknown.yml"].diagnostics == ["unsupported_kong_format"]
    assert files["custom.yaml"].diagnostics == ["no_supported_gateway_declarations"]
    assert files["link.yml"].sha256 is None
    assert files["absent.yml"].sha256 is None


@pytest.mark.parametrize(
    "value", ["../external.yaml", "/abs.json", ".git/file.yml", "not-a-config.py"]
)
def test_manifest_rejects_paths_outside_config_scope(value: str) -> None:
    with pytest.raises(ValueError):
        WorkspaceRepository(id="edge", path=Path("."), gateway_configs=[value])


def test_partial_inventory_limits_are_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = b"_format_version: '3.0'\nroutes: [{name: first}, {name: second}]"
    for name in ("kong.yml", "kong.yaml"):
        (tmp_path / name).write_bytes(raw)
    monkeypatch.setattr(inventory, "MAX_ROUTES", 1)
    monkeypatch.setattr(inventory, "MAX_FILES", 1)
    review = ScanEngine().scan(tmp_path).gateway_inventory
    assert review and review.omitted_files == 1 and review.omitted_routes == 1
    assert review.input_status == "partial"
    assert [r.route_name for r in review.files[0].routes] == ["first"]


def test_conflicting_service_references_never_pick_the_first_match(tmp_path: Path) -> None:
    path = tmp_path / "kong.yml"
    path.write_text(
        "_format_version: '3.0'\nservices:\n"
        "  - {name: duplicated, host: orders}\n"
        "  - {name: duplicated, host: billing}\n"
        "routes: [{name: top, service: {name: duplicated}}]\n"
    )
    report = inventory.review_gateway_configs(
        inventory.config_inputs("edge", tmp_path, [path]),
        {"orders": ["orders"], "billing": ["billing"]},
    )
    assert report
    [route] = report.files[0].routes
    assert (route.status, route.reason, route.repository_ids) == (
        "ambiguous",
        "ambiguous_service_ref",
        [],
    )
