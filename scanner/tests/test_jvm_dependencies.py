"""Exact JVM artifact dependency resolution across workspace repositories."""

from pathlib import Path

from aegify.config import AegifyConfig
from aegify.ir import ProgramGraphQuery
from aegify.scanner.engine import ScanEngine
from aegify.semantic.jvm_dependencies import (
    JvmArtifactCoordinate,
    JvmDependencyAnalysis,
    JvmDependencyAnalyzer,
)


def _write_provider(root: Path, version: str = "1.2.0") -> None:
    source = root / "src" / "main" / "java" / "Provider.java"
    source.parent.mkdir(parents=True)
    source.write_text("class Provider { void provide() {} }\n")
    (root / "pom.xml").write_text(
        "<project>\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.acme</groupId>\n"
        "  <artifactId>contracts</artifactId>\n"
        f"  <version>{version}</version>\n"
        "</project>\n"
    )


def _write_manifest(root: Path, repositories: list[str]) -> Path:
    manifest = root / "workspace.yml"
    manifest.write_text(
        "version: 1\nrepositories:\n"
        + "".join(
            f"  - id: {repository}\n    path: ./{repository}\n" for repository in repositories
        )
    )
    return manifest


def _scan(manifest: Path) -> tuple[ScanEngine, object]:
    config = AegifyConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)
    return engine, engine.scan_workspace(manifest)


def test_maven_property_dependency_resolves_exact_workspace_provider(
    tmp_path: Path,
):
    provider = tmp_path / "provider"
    consumer = tmp_path / "consumer"
    provider.mkdir()
    consumer.mkdir()
    _write_provider(provider)
    source = consumer / "src" / "main" / "java" / "Consumer.java"
    source.parent.mkdir(parents=True)
    source.write_text("class Consumer { void call() {} }\n")
    (consumer / "pom.xml").write_text(
        "<project>\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.acme</groupId>\n"
        "  <artifactId>consumer</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <properties><contracts.version>1.2.0</contracts.version></properties>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>com.acme</groupId>\n"
        "      <artifactId>contracts</artifactId>\n"
        "      <version>${contracts.version}</version>\n"
        "    </dependency>\n"
        "    <dependency>\n"
        "      <groupId>junit</groupId><artifactId>junit</artifactId>\n"
        "      <version>4.13.2</version><scope>test</scope>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    engine, result = _scan(_write_manifest(tmp_path, ["consumer", "provider"]))

    assert result.semantic_analysis.jvm_published_artifacts == 2
    assert result.semantic_analysis.jvm_declared_dependencies == 1
    assert result.semantic_analysis.jvm_locked_dependencies == 0
    assert result.semantic_analysis.jvm_exact_external_resolutions == 1
    assert result.semantic_analysis.jvm_unresolved_workspace_dependencies == 0
    artifact = JvmArtifactCoordinate(
        manager="maven",
        group="com.acme",
        artifact="contracts",
        version="1.2.0",
    )
    source_id = "repo:consumer:src/main/java/Consumer.java::Consumer.call()"
    sink_id = "repo:provider:src/main/java/Provider.java::Provider.provide()"
    assert ProgramGraphQuery(engine._last_program_graph).cross_repository_path(
        source_id, sink_id
    ) == [
        source_id,
        "repo:consumer:jvm-module:root:root",
        artifact.node_id,
        "repo:provider:jvm-module:root:root",
        sink_id,
    ]


def test_gradle_lockfile_promotes_dynamic_dependency_to_exact_resolution(
    tmp_path: Path,
):
    provider = tmp_path / "provider"
    consumer = tmp_path / "consumer"
    provider.mkdir()
    consumer.mkdir()
    _write_provider(provider)
    source = consumer / "src" / "main" / "java" / "Consumer.java"
    source.parent.mkdir(parents=True)
    source.write_text("class Consumer { void call() {} }\n")
    (consumer / "settings.gradle.kts").write_text('rootProject.name = "consumer"\n')
    (consumer / "build.gradle.kts").write_text(
        'group = "com.acme"\n'
        'version = "1.0.0"\n'
        'dependencies { implementation("com.acme:contracts:1.+") }\n'
    )
    (consumer / "gradle.lockfile").write_text(
        "com.acme:contracts:1.2.0=compileClasspath,runtimeClasspath\n"
    )
    engine, result = _scan(_write_manifest(tmp_path, ["consumer", "provider"]))

    assert result.semantic_analysis.jvm_dependency_lockfiles == 1
    assert result.semantic_analysis.jvm_dynamic_dependencies == 1
    assert result.semantic_analysis.jvm_locked_dependencies == 1
    assert result.semantic_analysis.jvm_exact_external_resolutions == 1
    assert result.semantic_analysis.jvm_unresolved_workspace_dependencies == 0
    artifact = JvmArtifactCoordinate("maven", "com.acme", "contracts", "1.2.0")
    edge = engine._last_program_graph.get_edge_data("repository:consumer", artifact.node_id)
    assert any(item["fidelity"] == "dependency-lock-exact" for item in edge.values())


def test_maven_dependency_version_mismatch_is_unresolved_and_conflicting(
    tmp_path: Path,
):
    provider = tmp_path / "provider"
    consumer = tmp_path / "consumer"
    provider.mkdir()
    consumer.mkdir()
    _write_provider(provider, version="1.2.0")
    source = consumer / "src" / "main" / "java" / "Consumer.java"
    source.parent.mkdir(parents=True)
    source.write_text("class Consumer { void call() {} }\n")
    (consumer / "pom.xml").write_text(
        "<project>\n"
        "  <groupId>com.acme</groupId><artifactId>consumer</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <dependencies><dependency>\n"
        "    <groupId>com.acme</groupId><artifactId>contracts</artifactId>\n"
        "    <version>2.0.0</version>\n"
        "  </dependency></dependencies>\n"
        "</project>\n"
    )
    engine, result = _scan(_write_manifest(tmp_path, ["consumer", "provider"]))

    assert result.semantic_analysis.jvm_exact_external_resolutions == 0
    assert result.semantic_analysis.jvm_unresolved_workspace_dependencies == 1
    assert result.semantic_analysis.jvm_dependency_version_conflicts == 1
    first = JvmArtifactCoordinate("maven", "com.acme", "contracts", "1.2.0")
    second = JvmArtifactCoordinate("maven", "com.acme", "contracts", "2.0.0")
    conflict = engine._last_program_graph.get_edge_data(first.node_id, second.node_id)
    assert any(item["kind"] == "jvm-version-conflict" for item in conflict.values())


def test_duplicate_workspace_providers_remain_ambiguous(tmp_path: Path):
    first = tmp_path / "provider-a"
    second = tmp_path / "provider-b"
    consumer = tmp_path / "consumer"
    first.mkdir()
    second.mkdir()
    consumer.mkdir()
    _write_provider(first)
    _write_provider(second)
    source = consumer / "src" / "main" / "java" / "Consumer.java"
    source.parent.mkdir(parents=True)
    source.write_text("class Consumer { void call() {} }\n")
    (consumer / "pom.xml").write_text(
        "<project>\n"
        "  <groupId>com.acme</groupId><artifactId>consumer</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <dependencies><dependency>\n"
        "    <groupId>com.acme</groupId><artifactId>contracts</artifactId>\n"
        "    <version>1.2.0</version>\n"
        "  </dependency></dependencies>\n"
        "</project>\n"
    )
    engine, result = _scan(_write_manifest(tmp_path, ["consumer", "provider-a", "provider-b"]))

    assert result.semantic_analysis.jvm_exact_external_resolutions == 0
    assert result.semantic_analysis.jvm_ambiguous_external_resolutions == 1
    assert result.semantic_analysis.jvm_unresolved_workspace_dependencies == 0
    artifact = JvmArtifactCoordinate("maven", "com.acme", "contracts", "1.2.0")
    resolved = [
        target
        for _, target, data in engine._last_program_graph.out_edges(artifact.node_id, data=True)
        if data.get("kind") == "resolved-jvm-provider"
    ]
    assert resolved == []


def test_gradle_monorepo_dependency_path_starts_at_exact_module(tmp_path: Path):
    commerce = tmp_path / "commerce"
    provider = tmp_path / "provider"
    commerce.mkdir()
    provider.mkdir()
    _write_provider(provider)
    api_source = commerce / "api" / "src" / "main" / "java" / "Api.java"
    domain_source = commerce / "domain" / "src" / "main" / "java" / "Domain.java"
    api_source.parent.mkdir(parents=True)
    domain_source.parent.mkdir(parents=True)
    api_source.write_text("class Api { void call() {} }\n")
    domain_source.write_text("class Domain { void local() {} }\n")
    (commerce / "settings.gradle.kts").write_text(
        'rootProject.name = "commerce"\ninclude("api", "domain")\n'
    )
    (commerce / "build.gradle.kts").write_text('group = "com.acme"\nversion = "1.0.0"\n')
    (commerce / "api" / "build.gradle.kts").write_text(
        "dependencies { implementation(libs.contracts) }\n"
    )
    (commerce / "domain" / "build.gradle.kts").write_text("plugins {}\n")
    catalog = commerce / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir()
    catalog.write_text(
        '[versions]\ncontracts = "1.2.0"\n'
        "[libraries]\n"
        'contracts = { module = "com.acme:contracts", version.ref = "contracts" }\n'
    )
    engine, result = _scan(_write_manifest(tmp_path, ["commerce", "provider"]))

    assert result.semantic_analysis.jvm_exact_external_resolutions == 1
    assert result.semantic_analysis.jvm_version_catalogs == 1
    assert result.semantic_analysis.jvm_catalog_dependencies == 1
    artifact = JvmArtifactCoordinate("maven", "com.acme", "contracts", "1.2.0")
    source_id = "repo:commerce:api/src/main/java/Api.java::Api.call()"
    sink_id = "repo:provider:src/main/java/Provider.java::Provider.provide()"
    assert ProgramGraphQuery(engine._last_program_graph).cross_repository_path(
        source_id, sink_id
    ) == [
        source_id,
        "repo:commerce:jvm-module:root:api",
        artifact.node_id,
        "repo:provider:jvm-module:root:root",
        sink_id,
    ]


def test_gradle_version_catalog_normalizes_aliases_and_bundles(tmp_path: Path):
    catalog = tmp_path / "libs.versions.toml"
    catalog.write_text(
        '[versions]\ncontracts = { strictly = "1.2.0" }\n'
        "[libraries]\n"
        'contracts-api = { group = "com.acme", name = "contracts", '
        'version.ref = "contracts" }\n'
        'logging = "org.slf4j:slf4j-api:2.0.17"\n'
        '[bundles]\ncore = ["contracts-api", "logging"]\n'
    )
    result = JvmDependencyAnalysis()

    aliases = JvmDependencyAnalyzer()._read_version_catalog(catalog, result)

    contracts = JvmArtifactCoordinate("maven", "com.acme", "contracts", "1.2.0")
    logging = JvmArtifactCoordinate("maven", "org.slf4j", "slf4j-api", "2.0.17")
    assert aliases["contracts.api"] == [contracts]
    assert aliases["logging"] == [logging]
    assert aliases["bundles.core"] == [contracts, logging]
