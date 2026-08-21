"""Tests for SCIP ingestion and JVM semantic dispatch overlays."""

import json
from pathlib import Path

from aegify.config import AegifyConfig
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.workspace import WorkspaceManifest
from aegify.semantic import SemanticAnalyzer
from aegify.semantic.jvm import JvmSemanticAnalyzer
from aegify.semantic.scip import ScipImporter


def test_scip_json_import_preserves_provider_roles_and_relationships(tmp_path: Path):
    index = tmp_path / "index.scip.json"
    index.write_text(
        json.dumps(
            {
                "metadata": {"toolInfo": {"name": "scip-java", "version": "test"}},
                "documents": [
                    {
                        "relativePath": "src/App.java",
                        "occurrences": [
                            {
                                "range": [2, 4, 7],
                                "symbol": "scip-java maven app 1 App#run().",
                                "symbolRoles": 1,
                            },
                            {
                                "range": [5, 8, 11],
                                "symbol": "scip-java maven lib 1 Service#run().",
                                "symbolRoles": 8,
                            },
                        ],
                        "symbols": [
                            {
                                "symbol": "scip-java maven app 1 App#run().",
                                "relationships": [
                                    {
                                        "symbol": ("scip-java maven lib 1 Service#run()."),
                                        "isImplementation": True,
                                        "isReference": True,
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
    )

    imported = ScipImporter().load(index, "app")

    assert imported.provider == "scip:scip-java"
    assert imported.documents == 1
    assert imported.occurrences == 2
    assert {edge.kind for edge in imported.relationships} == {
        "defined-in",
        "definition",
        "reference",
        "implementation",
        "reference-alias",
    }
    assert all(edge.fidelity == "compiler-index" for edge in imported.relationships)


def test_java_interface_and_cha_rta_dispatch_are_resolved(tmp_path: Path):
    repository = tmp_path / "service"
    repository.mkdir()
    source = repository / "App.java"
    source.write_text(
        "interface Service { String run(); }\n"
        'class Impl implements Service { public String run(){ return "x"; } }\n'
        "class App { void go(){ Service service = new Impl(); service.run(); } }\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="service",
        repository_root=repository,
    )
    assert ast is not None
    service = next(cls for cls in ast.classes if cls.name == "Service")
    impl = next(cls for cls in ast.classes if cls.name == "Impl")
    assert service.methods[0].name == "run"
    assert impl.base_classes == ["Service"]

    analysis = JvmSemanticAnalyzer().analyze([ast])

    kinds = {edge.kind for edge in analysis.relationships}
    assert {"inherits", "overrides", "cha-call", "rta-call"} <= kinds
    assert analysis.cha_edges == 2
    assert analysis.rta_edges == 1


def test_jvm_cha_rta_dispatch_preserves_overload_descriptor(tmp_path: Path):
    source = tmp_path / "Dispatch.java"
    source.write_text(
        "interface Service {\n"
        "  String run(String value);\n"
        "  int run(int value);\n"
        "}\n"
        "class Impl implements Service {\n"
        "  public String run(String value) { return value; }\n"
        "  public int run(int value) { return value; }\n"
        "}\n"
        "class Dispatch {\n"
        "  void go(String input) {\n"
        "    Service service = new Impl();\n"
        "    service.run(input);\n"
        "    service.run(7);\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None

    analysis = JvmSemanticAnalyzer().analyze([ast])

    rta_by_line = {
        edge.line: edge.target for edge in analysis.relationships if edge.kind == "rta-call"
    }
    assert rta_by_line == {
        12: "Impl.run(String)",
        13: "Impl.run(int)",
    }
    override_targets = {edge.target for edge in analysis.relationships if edge.kind == "overrides"}
    assert override_targets == {"Service.run(String)", "Service.run(int)"}


def test_jvm_points_to_narrows_alias_and_factory_return_receivers(tmp_path: Path):
    source = tmp_path / "FactoryFlow.java"
    source.write_text(
        "interface Service { void run(); }\n"
        "class Live implements Service { public void run(){} }\n"
        "class Decoy implements Service { public void run(){} }\n"
        "class FactoryFlow {\n"
        "  Service make(){ return new Live(); }\n"
        "  void go(){\n"
        "    Service returned = make();\n"
        "    Service alias = returned;\n"
        "    alias.run();\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None

    analysis = JvmSemanticAnalyzer().analyze([ast])

    rta_targets = {edge.target for edge in analysis.relationships if edge.kind == "rta-call"}
    assert rta_targets == {"Live.run()"}
    assert analysis.points_to_receiver_calls == 1
    assert analysis.points_to_return_edges >= 1
    assert analysis.points_to_alias_edges >= 1
    assert analysis.points_to_allocations >= 2  # root plus called context
    assert {edge.kind for edge in analysis.relationships} >= {
        "source-points-to",
        "points-to-return",
        "points-to-alias",
    }


def test_jvm_points_to_call_contexts_do_not_cross_contaminate_receivers(
    tmp_path: Path,
):
    source = tmp_path / "Contexts.java"
    source.write_text(
        "interface Service { void run(); }\n"
        "class First implements Service { public void run(){} }\n"
        "class Second implements Service { public void run(){} }\n"
        "class Contexts {\n"
        "  Service identity(Service value){ return value; }\n"
        "  void first(){\n"
        "    Service input = new First();\n"
        "    Service result = identity(input);\n"
        "    result.run();\n"
        "  }\n"
        "  void second(){\n"
        "    Service input = new Second();\n"
        "    Service result = identity(input);\n"
        "    result.run();\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None

    analysis = JvmSemanticAnalyzer().analyze([ast])

    rta_by_line = {
        edge.line: edge.target for edge in analysis.relationships if edge.kind == "rta-call"
    }
    assert rta_by_line == {9: "First.run()", 14: "Second.run()"}
    assert analysis.points_to_argument_edges == 2
    assert analysis.points_to_return_edges == 2
    assert analysis.points_to_contexts > len(ast.functions)
    assert analysis.points_to_truncated is False


def test_jvm_points_to_resolves_explicit_cross_repo_factory_without_decoy(
    tmp_path: Path,
):
    library = tmp_path / "library"
    application = tmp_path / "application"
    decoy = tmp_path / "decoy"
    library.mkdir()
    application.mkdir()
    decoy.mkdir()
    library_source = library / "Factory.java"
    application_source = application / "App.java"
    decoy_source = decoy / "Factory.java"
    library_source.write_text(
        "package com.acme.lib;\n"
        "public interface Service { void run(); }\n"
        "class Live implements Service { public void run(){} }\n"
        "public class Factory {\n"
        "  public static Service create(){ return new Live(); }\n"
        "}\n"
    )
    application_source.write_text(
        "package com.acme.api;\n"
        "import com.acme.lib.Factory;\n"
        "import com.acme.lib.Service;\n"
        "class App { void go(){\n"
        "  Service service = Factory.create();\n"
        "  service.run();\n"
        "} }\n"
    )
    decoy_source.write_text(
        "package com.bad;\n"
        "interface Service { void run(); }\n"
        "class Wrong implements Service { public void run(){} }\n"
        "public class Factory {\n"
        "  public static Service create(){ return new Wrong(); }\n"
        "}\n"
    )
    parser = ASTParser()
    asts = [
        parser.parse_file(path, repository_id=repository, repository_root=path.parent)
        for repository, path in (
            ("library", library_source),
            ("application", application_source),
            ("decoy", decoy_source),
        )
    ]
    parsed = [ast for ast in asts if ast is not None]

    analysis = JvmSemanticAnalyzer().analyze(parsed)

    application_edges = [
        edge
        for edge in analysis.relationships
        if edge.repository_id == "application" and edge.kind in {"points-to-call", "rta-call"}
    ]
    assert {(edge.kind, edge.target) for edge in application_edges} == {
        (
            "points-to-call",
            "repo:library:Factory.java::Factory.create()",
        ),
        ("rta-call", "repo:library:Factory.java::Live.run()"),
    }
    assert all("decoy" not in edge.target for edge in application_edges)

    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: library\n"
        "    path: ./library\n"
        "  - id: application\n"
        "    path: ./application\n"
        "    depends_on: [library]\n"
        "  - id: decoy\n"
        "    path: ./decoy\n"
    )
    config = AegifyConfig()
    config.scan.max_workers = 1
    config.llm.enabled = False
    engine = ScanEngine(config=config)

    scan = engine.scan_workspace(manifest)

    assert scan.semantic_analysis.jvm_points_to_receiver_calls == 1
    assert scan.semantic_analysis.jvm_points_to_direct_calls >= 1
    assert scan.semantic_analysis.jvm_points_to_return_edges >= 1
    caller = "repo:application:App.java::App.go()"
    call_targets = {
        target
        for source, target, data in engine._last_call_graph.edges(data=True)
        if source == caller and data.get("resolution") in {"points-to-call", "rta-call"}
    }
    assert call_targets == {
        "repo:library:Factory.java::Factory.create()",
        "repo:library:Factory.java::Live.run()",
    }


def test_jvm_type_identity_does_not_collapse_same_name_in_one_repository(
    tmp_path: Path,
):
    repository = tmp_path / "service"
    first = repository / "alpha" / "Service.java"
    second = repository / "beta" / "Service.java"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("package alpha; class Service {}\n")
    second.write_text("package beta; class Service {}\n")
    parser = ASTParser()
    asts = [
        parser.parse_file(
            path,
            repository_id="service",
            repository_root=repository,
        )
        for path in (first, second)
    ]

    analysis = JvmSemanticAnalyzer().analyze([ast for ast in asts if ast is not None])

    assert analysis.types == {
        "repo:service:jvm-type:alpha/Service.java::Service",
        "repo:service:jvm-type:beta/Service.java::Service",
    }


def test_workspace_semantic_summary_discovers_gradle_and_scip(tmp_path: Path):
    repository = tmp_path / "orders"
    source_root = repository / "api" / "src" / "main" / "kotlin"
    source_root.mkdir(parents=True)
    (repository / "settings.gradle.kts").write_text('include("api")\n')
    (repository / "build.gradle.kts").write_text("plugins {}\n")
    source = source_root / "Service.kt"
    source.write_text('class Service { fun run(): String = "ok" }\n')
    index = tmp_path / "orders.scip.json"
    index.write_text(
        json.dumps(
            {
                "metadata": {"toolInfo": {"name": "scip-java"}},
                "documents": [
                    {
                        "relativePath": "api/src/main/kotlin/Service.kt",
                        "occurrences": [],
                        "symbols": [],
                    }
                ],
            }
        )
    )
    manifest_path = tmp_path / "workspace.yml"
    manifest_path.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: orders\n"
        "    path: ./orders\n"
        "    scip_index: ./orders.scip.json\n"
    )
    manifest = WorkspaceManifest.load(manifest_path)
    ast = ASTParser().parse_file(
        source,
        repository_id="orders",
        repository_root=repository,
    )
    assert ast is not None

    bundle = SemanticAnalyzer().analyze(manifest, [ast])

    assert bundle.summary.fidelity == "hybrid"
    assert bundle.summary.scip_documents == 1
    assert bundle.summary.jvm_types == 1
    assert bundle.summary.providers == [
        "aegify-jvm-build",
        "aegify-jvm-source",
        "scip:scip-java",
    ]
    assert any(project.build_system == "gradle" for project in bundle.summary.build_projects)

    config = AegifyConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)
    scan_result = engine.scan_workspace(manifest_path)
    graph_file = tmp_path / "semantic.jsonl"
    engine.export_semantic_graph(graph_file)

    assert scan_result.semantic_analysis.fidelity == "hybrid"
    records = [json.loads(line) for line in graph_file.read_text().splitlines()]
    assert {record["record"] for record in records} == {"node", "edge"}
    assert any(
        record.get("kind") == "member-of-module" for record in records if record["record"] == "edge"
    )


def test_workspace_imports_multiple_scip_indexes_for_independent_monorepo_builds(
    tmp_path: Path,
):
    repository = tmp_path / "platform"
    first_source = repository / "first" / "src" / "First.java"
    second_source = repository / "second" / "src" / "Second.java"
    first_source.parent.mkdir(parents=True)
    second_source.parent.mkdir(parents=True)
    first_source.write_text("class First {}\n")
    second_source.write_text("class Second {}\n")
    for name, relative in (
        ("first", "first/src/First.java"),
        ("second", "second/src/Second.java"),
    ):
        index = tmp_path / f"{name}.scip.json"
        index.write_text(
            json.dumps(
                {
                    "metadata": {"toolInfo": {"name": "scip-java"}},
                    "documents": [{"relativePath": relative, "occurrences": [], "symbols": []}],
                }
            )
        )
    manifest_path = tmp_path / "workspace.yml"
    manifest_path.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: platform\n"
        "    path: ./platform\n"
        "    scip_indexes:\n"
        "      - ./first.scip.json\n"
        "      - ./second.scip.json\n"
    )
    manifest = WorkspaceManifest.load(manifest_path)
    parser = ASTParser()
    asts = [
        parser.parse_file(
            source,
            repository_id="platform",
            repository_root=repository,
        )
        for source in (first_source, second_source)
    ]

    bundle = SemanticAnalyzer().analyze(
        manifest,
        [ast for ast in asts if ast is not None],
    )

    assert bundle.summary.scip_documents == 2
    assert bundle.summary.providers == ["aegify-jvm-source", "scip:scip-java"]
