"""Tests for Spring DI/proxy and asynchronous framework overlays."""

from pathlib import Path

from codeguard.config import CodeGuardConfig
from codeguard.framework import SpringModelAnalyzer
from codeguard.ir.query import ProgramGraphQuery
from codeguard.scanner.ast_parser import ASTParser
from codeguard.scanner.engine import ScanEngine


def test_spring_di_security_transaction_and_reactor_edges(tmp_path: Path):
    source = tmp_path / "Orders.java"
    source.write_text(
        "interface OrderPort { String find(String id); }\n"
        "@Service class OrderService implements OrderPort {\n"
        "  @Transactional public String find(String id) { return id; }\n"
        "}\n"
        "@RestController class OrderController {\n"
        "  private final OrderPort orderService;\n"
        "  OrderController(OrderPort orderService) { this.orderService = orderService; }\n"
        "  @PreAuthorize(\"hasAuthority('orders:read')\")\n"
        "  public String get(String id) { return orderService.find(id); }\n"
        "  public Object reactive(Object mono) { return mono.flatMap(value -> value); }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="orders",
        repository_root=tmp_path,
    )
    assert ast is not None

    bundle = SpringModelAnalyzer().analyze([ast])

    assert bundle.summary.spring_components == 2
    assert bundle.summary.di_call_edges == 1
    assert bundle.summary.security_guards == 1
    assert bundle.summary.transaction_boundaries == 1
    assert bundle.summary.reactive_edges == 1
    assert {edge.kind for edge in bundle.relationships} >= {
        "reactive-continuation",
        "security-guard",
        "spring-di-call",
        "transaction-proxy",
    }


def test_workspace_kotlin_suspend_and_security_are_in_program_graph(tmp_path: Path):
    source = tmp_path / "Controller.kt"
    source.write_text(
        "@RestController\n"
        "class Controller {\n"
        "  @PreAuthorize(\"hasAuthority('read')\")\n"
        "  suspend fun load(id: String): String = id\n"
        "}\n"
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: api\n    path: .\n")
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    assert result.framework_analysis.coroutine_edges == 1
    assert result.framework_analysis.security_guards == 1
    kinds = {
        data["kind"]
        for _, _, data in engine._last_program_graph.edges(data=True)
        if data.get("overlay") == "framework"
    }
    assert {"coroutine-continuation", "security-guard"} <= kinds


def test_spring_di_dispatch_selects_only_compatible_overload(tmp_path: Path):
    source = tmp_path / "OverloadedPort.java"
    source.write_text(
        "interface Port {\n"
        "  String find(String value);\n"
        "  int find(int value);\n"
        "}\n"
        "@Service class PortService implements Port {\n"
        "  public String find(String value) { return value; }\n"
        "  public int find(int value) { return value; }\n"
        "}\n"
        "@RestController class Controller {\n"
        "  private final Port port;\n"
        "  Controller(Port port) { this.port = port; }\n"
        "  String get(String input) { return port.find(input); }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="service",
        repository_root=tmp_path,
    )
    assert ast is not None

    bundle = SpringModelAnalyzer().analyze([ast])

    targets = {edge.target for edge in bundle.relationships if edge.kind == "spring-di-call"}
    assert targets == {"repo:service:OverloadedPort.java::PortService.find(String)"}


def test_spring_qualifier_and_primary_select_exact_beans(tmp_path: Path):
    source = tmp_path / "QualifiedBeans.java"
    source.write_text(
        "interface Port { String run(String value); }\n"
        '@Service("fastPort") class FastPort implements Port {\n'
        "  public String run(String value) { return value; }\n"
        "}\n"
        "@Primary @Service class SafePort implements Port {\n"
        "  public String run(String value) { return value; }\n"
        "}\n"
        "@RestController class Controller {\n"
        "  private final Port selected;\n"
        "  private final Port defaultPort;\n"
        '  Controller(@Qualifier("fastPort") Port selected, Port defaultPort) {\n'
        "    this.selected = selected; this.defaultPort = defaultPort;\n"
        "  }\n"
        "  String get(String value) {\n"
        "    selected.run(value); return defaultPort.run(value);\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="service",
        repository_root=tmp_path,
    )
    assert ast is not None

    bundle = SpringModelAnalyzer().analyze([ast])

    edges = [edge for edge in bundle.relationships if edge.kind == "spring-di-call"]
    assert {edge.target for edge in edges} == {
        "repo:service:QualifiedBeans.java::FastPort.run(String)",
        "repo:service:QualifiedBeans.java::SafePort.run(String)",
    }
    by_target = {edge.target: edge for edge in edges}
    assert (
        by_target["repo:service:QualifiedBeans.java::FastPort.run(String)"].qualifier == "fastPort"
    )
    assert (
        by_target["repo:service:QualifiedBeans.java::FastPort.run(String)"].fidelity
        == "framework-model-qualifier"
    )
    assert (
        by_target["repo:service:QualifiedBeans.java::SafePort.run(String)"].fidelity
        == "framework-model-primary"
    )
    assert bundle.summary.qualified_bindings == 1
    assert bundle.summary.primary_resolutions == 1
    assert bundle.summary.ambiguous_bindings == 0


def test_spring_bean_factory_preserves_profile_and_property_conditions(
    tmp_path: Path,
):
    source = tmp_path / "ConditionalBeans.java"
    source.write_text(
        "interface Port { String run(String value); }\n"
        "class SafePort implements Port {\n"
        "  public String run(String value) { return value; }\n"
        "}\n"
        '@Profile("prod") @Configuration class PortConfiguration {\n'
        '@Bean(name = "safePort")\n'
        '@ConditionalOnProperty(name = "port.safe", havingValue = "true")\n'
        "  Port port() { return new SafePort(); }\n"
        "}\n"
        "@RestController class Controller {\n"
        '  @Qualifier("safePort") private final Port port;\n'
        "  Controller(Port port) { this.port = port; }\n"
        "  String get(String value) { return port.run(value); }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="service",
        repository_root=tmp_path,
    )
    assert ast is not None

    bundle = SpringModelAnalyzer().analyze([ast])

    calls = [edge for edge in bundle.relationships if edge.kind == "spring-di-call"]
    assert len(calls) == 1
    assert calls[0].target == ("repo:service:ConditionalBeans.java::SafePort.run(String)")
    assert calls[0].qualifier == "safePort"
    assert '@Profile("prod")' in calls[0].condition
    assert "@ConditionalOnProperty" in calls[0].condition
    assert bundle.summary.bean_factories == 1
    assert bundle.summary.conditional_candidates == 1
    assert {edge.kind for edge in bundle.relationships} >= {
        "spring-bean-factory",
        "spring-bean-type",
    }
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: service\n    path: .\n")
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)
    result = engine.scan_workspace(manifest)
    graph_calls = [
        data
        for _, _, data in engine._last_program_graph.edges(data=True)
        if data.get("kind") == "spring-di-call"
    ]
    assert len(graph_calls) == 1
    assert graph_calls[0]["qualifier"] == "safePort"
    assert "@ConditionalOnProperty" in graph_calls[0]["condition"]
    assert result.framework_analysis.conditional_candidates == 1


def test_kotlin_constructor_qualifier_selects_named_component(tmp_path: Path):
    source = tmp_path / "QualifiedController.kt"
    source.write_text(
        "interface Port { fun run(value: String): String }\n"
        '@Service("fastPort")\n'
        "class FastPort : Port {\n"
        "  override fun run(value: String): String = value\n"
        "}\n"
        "@Primary @Service\n"
        "class SafePort : Port {\n"
        "  override fun run(value: String): String = value\n"
        "}\n"
        "@RestController\n"
        'class Controller(@Qualifier("fastPort") private val port: Port) {\n'
        "  fun get(value: String): String = port.run(value)\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="service",
        repository_root=tmp_path,
    )
    assert ast is not None

    bundle = SpringModelAnalyzer().analyze([ast])

    calls = [edge for edge in bundle.relationships if edge.kind == "spring-di-call"]
    assert len(calls) == 1
    assert calls[0].target == ("repo:service:QualifiedController.kt::FastPort.run(String)")
    assert calls[0].qualifier == "fastPort"
    assert calls[0].fidelity == "framework-model-qualifier"


def test_unqualified_multiple_spring_beans_remain_explicit_candidates(tmp_path: Path):
    source = tmp_path / "AmbiguousBeans.java"
    source.write_text(
        "interface Port { String run(String value); }\n"
        "@Service class FastPort implements Port {\n"
        "  public String run(String value) { return value; }\n"
        "}\n"
        "@Service class SafePort implements Port {\n"
        "  public String run(String value) { return value; }\n"
        "}\n"
        "@RestController class Controller {\n"
        "  private final Port port;\n"
        "  Controller(Port port) { this.port = port; }\n"
        "  String get(String value) { return port.run(value); }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="service",
        repository_root=tmp_path,
    )
    assert ast is not None

    bundle = SpringModelAnalyzer().analyze([ast])

    calls = [edge for edge in bundle.relationships if edge.kind == "spring-di-call"]
    assert {edge.target for edge in calls} == {
        "repo:service:AmbiguousBeans.java::FastPort.run(String)",
        "repo:service:AmbiguousBeans.java::SafePort.run(String)",
    }
    assert {edge.fidelity for edge in calls} == {"framework-model-ambiguous"}
    assert bundle.summary.ambiguous_bindings == 1


def test_cross_repo_auto_configuration_uses_exact_artifact_provider_only(
    tmp_path: Path,
):
    consumer = tmp_path / "consumer"
    provider = tmp_path / "provider"
    decoy = tmp_path / "decoy"
    for root in (consumer, provider, decoy):
        (root / "src/main/java").mkdir(parents=True)

    def write_pom(root: Path, artifact: str, dependency: str = "") -> None:
        dependencies = (
            "<dependencies><dependency><groupId>com.acme</groupId>"
            f"<artifactId>{dependency}</artifactId><version>1.0.0</version>"
            "</dependency></dependencies>"
            if dependency
            else ""
        )
        (root / "pom.xml").write_text(
            "<project><modelVersion>4.0.0</modelVersion>"
            f"<groupId>com.acme</groupId><artifactId>{artifact}</artifactId>"
            f"<version>1.0.0</version>{dependencies}</project>\n"
        )

    write_pom(consumer, "consumer", "provider")
    write_pom(provider, "provider")
    write_pom(decoy, "decoy")
    (consumer / "src/main/java/Controller.java").write_text(
        "package com.acme.consumer;\n"
        "import com.acme.provider.Port;\n"
        "@RestController class Controller {\n"
        "  private final Port port;\n"
        "  Controller(Port port) { this.port = port; }\n"
        "  String get(String value) { return port.run(value); }\n"
        "}\n"
    )
    (provider / "src/main/java/ProviderConfiguration.java").write_text(
        "package com.acme.provider;\n"
        "interface Port { String run(String value); }\n"
        "class SafePort implements Port {\n"
        "  public String run(String value) { return value; }\n"
        "}\n"
        "@AutoConfiguration class ProviderConfiguration {\n"
        "  @Bean Port port() { return new SafePort(); }\n"
        "}\n"
    )
    (decoy / "src/main/java/DecoyConfiguration.java").write_text(
        "package com.acme.decoy;\n"
        "interface Port { String run(String value); }\n"
        "class DecoyPort implements Port {\n"
        "  public String run(String value) { return value; }\n"
        "}\n"
        "@AutoConfiguration class DecoyConfiguration {\n"
        "  @Bean Port port() { return new DecoyPort(); }\n"
        "}\n"
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\nrepositories:\n"
        "  - id: consumer\n    path: ./consumer\n"
        "  - id: provider\n    path: ./provider\n"
        "  - id: decoy\n    path: ./decoy\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    calls = [edge for edge in result.semantic_relationships if edge.kind == "spring-di-call"]
    # Framework relationships live in the normalized graph, not the semantic
    # result slice produced before the framework phase.
    assert calls == []
    framework_calls = [
        (source, target, data)
        for source, target, data in engine._last_program_graph.edges(data=True)
        if data.get("kind") == "spring-di-call"
    ]
    assert len(framework_calls) == 1
    source, target, evidence = framework_calls[0]
    assert source == "repo:consumer:src/main/java/Controller.java::Controller.get(String)"
    assert target == (
        "repo:provider:src/main/java/ProviderConfiguration.java::SafePort.run(String)"
    )
    assert evidence["fidelity"] == "framework-model-single"
    assert result.framework_analysis.cross_repository_di_edges == 1
    assert result.framework_analysis.ambiguous_bindings == 0
    assert ProgramGraphQuery(engine._last_program_graph).cross_repository_path(
        source,
        target,
    ) == [source, target]
