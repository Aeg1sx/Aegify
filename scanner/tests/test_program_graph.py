"""Tests for CFG/DFG/SSA and monorepo/multi-repo reachability."""

import json
from pathlib import Path

import networkx as nx
import pytest

from codeguard.config import CodeGuardConfig
from codeguard.ir import ContextQueryLimitError, ProgramGraphBuilder, ProgramGraphQuery
from codeguard.scanner.ast_parser import ASTParser
from codeguard.scanner.call_graph import CallGraphBuilder
from codeguard.scanner.engine import ScanEngine


def test_context_balanced_query_rejects_mismatched_return_callsite():
    graph: nx.MultiDiGraph[str] = nx.MultiDiGraph()
    graph.add_edge(
        "caller",
        "callee-entry",
        overlay="icfg",
        kind="interprocedural-call",
        callsite_id="call-a",
    )
    graph.add_edge("callee-entry", "callee-exit", overlay="cfg", kind="normal")
    graph.add_edge(
        "callee-exit",
        "wrong-continuation",
        overlay="icfg",
        kind="interprocedural-return",
        callsite_id="call-b",
    )
    graph.add_edge(
        "callee-exit",
        "right-continuation",
        overlay="icfg",
        kind="interprocedural-return",
        callsite_id="call-a",
    )
    query = ProgramGraphQuery(graph)

    assert query.shortest_path(
        "caller",
        "wrong-continuation",
        {"cfg", "icfg"},
    )
    assert query.context_balanced_path("caller", "wrong-continuation") == []
    assert query.context_balanced_path("caller", "right-continuation") == [
        "caller",
        "callee-entry",
        "callee-exit",
        "right-continuation",
    ]


def test_context_balanced_query_matches_nested_and_exception_returns():
    graph: nx.MultiDiGraph[str] = nx.MultiDiGraph()
    graph.add_edge(
        "start",
        "outer-entry",
        overlay="icfg",
        kind="interprocedural-call",
        callsite_id="outer",
    )
    graph.add_edge("outer-entry", "inner-call", overlay="cfg", kind="normal")
    graph.add_edge(
        "inner-call",
        "inner-entry",
        overlay="icfg",
        kind="interprocedural-bytecode-call",
        callsite_id="inner",
    )
    graph.add_edge(
        "inner-entry",
        "wrong-catch",
        overlay="icfg",
        kind="interprocedural-bytecode-throw",
        callsite_id="outer",
    )
    graph.add_edge(
        "inner-entry",
        "inner-catch",
        overlay="icfg",
        kind="interprocedural-bytecode-throw",
        callsite_id="inner",
    )
    graph.add_edge("inner-catch", "outer-exit", overlay="cfg", kind="normal")
    graph.add_edge(
        "outer-exit",
        "target",
        overlay="icfg",
        kind="interprocedural-return",
        callsite_id="outer",
    )
    query = ProgramGraphQuery(graph)

    assert query.context_balanced_path("start", "wrong-catch") == []
    assert query.context_balanced_path("start", "target") == [
        "start",
        "outer-entry",
        "inner-call",
        "inner-entry",
        "inner-catch",
        "outer-exit",
        "target",
    ]
    with pytest.raises(ContextQueryLimitError, match="max_call_depth=1"):
        query.context_balanced_reachable(
            "start",
            "target",
            max_call_depth=1,
        )


def test_context_balanced_query_bounds_recursive_call_stack():
    graph: nx.MultiDiGraph[str] = nx.MultiDiGraph()
    graph.add_edge(
        "start",
        "recursive-entry",
        overlay="icfg",
        kind="interprocedural-call",
        callsite_id="root-call",
    )
    graph.add_edge(
        "recursive-entry",
        "recursive-entry",
        overlay="icfg",
        kind="interprocedural-call",
        callsite_id="recursive-call",
    )
    graph.add_edge(
        "recursive-entry",
        "recursive-exit",
        overlay="cfg",
        kind="base-case",
    )
    graph.add_edge(
        "recursive-exit",
        "recursive-continuation",
        overlay="icfg",
        kind="interprocedural-return",
        callsite_id="recursive-call",
    )
    query = ProgramGraphQuery(graph)

    with pytest.raises(ContextQueryLimitError, match="max_call_depth=1"):
        query.context_balanced_path(
            "start",
            "recursive-continuation",
            max_call_depth=1,
            require_empty_stack=False,
        )
    assert query.context_balanced_path(
        "start",
        "recursive-continuation",
        max_call_depth=2,
        require_empty_stack=False,
    ) == [
        "start",
        "recursive-entry",
        "recursive-entry",
        "recursive-exit",
        "recursive-continuation",
    ]


def test_context_balanced_query_reports_state_limit_exhaustion():
    graph: nx.MultiDiGraph[str] = nx.MultiDiGraph()
    graph.add_edge("start", "middle", overlay="cfg", kind="normal")
    graph.add_edge("middle", "target", overlay="cfg", kind="normal")

    with pytest.raises(ContextQueryLimitError, match="max_states=1"):
        ProgramGraphQuery(graph).context_balanced_path(
            "start",
            "target",
            max_states=1,
        )


def test_program_graph_builds_cfg_ssa_dfg_alias_and_points_to(tmp_path: Path):
    source = tmp_path / "Flow.java"
    source.write_text(
        "class Flow {\n"
        "  String run(String input, boolean flag) {\n"
        "    String value;\n"
        '    if (flag) { value = input; } else { value = "safe"; }\n'
        "    String copy = value;\n"
        "    Service service = new Service();\n"
        "    while (flag) { copy = value; break; }\n"
        "    return copy;\n"
        "  }\n"
        "}\n"
        "class Service {}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="app",
        repository_root=tmp_path,
    )
    assert ast is not None

    bundle = ProgramGraphBuilder().build([ast])

    assert bundle.summary.functions == 1
    assert bundle.summary.cfg_nodes >= 10
    assert bundle.summary.branch_edges >= 4
    assert bundle.summary.dfg_edges > 0
    assert bundle.summary.ssa_phi_nodes >= 1
    assert bundle.summary.points_to_edges == 1
    assert bundle.summary.alias_edges > 0
    assert bundle.summary.data_state_nodes > 0
    assert bundle.summary.transformation_edges > 0
    function = ast.functions[0].symbol_id
    entry = f"{function}::cfg:entry"
    exit_node = f"{function}::cfg:exit"
    assert ProgramGraphQuery(bundle.graph).reachable(entry, exit_node, {"cfg"})
    break_edges = [
        (source_node, target)
        for source_node, target, data in bundle.graph.edges(data=True)
        if data.get("kind") == "break"
    ]
    assert len(break_edges) == 1
    assert bundle.graph.nodes[break_edges[0][1]]["kind"] == "control-join"
    transformations = [
        (source_node, target)
        for source_node, target, data in bundle.graph.edges(data=True)
        if data.get("kind") == "transforms"
    ]
    assert transformations
    assert all(
        bundle.graph.nodes[source_node]["kind"] == "data-state"
        and bundle.graph.nodes[target]["kind"] == "data-state"
        for source_node, target in transformations
    )


def test_repeated_callsites_are_preserved_in_interprocedural_cfg(tmp_path: Path):
    source = tmp_path / "Repeated.java"
    source.write_text(
        "class Repeated {\n"
        "  String clean(String value) { return value.trim(); }\n"
        "  String run(String first, String second) {\n"
        "    String a = clean(first);\n"
        "    String b = clean(second);\n"
        "    return b;\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="app",
        repository_root=tmp_path,
    )
    assert ast is not None
    functions = {function.name: function.symbol_id for function in ast.functions}
    assert functions.keys() >= {"clean", "run"}

    call_graph = CallGraphBuilder().build([ast])
    repeated_edges = [
        attributes
        for caller, callee, attributes in call_graph.edges(data=True)
        if caller == functions["run"] and callee == functions["clean"]
    ]
    assert [edge["line"] for edge in repeated_edges] == [4, 5]

    bundle = ProgramGraphBuilder().build([ast])
    call_edges, return_edges, callsites = ScanEngine._overlay_program_graph(
        bundle.graph,
        call_graph,
        [],
    )
    assert (call_edges, return_edges, callsites) == (2, 2, 2)

    clean_entry = f"{functions['clean']}::cfg:entry"
    clean_exit = f"{functions['clean']}::cfg:exit"
    run_statements = {
        data["line_start"]: node
        for node, data in bundle.graph.nodes(data=True)
        if data.get("kind") == "statement" and data.get("function") == functions["run"]
    }
    first_call = run_statements[4]
    second_call = run_statements[5]
    return_statement = run_statements[6]

    assert {
        source_node
        for source_node, target, data in bundle.graph.in_edges(clean_entry, data=True)
        if target == clean_entry and data.get("kind") == "interprocedural-call"
    } == {first_call, second_call}
    assert {
        target
        for _, target, data in bundle.graph.out_edges(clean_exit, data=True)
        if data.get("kind") == "interprocedural-return"
    } == {second_call, return_statement}
    assert ProgramGraphQuery(bundle.graph).reachable(
        first_call,
        return_statement,
        {"cfg", "icfg"},
    )

    config = CodeGuardConfig()
    config.scan.max_workers = 1
    result = ScanEngine(config=config).scan(source)
    assert result.program_graph.interprocedural_callsites == 2
    assert result.program_graph.interprocedural_call_edges == 2
    assert result.program_graph.interprocedural_return_edges == 2


def test_ambiguous_overload_does_not_create_interprocedural_cfg_edge(tmp_path: Path):
    source = tmp_path / "Ambiguous.java"
    source.write_text(
        "class Ambiguous {\n"
        "  String route(String value) { return value; }\n"
        "  String route(Integer value) { return value.toString(); }\n"
        "  String run(Object value) { return route(value); }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="app",
        repository_root=tmp_path,
    )
    assert ast is not None
    call_graph = CallGraphBuilder().build([ast])
    bundle = ProgramGraphBuilder().build([ast])

    call_edges, return_edges, callsites = ScanEngine._overlay_program_graph(
        bundle.graph,
        call_graph,
        [],
    )

    assert call_graph.number_of_edges() == 0
    assert (call_edges, return_edges, callsites) == (0, 0, 0)
    assert not any(data.get("overlay") == "icfg" for _, _, data in bundle.graph.edges(data=True))


def test_interprocedural_cfg_targets_only_selected_overload(tmp_path: Path):
    source = tmp_path / "Selected.java"
    source.write_text(
        "class Selected {\n"
        "  String route(String value) { return value; }\n"
        "  String route(int value) { return Integer.toString(value); }\n"
        '  String run() { return route("public"); }\n'
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="app",
        repository_root=tmp_path,
    )
    assert ast is not None
    overloads = {
        function.parameter_types[0]: function.symbol_id
        for function in ast.functions
        if function.name == "route"
    }
    caller = next(function.symbol_id for function in ast.functions if function.name == "run")
    call_graph = CallGraphBuilder().build([ast])
    bundle = ProgramGraphBuilder().build([ast])

    call_edges, return_edges, callsites = ScanEngine._overlay_program_graph(
        bundle.graph,
        call_graph,
        [],
    )

    assert (call_edges, return_edges, callsites) == (1, 1, 1)
    call_targets = {
        target
        for source_node, target, data in bundle.graph.edges(data=True)
        if data.get("kind") == "interprocedural-call"
        and data.get("caller") == caller
        and source_node != caller
    }
    assert call_targets == {f"{overloads['String']}::cfg:entry"}
    assert f"{overloads['int']}::cfg:entry" not in call_targets


def test_interprocedural_return_excludes_caller_exception_continuation(
    tmp_path: Path,
):
    source = tmp_path / "ExceptionalCall.java"
    source.write_text(
        "class ExceptionalCall {\n"
        "  String clean(String value) { return value.trim(); }\n"
        "  String run(String input) {\n"
        "    try {\n"
        "      String value = clean(input);\n"
        "      return value;\n"
        "    } catch (Exception error) {\n"
        '      return "fallback";\n'
        "    }\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="app",
        repository_root=tmp_path,
    )
    assert ast is not None
    functions = {function.name: function.symbol_id for function in ast.functions}
    call_graph = CallGraphBuilder().build([ast])
    bundle = ProgramGraphBuilder().build([ast])

    call_edges, return_edges, callsites = ScanEngine._overlay_program_graph(
        bundle.graph,
        call_graph,
        [],
    )

    assert (call_edges, return_edges, callsites) == (1, 1, 1)
    clean_exit = f"{functions['clean']}::cfg:exit"
    returned_to = {
        target
        for _, target, data in bundle.graph.out_edges(clean_exit, data=True)
        if data.get("kind") == "interprocedural-return"
    }
    assert len(returned_to) == 1
    assert all(bundle.graph.nodes[target].get("kind") != "control-join" for target in returned_to)
    catch_entries = {
        node
        for node, data in bundle.graph.nodes(data=True)
        if data.get("kind") == "control-join" and "catch-entry" in str(node)
    }
    assert returned_to.isdisjoint(catch_entries)
    assert any(
        target in catch_entries and data.get("kind") == "exception"
        for source_node, target, data in bundle.graph.edges(data=True)
        if bundle.graph.nodes[source_node].get("line_start") == 5
    )


def test_recursive_callsite_is_bounded_and_evidence_labeled(tmp_path: Path):
    source = tmp_path / "Recursive.java"
    source.write_text(
        "class Recursive {\n"
        "  int count(int value) {\n"
        "    if (value <= 0) return 0;\n"
        "    return count(value - 1);\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(
        source,
        repository_id="app",
        repository_root=tmp_path,
    )
    assert ast is not None
    function = ast.functions[0].symbol_id
    call_graph = CallGraphBuilder().build([ast])
    bundle = ProgramGraphBuilder().build([ast])

    call_edges, return_edges, callsites = ScanEngine._overlay_program_graph(
        bundle.graph,
        call_graph,
        [],
    )

    assert (call_edges, return_edges, callsites) == (1, 1, 1)
    icfg_edges = [
        data for _, _, data in bundle.graph.edges(data=True) if data.get("overlay") == "icfg"
    ]
    assert {edge["kind"] for edge in icfg_edges} == {
        "interprocedural-call",
        "interprocedural-return",
    }
    assert all(edge["callsite_id"].startswith("callsite:sha256:") for edge in icfg_edges)
    assert all(edge["caller"] == function and edge["callee"] == function for edge in icfg_edges)


def test_program_graph_models_try_catch_finally_and_switch(tmp_path: Path):
    source = tmp_path / "Exceptional.java"
    source.write_text(
        "class Exceptional {\n"
        "  String run(String input, int mode) {\n"
        "    try {\n"
        "      if (mode == 0) { return input; }\n"
        "      risky(input);\n"
        "    } catch (Exception error) {\n"
        "      recover(input);\n"
        "    } finally {\n"
        "      close(input);\n"
        "    }\n"
        "    switch (mode) {\n"
        "      case 1: use(input); break;\n"
        "      default: fallback(input);\n"
        "    }\n"
        "    return input;\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None

    bundle = ProgramGraphBuilder().build([ast])
    statements = {
        str(data.get("code", "")).strip(): node
        for node, data in bundle.graph.nodes(data=True)
        if data.get("kind") == "statement"
    }
    risky = next(node for code, node in statements.items() if code.startswith("risky"))
    recover = next(node for code, node in statements.items() if code.startswith("recover"))
    close = next(node for code, node in statements.items() if code.startswith("close"))
    use = next(node for code, node in statements.items() if code.startswith("use"))
    fallback = next(node for code, node in statements.items() if code.startswith("fallback"))
    query = ProgramGraphQuery(bundle.graph)

    assert bundle.summary.exception_edges >= 2
    assert bundle.summary.finally_edges >= 3
    assert bundle.summary.switch_edges >= 2
    assert query.reachable(risky, recover, {"cfg"})
    assert query.reachable(risky, close, {"cfg"})
    assert query.reachable(close, use, {"cfg"})
    assert query.reachable(close, fallback, {"cfg"})


def test_kotlin_when_emits_independent_case_edges(tmp_path: Path):
    source = tmp_path / "Choice.kt"
    source.write_text(
        "fun choose(mode: Int) {\n  when (mode) {\n    1 -> first()\n    else -> second()\n  }\n}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None

    bundle = ProgramGraphBuilder().build([ast])
    function = ast.functions[0].symbol_id
    when_node = next(
        node
        for node, data in bundle.graph.nodes(data=True)
        if data.get("function") == function and data.get("syntax_kind") == "when_expression"
    )
    case_targets = {
        target
        for _, target, data in bundle.graph.out_edges(when_node, data=True)
        if data.get("kind") in {"case", "default"}
    }

    assert len(case_targets) == 2
    assert bundle.summary.switch_edges >= 2


def test_python_and_kotlin_try_models_emit_exception_and_finally_edges(
    tmp_path: Path,
):
    samples = {
        "flow.py": (
            "def run():\n"
            "    try:\n"
            "        risky()\n"
            "    except Exception:\n"
            "        recover()\n"
            "    finally:\n"
            "        close()\n"
        ),
        "Flow.kt": (
            "fun run() {\n"
            "  try { risky() } catch (error: Exception) { recover() } "
            "finally { close() }\n"
            "}\n"
        ),
    }

    for name, content in samples.items():
        source = tmp_path / name
        source.write_text(content)
        ast = ASTParser().parse_file(source)
        assert ast is not None
        bundle = ProgramGraphBuilder().build([ast])
        assert bundle.summary.exception_edges >= 2, name
        assert bundle.summary.finally_edges >= 3, name


def test_declared_dependency_enables_labeled_multi_repo_reachability(tmp_path: Path):
    consumer = tmp_path / "consumer"
    provider = tmp_path / "provider"
    consumer.mkdir()
    provider.mkdir()
    (consumer / "Consumer.java").write_text("class Consumer { void callProvider() {} }\n")
    (provider / "Provider.java").write_text("class Provider { void sensitiveSink() {} }\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: consumer\n"
        "    path: ./consumer\n"
        "    depends_on: [provider]\n"
        "  - id: provider\n"
        "    path: ./provider\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    assert result.status == "completed"
    source = "repo:consumer:Consumer.java::Consumer.callProvider()"
    sink = "repo:provider:Provider.java::Provider.sensitiveSink()"
    path = ProgramGraphQuery(engine._last_program_graph).cross_repository_path(source, sink)
    assert path == [source, "repository:consumer", "repository:provider", sink]
    dependency = engine._last_program_graph.get_edge_data(
        "repository:consumer", "repository:provider"
    )
    assert next(iter(dependency.values()))["fidelity"] == "declared-dependency-coarse"


def test_structural_file_membership_is_not_security_reachability(tmp_path: Path):
    source = tmp_path / "Unrelated.java"
    source.write_text("class Unrelated {\n  void source() {}\n  void sink() {}\n}\n")
    ast = ASTParser().parse_file(source)
    assert ast is not None
    bundle = ProgramGraphBuilder().build([ast])

    assert (
        ProgramGraphQuery(bundle.graph).cross_repository_path("Unrelated.source", "Unrelated.sink")
        == []
    )


def test_scip_symbol_gives_precise_cross_repo_reachability(tmp_path: Path):
    consumer = tmp_path / "consumer"
    provider = tmp_path / "provider"
    consumer.mkdir()
    provider.mkdir()
    (consumer / "Consumer.java").write_text("class Consumer { void callProvider() {} }\n")
    (provider / "Provider.java").write_text("class Provider { void sensitiveSink() {} }\n")
    symbol = "scip-java maven provider 1 Provider#sensitiveSink()."
    consumer_index = tmp_path / "consumer.scip.json"
    provider_index = tmp_path / "provider.scip.json"
    consumer_index.write_text(
        json.dumps(
            {
                "metadata": {"toolInfo": {"name": "scip-java"}},
                "documents": [
                    {
                        "relativePath": "Consumer.java",
                        "occurrences": [{"range": [0, 0, 1], "symbol": symbol}],
                        "symbols": [],
                    }
                ],
            }
        )
    )
    provider_index.write_text(
        json.dumps(
            {
                "metadata": {"toolInfo": {"name": "scip-java"}},
                "documents": [
                    {
                        "relativePath": "Provider.java",
                        "occurrences": [{"range": [0, 0, 1], "symbol": symbol, "symbolRoles": 1}],
                        "symbols": [],
                    }
                ],
            }
        )
    )
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "version: 1\n"
        "repositories:\n"
        "  - id: consumer\n"
        "    path: ./consumer\n"
        "    scip_index: ./consumer.scip.json\n"
        "  - id: provider\n"
        "    path: ./provider\n"
        "    scip_index: ./provider.scip.json\n"
    )
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    source = "repo:consumer:Consumer.java::Consumer.callProvider()"
    sink = "repo:provider:Provider.java::Provider.sensitiveSink()"
    path = ProgramGraphQuery(engine._last_program_graph).cross_repository_path(source, sink)
    assert result.semantic_analysis.fidelity == "hybrid"
    assert path == [
        source,
        symbol,
        sink,
    ]
    reference = engine._last_program_graph.get_edge_data(source, symbol)
    definition = engine._last_program_graph.get_edge_data(symbol, sink)
    assert next(iter(reference.values()))["fidelity"] == "compiler-index"
    assert next(iter(definition.values()))["kind"] == "resolved-definition"


def test_gradle_module_dependency_enables_labeled_monorepo_reachability(
    tmp_path: Path,
):
    repository = tmp_path / "commerce"
    api_source = repository / "api" / "src" / "main" / "java" / "Api.java"
    domain_source = repository / "domain" / "src" / "main" / "java" / "Domain.java"
    api_source.parent.mkdir(parents=True)
    domain_source.parent.mkdir(parents=True)
    api_source.write_text("class Api { void read() {} }\n")
    domain_source.write_text("class Domain { void load() {} }\n")
    (repository / "settings.gradle.kts").write_text('include("api", "domain")\n')
    (repository / "build.gradle.kts").write_text("plugins {}\n")
    (repository / "api" / "build.gradle.kts").write_text(
        'dependencies { implementation(project(":domain")) }\n'
    )
    (repository / "domain" / "build.gradle.kts").write_text("plugins {}\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("version: 1\nrepositories:\n  - id: commerce\n    path: ./commerce\n")
    config = CodeGuardConfig()
    config.scan.max_workers = 1
    engine = ScanEngine(config=config)

    result = engine.scan_workspace(manifest)

    source = "repo:commerce:api/src/main/java/Api.java::Api.read()"
    sink = "repo:commerce:domain/src/main/java/Domain.java::Domain.load()"
    path = ProgramGraphQuery(engine._last_program_graph).cross_repository_path(source, sink)
    assert result.semantic_analysis.jvm_modules == 3
    assert result.semantic_analysis.jvm_module_edges == 1
    assert path == [
        source,
        "repo:commerce:jvm-module:root:api",
        "repo:commerce:jvm-module:root:domain",
        sink,
    ]
    dependency = engine._last_program_graph.get_edge_data(
        "repo:commerce:jvm-module:root:api",
        "repo:commerce:jvm-module:root:domain",
    )
    assert next(iter(dependency.values()))["fidelity"] == ("declared-module-dependency-coarse")
