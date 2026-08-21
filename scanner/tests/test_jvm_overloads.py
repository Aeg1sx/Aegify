"""Descriptor-aware Java/Kotlin identity and overload-resolution regressions."""

from pathlib import Path

from codeguard.config import CodeGuardConfig
from codeguard.ir import ProgramGraphBuilder
from codeguard.scanner.ast_parser import ASTParser
from codeguard.scanner.call_graph import CallGraphBuilder
from codeguard.scanner.dataflow import DataflowAnalyzer
from codeguard.scanner.engine import ScanEngine


def test_java_workspace_overloads_have_distinct_descriptor_ids(tmp_path: Path):
    source = tmp_path / "Overloads.java"
    source.write_text(
        "class Overloads {\n"
        "  String select(String value) { return value; }\n"
        "  int select(int value) { return value; }\n"
        "}\n"
    )

    ast = ASTParser().parse_file(
        source,
        repository_id="service",
        repository_root=tmp_path,
    )

    assert ast is not None
    symbols = {function.symbol_id for function in ast.functions}
    assert symbols == {
        "repo:service:Overloads.java::Overloads.select(String)",
        "repo:service:Overloads.java::Overloads.select(int)",
    }


def test_java_call_graph_resolves_overload_by_parameter_and_literal_type(
    tmp_path: Path,
):
    source = tmp_path / "Overloads.java"
    source.write_text(
        "class Overloads {\n"
        "  String select(String value) { return value; }\n"
        "  int select(int value) { return value; }\n"
        "  void run(String input) {\n"
        "    select(input);\n"
        "    select(7);\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None

    builder = CallGraphBuilder()
    graph = builder.build([ast])

    caller = "Overloads.run(String)"
    assert set(graph.successors(caller)) == {
        "Overloads.select(String)",
        "Overloads.select(int)",
    }
    targets_by_line = {
        attributes["call_site"].line: target
        for _, target, attributes in graph.out_edges(caller, data=True)
    }
    assert targets_by_line[5] == "Overloads.select(String)"
    assert targets_by_line[6] == "Overloads.select(int)"
    assert builder.overload_calls_resolved == 2
    assert builder.overload_calls_ambiguous == 0

    config = CodeGuardConfig()
    config.llm.enabled = False
    config.scan.max_workers = 1
    scan = ScanEngine(config=config).scan(tmp_path)
    assert scan.program_graph.overload_calls_resolved == 2
    assert scan.program_graph.overload_calls_ambiguous == 0


def test_overloaded_method_taint_does_not_enter_wrong_descriptor(tmp_path: Path):
    source = tmp_path / "OverloadTaint.java"
    source.write_text(
        "class OverloadTaint {\n"
        "  int identity(int value) {\n"
        "    Runtime.getRuntime().exec(String.valueOf(value));\n"
        "    return value;\n"
        "  }\n"
        '  String identity(String value) { return "safe"; }\n'
        '  @PostMapping("/run")\n'
        "  void run(String input) { identity(input); }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None
    call_graph = CallGraphBuilder().build([ast])
    program_graph = ProgramGraphBuilder().build([ast]).graph

    flows = DataflowAnalyzer().analyze([ast], call_graph, program_graph)

    assert flows == []


def test_unknown_overload_type_stays_ambiguous_instead_of_guessing(tmp_path: Path):
    source = tmp_path / "Ambiguous.java"
    source.write_text(
        "class Ambiguous {\n"
        "  String select(String value) { return value; }\n"
        "  int select(int value) { return value; }\n"
        "  void run(Object value) { select(transform(value)); }\n"
        "  Object transform(Object value) { return value; }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None
    builder = CallGraphBuilder()

    graph = builder.build([ast])

    assert list(graph.successors("Ambiguous.run(Object)")) == ["Ambiguous.transform(Object)"]
    assert builder.overload_calls_ambiguous == 1


def test_kotlin_default_parameter_and_vararg_arity_are_preserved(tmp_path: Path):
    source = tmp_path / "KotlinOverloads.kt"
    source.write_text(
        "class KotlinOverloads {\n"
        '  fun route(value: String, suffix: String = "safe") = value + suffix\n'
        "  fun route(vararg values: Int) = values.size\n"
        "  fun run(input: String) {\n"
        "    route(input)\n"
        "    route(1, 2, 3)\n"
        "  }\n"
        "}\n"
    )
    ast = ASTParser().parse_file(source)
    assert ast is not None

    graph = CallGraphBuilder().build([ast])

    assert set(graph.successors("KotlinOverloads.run(String)")) == {
        "KotlinOverloads.route(String,String)",
        "KotlinOverloads.route(Int...)",
    }
