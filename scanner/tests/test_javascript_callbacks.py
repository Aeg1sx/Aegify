"""Callback identity, lexical call targets and request data flow in JS and TS."""

from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.ir import ProgramGraphBuilder
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.dataflow import DataflowAnalyzer
from aegify.scanner.endpoint_detector import EndpointDetector
from aegify.scanner.engine import ScanEngine


@pytest.mark.parametrize("suffix", ["js", "ts"])
def test_sibling_handlers_keep_local_helpers_and_sink_arguments_separate(
    tmp_path: Path, suffix: str
):
    path = tmp_path / ("api." + suffix)
    path.write_text(
        "const express = require('express'); const app = express();\n"
        "app.get('/first', function(req, res) {\n"
        "  const copy = value => value;\n"
        "  let fixed = 'file', file = copy(req.query.file); fs.readFile(file);\n"
        "  return fetch(fixed);\n"
        "});\n"
        "app.get('/second', (req, res) => {\n"
        "  const copy = value => 'fixed';\n"
        "  const file = copy(req.query.file); fs.readFile(file);\n"
        "  return fetch(req.query.address);\n"
        "});\n"
        "function outside() { return copy('value'); }\n"
    )
    asts = ASTParser().parse_directory(tmp_path)
    graph = CallGraphBuilder().build(asts)
    flows = DataflowAnalyzer().analyze(asts, graph, ProgramGraphBuilder().build(asts).graph)
    assert {(f.sink.sink_type, f.sink.line) for f in flows} == {("file_access", 4), ("ssrf", 10)}
    ast = asts[0]
    helpers = [f for f in ast.functions if f.name == "copy"]
    assert len({f.symbol_id for f in helpers}) == 2
    assert [f.parameters for f in helpers] == [["value"], ["value"]]
    outside = next(f for f in ast.functions if f.name == "outside")
    assert not list(graph.successors(outside.symbol_id))


def test_same_line_routes_assign_calls_and_request_parameter_to_the_right_handler(tmp_path: Path):
    path = tmp_path / "api.js"
    path.write_text(
        "const express = require('express'); const app = express();\n"
        "app.get('/é', function(input, output) { return RegExp(input.param('q')); }); "
        "app.get('/two', (input, output) => RegExp(output.statusCode));\n"
    )
    ast = ASTParser().parse_file(path)
    assert ast is not None
    first, second = ast.functions
    registrations = [c for c in ast.calls if c.callee == "get"]
    assert [c.caller_symbol_id for c in registrations] == ["", ""]
    assert [c.javascript_handler for c in registrations] == [
        first.qualified_name,
        second.qualified_name,
    ]
    assert [c.caller_symbol_id for c in ast.calls if c.callee == "RegExp"] == [
        first.symbol_id,
        second.symbol_id,
    ]
    endpoints = EndpointDetector().detect([ast])
    assert {e.path: e.handler_function for e in endpoints} == {
        "/é": first.qualified_name,
        "/two": second.qualified_name,
    }
    config = AegifyConfig()
    config.llm.enabled = False
    findings = ScanEngine(config=config).scan(tmp_path).findings
    matched = [f for f in findings if f.rule_id == "AEG-A03-011"]
    assert len(matched) == 1
    assert matched[0].taint_flow.source.in_function == first.qualified_name


def test_deferred_body_and_shadowed_parameter_do_not_create_edges(tmp_path: Path):
    path = tmp_path / "scope.js"
    path.write_text(
        "function read(value) { return fs.readFile(value); }\n"
        "function outer(read) {\n"
        "  const later = () => req.query.value;\n"
        "  read(req.query.other);\n"
        "  return fetch(later);\n"
        "}\n"
    )
    asts = ASTParser().parse_directory(tmp_path)
    graph = CallGraphBuilder().build(asts)
    outer = next(f for f in asts[0].functions if f.name == "outer")
    assert not list(graph.successors(outer.symbol_id))
    flows = DataflowAnalyzer().analyze(asts, graph, ProgramGraphBuilder().build(asts).graph)
    assert not flows


def test_sink_uses_direct_helpers_returned_value(tmp_path: Path):
    (tmp_path / "api.js").write_text(
        "function read() { return req.query.file; }\n"
        "const fixed = value => 'fixed';\n"
        "function route(req) {\n"
        "  fs.readFile(fixed(req.query.file));\n"
        "  fs.readFile(read());\n"
        "  fetch(fixed(req.query.url) + req.query.extra);\n"
        "}\n"
    )
    asts = ASTParser().parse_directory(tmp_path)
    graph = CallGraphBuilder().build(asts)
    flows = DataflowAnalyzer().analyze(asts, graph, ProgramGraphBuilder().build(asts).graph)
    assert {(f.sink.sink_type, f.sink.line) for f in flows} == {("file_access", 5), ("ssrf", 6)}
    assert any(
        step.propagation_type == "return" for f in flows if f.sink.line == 5 for step in f.path
    )


def test_shared_url_preserves_request_provenance_for_each_handler(tmp_path: Path):
    for name, body in [
        ("one", "(value, res) => RegExp(value.param('q'))"),
        ("two", "function(request, response) { return RegExp(request.param('q')); }"),
    ]:
        (tmp_path / (name + ".js")).write_text(
            "const express = require('express'); const app = express();\n"
            f"app.get('/lookup', {body});\n"
        )
    config = AegifyConfig()
    config.llm.enabled = False
    result = ScanEngine(config=config).scan(tmp_path)
    assert {
        (Path(f.file_path).name, f.line_start)
        for f in result.findings
        if f.rule_id == "AEG-A03-011"
    } == {("one.js", 2), ("two.js", 2)}
    assert [e.path for e in result.endpoints] == ["/lookup"]
