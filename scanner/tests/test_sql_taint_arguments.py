"""Owned source-only checks for SQL text versus bound argument taint."""

from pathlib import Path

import pytest

from aegify.ir import ProgramGraphBuilder
from aegify.models import Language
from aegify.rules.sql_injection import SQLInjectionRule
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.dataflow import DataflowAnalyzer, SinkPattern, TaintConfig


def analyze(path: Path, config: TaintConfig | None = None, *, clear_facts: bool = False):
    ast = ASTParser().parse_file(path)
    assert ast is not None and ast.parse_error_count == 0
    if clear_facts:
        for call in ast.calls:
            call.query_expression = None
    graph = CallGraphBuilder().build([ast])
    analyzer = DataflowAnalyzer(config)
    flows = analyzer.analyze([ast], graph, ProgramGraphBuilder().build([ast]).graph)
    assert not analyzer.summary.truncated
    sql_flows = [flow for flow in flows if flow.sink.sink_type == "sql_query"]
    assert len(SQLInjectionRule().evaluate([ast], graph, flows)) == len(sql_flows)
    return sql_flows


@pytest.mark.parametrize("extension", ["js", "ts"])
@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ('db.execute({sql: "INSERT INTO t VALUES (?)", args: [value]});', 0),
        ('db.query({text: "SELECT * FROM t WHERE id=$1", values: [value]});', 0),
        ('db.execute("SELECT * FROM t WHERE id=?", [value]);', 0),
        ('const q={sql: "SELECT ?", args:[value]};\n  const alias=q;\n  db.execute(alias);', 0),
        ('db.execute({sql: "SELECT " + value, args: []});', 1),
        ("db.query({text: value, values: []});", 1),
        ('db.execute({sql: "SELECT ?", ...value});', 1),
        ('db.execute({sql: "SELECT ?", text: value});', 1),
        ('const q={sql: "SELECT ?", args:[value]};\n  q.sql=value;\n  db.execute(q);', 1),
        (
            'db.execute({sql:"SELECT ?", args:[value]}); db.execute({sql:value, args:[]});',
            1,
        ),
    ],
)
def test_object_binding_taint_does_not_replace_selected_sql_text(
    tmp_path: Path, extension: str, statement: str, expected: int
):
    path = tmp_path / f"owned.{extension}"
    path.write_text(
        f"function handler(req, db) {{\n  const value = req.query.value;\n  {statement}\n}}\n"
    )
    assert len(analyze(path)) == expected


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ('db.execute({"sql": "SELECT ?", "args": [value]})', 0),
        ('db.execute("SELECT ?", (value,))', 0),
        ('db.execute({"sql": "SELECT " + value, "args": []})', 1),
        ('db.execute({"sql": value, "args": []})', 1),
    ],
)
def test_python_query_object_preserves_dynamic_query_flows(
    tmp_path: Path, statement: str, expected: int
):
    path = tmp_path / "owned.py"
    path.write_text(
        "from flask import request\n"
        "def handler(db):\n"
        "    value = request.args.get('value')\n"
        f"    {statement}\n"
    )
    assert len(analyze(path)) == expected


def test_legacy_facts_keep_conservative_object_taint(tmp_path: Path):
    path = tmp_path / "owned.js"
    path.write_text(
        "function handler(req,db) {\n  const value=req.query.value;\n"
        '  db.execute({sql:"SELECT ?",args:[value]});\n}'
    )
    assert len(analyze(path, clear_facts=True)) == 1


def test_custom_nonzero_sql_sink_argument_is_not_overridden(tmp_path: Path):
    path = tmp_path / "owned.js"
    path.write_text(
        "function handler(req,db) {\n  const value=req.query.value;\n"
        '  db.query("SELECT 1",value);\n}'
    )
    config = TaintConfig.default()
    config.sinks[Language.JAVASCRIPT] = [SinkPattern("query", "sql_query", 1)]
    assert len(analyze(path, config)) == 1


def test_non_sql_sink_keeps_object_taint(tmp_path: Path):
    path = tmp_path / "owned.js"
    path.write_text(
        "function handler(req,db) {\n  const value=req.query.value;\n"
        '  db.query({sql:"SELECT ?",args:[value]});\n}'
    )
    ast = ASTParser().parse_file(path)
    assert ast is not None
    config = TaintConfig.default()
    config.sinks[Language.JAVASCRIPT] = [SinkPattern("query", "owned_other_sink", 0)]
    analyzer = DataflowAnalyzer(config)
    flows = analyzer.analyze(
        [ast], CallGraphBuilder().build([ast]), ProgramGraphBuilder().build([ast]).graph
    )
    assert len(flows) == 1 and flows[0].sink.sink_type == "owned_other_sink"
