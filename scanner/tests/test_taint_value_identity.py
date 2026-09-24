"""Source-only controls for identifier spelling and ordered Go statements."""

from pathlib import Path

import pytest

from aegify.ir import ProgramGraphBuilder
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.dataflow import DataflowAnalyzer


def _flows(directory: Path, sink_type: str = "file_access"):
    asts = ASTParser().parse_directory(directory)
    assert asts and all(ast.parse_error_count == 0 for ast in asts)
    analyzer = DataflowAnalyzer()
    flows = analyzer.analyze(
        asts, CallGraphBuilder().build(asts), ProgramGraphBuilder().build(asts).graph
    )
    assert not analyzer.summary.truncated
    return [flow for flow in flows if flow.sink.sink_type == sink_type]


@pytest.mark.parametrize("name", ["value", "Value", "VALUE", "_value"])
@pytest.mark.parametrize("interpolate", [False, True])
@pytest.mark.parametrize("overwrite", [False, True])
def test_python_identifier_spelling_and_overwrites(
    tmp_path: Path, name: str, interpolate: bool, overwrite: bool
):
    reset = f"    {name} = 'public.txt'\n" if overwrite else ""
    expression = f"f'prefix-{{{name}}}'" if interpolate else name
    (tmp_path / "names.py").write_text(
        "from flask import request\n"
        "def route():\n"
        f"    {name} = request.args.get('document')\n"
        f"{reset}"
        f"    return open({expression})\n"
    )
    flows = _flows(tmp_path)
    if overwrite:
        assert flows == []
    else:
        assert len(flows) == 1
        assert flows[0].source.line == 3 and flows[0].sink.line == 4


def test_uppercase_value_crosses_argument_and_return_edges(tmp_path: Path):
    (tmp_path / "helper.py").write_text(
        "def decorated(INPUT):\n    OUTPUT = f'prefix-{INPUT}.txt'\n    return OUTPUT\n"
    )
    (tmp_path / "route.py").write_text(
        "from flask import request\n"
        "from helper import decorated\n"
        "def route():\n"
        "    DATA = decorated(request.args.get('document'))\n"
        "    return open(DATA)\n"
    )
    flows = _flows(tmp_path)
    assert len(flows) == 1
    assert {"argument", "return", "sink"} <= {step.propagation_type for step in flows[0].path}


def test_class_names_and_static_literals_do_not_create_a_source(tmp_path: Path):
    (tmp_path / "unrelated.py").write_text(
        "from flask import request\n"
        "class Document:\n"
        "    @staticmethod\n"
        "    def public():\n"
        "        return 'public.txt'\n"
        "def route():\n"
        "    VALUE = request.args.get('unused')\n"
        "    NAME = Document.public()\n"
        "    return open(NAME)\n"
    )
    assert _flows(tmp_path) == []


@pytest.mark.parametrize("overwrite", [False, True])
def test_uppercase_object_field_load(tmp_path: Path, overwrite: bool):
    reset = "    Holder.Value = 'public.txt'\n" if overwrite else ""
    (tmp_path / "handler.py").write_text(
        "from flask import request\n"
        "class Box:\n"
        "    pass\n"
        "def handler():\n"
        "    Holder = Box()\n"
        "    Holder.Value = request.args.get('document')\n"
        f"{reset}"
        "    return open(Holder.Value)\n"
    )
    flows = _flows(tmp_path)
    if overwrite:
        assert flows == []
    else:
        assert len(flows) == 1
        assert flows[0].source.line == 6
        assert {"field-store", "field-load"} <= {step.propagation_type for step in flows[0].path}


@pytest.mark.parametrize("extension", ["js", "ts"])
@pytest.mark.parametrize("name", ["value", "Value", "VALUE"])
@pytest.mark.parametrize("overwrite", [False, True])
def test_javascript_and_typescript_value_spelling(
    tmp_path: Path, extension: str, name: str, overwrite: bool
):
    reset = f'  {name} = "public.txt";\n' if overwrite else ""
    (tmp_path / f"handler.{extension}").write_text(
        'import fs from "node:fs";\n'
        "function handler(req) {\n"
        f"  let {name} = req.query.document;\n"
        f"{reset}"
        f"  return fs.readFile({name});\n"
        "}\n"
    )
    flows = _flows(tmp_path)
    if overwrite:
        assert flows == []
    else:
        assert any(flow.source.line == 3 for flow in flows)
        assert all(not flow.sanitized for flow in flows)


@pytest.mark.parametrize("extension", ["java", "kt", "go"])
@pytest.mark.parametrize("overwrite", [False, True])
def test_jvm_and_go_value_identity(tmp_path: Path, extension: str, overwrite: bool):
    if extension == "java":
        reset = 'VALUE = "fixed";' if overwrite else ""
        source = (
            "class Handler {\n"
            "  void handle(HttpServletRequest request) {\n"
            '    String VALUE = request.getParameter("pattern");\n'
            f"    {reset}\n"
            "    Pattern.compile(VALUE);\n"
            "  }\n"
            "}\n"
        )
    elif extension == "kt":
        reset = 'VALUE = "fixed"' if overwrite else ""
        source = (
            "fun handle(request: HttpServletRequest) {\n"
            '    var VALUE = request.getParameter("pattern")\n'
            f"    {reset}\n"
            "    Pattern.compile(VALUE)\n"
            "}\n"
        )
    else:
        reset = 'VALUE = "fixed"' if overwrite else ""
        source = (
            'package sample\nimport "regexp"\nimport "net/http"\n'
            "func handle(r *http.Request) {\n"
            "    // A comment must not collapse the statement sequence.\n"
            '    VALUE := r.FormValue("pattern")\n'
            f"    {reset}\n"
            "    regexp.Compile(VALUE)\n"
            "}\n"
        )
    (tmp_path / f"handler.{extension}").write_text(source)
    flows = _flows(tmp_path, "regex_compile")
    if overwrite:
        assert flows == []
    else:
        assert any(flow.source.source_type == "http_param" for flow in flows)


@pytest.mark.parametrize("comment", ["", "// leading comment\n"])
def test_go_source_assignment_is_visible_to_later_sink(tmp_path: Path, comment: str):
    (tmp_path / "handler.go").write_text(
        'package sample\nimport "regexp"\nimport "net/http"\n'
        "func handle(r *http.Request) {\n"
        f"{comment}"
        '  value := r.FormValue("pattern")\n'
        "  regexp.Compile(value)\n"
        "}\n"
    )
    assert len(_flows(tmp_path, "regex_compile")) == 1
