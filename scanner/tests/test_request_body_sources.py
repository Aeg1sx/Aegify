"""Static body provenance at actual path operands."""

from textwrap import dedent

from aegify.config import AegifyConfig
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.dataflow import DataflowAnalyzer
from aegify.scanner.engine import ScanEngine


def test_request_body_reads_require_the_bound_receiver_and_real_operand(tmp_path):
    source = tmp_path / "handler.py"
    source.write_text(
        dedent("""
        import flask
        from flask import request as incoming
        from fastapi import Request as WebRequest
        from rest_framework.request import Request as ApiRequest
        from rest_framework.decorators import api_view as view
        def from_body():
            return open(incoming.json["name"])
        def from_data():
            return open(flask.request.data)
        def fixed():
            return open("request.json")  # request.data
        def unrelated(obj):
            request = obj
            return open(request.json)
        def nested(obj):
            return open(obj.request.json)
        def similar(obj):
            return open(obj.json)
        def shadowed(incoming):
            return open(incoming.json)
        def sibling_operand():
            return (incoming.json, open("incoming.json"))
        def formatted():
            return open(f"{incoming.json}")
        async def starlette(req: WebRequest):
            body = await req.json()
            return open(body["name"])
        def bound_method(req: WebRequest):
            return open(req.json)
        def drf(req: ApiRequest):
            return open(req.data["name"])
        @view(["POST"])
        def api_view_body(req):
            return open(req.data["name"])
        def store(obj):
            obj.json = "request.json"
            return open("present.json")
    """).lstrip()
    )
    parsed = ASTParser().parse_file(source)
    local = DataflowAnalyzer()._find_sources(parsed)
    observed = {(s.in_function, s.variable) for s in local if s.source_type == "http_body"}
    assert observed == {
        ("from_body", "incoming.json"),
        ("from_data", "flask.request.data"),
        ("sibling_operand", "incoming.json"),
        ("formatted", "incoming.json"),
        ("starlette", "req.json"),
        ("drf", "req.data"),
        ("api_view_body", "req.data"),
    }
    scan = ScanEngine(config=AegifyConfig()).scan_files(tmp_path, [source])
    findings = [
        f
        for f in scan.findings
        if f.rule_id == "AEG-PATH-001" and f.taint_flow.source.source_type == "http_body"
    ]
    assert {f.taint_flow.source.in_function for f in findings} == {
        "from_body",
        "from_data",
        "formatted",
        "starlette",
        "drf",
        "api_view_body",
    }
    assert all(f.blocks_ci for f in findings)


def test_legacy_call_arguments_still_distinguish_attributes_from_file_names(tmp_path):
    source = tmp_path / "before_parser_upgrade.py"
    source.write_text(
        "from flask import request\ndef handle():\n"
        '    open("request.json")\n    open(request.json["name"])\n'
    )
    parsed = ASTParser().parse_file(source).model_copy(update={"python_request_body_reads": None})
    reads = [s for s in DataflowAnalyzer()._find_sources(parsed) if s.source_type == "http_body"]
    assert [(r.line, r.variable) for r in reads] == [(4, 'request.json["name"]')]
