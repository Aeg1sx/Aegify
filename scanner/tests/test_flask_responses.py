"""Flask return contracts evaluated from syntax and the static program graph."""

from pathlib import Path
from textwrap import dedent, indent

import pytest

from aegify.config import AegifyConfig
from aegify.ir import ProgramGraphBuilder
from aegify.models import FindingDisposition
from aegify.rules.xss import FlaskResponseRule
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.dataflow import DataflowAnalyzer
from aegify.scanner.engine import ScanEngine
from aegify.scanner.flask_responses import project_routers, registered_import

SETUP = (
    "from flask import Flask as App, request as req, Response, make_response, jsonify\n"
    "from html import escape as encode\n"
    "from markupsafe import escape as markup_escape\n"
    "app = App(__name__)\n"
)


def _view(path, body, decorator="@app.get('/')", setup=SETUP):
    (path / "view.py").write_text(
        setup + decorator + "\ndef view():\n" + indent(dedent(body).strip(), "    ") + "\n"
    )


def _findings(directory):
    asts = ASTParser().parse_directory(directory)
    assert asts and all(ast.parse_error_count == 0 for ast in asts)
    graph = CallGraphBuilder().build(asts)
    analyzer = DataflowAnalyzer()
    flows = analyzer.analyze(asts, graph, ProgramGraphBuilder().build(asts).graph)
    assert not analyzer.summary.truncated
    return [
        finding
        for finding in FlaskResponseRule().evaluate(asts, graph, flows)
        if finding.taint_flow.sink.function == "flask.view.return"
    ]


@pytest.mark.parametrize(
    "statement",
    [
        "return raw",
        "return f'<p>{raw}</p>'",
        "return f'<p>{encode(raw)} {raw}</p>'",
        "return '<p>{shown}</p>'.format(unused='ok', shown=raw)",
        "return '{0[name]}'.format({'name': raw, 'other': 'ok'})",
        "return '%(shown)s %%' % {'shown': raw, 'other': 'ok'}",
        "return '<p>%s</p>' % raw",
        "return '<p>' + raw + '</p>'",
        "return raw, 202, {'X-Label': 'demo'}",
        "return raw, [('Content-Type', 'text/html; charset=utf-8')]",
        "return Response(response=raw, mimetype='text/html')",
        "return make_response(raw, 200, {'Content-Disposition': 'inline'})",
        "body = f'<p>{raw}</p>'\nraw = 'fixed'\nreturn body",
        "body = '<p>'\nbody += str(raw)\nbody += '</p>'\nreturn body",
        "values = {'shown': raw}\nreturn '{0[shown]}'.format(values)",
        "box = [raw, 'public']\nreturn box[0]",
        "return f'<script>{encode(raw)}</script>'",
        "body = '<script>'\nbody += encode(raw)\nbody += '</script>'\nreturn body",
        "return '<script>' + encode(raw) + '</script>'",
        "return '<p%s>' % encode(raw)",
        "response = make_response(raw)\nreturn response",
        "return f\"{req.args.get('id', default=raw, type=int)}\"",
    ],
)
def test_http_value_reaches_one_advisory_return(tmp_path, statement):
    _view(tmp_path, "raw = req.args['label']\n" + statement)
    findings = _findings(tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule_id, finding.disposition) == (
        "AEG-FLASK-XSS-001",
        FindingDisposition.ADVISORY,
    )
    flow = finding.taint_flow
    assert flow.source.line == 7
    assert flow.sink.line == 8 + statement.count("\n")
    assert flow.sink.sink_type == "flask_html_body"
    assert "response-body" in {step.propagation_type for step in flow.path}


@pytest.mark.parametrize(
    "statement",
    [
        "return f'<p>{encode(raw)}</p>'",
        """return f'<div class="row">{markup_escape(raw)}</div>'""",
        "return '<p>' + encode(raw) + '</p>'",
        "return {'label': raw}",
        "return [raw]",
        "return jsonify({'label': raw})",
        "return raw, {'Content-Type': 'text/plain'}",
        "return raw, 200, {'Content-Type': raw}",
        "return 'OK', {'X-Label': raw}",
        "return Response(raw, content_type='application/json')",
        "return Response(raw, headers={'Content-Disposition': 'attachment'})",
        "response = make_response(raw)\nresponse.mimetype = 'text/plain'\nreturn response",
        "response = make_response(raw)\nother = response\n"
        "other.content_type = 'text/plain'\nreturn other",
        "response = make_response(raw)\nother = response\n"
        "response.content_type = 'text/plain'\nreturn other",
        "return 'fixed {chosen}'.format(chosen='public', unused=raw)",
        "return '{0[name]}'.format({'name': 'public', 'other': raw})",
        "values = {'name':'public','other':raw}\nreturn '{0[name]}'.format(values)",
        "return '%(name)s' % {'name': 'public', 'other': raw}",
        "box = [raw, 'fixed']\nreturn f'{box[1]}'",
        "raw = 'public'\nreturn raw",
        "return f\"{req.args.get('id', type=int)}\"",
        "number = req.args.get('id', type=float)\nreturn f'{number}'",
        "return raw_number if False else 'fixed'",
    ],
)
def test_other_body_or_encoded_text_has_no_response_advisory(tmp_path, statement):
    _view(tmp_path, "raw = req.args['label']\n" + statement)
    assert _findings(tmp_path) == []


def test_per_return_handles_json_and_html_separately(tmp_path):
    _view(
        tmp_path,
        "raw = req.args['label']\nif req.args['kind'] == 'json':\n"
        "    return jsonify(raw)\nreturn f'{raw}'",
    )
    assert [item.taint_flow.sink.line for item in _findings(tmp_path)] == [10]


@pytest.mark.parametrize("escaped", [False, True])
def test_early_return_cannot_overwrite_the_later_html_body(tmp_path, escaped):
    source = "encode(raw)" if escaped else "raw"
    _view(
        tmp_path,
        f"""
        raw = req.args['label']
        shown = f'<p>{{{source}}}</p>'
        for label in ('first', 'second'):
            if label == raw:
                shown = 'fixed'
                return make_response(shown)
        response = make_response('<main>{{}}</main>'.format(shown))
        response.headers['Cache-Control'] = 'private'
        return response
    """,
    )
    findings = _findings(tmp_path)
    if escaped:
        assert not findings
    else:
        assert len(findings) == 1
        finding = findings[0]
        assert finding.line_start == finding.line_end == 13
        assert finding.taint_flow.sink.line == 15
        assert [(s.line, s.propagation_type) for s in finding.taint_flow.path][-2:] == [
            (13, "response-construction"),
            (15, "sink"),
        ]


@pytest.mark.parametrize(
    ("pattern", "body", "expected"),
    [
        (r"[^a-zA-Z0-9\s\.,!?-]", "return f'<p>{raw}</p>'", False),
        (r"[^0-9]", "return raw", False),
        (r"[^0-z]", "return f'<p>{raw}</p>'", True),
        (r"[^a-z<]", "return f'<p>{raw}</p>'", True),
        (r"[^a-z]", "return f'<script>{raw}</script>'", True),
        (r"[^a-z]", "return f'<a href=\"{raw}\">link</a>'", True),
    ],
)
def test_character_filter_depends_on_exact_alphabet_and_html_context(
    tmp_path, pattern, body, expected
):
    _view(
        tmp_path,
        "raw = req.args['label']\n"
        f"raw = remove({pattern!r}, '', raw)\n"
        "raw = remove('secret', '', raw, flags=flags)\n" + body,
        setup=SETUP + "from re import sub as remove, IGNORECASE as flags\n",
    )
    findings = _findings(tmp_path)
    assert bool(findings) is expected
    if expected and pattern == "[^a-z]":
        assert "character filter" in findings[0].message


def test_partial_or_project_defined_filter_is_not_a_text_encoding(tmp_path):
    for expr in (
        "re.sub('[^a-z]', '', raw, count=1)",
        "re.sub('[^a-z]', replacement, raw)",
        "re.sub('[^a-z]', '', raw) + req.args['other']",
    ):
        _view(
            tmp_path,
            f"raw = req.args['label']\nraw = {expr}\nreturn f'<p>{{raw}}</p>'",
            setup=SETUP + "import re\n",
        )
        assert _findings(tmp_path)
    (tmp_path / "re.py").write_text("def sub(pattern, replacement, value): return value\n")
    _view(
        tmp_path,
        "raw = req.args['label']\nraw = re.sub('[^a-z]', '', raw)\nreturn f'<p>{raw}</p>'",
        setup=SETUP + "import re\n",
    )
    assert _findings(tmp_path)


@pytest.mark.parametrize(
    ("setup", "decorator"),
    [
        (SETUP, ""),
        (
            "from other import Router\nfrom flask import request as req\napp = Router()\n",
            "@app.route('/')",
        ),
        (SETUP + "app = another_router\n", "@app.get('/')"),
        (SETUP + "app.response_class = PlainResponse\n", "@app.route('/')"),
        ("from other import app\nfrom flask import request as req\n", "@app.route('/')"),
    ],
)
def test_unproven_global_router(tmp_path, setup, decorator):
    _view(tmp_path, "return req.args['name']", decorator=decorator, setup=setup)
    assert _findings(tmp_path) == []


@pytest.mark.parametrize(
    ("router", "method", "expected"),
    [
        ("app", "route", "flask_injected_html"),
        ("app: App", "get", "flask_html_body"),
        ("app: Foreign", "route", None),
        ("app", "get", None),
    ],
)
def test_factory_parameter(tmp_path, router, method, expected):
    (tmp_path / "view.py").write_text(
        SETUP + f"def register({router}):\n    @app.{method}('/')\n"
        "    def show():\n        return req.args['name']\n"
    )
    findings = _findings(tmp_path)
    assert [f.taint_flow.sink.sink_type for f in findings] == ([expected] if expected else [])
    if expected == "flask_injected_html":
        assert "factory" in findings[0].message
        assert findings[0].disposition == FindingDisposition.ADVISORY


@pytest.mark.parametrize(
    "reference", ["from . import bp", "from pkg import bp", "import pkg as routes"]
)
def test_project_blueprint_matches_within_the_same_repository(tmp_path: Path, reference):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("from flask import Blueprint as BP\nbp = BP('p', __name__)\n")
    base = "routes.bp" if reference.endswith(" as routes") else "bp"
    _view(
        pkg,
        "return req.headers['X-Label']",
        decorator=f"@{base}.route('/')",
        setup=reference + "\nfrom flask import request as req\n",
    )
    assert [f.taint_flow.sink.sink_type for f in _findings(tmp_path)] == ["flask_html_body"]
    asts = ASTParser().parse_directory(tmp_path)
    exporting = next(f for f in asts if f.flask_routers)
    importing = next(f for f in asts if f.flask_responses)
    exporting.repository_id = "one"
    importing.repository_id = "two"
    assert not registered_import(
        importing, importing.flask_responses[0].router, project_routers(asts)
    )


def test_default_engine_dispatches_the_packaged_flask_rule(tmp_path):
    _view(tmp_path, "return req.args['name']")
    config = AegifyConfig()
    config.llm.enabled = False
    config.storage.backend = "memory"
    result = ScanEngine(config=config).scan(tmp_path)
    assert result.status == "completed"
    matched = [f for f in result.findings if f.rule_id == "AEG-FLASK-XSS-001"]
    assert len(matched) == 1
    assert matched[0].disposition == FindingDisposition.ADVISORY


@pytest.mark.parametrize(
    ("reference", "template"),
    [
        ("from .pages import PAGE as content", "content"),
        ("import web.pages as content", "content.PAGE"),
        ("from web.pages import *", "PAGE"),
    ],
)
def test_imported_format_selects_only_the_used_field(tmp_path, reference, template):
    web = tmp_path / "web"
    web.mkdir()
    (web / "__init__.py").write_text("")
    provider = web / "pages.py"
    setup = reference + "\n" + SETUP
    _view(
        web,
        "raw = req.args['display']\n"
        f"response = make_response({template}.format(shown=raw, safe='hello'))\n"
        "response.headers['X-Request-Id'] = 'review'\nreturn response",
        setup=setup,
    )
    for field, expected in (("shown", 1), ("safe", 0)):
        provider.write_text(f"PAGE = '<p>{{{field}}}</p>'\n")
        assert len(_findings(tmp_path)) == expected


@pytest.mark.parametrize(
    ("module", "reference", "statement"),
    [
        ("PAGE = get_template()\n", "from pages import *", "return PAGE.format(raw)"),
        ("PAGE = '{}'\nPAGE = 'hello'\n", "from pages import PAGE", "return PAGE.format(raw)"),
        ("PAGE = '{}'\n__all__ = []\n", "from pages import *", "return PAGE.format(raw)"),
        ("PAGE = '{}'\n__all__ = ['absent']\n", "from pages import *", "return PAGE.format(raw)"),
        ("PAGE = '{}'\nApp = {}\n", "from pages import *", "return PAGE.format(raw)"),
        ("PAGE = '{}'\n", "from pages import PAGE", "PAGE = 'hello'\nreturn PAGE.format(raw)"),
        ("PAGE = '{}'\n", "import pages", "pages.PAGE = 'hello'\nreturn pages.PAGE.format(raw)"),
        ("PAGE = '<p>%s</p>'\n", "from pages import PAGE", "return PAGE % encode(raw)"),
        ("PAGE = '{}'\n", "from pages import *\nfrom other import *", "return PAGE.format(raw)"),
    ],
)
def test_unproven_or_safe_imported_format_has_no_advisory(tmp_path, module, reference, statement):
    (tmp_path / "pages.py").write_text(module)
    _view(tmp_path, "raw = req.args['display']\n" + statement, setup=reference + "\n" + SETUP)
    assert not _findings(tmp_path)


def test_imported_percent_format_honors_explicit_star_exports(tmp_path):
    (tmp_path / "pages.py").write_text(
        "App = 3\n_PAGE = '<p>%(display)s</p>'\n__all__ = ['_PAGE']\n"
    )
    _view(
        tmp_path,
        "return _PAGE % {'display': req.args.get('label')}",
        setup="from pages import *\n" + SETUP,
    )
    assert len(_findings(tmp_path)) == 1


def test_link_requires_unique_module_and_unchanged_scan_snapshot(tmp_path):
    from aegify.scanner.flask_responses import linked_response_facts

    provider = tmp_path / "pages.py"
    provider.write_text("PAGE = '{}'\n")
    _view(
        tmp_path, "return PAGE.format(req.args['label'])", setup="from pages import PAGE\n" + SETUP
    )
    asts = ASTParser().parse_directory(tmp_path)
    template = next(f for f in asts if f.module_path == "pages.py")
    assert len(linked_response_facts(asts)) == 1
    duplicate = template.model_copy(update={"module_path": "src/pages.py"})
    assert not linked_response_facts([*asts, duplicate])
    template.repository_id = "elsewhere"
    assert not linked_response_facts(asts)
    template.repository_id = ""
    provider.write_text("PAGE = 'changed'\n")
    assert not linked_response_facts(asts)
    provider.rename(tmp_path / "original.py")
    provider.symlink_to(tmp_path / "original.py")
    (tmp_path / "original.py").write_text("PAGE = '{}'\n")
    assert not linked_response_facts(asts)


@pytest.mark.parametrize(
    "write",
    [
        "response.headers['Content-Type'] = 'application/json'",
        "response.headers['Content-Disposition'] = 'attachment'",
        "response.headers[key] = 'value'",
        "response.headers['X-Request-Id'] = choose(response)",
        "response.headers['X-Request-Id'] = raw",
        "response.headers['X-Request-Id'] = 'a\\nb'",
        "response.headers.update({})",
        "touch(response)",
    ],
)
def test_response_with_unresolved_mutation(tmp_path, write):
    _view(
        tmp_path,
        f"raw = req.args['label']\nresponse = make_response(raw)\n{write}\nreturn response",
    )
    assert not _findings(tmp_path)


@pytest.mark.parametrize(
    ("setup", "body", "count"),
    [
        ("", "if len(raw) >= 0:\n    return 'fixed'\nreturn raw", 0),
        ("", "limit = 7\ntext = 'fixed' if 2 * limit > 10 else raw\nreturn f'<p>{text}</p>'", 0),
        ("", "limit = 3\ntext = 'fixed' if 2 * limit > 10 else raw\nreturn f'<p>{text}</p>'", 1),
        ("", "if len(raw) < 0:\n    return raw\nreturn 'fixed'", 0),
        ("", "if len(raw) > 0:\n    return 'fixed'\nreturn raw", 1),
        ("len = measure\n", "if len(raw) >= 0:\n    return 'fixed'\nreturn raw", 1),
        ("", "if True:\n    return 'fixed'\nreturn raw", 0),
        ("", "text = 'ready' if raw else 'waiting'\nreturn '<p>{}</p>'.format(text)", 0),
        (
            "",
            "text = '{chosen}'.format(chosen='fixed', unused=raw)\nreturn '<p>{}</p>'.format(text)",
            0,
        ),
        ("", "text = '{0}'.format(raw) if raw else 'waiting'\nreturn '<p>{}</p>'.format(text)", 1),
    ],
)
def test_conditions_and_nested_formats(tmp_path, setup, body, count):
    _view(tmp_path, "raw = req.args['label']\n" + body, setup=SETUP + setup)
    assert len(_findings(tmp_path)) == count


def test_project_module_named_flask(tmp_path):
    (tmp_path / "flask.py").write_text("class Flask: pass\n")
    (tmp_path / "pages.py").write_text("PAGE = '{}'\n")
    _view(
        tmp_path, "return PAGE.format(req.args['label'])", setup="from pages import PAGE\n" + SETUP
    )
    assert not _findings(tmp_path)
