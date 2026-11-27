from textwrap import dedent

import pytest

from aegify.scanner.engine import ScanEngine


@pytest.mark.parametrize(
    ("imports", "setup", "compile_template", "reported"),
    [
        (
            "from django.template import engines",
            "engine = engines['django']",
            "engine.from_string('Hello ' + text)",
            True,
        ),
        (
            "from django.template import Engine",
            "engine = Engine()",
            "engine.from_string(template_code=text)",
            True,
        ),
        ("from django.template import Template as T", "", "T(template_string=text)", True),
        (
            "from jinja2 import Environment as Env",
            "env = Env()",
            "env.from_string(globals={}, source=text)",
            True,
        ),
        (
            "from flask import render_template_string as render",
            "",
            "render(source=text, value='fixed')",
            True,
        ),
        (
            "from flask import render_template_string as render",
            "",
            "render(source='Hello {{ value }}', value=text)",
            False,
        ),
        (
            "from jinja2 import Template",
            "",
            "Template('Hello {{ value }}').render(value=text)",
            False,
        ),
        (
            "from django.template import Template",
            "Template = custom_compiler",
            "Template(text)",
            False,
        ),
        (
            "from django.template import engines",
            "engine = other['django']",
            "engine.from_string(text)",
            False,
        ),
        (
            "from jinja2 import Environment",
            "env = Environment(); env.from_string = custom",
            "env.from_string(text)",
            False,
        ),
        (
            "from jinja2 import Environment",
            "env = Environment()",
            "env.from_string('Hello {{ value }}', globals={'value': text})",
            False,
        ),
    ],
)
def test_template_program_vs_context(tmp_path, imports, setup, compile_template, reported):
    path = tmp_path / "views.py"
    path.write_text(
        dedent(f"""\
        {imports}
        def preview(request):
            text = request.GET.get('title')
            {setup}
            return {compile_template}
        """)
    )
    findings = ScanEngine().scan_files(tmp_path, [path]).findings
    hits = [f for f in findings if f.cwe_id == 1336]
    assert [(f.rule_id, f.line_start, f.taint_flow.source.line) for f in hits] == (
        [("AEG-TMPL-001", 5, 3)] if reported else []
    )


def test_template_input_across_files_and_local_module_shadow(tmp_path):
    handler = tmp_path / "views.py"
    handler.write_text(
        "from renderer import compile_title\n"
        "def view(request):\n    return compile_title(request.GET.get('title'))\n"
    )
    renderer = tmp_path / "renderer.py"
    renderer.write_text(
        "from django.template import Template\n"
        "def compile_title(title):\n    return Template(title)\n"
    )
    engine = ScanEngine()
    hits = [
        f
        for f in engine.scan_files(tmp_path, [handler, renderer]).findings
        if f.rule_id == "AEG-TMPL-001"
    ]
    assert len(hits) == 1
    assert hits[0].taint_flow.source.file_path.endswith("views.py")
    assert hits[0].taint_flow.sink.file_path.endswith("renderer.py")
    shadow = tmp_path / "django.py"
    shadow.write_text("template = None\n")
    assert not any(
        f.rule_id == "AEG-TMPL-001"
        for f in engine.scan_files(tmp_path, [handler, renderer, shadow]).findings
    )
