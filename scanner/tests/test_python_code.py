"""A code-content constraint must belong to the resolved Python call and its exact input."""

from textwrap import indent

import pytest

from aegify.config import AegifyConfig
from aegify.models import CallSite, FileAST, Language
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_code import code_inputs, code_operand
from aegify.scanner.python_requests import custom_request_data
from aegify.scanner.python_scope import PythonModules

HEADER = (
    "from flask import request\n"
    "from builtins import eval as interpret, type as kind\n"
    "import builtins as b\n"
)
READ = 'text = request.args.get("expression", "")'
FULL = """text.startswith("'") and text.endswith("'") and "'" not in text[1:-1]"""


def function(body, params="opaque"):
    return HEADER + f"def inspect_input({params}):\n" + indent(body, "    ") + "\n"


def constraint(body, params="opaque"):
    (fact,) = code_inputs(function(body, params).encode()).values()
    return fact.literal_constraint


@pytest.mark.parametrize("quote", ["'", '"'])
@pytest.mark.parametrize("api", ["eval", "exec", "interpret", "b.exec"])
def test_all_three_edges_bind_the_literal_used_as_the_program(quote, api):
    q = repr(quote)
    precheck = (
        f"if not text.startswith({q}) or not text.endswith({q}) or {q} in text[1:-1]:\n    return"
    )
    assert constraint(f"{READ}\n{precheck}\n{api}(text)") == "quoted_text"
    assert (
        constraint(
            f"{READ}\nif text[0] == {q} and {q} == text[-1] and {q} not in text[1:-1]:"
            f"\n    {api}(text)"
        )
        == "quoted_text"
    )


@pytest.mark.parametrize(
    "condition",
    [
        """text.startswith("'") and text.endswith("'")""",
        """text.startswith("'") or text.endswith("'") or "'" not in text[1:-1]""",
        """text.startswith('"') and text.endswith("'") and "'" not in text[1:-1]""",
        """text.startswith("'") and text.endswith("'") and '"' not in text[1:-1]""",
        """text.startswith("'") and text.endswith("'") and "'" not in text[2:-1]""",
        """text.startswith("'") and text.endswith("'") and "'" not in text[1:-1:2]""",
        """text.startswith("'", 1) and text.endswith("'") and "'" not in text[1:-1]""",
        """text[0] != "'" and text[-1] == "'" and "'" not in text[1:-1]""",
    ],
)
def test_ambiguous_or_partial_guard_keeps_dynamic_input(condition):
    assert constraint(f"{READ}\nif {condition}:\n    eval(text)") == ""


@pytest.mark.parametrize(
    "body",
    [
        f"if {FULL}:\n    pass\neval(text)",
        f"if {FULL}:\n    text = opaque\n    eval(text)",
        f"if {FULL}:\n    eval(text + opaque)",
        f"if {FULL}:\n    eval(opaque)",
        f"if not ({FULL}):\n    print('invalid')\neval(text)",
        f"try:\n    if not ({FULL}):\n        raise ValueError()"
        "\nexcept ValueError:\n    pass\neval(text)",
        f"for item in opaque:\n    if {FULL}:\n        eval(text)",
        f"if {FULL}:\n    def change():\n        nonlocal text\n        text = opaque"
        "\n    change()\n    eval(text)",
    ],
)
def test_control_flow_and_value_identity(body):
    assert constraint(READ + "\n" + body) == ""


@pytest.mark.parametrize(
    "expression",
    [
        "opaque",
        "str(opaque)",
        "b.str(opaque)",
        'f"{opaque}"',
        "opaque.as_text()",
        'request.args.get("expression", type=opaque)',
        'request.args.get("expression", opaque)',
        'request.data.decode("application-codec")',
    ],
)
def test_concrete_type_is_required_for_string_methods_and_representation(expression):
    assert constraint(f"text = {expression}\nif {FULL}:\n    eval(text)") == ""
    assert constraint(f"text = {expression}\neval(repr(text))") == ""


def test_runtime_type_guard_can_bind_an_otherwise_unknown_value():
    for check in ["kind(text) is str", "b.str is b.type(text)"]:
        assert (
            constraint(f"if {check} and {FULL}:\n    eval(text)", params="text: str")
            == "quoted_text"
        )
    assert (
        constraint("if type(text) is not str:\n    return\neval(b.repr(text))", params="text")
        == "repr_text"
    )
    assert constraint(f"if isinstance(text, str) and {FULL}:\n    eval(text)", params="text") == ""
    assert constraint(f"if kind(text) is str and {FULL}:\n    eval(text)", params="text, str") == ""
    assert (
        constraint(f"if type(text) is str and {FULL}:\n    eval(text)", params="text, type") == ""
    )


def test_representation_proof_applies_when_the_representation_was_created():
    assert constraint(READ + "\nprepared = repr(text)\ninterpret(prepared)") == "repr_text"
    assert (
        constraint("prepared = repr(text)\nif type(text) is str:\n    eval(prepared)", "text") == ""
    )
    assert constraint(READ + "\ninterpret(repr(text) + text)") == ""
    assert constraint(READ + "\ninterpret(repr(text))", "repr") == ""
    assert constraint(READ + "\nb.repr = opaque\neval(repr(text))") == ""
    assert constraint("b.str = opaque\ntext = str(opaque)\neval(repr(text))") == ""


def test_identical_lines_keep_each_calls_own_source_operand():
    src = function(READ + f"\nif {FULL}:\n    b.exec(text); interpret(opaque)")
    facts = sorted(code_inputs(src.encode()).items())
    assert [(fact.api, fact.literal_constraint) for _, fact in facts] == [
        ("builtins.exec", "quoted_text"),
        ("builtins.eval", ""),
    ]
    assert facts[0][0][0] == facts[1][0][0]
    assert constraint(READ + "\nreturn eval(*(text,))") == ""


@pytest.mark.parametrize(
    "setup",
    [
        "app.request_class = CustomRequest",
        "class App(Flask):\n    request_class = CustomRequest",
        'setattr(app, "request_class", CustomRequest)',
        "class Form(Request):\n    parameter_storage_class = CustomDict",
    ],
)
def test_configured_request_hooks_are_repository_scoped(tmp_path, setup):
    (tmp_path / "views.py").write_text(function(READ + f"\nif {FULL}:\n    eval(text)"))
    (tmp_path / "app.py").write_text(setup)
    files = ASTParser().parse_directory(tmp_path)
    view = next(f for f in files if f.module_path == "views.py")
    app = next(f for f in files if f.module_path == "app.py")
    call = next(c for c in view.calls if c.python_code_input)
    assert app.python_custom_request_data
    assert code_operand(call, view, PythonModules(files)) == ("eval", 0)
    app.repository_id = "another-application"
    assert code_operand(call, view, PythonModules(files)) is None


def test_modified_local_request_or_shadow_dependency_keeps_warning(tmp_path):
    assert constraint("request.args.get = opaque\n" + READ + f"\nif {FULL}:\n    eval(text)") == ""
    assert not custom_request_data(b"# request_class appears only in a comment\n")
    (tmp_path / "views.py").write_text(function(READ + f"\nif {FULL}:\n    eval(text)"))
    (view,) = ASTParser().parse_directory(tmp_path)
    call = next(c for c in view.calls if c.python_code_input)
    shadow = FileAST(file_path="flask.py", module_path="flask.py", language=Language.PYTHON)
    assert code_operand(call, view, PythonModules([view, shadow])) == ("eval", 0)
    (tmp_path / "views.py").write_text(
        function(f"if type(text) is str and {FULL}:\n    eval(text)", "text")
    )
    (checked,) = ASTParser().parse_directory(tmp_path)
    exact = next(c for c in checked.calls if c.python_code_input)
    assert code_operand(exact, checked, PythonModules([checked, shadow])) is None


def test_generic_methods_and_old_serialized_calls_keep_existing_coverage():
    file = FileAST(file_path="cached.py", module_path="cached.py", language=Language.PYTHON)
    for receiver, expected in [(None, "eval"), ("service", "service.eval")]:
        call = CallSite(
            callee="eval", receiver=receiver, file_path=file.file_path, line=1, column=0
        )
        assert code_operand(call, file, PythonModules([file])) == (expected, 0)
    assert not code_inputs(
        function("service.eval(text)\neval(text)", "text, eval, service").encode()
    )


def test_local_alias_must_have_a_reaching_builtin_assignment():
    assert constraint(READ + "\nrun = b.exec\nrun(text)") == ""
    assert constraint(READ + f"\nrun = interpret\nif {FULL}:\n    run(text)") == "quoted_text"
    for other in ["run = opaque", "if opaque:\n    run = opaque"]:
        assert not code_inputs(function(READ + "\nrun = b.eval\n" + other + "\nrun(text)").encode())


def test_normal_scan_reports_raw_alias_and_retains_the_file_operand(tmp_path):
    (tmp_path / "views.py").write_text(
        function(READ + f"\ninterpret(text)\nif {FULL}:\n    eval(text)\n    open(text)")
    )
    config = AegifyConfig()
    config.llm.enabled = False
    config.storage.backend = "memory"
    file = tmp_path / "views.py"
    result = ScanEngine(config=config).scan_files(tmp_path, [file])
    assert result.status == "completed"
    actual = {(f.rule_id, f.line_start) for f in result.findings}
    assert {pair for pair in actual if pair[0] in {"AEG-EXEC-001", "AEG-A03-007"}} == {
        ("AEG-EXEC-001", 6),
        ("AEG-A03-007", 6),
    }
    assert ("AEG-PATH-001", 9) in actual
