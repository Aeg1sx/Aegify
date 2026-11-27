"""Parse inert fixtures only: literal text is not a variable read."""

from pathlib import Path

import pytest

from tests.test_taint_value_identity import _flows


@pytest.mark.parametrize(
    "expression",
    [
        "'{value}.txt'",
        "'$value.txt'",
        "r'{value}.txt'",
        "'fixed-{value}'.format(value='public')",
        "f'{{value}}.txt'",
        "'public.txt'  # {value}",
    ],
)
def test_literal_template_text_does_not_taint_a_fixed_path(tmp_path: Path, expression: str):
    (tmp_path / "route.py").write_text(
        "from flask import request\n"
        "def route():\n"
        "    value = request.args.get('unused')\n"
        f"    path = {expression}\n"
        "    return open(path)\n"
    )
    assert _flows(tmp_path) == []


@pytest.mark.parametrize(
    "statement",
    [
        "path: str = value",
        "path = value\n    path += '.txt'",
        "path = f'{value}.txt'",
        "path = '{}.txt'.format(value)",
        "path = f'{value!s:>10}'",
    ],
)
def test_real_reads_and_augmented_assignments_preserve_flow(tmp_path: Path, statement: str):
    (tmp_path / "route.py").write_text(
        "from flask import request\n"
        "def route():\n"
        "    value = request.args.get('document')\n"
        f"    {statement}\n"
        "    return open(path)\n"
    )
    flows = _flows(tmp_path)
    assert len(flows) == 1
    assert flows[0].source.line == 3


def test_annotation_without_assignment_does_not_clear_existing_flow(tmp_path: Path):
    (tmp_path / "route.py").write_text(
        "from flask import request\n"
        "def route():\n"
        "    path = request.args.get('document')\n"
        "    path: str\n"
        "    return open(path)\n"
    )
    assert len(_flows(tmp_path)) == 1


@pytest.mark.parametrize("condition", ["not path", "path is None"])
def test_optional_default_retains_the_branch_that_skips_it(tmp_path: Path, condition: str):
    (tmp_path / "route.py").write_text(
        "from flask import request\ndef route():\n    path = request.args.get('document')\n"
        f"    if {condition}:\n        path = 'public.txt'\n    return open(path)\n"
    )
    assert len(_flows(tmp_path)) == 1


@pytest.mark.parametrize(
    ("previous", "predicate", "expected_flows"),
    [
        ("n = 5", "n * 3 > 12", 0),
        ("n = 4", "n * 3 > 12", 1),
        ("n = request.args.get('n')", "n == 5", 1),
        ("n = 5\n    if refresh():\n        n = 3", "n * 3 > 12", 1),
        ("n = 5", "n ** 1000000 > 12", 1),
    ],
)
def test_only_proven_local_integer_branches_select_a_value(
    tmp_path: Path, previous: str, predicate: str, expected_flows: int
):
    (tmp_path / "route.py").write_text(
        "from flask import request\ndef route():\n    data = request.args.get('document')\n"
        f"    {previous}\n    path = 'public.txt' if {predicate} else data\n    return open(path)\n"
    )
    assert len(_flows(tmp_path)) == expected_flows


@pytest.mark.parametrize(
    "condition,expected",
    [("'hi' in mode", 1), ("'missing' in mode", 0), ("'hi' not in mode", 0)],
)
def test_literal_condition_selects_only_its_executable_assignment(tmp_path, condition, expected):
    (tmp_path / "route.py").write_text(
        "from flask import request\ndef route():\n    value = request.args.get('document')\n"
        "    mode = 'archive'\n"
        f"    if {condition}:\n        path = value\n    else:\n        path = 'public'\n"
        "    return open(path)\n"
    )
    assert len(_flows(tmp_path)) == expected


def test_constant_false_without_an_alternative_cannot_restore_dead_calls(tmp_path):
    (tmp_path / "route.py").write_text(
        "from flask import request\ndef route():\n    if False:\n        open(request.args['x'])\n"
    )
    assert not _flows(tmp_path)


@pytest.mark.parametrize("index,expected", [(0, 1), (1, 0), (2, 1), (3, 0)])
def test_literal_match_respects_order_and_wildcard(tmp_path, index, expected):
    (tmp_path / "route.py").write_text(
        "from flask import request\ndef route():\n    value = request.args['document']\n"
        f"    modes = 'abcd'\n    mode = modes[{index}]\n    match mode:\n"
        "        case 'a' | 'c':\n            path = value\n"
        "        case 'b':\n            path = 'second'\n"
        "        case _:\n            path = 'other'\n    return open(path)\n"
    )
    assert len(_flows(tmp_path)) == expected


@pytest.mark.parametrize(
    "iteration,name,origin",
    [
        ("field in incoming.form.keys()", "field", "http_param"),
        ("field in incoming.cookies", "field", "http_cookie"),
        ("field in incoming.headers.values()", "field", "http_header"),
        ("key, value in incoming.headers.items()", "value", "http_header"),
        ("key, value in incoming.headers", "key", "http_header"),
    ],
)
def test_request_collection_entries_retain_their_origin(tmp_path, iteration, name, origin):
    (tmp_path / "route.py").write_text(
        "from flask import request as incoming\n"
        "def route():\n    item = 'fixed'\n"
        f"    for {iteration}:\n        item = {name}\n        break\n    return open(item)\n"
    )
    (flow,) = _flows(tmp_path)
    assert flow.source.source_type == origin and flow.source.line == 4


def test_an_unrelated_request_like_object_does_not_supply_loop_input(tmp_path):
    (tmp_path / "route.py").write_text(
        "from flask import request as incoming\ndef route(incoming):\n"
        "    for field in incoming.form.keys():\n        return open(field)\n"
    )
    assert not _flows(tmp_path)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ("text=value, ignored='local'", True),
        ("ignored=value, text='local'", False),
        ("value", False),
        ("'local', text=value", True),
    ],
)
def test_typed_text_iteration_preserves_the_supplied_argument(tmp_path, arguments, expected):
    (tmp_path / "labels.py").write_text(
        "def label(ignored: str, *, text: str = 'fixed'):\n"
        "    out = ''\n    for char in text:\n        out += char\n    return out\n"
    )
    (tmp_path / "form.py").write_text(
        "from flask import request\nfrom labels import label\ndef submit():\n"
        "    value = request.args['name']\n"
        f"    chosen = label({arguments})\n    return open(chosen)\n"
    )
    flows = _flows(tmp_path)
    assert len(flows) == int(expected)
    if expected:
        assert [
            (Path(step.file_path).name, step.line)
            for step in flows[0].path
            if step.propagation_type == "iteration"
        ] == [("labels.py", 3)]


def test_a_loop_can_execute_zero_times_or_replace_its_element(tmp_path):
    path = tmp_path / "view.py"
    prefix = (
        "from flask import request\ndef register():\n"
        "    char = request.args['key']\n    chars = ''\n"
        "    for char in chars:\n        pass\n"
    )
    path.write_text(prefix + "    return open(char)\n")
    assert len(_flows(tmp_path)) == 1
    path.write_text(prefix + "    char = 'local'\n    return open(char)\n")
    assert not _flows(tmp_path)


def test_python_call_arguments_follow_the_declared_signature(tmp_path):
    from inspect import signature

    from aegify.models import Language
    from aegify.scanner.ast_parser import ASTParser
    from aegify.scanner.taint_v2 import StructuredTaintAnalyzer

    def select(first, /, second: str, *tags: str, text: str = "", **attributes):
        pass

    path = tmp_path / "form.py"
    path.write_text(
        "def select(first, /, second: str, *tags: str, text: str = '', **attributes): pass\n"
        "def other():\n"
        "    select(a, b, c, text=d, color=e)\n"
        "    select(a, text=d, second=b, color=e)\n"
        "    select(a, *items, text=d, **extra)\n"
        "class Labels:\n"
        "    @classmethod\n    def name(cls, value: str): pass\n"
        "    @staticmethod\n    def fixed(value: str): pass\n"
        "    def instance(self, value: str): pass\n"
        "def methods(obj):\n    Labels.name(a)\n    Labels.fixed(a)\n"
        "    obj.instance(b)\n    Labels.instance(obj, b)\n"
    )
    parsed = ASTParser().parse_file(path)
    assert parsed
    functions = {fn.qualified_name: fn for fn in parsed.functions}
    target = functions["select"]
    assert target.parameters == list(signature(select).parameters)
    assert target.python_parameter_kinds == [
        "positional_only",
        "regular",
        "varargs",
        "keyword_only",
        "kwargs",
    ]
    calls = sorted(parsed.calls, key=lambda call: call.line)
    bind = StructuredTaintAnalyzer._parameter_bindings
    for call, positional, named in [
        (calls[0], ["a", "b", "c"], {"text": "d", "color": "e"}),
        (calls[1], ["a"], {"text": "d", "second": "b", "color": "e"}),
    ]:
        bound = signature(select).bind(*positional, **named).arguments
        supplied = [*positional, *named.values()]
        for index, parameter in bind(call, target, Language.PYTHON):
            value = bound[parameter]
            values = (
                list(value.values())
                if isinstance(value, dict)
                else value
                if isinstance(value, tuple)
                else [value]
            )
            assert supplied[index] in values
        assert len(bind(call, target, Language.PYTHON)) == len(supplied)
    expanded = set(bind(calls[2], target, Language.PYTHON))
    assert expanded == {
        (0, "first"),
        (1, "second"),
        (1, "tags"),
        (2, "text"),
        (3, "attributes"),
        (3, "second"),
    }
    assert "name" not in functions and "fixed" not in functions
    for call in calls[3:]:
        target = functions["Labels." + call.callee]
        expected = [(0, "self"), (1, "value")] if len(call.arguments) == 2 else [(0, "value")]
        assert bind(call, target, Language.PYTHON) == expected


@pytest.mark.parametrize(
    ("sequence", "slot", "expected"),
    [
        (
            "items = []\nitems.append('first')\nitems.append(value)\n"
            "items.append('last')\nitems.pop(0)",
            "0",
            True,
        ),
        (
            "items = []\nitems.append('first')\nitems.append(value)\n"
            "items.append('last')\nitems.pop(0)",
            "-1",
            False,
        ),
        ("items = [value, 'fixed']\nitems[0] = 'replaced'", "0", False),
        ("items = ['fixed']\nitems.insert(-20, value)\nvalue = 'replaced'", "0", True),
        ("items = (value, 'fixed')", "-1", False),
        ("items = ['fixed', value]\nitems.pop()", "0", False),
    ],
)
def test_selected_sequence_slot_preserves_the_value_at_write(tmp_path, sequence, slot, expected):
    lines = [
        "value = request.args['name']",
        *sequence.splitlines(),
        f"path = items[{slot}]",
        "return open(path)",
    ]
    (tmp_path / "route.py").write_text(
        "from flask import request\ndef view():\n    " + "\n    ".join(lines) + "\n"
    )
    flows = _flows(tmp_path)
    assert len(flows) == int(expected)
    if expected:
        assert "keyed-store" in {step.propagation_type for step in flows[0].path}


@pytest.mark.parametrize(
    "sequence",
    [
        "items = ['fixed']\nother = items\nother[0] = value",
        "items = other = ['fixed']\nother[0] = value",
        "items = ['fixed']\nchange(items)",
        "items = ['fixed']\nif flag:\n    items[0] = value",
        "items = [value]\nitems.pop(which)",
        "items = [value]\nitems.extend(external)",
        "items = [*external]",
        "items = [value]\nwhile flag:\n    items.append(value)",
    ],
)
def test_ambiguous_mutations_have_no_exact_slot_fact(tmp_path, sequence):
    from aegify.scanner.ast_parser import ASTParser

    path = tmp_path / "app.py"
    lines = [*sequence.splitlines(), "result = items[0]", "return result"]
    path.write_text("def view(value, external, flag, which):\n    " + "\n    ".join(lines) + "\n")
    assert ASTParser().parse_file(path).python_stored_reads == []
