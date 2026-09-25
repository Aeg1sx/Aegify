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
