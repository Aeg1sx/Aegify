"""Only static source is inspected. No fixture filesystem operation is executed."""

from pathlib import Path
from textwrap import indent

import networkx as nx
import pytest

from aegify.models import EvidenceState, FindingDisposition
from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser
from tests.test_taint_value_identity import _flows


def _fixture(tmp_path, imports, body):
    path = tmp_path / "routes.py"
    path.write_text(
        "from flask import request\n"
        + imports
        + "\ndef view():\n"
        + "    value = request.args.get('document')\n"
        + indent(body, "    ")
        + "\n"
    )
    return path


@pytest.mark.parametrize(
    ("imports", "body", "api", "index"),
    [
        (
            "from codecs import open as reader",
            "return reader(encoding='utf8', filename=value)",
            "codecs.open",
            1,
        ),
        ("import os as fs", "return fs.open(flags=0, path=value)", "os.open", 1),
        (
            "from pathlib import Path as P",
            "base = P('reports')\np = base / value\nreturn p.read_text()",
            "pathlib.Path.read_text",
            -1,
        ),
        (
            "from pathlib import Path",
            "return Path('reports').joinpath(value).open()",
            "pathlib.Path.open",
            -1,
        ),
        (
            "from pathlib import Path",
            "return Path('known').rename(target=value)",
            "pathlib.Path.rename",
            0,
        ),
        ("from shutil import copy2 as copy", "copy(dst=value, src='fixed')", "shutil.copy2", 0),
        ("import shutil", "shutil.copy('fixed', value)", "shutil.copy", 1),
        ("from flask import send_file", "return send_file(value)", "flask.send_file", 0),
    ],
)
def test_actual_path_operand(tmp_path, imports, body, api, index):
    _fixture(tmp_path, imports, body)
    flows = _flows(tmp_path)
    assert [(f.sink.function, f.sink.argument_index) for f in flows] == [(api, index)]
    assert flows[0].source.source_type == "http_param"


@pytest.mark.parametrize(
    ("imports", "body"),
    [
        ("from pathlib import Path", "path = Path(value)\nreturn str(path)"),
        ("import os", "name = os.path.join('reports', value)\nreturn open('fixed.txt')"),
        ("from pathlib import Path", "return Path('known').write_text(value)"),
        ("import codecs", "return codecs.open('known', encoding=value)"),
        ("import io", "return io.open(mode=value, file='known')"),
        ("import shutil", "return shutil.copy2('first', 'second', follow_symlinks=value)"),
        ("from pathlib import Path", "p = Path(value)\np = other()\nreturn p.open()"),
        ("", "open = widget.open\nreturn open(value)"),
        ("import os as fs", "fs = widget\nreturn fs.open(value)"),
        ("from pathlib import Path", "return widget.read_text(value)"),
        (
            "from flask import send_file\nfrom io import BytesIO",
            "stream = BytesIO(value)\nreturn send_file(stream, download_name='known')",
        ),
        ("from pathlib import Path", "return open(**value)"),
        (
            "from flask import send_file",
            "return send_file(open('known.pdf', 'rb'), download_name=value)",
        ),
        (
            "from flask import send_file",
            "with open('known.pdf', 'rb') as stream:\n"
            "    return send_file(stream, download_name=value)",
        ),
        (
            "from flask import send_file\nfrom pathlib import Path",
            "stream = Path('known.pdf').open('rb')\nreturn send_file(stream, download_name=value)",
        ),
    ],
)
def test_path_selection_controls(tmp_path, imports, body):
    path = _fixture(tmp_path, imports, body)
    flows = _flows(tmp_path)
    assert flows == []
    rule = _path_rule()
    assert rule.evaluate([ASTParser().parse_file(path)], nx.MultiDiGraph(), flows) == []


def _path_rule():
    pack = Path(__file__).resolve().parents[2] / "rules/a01-broken-access-control/python_access.yml"
    return next(rule for rule in load_yaml_rules(pack) if rule.definition.id == "AEG-AC-PY-006")


@pytest.mark.parametrize(
    ("imports", "body", "api"),
    [
        ("import os", "return os.path.exists(value)", "os.path.exists"),
        (
            "from pathlib import Path",
            "return Path('reports', value).is_file()",
            "pathlib.Path.is_file",
        ),
    ],
)
def test_metadata_path_is_advisory_with_real_evidence(tmp_path, imports, body, api):
    path = _fixture(tmp_path, imports, body)
    assert not _flows(tmp_path)
    flows = _flows(tmp_path, "file_metadata")
    assert len(flows) == 1 and flows[0].sink.function == api
    [finding] = _path_rule().evaluate([ASTParser().parse_file(path)], nx.MultiDiGraph(), flows)
    assert finding.disposition == FindingDisposition.ADVISORY
    assert finding.evidence_state == EvidenceState.REACHABLE
    assert finding.line_start == flows[0].sink.line


@pytest.mark.parametrize(
    ("imports", "assignment"),
    [
        ("from html import escape as encode", "path = encode(value)"),
        ("import shlex", "path = shlex.quote(value)"),
        ("import html", "path = value + html.escape('fixed')"),
        ("", "path = validate_label(value)"),
    ],
)
def test_encoding_does_not_constrain_the_file_location(tmp_path, imports, assignment):
    _fixture(tmp_path, imports, assignment + "\nreturn open(path)")
    [flow] = _flows(tmp_path)
    assert not flow.sanitized


@pytest.mark.parametrize(
    ("imports", "body", "expected"),
    [
        ("from html import escape as encode", "name = encode(value)", True),
        ("import html", "name = value + html.escape('fixed')", False),
        ("import html", "html = widget\nname = html.escape(value)", False),
    ],
)
def test_only_the_encoded_html_value_carries_the_sanitizer(tmp_path, imports, body, expected):
    _fixture(tmp_path, imports, body + "\nreturn Markup(name)")
    [flow] = _flows(tmp_path, "xss")
    assert flow.sanitized is expected


@pytest.mark.parametrize(
    ("body", "count"),
    [
        ("if os.path.exists(value):\n    return 'present'\nreturn 'absent'", 1),
        ("if not (os.path.exists(\n    value\n)):\n    return 'absent'", 1),
        ("while os.path.isfile(value):\n    break", 1),
        ("if os.path.exists('known'):\n    return value", 0),
        ("if False and os.path.exists(value):\n    return 'absent'", 0),
        ("if False:\n    if os.path.isfile(value):\n        return 'never'\nreturn 'done'", 0),
    ],
)
def test_filesystem_predicates_select_only_evaluated_operands(tmp_path, body, count):
    _fixture(tmp_path, "import os", body)
    assert len(_flows(tmp_path, "file_metadata")) == count


def test_local_named_validator_uses_its_actual_return(tmp_path):
    _fixture(
        tmp_path,
        "def validate_path(name):\n    return name",
        "path = validate_path(value)\nreturn open(path)",
    )
    [flow] = _flows(tmp_path)
    assert not flow.sanitized
