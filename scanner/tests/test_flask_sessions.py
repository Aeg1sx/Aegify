"""Owned source inputs. Only the scanner reads the fixture text."""

from pathlib import Path

import networkx as nx
import pytest

from aegify.models import FindingDisposition
from aegify.rules.flask_session import FlaskSessionRule
from tests.test_taint_value_identity import _flows


@pytest.mark.parametrize(
    ("imports", "target", "field"),
    [
        ("import flask", "flask.session['userid'] = data", "identity"),
        ("from flask import session", "session[data] = 'on'", "key"),
        ("import flask as web", "web.session['role'] = data", "identity"),
        ("from flask import session as state", "state['_user_id'] = data", "identity"),
    ],
)
def test_request_flow_into_session_identity(tmp_path: Path, imports: str, target: str, field: str):
    (tmp_path / "app.py").write_text(
        f"{imports}\nfrom flask import request\ndef save():\n"
        f"    data = request.args.get('example')\n    {target}\n"
    )
    flows = _flows(tmp_path, "session_" + field)
    findings = FlaskSessionRule().evaluate([], nx.MultiDiGraph(), flows)
    assert len(findings) == 1
    assert findings[0].cwe_id == 501 and findings[0].line_start == 5
    assert findings[0].disposition == FindingDisposition.ADVISORY
    assert flows[0].source.line == 4


@pytest.mark.parametrize(
    "source",
    [
        "from flask import session\ndef save(session):\n"
        "    session['role'] = request.args.get('role')",
        "from flask import session\ndef save():\n    session = {}\n"
        "    session['role'] = request.args.get('role')",
        "from flask import session\ndef save():\n    session['theme'] = request.args.get('theme')",
        "from flask import session\ndef save():\n    session['role'] = 'viewer'",
        "from flask import session\ndef save():\n    key = request.args.get('role')\n"
        "    key = 'theme'\n"
        "    session[key] = 'blue'",
        "def sibling():\n    import flask as web\ndef save():\n"
        "    web.session['role'] = request.args.get('role')",
        "from other import session\ndef save():\n    session['role'] = request.args.get('role')",
    ],
)
def test_unrelated_state_and_shadowed_names(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text("from flask import request\n" + source + "\n")
    assert _flows(tmp_path, "session_key") == []
    assert _flows(tmp_path, "session_identity") == []
