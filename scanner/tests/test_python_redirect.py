"""Source-only checks for the destination and validation of an HTTP redirect."""

from textwrap import dedent, indent

import pytest

from aegify.config import AegifyConfig
from aegify.models import CallSite, FileAST, Language
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_redirect import redirect_operand
from aegify.scanner.python_scope import PythonModules
from tests.test_taint_value_identity import _flows


def sample(body):
    return (
        "from flask import request, redirect as move\n"
        "from urllib.parse import urlsplit as split\n"
        "from django.utils.http import url_has_allowed_host_and_scheme as allowed\n"
        "def finish(service):\n"
        "    target = request.cookies.get('return_to', '/')\n"
        + indent(dedent(body).strip(), "    ")
        + "\n"
    )


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("move(target)", ("flask.redirect", 0)),
        ("move(code=302, location=target)", ("flask.redirect", 1)),
        (
            "from django.shortcuts import redirect as go\ngo(to=target)",
            ("django.shortcuts.redirect", 0),
        ),
        (
            "from werkzeug.utils import redirect as go\ngo(location=target)",
            ("werkzeug.utils.redirect", 0),
        ),
        (
            "from django.http import HttpResponsePermanentRedirect as Permanent\n"
            "Permanent(redirect_to=target)",
            ("django.http.HttpResponsePermanentRedirect", 0),
        ),
        (
            "from starlette.responses import RedirectResponse\n"
            "RedirectResponse(status_code=303, url=target)",
            ("starlette.responses.RedirectResponse", 1),
        ),
        (
            "from fastapi.responses import RedirectResponse as Go\nGo(target)",
            ("fastapi.responses.RedirectResponse", 0),
        ),
        ("move('/dashboard', code=target)", None),
        ("service.redirect(target)", None),
        ("move = service\nmove(target)", None),
    ],
)
def test_only_the_destination_of_the_imported_api_is_a_sink(tmp_path, call, expected):
    (tmp_path / "views.py").write_text(sample(call))
    found = [
        (flow.sink.function, flow.sink.argument_index) for flow in _flows(tmp_path, "redirect")
    ]
    assert found == ([expected] if expected else [])


@pytest.mark.parametrize(
    ("body", "flagged"),
    [
        (
            """parts = split(target)
if parts.scheme in ('https', 'http') and parts.netloc == 'account.example.org':
    return move(target)""",
            False,
        ),
        (
            """try:
    parts = split(target)
    if parts.netloc not in {'account.example.org:8443'} or parts.scheme != 'https':
        return None
except ValueError:
    return None
return move(target)""",
            False,
        ),
        (
            "if allowed(allowed_hosts=('account.example.org',), url=target, require_https=True):\n"
            "    return move(target)",
            False,
        ),
        ("if not allowed(target, None):\n    return None\nreturn move(target)", False),
        (
            "parts = split(target)\n"
            "if parts.netloc == 'account.example.org':\n"
            "    return move(target)",
            True,
        ),
        (
            "parts = split(target)\n"
            "if parts.hostname == 'account.example.org' and parts.scheme == 'https':\n"
            "    return move(target)",
            True,
        ),
        (
            "parts = split(target)\n"
            "if parts.netloc in 'account.example.org' and parts.scheme == 'https':\n"
            "    return move(target)",
            True,
        ),
        (
            "parts = split(target)\n"
            "if parts.netloc == 'account.example.org' or parts.scheme == 'https':\n"
            "    return move(target)",
            True,
        ),
        (
            "parts = split(target)\n"
            "if parts.netloc == 'account.example.org' and parts.scheme == 'service':\n"
            "    return move(target)",
            True,
        ),
        ("if allowed(target, service.hosts):\n    return move(target)", True),
        ("if allowed('/home', None):\n    return move(target)", True),
        ("if allowed(target, None):\n    return None\nreturn move(target)", True),
        (
            "if not allowed(target, None):\n"
            "    return None\n"
            "target = request.cookies.get('alternate')\n"
            "return move(target)",
            True,
        ),
        (
            "try:\n"
            "    if not allowed(target, None):\n"
            "        return None\n"
            "except ValueError:\n"
            "    pass\n"
            "return move(target)",
            True,
        ),
        ("allowed = service.check\nif allowed(target, None):\n    return move(target)", True),
        (
            "values = ['account.example.org']\n"
            "service.configure(values)\n"
            "if allowed(target, values):\n"
            "    return move(target)",
            True,
        ),
    ],
)
def test_guards_check_the_unchanged_destination_on_the_redirect_branch(tmp_path, body, flagged):
    (tmp_path / "views.py").write_text(sample(body))
    assert bool(_flows(tmp_path, "redirect")) is flagged


def test_scoped_dependencies_and_older_cached_ast(tmp_path):
    (tmp_path / "views.py").write_text(sample("if allowed(target, None):\n    return move(target)"))
    (file,) = ASTParser().parse_directory(tmp_path)
    call = next(call for call in file.calls if call.python_redirect)
    file.repository_id = "accounts"
    local = FileAST(
        file_path="src/django/__init__.py",
        module_path="src/django/__init__.py",
        repository_id="accounts",
        language=Language.PYTHON,
    )
    assert redirect_operand(call, file, PythonModules([file, local])) == ("flask.redirect", 0)
    local.repository_id = "billing"
    assert redirect_operand(call, file, PythonModules([file, local])) is None
    old = CallSite(callee="redirect", file_path="legacy.py", line=4, column=0)
    assert redirect_operand(old, file, PythonModules([file])) is None
    file.python_redirect_resolved = False
    assert redirect_operand(old, file, PythonModules([file])) == ("redirect", 0)


def test_engine_emits_one_redirect_finding_at_the_correct_line(tmp_path):
    view = tmp_path / "views.py"
    view.write_text(sample("move('/dashboard', code=target)\nreturn move(location=target)"))
    config = AegifyConfig()
    config.llm.enabled = False
    config.storage.backend = "memory"
    result = ScanEngine(config=config).scan_files(tmp_path, [view])
    assert result.status == "completed"
    assert [(f.rule_id, f.line_start) for f in result.findings if f.cwe_id == 601] == [
        ("AEG-A04-006", 7)
    ]
