"""The scanner reads these directory search examples as text."""

from textwrap import dedent, indent

import pytest

from aegify.config import AegifyConfig
from aegify.models import CallSite, FileAST, Language
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_ldap import LDAPConnections, search_facts
from tests.test_taint_value_identity import _flows


def sample(body):
    return (
        "from ldap3 import Connection as Directory\n"
        "from ldap import initialize as connect\n"
        "from ldap3.utils.conv import escape_filter_chars as encode\n"
        "from ldap.filter import filter_format as format_filter\n"
        "from flask import request\n"
        "def lookup(server, options):\n"
        "    value = request.args.get('display')\n" + indent(dedent(body).strip(), "    ") + "\n"
    )


@pytest.mark.parametrize(
    ("call", "wanted"),
    [
        ("Directory(server).search('base', value)", ("ldap3.Connection.search", 1)),
        (
            "Directory(server).search(search_filter=value, search_base='base')",
            ("ldap3.Connection.search", 0),
        ),
        ("connect(server).search('base', 1, value)", ("ldap.ldapobject.LDAPObject.search", 2)),
        (
            "connect(server).search_ext_s(filterstr=value, scope=1, base='base')",
            ("ldap.ldapobject.LDAPObject.search_ext_s", 0),
        ),
        ("Directory(server).search(value, '(cn=service)', attributes=[value])", None),
        ("connect(server).search(value, 1, '(cn=service)')", None),
        ("Directory(server).search_s('base', 1, value)", None),
        ("options.search('base', value)", None),
        ("Directory(server).search(*options, search_filter=value)", None),
        ("Directory = options\nDirectory(server).search('base', value)", None),
        (
            "client = Directory(server)\nother = client\n"
            "other.search = options\nclient.search('base', value)",
            None,
        ),
    ],
)
def test_resolved_client_and_filter_operand(tmp_path, call, wanted):
    (tmp_path / "directory.py").write_text(sample(call))
    assert [
        (f.sink.function, f.sink.argument_index) for f in _flows(tmp_path, "ldap_search_filter")
    ] == ([wanted] if wanted else [])


@pytest.mark.parametrize(
    ("expression", "flagged"),
    [
        ('f"(cn={encode(value)})"', False),
        ('"(uid=" + encode(value) + ")"', False),
        ('"(cn=%s)" % encode(value)', False),
        ('"(cn={})".format(encode(value))', False),
        ('format_filter("(cn=%s)", [value])', False),
        ('f"(cn={value})"', True),
        ('f"({encode(value)}=service)"', True),
        ('f"(cn={encode(value)}{value})"', True),
        ('format_filter(value, ["staff"])', True),
        ('f"(cn={dn_encode(value)})"', True),
    ],
)
def test_filter_encoders_apply_only_in_fixed_value_position(tmp_path, expression, flagged):
    (tmp_path / "search.py").write_text(
        sample(
            "from ldap.dn import escape_dn_chars as dn_encode\n"
            f"selected = {expression}\nclient = Directory(server)\n"
            "alias = client\nalias.search('base', selected)"
        )
    )
    assert bool(_flows(tmp_path, "ldap_search_filter")) is flagged


@pytest.mark.parametrize(
    "definition",
    [
        "async def open_directory(server):\n    return Directory(server)",
        "def open_directory(server):\n    yield Directory(server)\n    return Directory(server)",
        "def open_directory(server):\n    if server: return Directory(server)\n    return server",
        "def open_directory(server):\n    if server: return Directory(server)",
        "def open_directory(server):\n    c = Directory(server)\n    alias = c\n"
        "    alias.search = server\n    return c",
        "def open_directory(server):\n    return Directory(server)\nopen_directory = other",
    ],
)
def test_uncertain_factories_do_not_claim_a_directory_connection(definition):
    factories, _ = search_facts(
        ("from ldap3 import Connection as Directory\n" + definition).encode()
    )
    assert not factories


def test_factory_uses_repository_module_and_consumer_operand(tmp_path):
    root = tmp_path / "team"
    root.mkdir()
    helper = root / "clients.py"
    helper.write_text(
        "from ldap3 import Connection as Client\ndef directory(server):\n"
        "    connection = Client(server)\n    return connection\n"
    )
    view = root / "views.py"
    view.write_text(
        sample(
            "from .clients import directory as open_client\n"
            "client = open_client(server)\n"
            "client.search('base', value)\n"
            "client.search('base', '(cn=staff)', attributes=[value])\n"
            "client.search(search_base='base', search_filter=request.args.get('display'))"
        )
    )
    config = AegifyConfig()
    config.llm.enabled = False
    config.storage.backend = "memory"
    result = ScanEngine(config=config).scan_files(tmp_path, [helper, view])
    assert result.status == "completed"
    findings = [f for f in result.findings if f.cwe_id == 90]
    assert {(f.rule_id, f.line_start) for f in findings} == {
        ("AEG-A03-001", 10),
        ("AEG-A03-001", 12),
    }
    assert all(
        f.taint_flow and f.taint_flow.sink.function == "ldap3.Connection.search" for f in findings
    )

    files = ASTParser().parse_directory(tmp_path)
    for file in files:
        file.module_path = "team/" + ("clients.py" if file.python_ldap_factories else "views.py")
        file.repository_id = "common"
    consumer = next(file for file in files if file.module_path.endswith("views.py"))
    call = next(call for call in consumer.calls if call.python_ldap_search)
    assert LDAPConnections(files).operand(call, consumer) == ("ldap3.Connection.search", 1)
    assert (
        LDAPConnections(
            [
                *files,
                FileAST(
                    file_path="ldap3.py",
                    module_path="ldap3.py",
                    language=Language.PYTHON,
                    repository_id="common",
                ),
            ]
        ).operand(call, consumer)
        is None
    )
    consumer.repository_id = "other"
    assert LDAPConnections(files).operand(call, consumer) is None
    assert (
        LDAPConnections(files).operand(
            CallSite(callee="search", file_path="old.py", line=1, column=0), consumer
        )
        is None
    )
