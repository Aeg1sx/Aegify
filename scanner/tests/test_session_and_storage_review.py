"""Exercise the parsed rule contracts using inert application source."""

from pathlib import Path

import networkx as nx
import pytest

from aegify.models import FileAST
from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser

RULES = Path(__file__).resolve().parents[2] / "rules"
SESSION = next(
    r
    for r in load_yaml_rules(RULES / "a07-auth-failures/session_management.yml")
    if r.definition.id == "AEG-SESS-002"
)
RACE = next(
    r
    for r in load_yaml_rules(RULES / "a04-insecure-design/race_conditions.yml")
    if r.definition.id == "AEG-RACE-004"
)


def scan(tmp, filename, source, rule):
    p = tmp / filename
    p.write_text(source)
    ast = ASTParser().parse_file(p, repository_root=tmp)
    assert ast is not None and not ast.parse_error_count
    restored = FileAST.model_validate_json(ast.model_dump_json())
    return rule.evaluate([restored], nx.DiGraph(), [])


@pytest.mark.parametrize(
    "name,source,lines",
    [
        (
            "settings.py",
            "from starlette.middleware.sessions import SessionMiddleware as Session\n"
            "Session(app, secret_key=key)\n"
            "Session(app, secret_key=key, max_age=None)\n",
            [3],
        ),
        (
            "setup.py",
            "from starlette.middleware.sessions import SessionMiddleware as S\n"
            "from starlette.middleware import Middleware\n"
            "Middleware(S, secret_key=key, max_age=None)\n"
            "Middleware(S, secret_key=key, max_age=0)\n",
            [3],
        ),
        (
            "api.py",
            "from fastapi import FastAPI\n"
            "from starlette.middleware.sessions import SessionMiddleware as S\n"
            "app=FastAPI()\n"
            "app.add_middleware(S, secret_key=key, max_age=None)\n",
            [4],
        ),
        (
            "scope.py",
            "from starlette.middleware.sessions import SessionMiddleware as S\n"
            "def start(S):\n"
            "    S(app, secret_key=key, max_age=None)\n",
            [],
        ),
        ("config.py", "class SessionManager: pass\nstore = SessionManager()\n", []),
        (
            "helper.py",
            "from starlette.middleware.sessions import SessionMiddleware as S\n"
            "unknown.add_middleware(S, secret_key=key, max_age=None)\n",
            [],
        ),
        (
            "opts.py",
            "from starlette.middleware.sessions import SessionMiddleware as S\n"
            "S(app, secret_key=key, max_age=None, **opts)\n",
            [],
        ),
        (
            "app.js",
            "const middleware = require('express-session');\n"
            "app.use(middleware({secret, cookie: {httpOnly:true}}));",
            [2],
        ),
        (
            "app.ts",
            "import configure from 'express-session';\n"
            "app.use(configure({secret, cookie: {maxAge: null}}));",
            [2],
        ),
        (
            "custom.js",
            "const session=require('express-session');\napp.use(session({secret, store: custom}));",
            [],
        ),
        (
            "bounded.js",
            "import session from 'express-session';\nsession({secret, cookie: {maxAge: 60000}});",
            [],
        ),
        (
            "cookie.js",
            "import session from 'express-session';\n"
            "session({secret, cookie: {expires: new Date()}});",
            [],
        ),
        (
            "spread.js",
            "import session from 'express-session';\nsession({secret, cookie: {...options}});",
            [],
        ),
        (
            "unresolved.js",
            "import session from 'express-session';\nsession({secret, ...unknown});",
            [],
        ),
        (
            "shadow.js",
            "import session from 'express-session';\nfunction run(session){ session({secret}); }",
            [],
        ),
        (
            "require.js",
            "function require(x){ return custom; }\n"
            "const s=require('express-session');\n"
            "s({secret});",
            [],
        ),
        (
            "types.ts",
            "import type session from 'express-session';\n"
            "function start(session: any){ session({secret}); }",
            [],
        ),
        ("misc.js", "async function close(){ return auth.registered_sessions(store); }", []),
    ],
)
def test_session_configuration(tmp_path, name, source, lines):
    findings = scan(tmp_path, name, source, SESSION)
    assert [f.line_start for f in findings] == lines
    assert all(f.disposition == "advisory" and not f.code_snippet for f in findings)


@pytest.mark.parametrize(
    "namespace,receiver,interval,expected",
    [
        ("jakarta", "session", "0", True),
        ("javax", "req.getSession(false)", "-1", True),
        ("jakarta", "req.getSession()", "-2147483648", True),
        ("jakarta", "session", "300", False),
        ("javax", "session", "limit", False),
        ("custom", "session", "0", False),
    ],
)
def test_typed_servlet_expiry(tmp_path, namespace, receiver, interval, expected):
    code = (
        f"import {namespace}.servlet.http.HttpSession;\n"
        f"import {namespace}.servlet.http.HttpServletRequest;\n"
        f"class Web {{ void config(HttpSession session, HttpServletRequest req, int limit) {{\n"
        f" {receiver}.setMaxInactiveInterval({interval});\n}} }}"
    )
    assert [f.line_start for f in scan(tmp_path, "Web.java", code, SESSION)] == (
        [4] if expected else []
    )


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "row = order_repo.findById(key)\n"
            "if row.active:\n"
            "    row.state = 'approved'\n"
            "    order_repo.save(row)",
            [(4, "blocking")],
        ),
        ("if not order_repo.findOne(key):\n    order_repo.create(key)", [(2, "advisory")]),
        (
            "row = cur.execute('SELECT state FROM orders WHERE id=?', (key,)).fetchone()\n"
            "if not row:\n"
            "    return\n"
            "cur.execute('UPDATE orders SET state=? WHERE id=?', vals)",
            [(4, "advisory")],
        ),
        (
            "row = cur.execute('SELECT state FROM orders FOR UPDATE').fetchone()\n"
            "if row:\n"
            "    cur.execute('DELETE FROM orders')",
            [],
        ),
        (
            "row = cur.execute('SELECT state FROM orders').fetchone()\n"
            "if row:\n"
            "    cur.execute('DELETE FROM audit')",
            [],
        ),
        (
            "row = cur.execute('SELECT state FROM orders').fetchone()\n"
            "if row:\n"
            "    other.execute('DELETE FROM orders')",
            [],
        ),
        ("row = order_repo.findById(key)\nif other:\n    order_repo.save(row)", []),
        ("row = order_repo.findById(key)\nif row:\n    other_repo.save(row)", []),
        ("row = order_repo.findById(key)\nif row:\n    pass\norder_repo.save(row)", []),
        (
            "with transaction.atomic():\n"
            "    row = order_repo.findById(key)\n"
            "    if row:\n"
            "        order_repo.save(row)",
            [],
        ),
        (
            "with open(path):\n"
            "    row = order_repo.findById(key)\n"
            "    if row:\n"
            "        order_repo.save(row)",
            [(4, "blocking")],
        ),
        ("row = self._find_nodes(root)\nif row:\n    types.update(bindings)", []),
        ("row = 'order_repo.findById(key)'\nif row:\n    logger.info('order_repo.save(row)')", []),
    ],
)
def test_database_condition(tmp_path, source, expected):
    findings = scan(
        tmp_path,
        "workflow.py",
        "def run(key):\n" + "\n".join("    " + line for line in source.splitlines()),
        RACE,
    )
    assert [(f.line_start - 1, f.disposition.value) for f in findings] == expected


@pytest.mark.parametrize(
    "name,source,expected",
    [
        (
            "write.ts",
            "async function run(key: string){\n"
            "const item=await prisma.order.findUnique({where:{id:key}});\n"
            "if(item){\n"
            " await prisma.order.update({where:{id:key},data:{state:'ok'}});\n"
            "}}",
            [4],
        ),
        (
            "other.ts",
            "async function run(key: string){\n"
            "const item=await prisma.order.findUnique({where:{id:key}});\n"
            "if(item){await prisma.customer.update({data:{state:'ok'}});}}",
            [],
        ),
        (
            "write.js",
            "async function run(key){\n"
            "const row=await db.query('SELECT id FROM orders');\n"
            "if(row){await db.query('UPDATE orders SET state=1');}}",
            [3],
        ),
        (
            "guard.js",
            "async function run(key){\n"
            "const row=await prisma.order.findFirst({});\n"
            "if(!row) return;\n"
            "await prisma.order.delete({where:{id:key}});}",
            [4],
        ),
        (
            "guard.java",
            "class App { void run(Store order_repo, String id){\n"
            "Row row=order_repo.findById(id);\n"
            "if(row!=null){order_repo.save(row);}}}",
            [3],
        ),
        (
            "guard.go",
            "package x\n"
            "func run(db DB){\n"
            'row := db.QueryRow("SELECT state FROM orders")\n'
            "if row != nil {\n"
            ' db.Exec("UPDATE orders SET state=1")\n'
            "}\n"
            "}",
            [5],
        ),
    ],
)
def test_database_owners_across_languages(tmp_path, name, source, expected):
    assert [f.line_start for f in scan(tmp_path, name, source, RACE)] == expected


def test_session_configuration_exports_location_without_nearby_secret(tmp_path):
    import json

    from aegify.config import AegifyConfig
    from aegify.reporter.sarif import SARIFReporter
    from aegify.scanner.engine import ScanEngine

    path = tmp_path / "app.js"
    path.write_text(
        "const middleware = require('express-session');\n"
        "app.use(middleware({\n  secret: 'fixture-only-marker',\n}));\n"
    )
    result = ScanEngine(config=AegifyConfig.model_construct()).scan(path)
    findings = [
        r
        for r in SARIFReporter().generate(result)["runs"][0]["results"]
        if r["ruleId"] == SESSION.definition.id
    ]
    assert len(findings) == 1
    location = findings[0]["locations"][0]["physicalLocation"]
    assert location["region"]["startLine"] == 2
    assert "contextRegion" not in location and "snippet" not in location["region"]
    assert "fixture-only-marker" not in json.dumps(findings)


def test_project_local_starlette_module_is_not_the_external_signer(tmp_path):
    parser = ASTParser()
    local = tmp_path / "starlette" / "__init__.py"
    local.parent.mkdir()
    local.write_text("")
    path = tmp_path / "app.py"
    path.write_text(
        "from starlette.middleware.sessions import SessionMiddleware as S\n"
        "S(app, secret_key=key, max_age=None)\n"
    )
    files = [parser.parse_file(p, repository_root=tmp_path) for p in (local, path)]
    assert files[1].session_expiry
    assert not SESSION.evaluate(files, nx.DiGraph(), [])


@pytest.mark.parametrize(
    "statement",
    [
        "cur.execute('UPDATE orders SET state=1 WHERE id=20')",
        "cur.execute('UPDATE orders SET state=1 WHERE id=10 AND version=?', (version,))",
        "cur.execute('INSERT INTO orders(id) VALUES (10) ON CONFLICT DO NOTHING')",
        "cur.execute('UPDATE orders SET state=' + value + ' WHERE id=10')",
    ],
)
def test_sql_review_withholds_known_different_rows_atomic_or_dynamic_writes(tmp_path, statement):
    source = (
        "def run(cur):\n"
        "    row = cur.execute('SELECT state FROM orders WHERE id=10').fetchone()\n"
        f"    if row:\n        {statement}\n"
    )
    assert not scan(tmp_path, "operations.py", source, RACE)


@pytest.mark.parametrize("module_name", ["conditional_storage", "session_expiry"])
def test_cached_asts_track_both_detectors(tmp_path, monkeypatch, module_name):
    from aegify.scanner import ast_parser

    ast_parser.parser_fingerprint.cache_clear()
    original = ast_parser.parser_fingerprint()
    changed = tmp_path / "source.py"
    changed.write_text("# different source for digest calculation\n")
    with monkeypatch.context() as patch:
        patch.setattr(getattr(ast_parser, module_name), "__file__", str(changed))
        ast_parser.parser_fingerprint.cache_clear()
        assert ast_parser.parser_fingerprint() != original
    ast_parser.parser_fingerprint.cache_clear()
    assert ast_parser.parser_fingerprint() == original
