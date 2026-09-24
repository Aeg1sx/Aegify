"""Owned SQL construction fixtures: source parsing, never database execution."""

from time import perf_counter

import networkx as nx
import pytest

from aegify.config import AegifyConfig
from aegify.models import EvidenceState, FileAST, FindingDisposition
from aegify.rules.sql_injection import SQLStringConcatRule
from aegify.scanner import sql_queries
from aegify.scanner.ast_parser import ASTParser, parser_fingerprint
from aegify.scanner.engine import ScanEngine


def parse(tmp_path, filename, source):
    path = tmp_path / filename
    path.write_text(source)
    ast = ASTParser().parse_file(path)
    assert ast is not None and ast.parse_error_count == 0
    return ast


CASES = [
    (
        "match.py",
        'q="SELECT 1"\nmatch flag:\n case 1:\n  q="SELECT "+value\n'
        ' case _:\n  q="SELECT 2"\ndb.execute(q)',
        1,
    ),
    (
        "match_constants.py",
        'q="SELECT 1"\nmatch flag:\n case 1:\n  q="SELECT 2"\n'
        ' case _:\n  q="SELECT 3"\ndb.execute(q)',
        0,
    ),
    (
        "switch.js",
        'let q="SELECT 1"; switch(flag){case 1:q=`SELECT ${value}`;break;'
        'default:q="SELECT 2";} db.query(q);',
        1,
    ),
    (
        "switch_constants.js",
        'let q="SELECT 1"; switch(flag){case 1:q="SELECT 2";break;'
        'default:q="SELECT 3";} db.query(q);',
        0,
    ),
    ("ternary.py", 'db.execute("SELECT "+value if flag else "SELECT 1")', 1),
    ("ternary_condition.py", 'db.execute("SELECT 1" if "SELECT "+value else "SELECT 2")', 0),
    ("ternary_guard.py", 'db.execute("SELECT "+value if False else "SELECT 2")', 0),
    ("ternary.js", 'db.query(flag ? `SELECT ${value}` : "SELECT 1");', 1),
    ("ternary_condition.js", 'db.query(`SELECT ${value}` ? "SELECT 1" : "SELECT 2");', 0),
    ("ternary_guard.js", 'db.query(true ? "SELECT 1" : `SELECT ${value}`);', 0),
    ("args_spread.py", 'db.execute(*["SELECT "+value, (other,)])', 1),
    ("args_spread_bound.py", 'db.execute(*["SELECT ?", ("SELECT "+value,)])', 0),
    ("args_spread_unknown.py", 'db.execute("SELECT ?", *values)', 0),
    ("kwargs.py", 'db.execute(**{"sql":"SELECT "+value})', 1),
    ("kwargs_bound.py", 'db.execute(**{"sql":"SELECT ?","parameters":("SELECT "+value,)})', 0),
    ("args_spread.js", "db.query(...[`SELECT ${value}`, [other]]);", 1),
    ("args_spread_bound.js", 'db.query(...["SELECT $1", ["SELECT "+value]]);', 0),
    ("args_spread_unknown.js", 'db.query("SELECT $1", ...values);', 0),
    (
        "loop_shadow.js",
        'const q="SELECT 1"; for(const q of values){db.query("SELECT "+q);} db.query(q);',
        1,
    ),
    ("guarded.py", 'q="SELECT "+value\nif True:\n q="SELECT ?"\ndb.execute(q,(value,))', 0),
    (
        "elif.py",
        'q="SELECT 1"\nif flag:\n q="SELECT "+value\nelif other:\n q="SELECT 2"\n'
        'else:\n q="SELECT 3"\ndb.execute(q)',
        1,
    ),
    (
        "try.py",
        'q="SELECT 1"\ntry:\n q="SELECT "+value\nexcept Error:\n q="SELECT 2"\ndb.execute(q)',
        1,
    ),
    (
        "finally.py",
        'q="SELECT 1"\ntry:\n q="SELECT "+value\nfinally:\n q="SELECT 2"\ndb.execute(q)',
        0,
    ),
    ("loop_target.py", 'value="fixed"\nfor value in values:\n db.execute("SELECT "+value)', 1),
    (
        "try.js",
        'let q="SELECT 1"; try {q=`SELECT ${value}`;} catch(error){q="SELECT 2";} db.query(q);',
        1,
    ),
    (
        "finally.js",
        'let q="SELECT 1"; try {q=`SELECT ${value}`;} finally {q="SELECT 2";} db.query(q);',
        0,
    ),
    ("literal.py", "db.execute(\"SELECT name FROM t WHERE name LIKE 'fixed_%'\")", 0),
    ("operators.py", "db.execute(\"SELECT 'a+b f-quote .format( 100%'\")", 0),
    ("bound.py", 'db.execute("SELECT * FROM t WHERE value=%s", (value,))', 0),
    ("bound_arithmetic.py", 'db.execute("SELECT * FROM t WHERE value=?", (now + 1,))', 0),
    ("bound_sql_text.py", 'db.execute("INSERT INTO t VALUES (?)", ("SELECT " + value,))', 0),
    ("concat.py", 'db.execute("SELECT * FROM t WHERE value=" + value)', 1),
    ("literal_concat.py", 'db.execute("SE" + "LECT 1")', 0),
    ("split_prefix.py", 'db.execute("SE" + "LECT " + value)', 1),
    ("percent.py", 'db.execute("SELECT %s" % value)', 1),
    ("percent_tuple.py", 'db.execute("SELECT %s" % (value,))', 1),
    ("percent_constant.py", 'db.execute("SELECT %s" % ("fixed",))', 0),
    ("percent_escaped.py", "db.execute(\"SELECT '%%'\" % ())", 0),
    ("percent_extra.py", 'db.execute("SELECT 1" % value)', 0),
    ("format.py", 'db.execute("SELECT {}".format(value))', 1),
    ("format_keyword.py", 'db.execute("SELECT {name}".format(name=value))', 1),
    ("format_map.py", 'db.execute("SELECT {name}".format_map({"name":value}))', 1),
    ("format_constant.py", 'db.execute("SELECT {}".format("fixed"))', 0),
    ("format_unused.py", 'db.execute("SELECT 1".format(value))', 0),
    ("format_escaped.py", "db.execute(\"SELECT '{{name}}'\".format(value))", 0),
    ("fstring.py", 'db.execute(f"SELECT {value}")', 1),
    ("fstring_constant.py", 'db.execute(f"SELECT {1}")', 0),
    ("fstring_literal.py", "db.execute(f\"SELECT '{{value}}'\")", 0),
    ("multiline.py", 'db.execute(f"""SELECT name\nFROM t WHERE id={value}""")', 1),
    ("escaped_python.py", r'db.execute("\u0053ELECT " + value)', 1),
    ("keyword.py", 'db.execute(sql="SELECT " + value, parameters=(other,))', 1),
    ("keyword_bound.py", 'db.execute(sql="SELECT ?", parameters=("SELECT " + value,))', 0),
    (
        "local.py",
        'def run(value):\n prefix="SELECT "\n query=prefix+value\n copy=query\n db.execute(copy)',
        1,
    ),
    (
        "reassigned_safe.py",
        'query="SELECT "+value\nquery="SELECT ?"\ndb.execute(query,(value,))',
        0,
    ),
    ("reassigned_dynamic.py", 'query="SELECT ?"\nquery="SELECT "+value\ndb.execute(query)', 1),
    ("conditional.py", 'query="SELECT 1"\nif flag:\n query="SELECT "+value\ndb.execute(query)', 1),
    (
        "conditional_constant.py",
        'query="SELECT 1"\nif flag:\n query="SELECT 2"\ndb.execute(query)',
        0,
    ),
    (
        "branch_local.py",
        'if flag:\n query="SELECT "+value\n db.execute(query)\n'
        'else:\n query="SELECT 1"\n db.execute(query)',
        1,
    ),
    ("augmented.py", 'query="SELECT "\nquery += value\ndb.execute(query)', 1),
    ("loop.py", 'query="SELECT "\nfor value in values:\n query += value\ndb.execute(query)', 1),
    (
        "loop_carried.py",
        'query="SELECT "\nfor value in values:\n db.execute(query)\n query += value',
        1,
    ),
    ("scope.py", 'def first(value):\n query="SELECT "+value\ndef second():\n db.execute(query)', 0),
    ("wrapper.py", 'db.execute(text("SELECT " + value))', 1),
    ("numeric.py", "db.execute(10 + value)", 0),
    ("non_sql.py", 'db.execute("selected item " + value)', 0),
    ("literal.js", "db.query(\"SELECT 'prefix_%'\");", 0),
    ("bound.js", 'db.query("SELECT $1", [Date.now() + 1]);', 0),
    ("bound_sql_text.js", 'db.query("INSERT INTO t VALUES ($1)", ["SELECT " + value]);', 0),
    ("concat.js", 'db.query("SELECT " + value);', 1),
    ("constant.js", 'db.query("SE" + "LECT 1");', 0),
    ("template.js", "db.query(`SELECT ${value}`);", 1),
    ("template_constant.js", "db.query(`SELECT ${42}`);", 0),
    ("template_escaped.js", r"db.query(`SELECT \${value}`);", 0),
    ("escaped_js.js", r'db.query("\u{53}ELECT " + value);', 1),
    ("query_selector.js", 'document.querySelector("SELECT " + value);', 0),
    ("execute_suffix.js", 'service.executeHandler("SELECT " + value);', 0),
    ("prepared.js", 'db.prepare("SELECT ?").run("SELECT " + value);', 0),
    ("prepared_dynamic.js", 'db.prepare("SELECT " + value).run();', 1),
    ("tag.js", "db.query(sql`SELECT ${value}`);", 0),
    ("option.js", 'db.execute({sql:"SELECT " + value,args:[other]});', 1),
    ("option_bound.js", 'db.execute({sql:"SELECT ?",args:[Date.now()+1]});', 0),
    ("pg_option.js", "db.query({text:`SELECT ${value}`,values:[other]});", 1),
    ("pg_bound.js", 'db.query({text:"SELECT $1",values:["SELECT " + value]});', 0),
    (
        "nested_option.js",
        'db.execute({metadata:{sql:"SELECT " + value},sql:"SELECT ?",args:[other]});',
        0,
    ),
    ("duplicate_safe.js", 'db.execute({sql:"SELECT "+value,sql:"SELECT ?",args:[value]});', 0),
    ("duplicate_dynamic.js", 'db.execute({sql:"SELECT ?",sql:"SELECT "+value});', 1),
    ("spread_safe.js", 'db.execute({...{sql:"SELECT "+value},sql:"SELECT ?"});', 0),
    ("spread_dynamic.js", 'db.execute({...{sql:"SELECT "+value}});', 1),
    ("computed.js", 'db.execute({["sql"]:"SELECT " + value});', 1),
    ("shorthand.js", 'const sql="SELECT "+value; db.execute({sql,args:[other]});', 1),
    ("local_option.js", 'const query={sql:"SELECT "+value}; db.execute(query);', 1),
    (
        "property.js",
        'const query={sql:"SELECT ?"}; query.sql="SELECT "+value; db.execute(query);',
        1,
    ),
    (
        "alias_property.js",
        'const query={sql:"SELECT ?"}; const alias=query; '
        'alias.sql="SELECT "+value; db.execute(query);',
        1,
    ),
    (
        "alias_safe.js",
        'const query={sql:"SELECT "+value}; const alias=query; '
        'alias.sql="SELECT ?"; db.execute(query);',
        0,
    ),
    ("comment.js", 'db.query(/* selected SQL */ "SELECT " + value, /* bound */ [other]);', 1),
    ("branch.js", 'let q="SELECT 1"; if (flag) { q=`SELECT ${value}`; } db.query(q);', 1),
    ("shadow.js", 'const q="SELECT 1"; if(flag) { const q=`SELECT ${value}`; } db.query(q);', 0),
    (
        "shadow_inner.js",
        'const q="SELECT 1"; if(flag) { const q=`SELECT ${value}`; db.query(q); }',
        1,
    ),
    ("as.ts", "db.query((`SELECT ${value}` as string));", 1),
    ("satisfies.ts", "db.execute(({sql:`SELECT ${value}`} satisfies Query));", 1),
    ("nonnull.ts", "db.query((`SELECT ${value}`)!);", 1),
    ("view.tsx", "const view=<p/>; db.query(`SELECT ${value}`);", 1),
    ("unsafe_method.ts", "db.$queryRawUnsafe(`SELECT ${value}`);", 1),
]


@pytest.mark.parametrize(("filename", "source", "expected"), CASES, ids=[case[0] for case in CASES])
def test_query_expression_candidates_and_close_negatives(tmp_path, filename, source, expected):
    ast = parse(tmp_path, filename, source)
    restored = FileAST.model_validate_json(ast.model_dump_json())
    for tree in [ast, restored]:
        findings = SQLStringConcatRule().evaluate([tree], nx.DiGraph(), [])
        assert len(findings) == expected, [item.message for item in findings]
        assert all(
            item.evidence_state == EvidenceState.CANDIDATE
            and item.disposition == FindingDisposition.ADVISORY
            for item in findings
        )
        assert tree.query_expression_limit_count == 0


def test_selected_query_and_origin_evidence_survives_serialization(tmp_path):
    tree = parse(
        tmp_path,
        "trace.ts",
        'function run(value:string){\n const prefix="SELECT ";\n const sql=prefix+value;\n'
        " db.execute({sql,args:[99]});\n}",
    )
    call = next(call for call in tree.calls if call.callee == "execute")
    facts = call.query_expression
    assert facts is not None and facts.version == 1
    assert facts.state == "constructed" and facts.has_sql
    assert facts.selection == "positional:0.sql"
    assert facts.origin_lines == [2, 3]
    assert facts.constructions == ["concatenation"]
    restored = FileAST.model_validate_json(tree.model_dump_json())
    assert (
        next(call for call in restored.calls if call.callee == "execute").query_expression == facts
    )
    legacy = tree.model_dump()
    for item in legacy["calls"]:
        item.pop("query_expression", None)
    assert all(call.query_expression is None for call in FileAST.model_validate(legacy).calls)
    assert len(parser_fingerprint()) == 64


def test_unknown_object_effects_are_visible_and_do_not_invent_constant_proof(tmp_path):
    for source in [
        'db.execute({sql:"SELECT ?",...options});',
        'const q={sql:"SELECT ?"}; mutate(q); db.execute(q);',
        'db.execute({sql:"SELECT ?",[key]:value});',
        "db.execute(...options);",
    ]:
        tree = parse(tmp_path, "unknown.js", source)
        facts = next(call for call in tree.calls if call.callee == "execute").query_expression
        assert facts is not None and facts.state == "unknown" and facts.uncertainties, source
        assert SQLStringConcatRule().evaluate([tree], nx.DiGraph(), []) == []


def test_query_expression_budget_surfaces_as_incomplete_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(sql_queries, "MAX_TEXT", 48)
    source = 'db.execute("SELECT ' + "x" * 64 + '" + value)'
    path = tmp_path / "budget.py"
    path.write_text(source)
    config = AegifyConfig.model_construct()
    config.llm.enabled = False
    engine = ScanEngine(config=config)
    result = engine.scan_files(tmp_path, [path])
    assert result.status == "partial"
    assert any(gap.code == "sql_expression_limit" for gap in result.analysis_gaps)


def test_loop_replay_retains_a_later_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(sql_queries, "MAX_TEXT", 48)
    tree = parse(
        tmp_path,
        "loop_budget.py",
        'q="SELECT "+value\nfor item in items:\n db.execute(q)\n q=q+"' + "x" * 64 + '"',
    )
    facts = next(call for call in tree.calls if call.callee == "execute").query_expression
    assert facts is not None and facts.state == "unknown"
    assert "expression_limit" in facts.uncertainties
    assert tree.query_expression_limit_count == 1


def test_object_merges_and_incremental_fields_have_bounded_work(tmp_path, monkeypatch):
    monkeypatch.setattr(sql_queries, "MAX_MERGE_STEPS", 8)
    nested = (
        'let a={sql:"SELECT ?"}, b={sql:"SELECT ?"}, q;'
        + "a.self=a;b.self=b;" * 30
        + "if(flag){q=a;}else{q=b;} db.execute(q);"
    )
    many_fields = (
        'const q={sql:"SELECT ?"};'
        + "".join(f"q.field{index}=1;" for index in range(sql_queries.MAX_FIELDS + 2))
        + "db.execute(q);"
    )
    started = perf_counter()
    for name, source in [("merge.js", nested), ("fields.js", many_fields)]:
        tree = parse(tmp_path, name, source)
        facts = next(call for call in tree.calls if call.callee == "execute").query_expression
        assert facts is not None and facts.state == "unknown", name
        assert "expression_limit" in facts.uncertainties
        assert tree.query_expression_limit_count == 1
    assert perf_counter() - started < 10


def test_many_fixed_queries_are_bounded_and_do_not_create_findings(tmp_path):
    source = "\n".join(
        f"db.query(\"SELECT {index} WHERE 'x' LIKE 'x%'\", [now+1]);" for index in range(600)
    )
    started = perf_counter()
    tree = parse(tmp_path, "many.ts", source)
    assert tree.query_expression_limit_count == 0
    assert len(tree.calls) == 600
    assert SQLStringConcatRule().evaluate([tree], nx.DiGraph(), []) == []
    assert perf_counter() - started < 10
