"""JDBC query text, typed receivers and scoped string origins in static source."""

import networkx as nx
import pytest

from aegify.rules.sql_injection import SQLStringConcatRule
from aegify.scanner import java_sql
from aegify.scanner.ast_parser import ASTParser


def review(tmp_path, body, params="Connection c, Statement s, String input", extra=""):
    source = f"""import java.sql.Connection;
import java.sql.Statement;
import javax.sql.DataSource;
import jakarta.servlet.http.HttpServletRequest;
class Queries {{
    {extra}
    void run({params}) throws Exception {{
        {body}
    }}
}}
"""
    path = tmp_path / "Queries.java"
    path.write_text(source)
    ast = ASTParser().parse_file(path)
    assert ast is not None and ast.parse_error_count == 0
    findings = SQLStringConcatRule().evaluate([ast], nx.DiGraph(), [])
    return ast, findings


@pytest.mark.parametrize(
    "body",
    [
        'c.prepareStatement("SELECT ?" + input, 1);',
        'c.prepareCall("{call " + input + "}");',
        's.execute("UPDATE " + input, 1);',
        's.executeQuery("SELECT " + input);',
        's.executeUpdate("DELETE FROM " + input);',
        's.executeLargeUpdate("UPDATE " + input);',
        's.addBatch("INSERT INTO " + input);',
        'String sql = "SELECT " + input; String alias = (sql); s.execute(alias);',
        'try (Statement local = c.createStatement()) { local.executeQuery("SELECT " + input); }',
        'c.createStatement().executeQuery("SELECT " + input);',
    ],
)
def test_selects_first_sql_argument(tmp_path, body):
    ast, findings = review(tmp_path, body)
    assert len(findings) == 1
    facts = next(call.query_expression for call in ast.calls if call.query_expression)
    assert facts.state == "constructed"
    assert facts.selection == "first_positional"
    assert facts.origin_lines == [7]


def test_servlet_read_survives_null_default_and_partial_binding(tmp_path):
    ast, findings = review(
        tmp_path,
        """String name = req.getParameter("name");
        if (null == name) { name = ""; }
        String sql = "SELECT id FROM users WHERE status=? AND name='" + name + "'";
        var ps = c.prepareStatement(sql);
        ps.setString(1, "active");
        ps.execute();""",
        "java.sql.Connection c, HttpServletRequest req",
    )
    assert [finding.line_start for finding in findings] == [11]
    assert [
        (call.callee, call.query_expression.origin_lines)
        for call in ast.calls
        if call.query_expression
    ] == [("prepareStatement", [8])]


def test_datasource_factory_types_with_inferred_locals(tmp_path):
    _, findings = review(
        tmp_path,
        "var db = pool.getConnection(); var stmt = db.createStatement(); "
        'stmt.execute("SELECT " + input);',
        "DataSource pool, String input",
    )
    assert len(findings) == 1


@pytest.mark.parametrize(
    ("body", "params", "extra"),
    [
        (
            'var p = c.prepareStatement("SELECT id FROM t WHERE value=?"); '
            "p.setString(1,input); p.execute();",
            "Connection c, String input",
            "",
        ),
        (
            'c.prepareStatement("SELECT 1", new String[]{"SELECT " + input});',
            "Connection c, String input",
            "",
        ),
        (
            's.execute("SELECT " + ("x".equals(input) ? "x" : "y"));',
            "Statement s, String input",
            "",
        ),
        (
            'String q = "SELECT "+input; q = "SELECT 1"; s.execute(q);',
            "Statement s, String input",
            "",
        ),
        (
            'String q = "x"; if (input != null) q = "fixed"; s.execute("SELECT " + q);',
            "Statement s, String input",
            "",
        ),
        (
            's.execute("SELECT " + sanitize(input));',
            "Statement s, String input",
            "String sanitize(String s) { return s; }",
        ),
        (
            's.execute("SELECT " + req.getParameter("name"));',
            "Statement s, FakeRequest req",
            "interface FakeRequest { String getParameter(String s); }",
        ),
        (
            's.execute("SELECT " + input);',
            "Local s, String input",
            "interface Local { void execute(String q); }",
        ),
        (
            's.execute("SELECT " + input);',
            "Statement s, String input",
            "interface Statement { void execute(String q); }",
        ),
        ('s.execute("SELECT " + input);', "Statement s, String input", "class String {}"),
        (
            '{ String q="SELECT "+input; } s.execute(q);',
            "Statement s, String input",
            'String q = "SELECT 1";',
        ),
        ('s.execute("SELECT " + input.length());', "Statement s, String input", ""),
        (
            'Runnable f = () -> s.execute("SELECT " + input);',
            "Local s, String input",
            "interface Local { void execute(String q); }",
        ),
        (
            'var s = factory.createStatement(); s.execute("SELECT " + input);',
            "Factory factory, String input",
            "interface Factory { Statement createStatement(); }",
        ),
    ],
)
def test_bound_unknown_and_fixed_values(tmp_path, body, params, extra):
    _, findings = review(tmp_path, body, params, extra)
    assert findings == []


def test_reports_exhaustion_without_positive_fact(tmp_path, monkeypatch):
    monkeypatch.setattr(java_sql, "_MAX_EXPRESSION", 2)
    ast, findings = review(tmp_path, 's.execute("SELECT " + input);')
    assert not findings
    assert ast.query_expression_limit_count == 1


def test_long_identifiers_do_not_alias_on_text_limit(tmp_path):
    field = "f" * 257
    parameter = "p" * 257
    _, findings = review(
        tmp_path,
        f's.execute("SELECT " + {field});',
        f"Statement s, String {parameter}",
        f'final String {field} = "x";',
    )
    assert findings == []
