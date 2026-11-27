"""Parse servlet source controls without executing the application."""

from pathlib import Path

import networkx as nx
import pytest

from aegify.models import EvidenceState, FileAST, FindingDisposition
from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser


def parse(tmp_path, body, namespace="jakarta", extra="", tail=""):
    path = tmp_path / "Tokens.java"
    path.write_text(
        f"import {namespace}.servlet.http.HttpSession;\n"
        f"import {namespace}.servlet.http.Cookie;\n"
        f"import {namespace}.servlet.http.HttpServletRequest;\n"
        "import java.util.Random;\n"
        f"{extra}\nclass Tokens {{\n"
        "void save(HttpSession session, HttpSession second, "
        "HttpServletRequest req, Cookie cookie, String suffix) {\n" + body + "\n}\n" + tail + "\n}"
    )
    ast = ASTParser().parse_file(path)
    assert ast is not None
    return FileAST.model_validate_json(ast.model_dump_json())


@pytest.mark.parametrize("namespace", ["jakarta", "javax"])
def test_evidence_in_both_rule_packs(tmp_path: Path, namespace):
    ast = parse(
        tmp_path,
        """Random rng = new Random();
long sample = rng.nextLong();
String value = Long.toString(sample);
String key = "rememberMe" + suffix;
Cookie[] received = req.getCookies();
Cookie presented = received[0];
if (presented.getValue().equals(req.getSession().getAttribute(key))) return;
req.getSession().setAttribute(key, value);""",
        namespace,
    )
    (fact,) = ast.credential_randomness
    assert (fact.generator, fact.generator_line, fact.comparison_line, fact.use_line) == (
        "java.util.Random.nextLong",
        9,
        14,
        15,
    )
    root = Path(__file__).resolve().parents[2] / "rules"
    for pack, identifier in [
        ("insecure_crypto.yml", "AEG-CRYPTO-002"),
        ("a02-cryptographic-failures/crypto.yml", "AEG-A02-004"),
    ]:
        rule = next(r for r in load_yaml_rules(root / pack) if r.definition.id == identifier)
        (finding,) = rule.evaluate([ast], nx.MultiDiGraph(), [])
        assert finding.line_start == fact.use_line
        assert "java.security.SecureRandom" in finding.message
        assert finding.disposition == FindingDisposition.ADVISORY
        assert finding.evidence_state == EvidenceState.REACHABLE


@pytest.mark.parametrize(
    "expression, generator",
    [
        ("java.lang.Math.random()", "java.lang.Math.random"),
        ("String.valueOf(new java.util.Random().nextInt(20))", "java.util.Random.nextInt"),
        ("Double.toString(Math.random()).substring(2)", "java.lang.Math.random"),
    ],
)
def test_named_session_key(tmp_path, expression, generator):
    (fact,) = parse(
        tmp_path, f'session.setAttribute("csrf_token", {expression});'
    ).credential_randomness
    assert (fact.generator, fact.comparison_line) == (generator, None)


@pytest.mark.parametrize(
    "body, extra, tail",
    [
        ('session.setAttribute("auth_token", new java.security.SecureRandom().nextInt());', "", ""),
        ('session.setAttribute("auth_token", new Random(){ }.nextInt());', "", ""),
        ('session.setAttribute("theme", Math.random());', "", ""),
        ('double x = Math.random(); session.setAttribute("auth_token", suffix);', "", ""),
        ('double x = Math.random(); x = 0; session.setAttribute("auth_token", x);', "", ""),
        ('session.setAttribute("auth_token", Math.random());', "import example.Math;", ""),
        ('session.setAttribute("auth_token", Math.random());', "", "Helper Math;"),
        ('session.setAttribute("auth_token", Math.random());', "", "class Math {}"),
        (
            'session.setAttribute("auth_token", Integer.toString(new Random().nextInt()));',
            "import example.Integer;",
            "",
        ),
        ('session.setAttribute("auth_token", new Random().nextInt());', "", "class Random {}"),
        ('Helper store = new Helper(); store.setAttribute("auth_token", Math.random());', "", ""),
        ('session.setAttribute("auth_token", transform(Math.random()));', "", ""),
        ('Runnable r = () -> session.setAttribute("auth_token", Math.random());', "", ""),
    ],
)
def test_unknown_or_nonsecurity_use(tmp_path, body, extra, tail):
    assert parse(tmp_path, body, extra=extra, tail=tail).credential_randomness == []


@pytest.mark.parametrize(
    "key, check, after",
    [
        (
            '"theme" + suffix',
            "if (cookie.getValue().equals(session.getAttribute(key))) return;",
            "",
        ),
        (
            '"rememberMe" + suffix',
            "if (cookie.getValue().equals(second.getAttribute(key))) return;",
            "",
        ),
        (
            '"rememberMe" + suffix',
            'if (cookie.getValue().equals(session.getAttribute("other"))) return;',
            "",
        ),
        (
            '"rememberMe" + suffix',
            "boolean ignored = cookie.getValue().equals(session.getAttribute(key));",
            "",
        ),
        (
            '"rememberMe" + suffix',
            "if (cookie.getValue().equals(session.getAttribute(key))) return;",
            "session.removeAttribute(key);",
        ),
        ('"rememberMe" + suffix', "if (suffix.equals(session.getAttribute(key))) return;", ""),
    ],
)
def test_dynamic_slot_requires_consistent_evidence(tmp_path, key, check, after):
    assert not parse(
        tmp_path,
        f"String key = {key};\n{check}\nsession.setAttribute(key, Math.random());\n{after}",
    ).credential_randomness
