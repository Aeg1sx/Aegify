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


@pytest.mark.parametrize(
    "encoder",
    [
        "java.util.Base64.getEncoder().encodeToString(bytes)",
        "java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)",
        "java.util.HexFormat.of().formatHex(bytes)",
        "org.owasp.esapi.ESAPI.encoder().encodeForBase64(bytes, false)",
    ],
)
def test_byte_generator_and_encoder_reach_the_servlet_write(tmp_path, encoder):
    ast = parse(
        tmp_path,
        f"""byte[] bytes = new byte[24];
        new Random().nextBytes(bytes);
        String token = {encoder};
        new java.security.SecureRandom().nextBytes(bytes);
        session.setAttribute("auth_token", token);""",
    )
    (fact,) = ast.credential_randomness
    assert fact.generator == "java.util.Random.nextBytes"
    assert fact.generator_line == 9
    assert fact.encoding_line == 10
    assert fact.use_line == 12


@pytest.mark.parametrize(
    "before,fill,after,encoder",
    [
        ("", "secure.nextBytes(bytes);", "", "java.util.Base64.getEncoder().encodeToString(bytes)"),
        ("", "new Random().nextBytes(bytes);", "secure.nextBytes(bytes);", None),
        ("", "new Random().nextBytes(bytes);", "bytes[0] = 3;", None),
        ("", "new Random().nextBytes(bytes);", "consume(bytes);", None),
        (
            "byte[] alias = bytes;",
            "new Random().nextBytes(bytes);",
            "secure.nextBytes(alias);",
            None,
        ),
        (
            "Runnable job = () -> consume(bytes);",
            "new Random().nextBytes(bytes);",
            "job.run();",
            None,
        ),
        ("", "if (suffix.isEmpty()) new Random().nextBytes(bytes);", "", None),
        ("", "new Random().nextBytes(bytes);", "", "codec.encodeToString(bytes)"),
        (
            "",
            "new Random().nextBytes(bytes);",
            "",
            "other.Base64.getEncoder().encodeToString(bytes)",
        ),
        ("", "new Random().nextBytes(bytes);", "", "java.util.HexFormat.of().formatHex(other)"),
    ],
)
def test_mutated_escaped_and_unknown_buffers_are_not_attributed(
    tmp_path, before, fill, after, encoder
):
    expression = encoder or "java.util.Base64.getEncoder().encodeToString(bytes)"
    ast = parse(
        tmp_path,
        f"""byte[] bytes = new byte[24];
        java.security.SecureRandom secure = new java.security.SecureRandom();
        {before}
        {fill}
        {after}
        String token = {expression};
        session.setAttribute("auth_token", token);""",
    )
    assert not ast.credential_randomness


def registry(tmp_path, **changes):
    fields = dict(
        init="new Random()",
        identifier='"id-" + System.nanoTime() + this.generator.nextLong()',
        stored="new WebSession(id)",
        returned="id",
        lookup="id",
        extra="",
        read_type="WebSession",
        key="id",
    )
    fields.update(changes)
    path = tmp_path / "Sessions.java"
    path.write_text(
        """import java.util.Map;
import java.util.HashMap;
import java.util.Random;
class Sessions {{
    private Random generator = {init};
    private Map<String, WebSession> active = new HashMap<>();
    String issue(String idHint) {{
        String id = {identifier};
        active.put({key}, {stored});
        return {returned};
    }}
    {read_type} lookup(String id) {{ return this.active.get({lookup}); }}
    {extra}
}}
class WebSession {{ WebSession(String key) {{}} }}
""".format_map(fields)
    )
    tree = ASTParser().parse_file(path)
    assert tree is not None
    return FileAST.model_validate_json(tree.model_dump_json()).credential_randomness


def test_session_registry_matches_all_three_uses_of_the_same_identifier(tmp_path):
    (fact,) = registry(tmp_path)
    assert fact.generator == "java.util.Random.nextLong"
    assert (fact.generator_line, fact.use_line) == (8, 9)
    assert fact.use == "session registry key returned to the caller"


@pytest.mark.parametrize(
    "changes",
    [
        {"init": "new java.security.SecureRandom()"},
        {"init": "new Random() { }"},
        {"identifier": 'new java.security.SecureRandom().nextLong() + "-" + generator.nextLong()'},
        {"identifier": "idHint + generator.nextLong()"},
        {"stored": "new WebSession(idHint)"},
        {"key": "idHint"},
        {"returned": "idHint"},
        {"lookup": '"constant"'},
        {"extra": "void rotate() { this.generator = new java.security.SecureRandom(); }"},
        {"extra": "void reset() { this.active = new HashMap<>(); }"},
    ],
)
def test_registry_requires_known_generation_registration_lookup_and_return(tmp_path, changes):
    assert not registry(tmp_path, **changes)


@pytest.mark.parametrize("allocation", ["new byte[0]", "new byte[] {}", "existing"])
def test_byte_flow_requires_fresh_nonempty_storage(tmp_path, allocation):
    tree = parse(
        tmp_path,
        f"""
        byte[] bytes = {allocation};
        new Random().nextBytes(bytes);
        session.setAttribute("auth_token", java.util.HexFormat.of().formatHex(bytes));
    """,
    )
    assert not tree.credential_randomness


@pytest.mark.parametrize(
    "earlier,current,expected",
    [
        ("0.0", "new Random().nextDouble()", True),
        ("new Random().nextDouble()", "0.0", False),
    ],
)
def test_closed_block_cannot_supply_a_later_same_named_binding(
    tmp_path, earlier, current, expected
):
    ast = parse(
        tmp_path,
        f"""
        if (suffix.isEmpty()) {{ double sample = {earlier}; display(sample); }}
        double sample = {current};
        session.setAttribute("auth_token", Double.toString(sample));
    """,
    )
    assert bool(ast.credential_randomness) == expected
