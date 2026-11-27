"""Static credential-use controls. Test programs are parsed as source text only."""

from pathlib import Path
from textwrap import dedent, indent

import networkx as nx
import pytest

from aegify.models import EvidenceState, FindingDisposition
from aegify.rules.yaml_rule import SemanticSpec, load_yaml_rules
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.credential_randomness import credential_uses


def _source(body: str, imports: str = "", args: str = "store") -> str:
    return (
        f"import random as rng\nfrom flask import request, session\n{imports}\ndef issue({args}):\n"
        + indent(dedent(body).strip(), "    ")
        + "\n"
    )


@pytest.mark.parametrize(
    ("imports", "expression", "name"),
    [
        ("", "str(rng.normalvariate())[2:]", "random.normalvariate"),
        (
            "from base64 import urlsafe_b64encode as encode",
            "encode(rng.randbytes(16))",
            "random.randbytes",
        ),
        ("from random import getrandbits as bits", "hex(bits(64))", "random.getrandbits"),
        ("", "rng.Random().randint(2, 40)", "random.Random.randint"),
    ],
)
def test_cookie_state_source_and_both_uses(imports, expression, name):
    source = _source(
        f"""
        value = {expression}
        if request.cookies.get('remember') == store['token']:
            return True
        else:
            store['token'] = value
    """,
        imports,
    )
    (result,) = credential_uses(source.encode())
    assert (result.generator, result.generator_line, result.use_line, result.comparison_line) == (
        name,
        5,
        9,
        6,
    )


@pytest.mark.parametrize(
    "body, imports, args",
    [
        ("session['csrf_token'] = rng.SystemRandom().getrandbits(64)", "", ""),
        ("session['csrf_token'] = secure(16)", "from secrets import token_hex as secure", ""),
        ("session['csrf_token'] = secure(16).hex()", "from os import urandom as secure", ""),
        ("session['csrf_token'] = rng.randbytes(16)", "", "rng"),
        ("session['csrf_token'] = rng.randbytes(16)", "", "session"),
        ("session['theme'] = rng.choice(['light','dark'])", "", ""),
        ("return rng.getrandbits(32)", "", ""),
        ("x = rng.randbytes(16)\nx = 'constant'\nsession['csrf_token'] = x", "", ""),
        ("session['csrf_token'] = str(rng.randint(2, 40))", "", "str"),
        ("rng.getrandbits = external\nsession['csrf_token'] = rng.getrandbits(64)", "", "external"),
        ("session['csrf_token'] = wrapper(rng.randbytes(16))", "", "wrapper"),
        (
            "if enabled:\n    value = rng.randbytes(16)\nelse:\n    session['csrf_token'] = value",
            "",
            "enabled",
        ),
        (
            "x = rng.getrandbits(32)\nstore['one'] = x\n"
            "return request.cookies['x'] == store['two']",
            "",
            "store",
        ),
        (
            "x = rng.getrandbits(32)\nstore['one'] = x\nstore['one'] = 0\n"
            "return request.cookies['x'] == store['one']",
            "",
            "store",
        ),
        (
            "store['one'] = rng.getrandbits(32)\nstore.clear()\n"
            "return request.cookies['x'] == store['one']",
            "",
            "store",
        ),
        (
            "local = {}\nif request.cookies['x'] == local['one']:\n    return\n"
            "local['one'] = rng.getrandbits(32)",
            "",
            "",
        ),
        ("return request.headers['Accept'] == str(rng.random())", "", ""),
        ("return request.cookies['x'] == str(rng.random())", "", "request"),
        ("return rng.getrandbits(8) == unrelated.cookies.get('sid')", "", "unrelated"),
        ("return [rng.getrandbits(12) == request.cookies['x'] for rng in store]", "", "store"),
    ],
)
def test_unproven_security_context(body, imports, args):
    assert credential_uses(_source(body, imports, args).encode()) == []


def test_real_rule_entry_points_and_static_location(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        _source(
            """
        generator = rng.Random()
        expected = generator.randbytes(24).hex()
        presented = request.headers.get('X-CSRF-Token')
        return compare(expected, presented)
    """,
            "from hmac import compare_digest as compare",
        )
    )
    parsed = ASTParser().parse_file(path)
    assert parsed is not None
    root = Path(__file__).resolve().parents[2] / "rules"
    for pack, identifier in [
        ("insecure_crypto.yml", "AEG-CRYPTO-002"),
        ("a02-cryptographic-failures/crypto.yml", "AEG-A02-004"),
    ]:
        rule = next(
            rule for rule in load_yaml_rules(root / pack) if rule.definition.id == identifier
        )
        (finding,) = rule.evaluate([parsed], nx.MultiDiGraph(), [])
        assert finding.line_start == 8 and "random.Random.randbytes on line 6" in finding.message
        assert finding.disposition == FindingDisposition.ADVISORY
        assert finding.evidence_state == EvidenceState.REACHABLE


def test_real_flask_alias_and_locally_created_mapping():
    facts = credential_uses(
        _source("""
        import flask as web
        local = {}
        local['verification'] = rng.getrandbits(32)
        web.session['csrf_token'] = rng.randbytes(32).hex()
        return local['verification'] == web.request.cookies['input']
    """).encode()
    )
    assert [(f.use_line, f.comparison_line) for f in facts] == [(7, 9), (8, None)]
    assert not SemanticSpec(
        {"kind": "credential_randomness", "read_callee": "unused"}
    ).is_executable
