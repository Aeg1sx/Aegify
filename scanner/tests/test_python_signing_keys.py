"""Static JWT signing-key evidence and disclosure controls using synthetic inputs."""

import json

import pytest

from aegify.config import AegifyConfig
from aegify.llm.prompts import format_pr_finding
from aegify.llm.sources import SourceCatalog
from aegify.models import ScanResult
from aegify.reporter.sarif import SARIFReporter
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_signing_keys import (
    REDACTED_SIGNING_KEY,
    redact_signing_source,
    signing_keys,
)

CANARY = "review-only-synthetic-material"


@pytest.mark.parametrize(
    ("source", "line", "use", "api"),
    [
        ("from jwt import encode\nprint(encode({},'demo'))", 2, 2, "jwt.encode"),
        ("from jose import jwt\ntoken = jwt.encode({},b'demo')", 2, 2, "jose.jwt.encode"),
        ("import jwt\njwt.encode({},'demo',headers={'alg':'HS256'})", 2, 2, "jwt.encode"),
        (
            "from jose import jwt as signer\nA='HS384'\nK=b'owned'\ndef issue(x):\n"
            "    return signer.encode(x,K,algorithm=A)",
            3,
            5,
            "jose.jwt.encode",
        ),
        (
            "from jwt import encode as sign\ndef issue(x):\n    key = 'owned'\n"
            "    other = key\n    return sign(payload=x, key=other, algorithm='HS512')",
            3,
            5,
            "jwt.encode",
        ),
        (
            "import jwt\ndef wrapper():\n    data = 'owned'\n    def issue(x):\n"
            "        return jwt.encode(x,data,'HS256')",
            3,
            5,
            "jwt.encode",
        ),
        (
            "from jose.jwt import encode\ndef f(x):\n"
            "    return encode(claims=x, key='demo',algorithm='HS256',headers={'kid':'example'})",
            3,
            3,
            "jose.jwt.encode",
        ),
        (
            "import jwt\nkey='module'\nclass C:\n    key='unrelated'\n"
            "    def f(self,x):\n        return jwt.encode(x,key,'HS256')",
            2,
            6,
            "jwt.encode",
        ),
    ],
)
def test_resolved_signer_and_literal_coordinates(source, line, use, api):
    facts = signing_keys(source.encode())
    assert [(f.line, f.use_line, f.api) for f in facts] == [(line, use, api)]


@pytest.mark.parametrize(
    "body",
    [
        "return jwt.encode(x, read_key(), algorithm='HS256')",
        "return jwt.encode(x, key, algorithm='RS256')",
        "return jwt.encode(x, 'ssh-ed25519 example-public-material')",
        "return jwt.encode(x, '-----BEGIN PUBLIC KEY----- example')",
        "return jwt.encode(x, key, algorithm=choose())",
        "return jwt.encode(x, key, algorithm='HS256', headers=h)",
        "return jwt.encode(x, key, algorithm='HS256', headers={'alg':'RS256'})",
        "return jwt.encode(x, key, algorithm='HS256', headers={**h})",
        "return jwt.encode(x, key, 'HS256', {}, headers=h)",
        "return jwt.encode(key=key, algorithm='HS256')",
        "return jwt.encode(x, key, 'HS256', **opts)",
        "return jwt.decode(x,key,algorithms=['HS256'])",
        "key = lookup()\n    return jwt.encode(x, key, algorithm='HS256')",
        "jwt = handler\n    return jwt.encode(x,key,'HS256')",
        "return jwt.encode(x,key,'HS256')\n    key = lookup()",
        "return jwt.encode(x,key,'HS256')\ndef rotate():\n    global key\n    key = lookup()",
    ],
)
def test_unproven_key_algorithm_call_or_binding(body):
    assert not signing_keys(("import jwt\nkey='owned'\ndef f(x):\n    " + body).encode())


def test_literal_projection_preserves_context_and_line_numbers():
    raw = (
        "from jwt import encode\r\ndef f(x):\r\n"
        f'    café = """{CANARY}\r\nsecond-line"""\r\n'
        "    return encode(x,café,'HS256')\r\n"
    ).encode("utf-8-sig")
    facts = signing_keys(raw)
    assert len(facts) == 1
    safe = redact_signing_source(raw, facts)
    assert safe.splitlines()[2:4] == ["    café = " + REDACTED_SIGNING_KEY, REDACTED_SIGNING_KEY]
    assert safe.count("\n") == raw.count(b"\n")
    assert CANARY not in safe and "second-line" not in safe


def test_non_utf8_source_withholds_affected_lines():
    raw = (
        "# coding: latin-1\nimport jwt\ndef f(x):\n    café = '"
        + CANARY
        + "'\n    return jwt.encode(x,café,'HS256')\n"
    ).encode("latin-1")
    facts = signing_keys(raw)
    assert len(facts) == 1
    assert redact_signing_source(raw, facts).splitlines()[3] == REDACTED_SIGNING_KEY


def _engine():
    return ScanEngine(
        AegifyConfig.model_validate(
            {
                "llm": {"enabled": False},
                "storage": {"backend": "memory"},
                "rules": {"severity_threshold": "low"},
            }
        )
    )


@pytest.mark.parametrize("inline", [True, False])
def test_scan_export_and_reopened_review_hide_value(tmp_path, inline):
    root = tmp_path / "src"
    root.mkdir()
    file = root / "auth.py"
    body = (
        ("    return jwt.encode(data, " + repr(CANARY) + ", algorithm='HS256')\n")
        if inline
        else (
            "    SECRET_KEY = "
            + repr(CANARY)
            + "\n    return jwt.encode(data, SECRET_KEY, algorithm='HS256')\n"
        )
    )
    file.write_text("from jose import jwt\ndef issue(data):\n" + body)
    engine = _engine()
    result = engine.scan_files(root, [file])
    assert result.status == "completed" and not result.analysis_gaps
    signing = [f for f in result.findings if f.rule_id == "AEG-A02-001"]
    assert [(f.line_start, f.line_end, f.cwe_id) for f in signing] == [(3, 3, 321)]
    assert f"line {3 if inline else 4}" in signing[0].message
    assert "jwt.encode" in signing[0].code_snippet
    assert REDACTED_SIGNING_KEY in signing[0].code_snippet
    assert CANARY not in result.model_dump_json()
    assert CANARY not in json.dumps(SARIFReporter().generate(result))
    assert all(
        CANARY not in format_pr_finding(i, f.model_dump()) for i, f in enumerate(result.findings)
    )
    path = tmp_path / "graph.jsonl"
    engine.export_program_graph(path)
    assert CANARY not in path.read_text()
    assert any(
        json.loads(line).get("kind") == "statement" for line in path.read_text().splitlines()
    )

    parsed = ASTParser().parse_file(file, repository_root=root)
    assert parsed is not None
    for catalog in (
        SourceCatalog.capture([parsed], {"local": root}),
        SourceCatalog.from_scan(
            ScanResult.model_validate_json(result.model_dump_json()), {"local": root}
        ),
    ):
        request = {"repository_id": "local", "path": "auth.py", "line_start": 3, "line_end": 3}
        excerpt = catalog.read(request)
        assert CANARY not in excerpt["content"]
        assert catalog.valid_citation(excerpt["citation"])
        assert not catalog.search({"repository_id": "local", "query": CANARY})["matches"]

    file.write_text(file.read_text().replace(CANARY, "replacement-synthetic-material"))
    engine._enrich_snippets(signing, [parsed])
    assert signing[0].code_snippet == REDACTED_SIGNING_KEY


def test_shadowing_project_is_not_a_signer(tmp_path):
    (tmp_path / "jwt.py").write_text("def encode(*args): return 'ok'\n")
    (tmp_path / "auth.py").write_text(
        "import jwt\ndef f(x): return jwt.encode(x,'owned','HS256')\n"
    )
    result = _engine().scan_files(tmp_path, sorted(tmp_path.glob("*.py")))
    assert result.status == "completed"
    assert "AEG-A02-001" not in {f.rule_id for f in result.findings}
