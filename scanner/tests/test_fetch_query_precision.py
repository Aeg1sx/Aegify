from pathlib import Path

import networkx as nx
import pytest

from aegify.models import FileAST, FindingDisposition
from aegify.rules.yaml_rule import PatternSpec, load_yaml_rules
from aegify.scanner.ast_parser import ASTParser

RULES = Path(__file__).resolve().parents[2] / "rules"
CASES = {
    "AEG-A07-006": "a07-auth-failures/auth.yml",
    "AEG-OAUTH-003": "a07-auth-failures/oauth_security.yml",
    "AEG-API-015": "api-security/api_advanced.yml",
}


@pytest.mark.parametrize("suffix", ["js", "ts"])
def test_fetch_credentials_follow_the_url_query_at_the_call_site(tmp_path: Path, suffix: str):
    source = tmp_path / f"client.{suffix}"
    # Separate source files keep the production rule's per-file cap from masking a control.
    examples = [
        (
            'globalThis.fetch(base + "/audit?format=jsonl", '
            "{headers: {cookie: `authjs.session-token=${value}`}});",
            set(),
        ),
        (
            'fetch(base + "?format=jsonl&access_token=" + value, '
            '{headers: {Accept: "application/json"}});',
            set(CASES),
        ),
        ('window.fetch(base + "?sort_token=index");', set()),
        ('self.fetch(base + "?format=jsonl", {body: "?token=" + value});', set()),
        (
            'fetch(new Request(base + `?token=${value}`, {headers: {Accept: "text/plain"}}));',
            set(CASES),
        ),
        ('fetch(new Request(base, {headers: {url: "/test?token=fixture"}}));', set()),
        ("fetch(new URL(`/audit?access%5Ftoken=${value}`, base).href);", set(CASES)),
        ('fetch(base + "#section?token=fixture");', set()),
        ('fetch(base + "?q=value?token=fixture");', set()),
        ('fetch(`/file/${format("?token=fixture")}`);', set()),
        ('fetch(base + "?token=");', set()),
        ('fetch("/records?format=json&refresh_token=" + value);', {"AEG-OAUTH-003"}),
        ('fetch("/accounts?password=" + value);', {"AEG-API-015"}),
        ('fetch(new Request(base + "?sid=" + value).url);', {"AEG-A07-006"}),
        ('fetch("/public?format=json", {headers: {url: "/test?token=fixture"}});', set()),
        (
            'fetch("/publish?token=" + value, {headers: {Authorization: "Bearer " + value}});',
            set(CASES),
        ),
    ]
    rules = {
        key: next(rule for rule in load_yaml_rules(RULES / file) if rule.definition.id == key)
        for key, file in CASES.items()
    }
    for statement, expected in examples:
        source.write_text("function download(base, value) {\n" + statement + "\n}\n")
        tree = ASTParser().parse_file(source)
        assert tree is not None
        cached = FileAST.model_validate_json(tree.model_dump_json())
        hits = [hit for rule in rules.values() for hit in rule.evaluate([cached], nx.DiGraph(), [])]
        assert {hit.rule_id for hit in hits} == expected, statement
        assert all(
            hit.line_start == 2 and hit.disposition == FindingDisposition.ADVISORY for hit in hits
        )


@pytest.mark.parametrize("keys", [[], "token", ["bad key"], [7]])
def test_fetch_query_selector_rejects_invalid_rule_input(keys):
    with pytest.raises(ValueError, match="fetch_query_keys"):
        PatternSpec({"callee": "fetch", "fetch_query_keys": keys})
