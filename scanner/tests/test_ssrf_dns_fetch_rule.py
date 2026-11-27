"""Run just the bundled DNS/fetch rule over parsed, never-executed sources."""

from pathlib import Path
from time import monotonic

import pytest

from aegify.models import EvidenceState, FindingDisposition
from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder


@pytest.fixture(scope="module")
def rule():
    path = Path(__file__).parents[2] / "rules/a10-ssrf/ssrf_advanced.yml"
    return next(rule for rule in load_yaml_rules(path) if rule.definition.id == "AEG-SSRF-ADV-001")


def evaluate(rule, path, source):
    path.write_text(source)
    file_ast = ASTParser().parse_file(path)
    assert file_ast is not None and not file_ast.parse_diagnostics
    return rule.evaluate([file_ast], CallGraphBuilder().build([file_ast]), [])


@pytest.mark.parametrize(
    ("name", "pair", "split", "reverse"),
    [
        (
            "client.py",
            "def review(host):\n    socket.getaddrinfo(host, 443)\n    return requests.get(host)\n",
            "def inspect(host):\n    return socket.getaddrinfo(host, 443)\n"
            "def deliver(host):\n    return requests.get(host)\n",
            "def review(host):\n    requests.get(host)\n    return socket.getaddrinfo(host, 443)\n",
        ),
        (
            "lookup.py",
            "async def fetch_document(address):\n    gethostbyname(address)\n"
            "    return urllib.request.urlopen(address)\n",
            "def fetch_document(address):\n    return gethostbyname(address)\n"
            "def deliver(address):\n    return urllib.request.urlopen(address)\n",
            "def fetch_document(address):\n    urllib.request.urlopen(address)\n"
            "    return gethostbyname(address)\n",
        ),
        (
            "client.js",
            "function review(host) {\n  dns.lookup(host);\n  return fetch(host);\n}\n",
            "function inspect(host) {\n  return dns.lookup(host);\n}\n"
            "function deliver(host) {\n  return fetch(host);\n}\n",
            "function review(host) {\n  fetch(host);\n  return dns.lookup(host);\n}\n",
        ),
    ],
)
def test_dns_fetch_evidence_stays_in_function_order(tmp_path, rule, name, pair, split, reverse):
    path = tmp_path / name
    found = evaluate(rule, path, pair)
    assert found and all(
        item.evidence_state == EvidenceState.CANDIDATE
        and item.disposition == FindingDisposition.ADVISORY
        for item in found
    )
    assert not evaluate(rule, path, split)
    assert not evaluate(rule, path, reverse)


def test_dns_pair_in_outer_body_keeps_unrelated_nested_helper(tmp_path, rule):
    source = (
        "def fetch_document(address):\n"
        "    def label():\n        return 'doc'\n"
        "    gethostbyname(address)\n"
        "    return urllib.request.urlopen(address)\n"
    )
    assert evaluate(rule, tmp_path / "nested.py", source)


def test_many_lookup_functions_without_http_finish_within_rule_budget(tmp_path, rule):
    assert all(pattern.scope == "function" for pattern in rule.spec.patterns)
    path = tmp_path / "inventory.py"
    path.write_text(
        "".join(
            f"def fetch_metadata_{i}(address):\n    return gethostbyname(address)\n\n"
            for i in range(500)
        )
    )
    file_ast = ASTParser().parse_file(path)
    assert file_ast is not None and len(file_ast.functions) == 500
    graph = CallGraphBuilder().build([file_ast])
    started = monotonic()
    assert rule.evaluate([file_ast], graph, []) == []
    assert monotonic() - started < 2
