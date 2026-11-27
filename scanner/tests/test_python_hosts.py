from textwrap import dedent

import pytest

from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_hosts import host_checks


@pytest.mark.parametrize(
    ("comparison", "flag"),
    [
        ("host.startswith('api.example.org')", True),
        ("host.endswith('example.org')", True),
        ("host.endswith('.example.org')", False),
        ("host == 'example.org'", False),
        ("host.startswith('api-')", False),
        ("host.startswith(value)", False),
        ("path.startswith('example.org')", False),
    ],
)
def test_parsed_host_comparisons(comparison, flag):
    source = f"""from urllib.parse import urlsplit as split
def check(value):
    path = split(value).path
    host = split(value).hostname
    return {comparison}
"""
    facts = host_checks(source.encode())
    assert [fact.line for fact in facts] == ([5] if flag else [])


def test_partial_host_policy_scan_and_repaired_control(tmp_path):
    path = tmp_path / "policy.py"
    source = dedent("""\
        from urllib.parse import urlparse
        TRUSTED = "127.0.0.1"
        class Policy:
            @staticmethod
            def local(address):
                parsed = urlparse(address)
                return parsed.netloc.startswith(TRUSTED)
        """)
    engine = ScanEngine()
    for expression, flagged in [
        ("parsed.netloc.startswith(TRUSTED)", True),
        ("parsed.hostname == TRUSTED", False),
    ]:
        path.write_text(source.replace("parsed.netloc.startswith(TRUSTED)", expression))
        result = engine.scan_files(tmp_path, [path])
        assert "AEG-HOST-001" in result.evaluated_rules
        hits = [item for item in result.findings if item.rule_id == "AEG-HOST-001"]
        assert [(f.line_start, f.cwe_id, f.disposition.value) for f in hits] == (
            [(7, 187, "advisory")] if flagged else []
        )
    path.write_text(source)
    shadow = tmp_path / "urllib.py"
    shadow.write_text("parse = None\n")
    assert not any(
        f.rule_id == "AEG-HOST-001" for f in engine.scan_files(tmp_path, [path, shadow]).findings
    )
