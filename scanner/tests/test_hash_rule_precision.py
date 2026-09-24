"""Algorithm-selection regressions over source fixtures; fixture code is not run."""

import time
from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.models import EvidenceState, FindingDisposition
from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.engine import ScanEngine

RULE_FILE = Path(__file__).parents[2] / "rules/a02-cryptographic-failures/crypto.yml"
HASH_RULES = {"AEG-A02-002", "AEG-A02-003"}


def scan(tmp_path: Path, name: str, source: str):
    target = tmp_path / name
    target.write_text(source)
    config = AegifyConfig()
    config.llm.enabled = False
    config.rules.severity_threshold = "low"
    config.rules.custom_rules = str(RULE_FILE)
    result = ScanEngine(config=config).scan(target)
    assert result.status.value == "completed"
    assert not result.analysis_gaps
    return [finding for finding in result.findings if finding.rule_id in HASH_RULES]


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        (
            "direct.py",
            "import hashlib\ndef f(data):\n return hashlib.md5(data).hexdigest()\n",
            "AEG-A02-002",
        ),
        (
            "imported.py",
            "from hashlib import md5\ndef f(data):\n return md5(data).hexdigest()\n",
            "AEG-A02-002",
        ),
        (
            "generic.py",
            "import hashlib\ndef f(data):\n return hashlib.new('md5', data).hexdigest()\n",
            "AEG-A02-002",
        ),
        (
            "named.py",
            "import hashlib\ndef f(data):\n return hashlib.new(name='md5', data=data)\n",
            "AEG-A02-002",
        ),
        (
            "node.js",
            "import crypto from 'node:crypto';\n"
            "export const f = data => crypto.createHash('md5').update(data).digest('hex');",
            "AEG-A02-002",
        ),
        (
            "node.ts",
            "import {createHash} from 'node:crypto';\n"
            "export const f = (data: string) => createHash('MD5').update(data).digest('hex');",
            "AEG-A02-002",
        ),
        (
            "Digest.java",
            "import java.security.MessageDigest;\nclass Digest { Object f() throws Exception { "
            'return MessageDigest.getInstance("MD5"); } }',
            "AEG-A02-002",
        ),
        (
            "digest.go",
            'package fixture\nimport "crypto/md5"\nfunc f() { _ = md5.New() }\n',
            "AEG-A02-002",
        ),
        (
            "digest.rs",
            "fn digest(input: &[u8]) { let _value = md5::compute(input); }",
            "AEG-A02-002",
        ),
        (
            "digest.swift",
            "import CryptoKit\n"
            "func digest(data: Data) { let value = Insecure.MD5.hash(data: data) }",
            "AEG-A02-002",
        ),
        (
            "Digest.kt",
            'import java.security.MessageDigest\nfun digest() = MessageDigest.getInstance("MD5")',
            "AEG-A02-002",
        ),
        (
            "sha1.py",
            "import hashlib\ndef f(data):\n return hashlib.sha1(data).hexdigest()\n",
            "AEG-A02-003",
        ),
        (
            "generic_sha1.py",
            "import hashlib\ndef f(data):\n return hashlib.new('SHA1', data)\n",
            "AEG-A02-003",
        ),
        (
            "sha1.ts",
            "import {createHash} from 'node:crypto';\n"
            "export const f = data => createHash('sha1').update(data).digest('hex');",
            "AEG-A02-003",
        ),
        (
            "Sha1.java",
            "import java.security.MessageDigest;\nclass Sha1 { Object f() throws Exception { "
            'return MessageDigest.getInstance("SHA-1"); } }',
            "AEG-A02-003",
        ),
        (
            "sha1.go",
            'package fixture\nimport "crypto/sha1"\nfunc f() { _ = sha1.New() }\n',
            "AEG-A02-003",
        ),
        (
            "sha1.rs",
            "use sha1::{Digest, Sha1};\nfn digest() { let _value = Sha1::new(); }",
            "AEG-A02-003",
        ),
    ],
)
def test_selected_weak_algorithm_is_one_advisory_candidate(tmp_path, name, source, expected):
    findings = scan(tmp_path, name, source)
    assert [finding.rule_id for finding in findings] == [expected]
    assert findings[0].disposition == FindingDisposition.ADVISORY
    assert findings[0].evidence_state == EvidenceState.CANDIDATE
    assert "review" in findings[0].message


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "sha256.ts",
            "import {createHash} from 'node:crypto';\n"
            "export const f = data => createHash('sha256').update(data).digest('hex');",
        ),
        (
            "sha512.js",
            "import crypto from 'node:crypto';\n"
            "export const f = data => crypto.createHash('sha512').update(data).digest('hex');",
        ),
        (
            "factory.java",
            'class Digest { Object f() { return MessageDigest.getInstance("SHA-256"); } }',
        ),
        (
            "safe.py",
            "import hashlib\ndef f(data):\n"
            " return hashlib.new('sha256', b'md5 sha1').hexdigest()\n",
        ),
        ("options.ts", "export const f = () => createHash('sha256', {metadata: 'md5 sha1'});"),
        ("decoy.ts", "export const f = () => unrelated_createHash('md5');"),
        ("decoy.py", "def f(data):\n return record_md5_metadata(data)\n"),
        ("dynamic.ts", "export const f = algorithm => createHash(algorithm);"),
        ("expression.ts", "export const f = algorithm => createHash('md5' + algorithm);"),
        ("literal.ts", "export const f = () => createHash('md5-metadata');"),
        ("literal.py", 'def f(data):\n return hashlib.new("not md5", data)\n'),
        ("algorithm_data.py", "def f(data):\n return hashlib.new('sha256', data='sha1')\n"),
        (
            "metadata.py",
            "def models():\n return SinkPattern('hashlib.sha1', 'crypto_operation', 0)\n",
        ),
    ],
)
def test_unselected_or_unresolved_weak_algorithm_does_not_get_a_verdict(tmp_path, name, source):
    assert scan(tmp_path, name, source) == []


def test_stronger_algorithm_nearby_does_not_erase_selected_md5(tmp_path):
    findings = scan(
        tmp_path,
        "mixed.py",
        "import hashlib\ndef f(data):\n return hashlib.md5(data), hashlib.sha256(data)\n",
    )
    assert [finding.rule_id for finding in findings] == ["AEG-A02-002"]


def test_hash_selection_patterns_stay_bounded_for_repeated_safe_calls(tmp_path):
    target = tmp_path / "safe_hashes.ts"
    target.write_text("createHash('sha256', {description: 'md5 sha1'});\n" * 1000)
    ast = ASTParser().parse_file(target)
    rules = [rule for rule in load_yaml_rules(RULE_FILE) if rule.definition.id in HASH_RULES]
    graph = CallGraphBuilder().build([ast])
    started = time.monotonic()
    assert all(rule.evaluate([ast], graph, []) == [] for rule in rules)
    assert time.monotonic() - started < 2
