"""Tests for the YAML-based custom rule system."""

from pathlib import Path
from textwrap import dedent

import pytest

from aegify.config import AegifyConfig
from aegify.rules.yaml_rule import _parse_rule, load_yaml_rules
from aegify.scanner.engine import ScanEngine

FIXTURES = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).parent.parent.parent / "rules"


class TestYAMLRuleParsing:
    def test_parse_single_rule(self):
        data = {
            "id": "TEST-001",
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "high",
            "confidence": 0.8,
            "languages": ["python"],
            "cwe_id": 89,
            "patterns": [
                {"callee": "eval", "args_match": ".*"},
            ],
            "message": "Found {callee} at line {line}",
        }
        rule = _parse_rule(data)
        assert rule.definition.id == "TEST-001"
        assert rule.definition.name == "Test Rule"
        assert rule.definition.severity.value == "high"
        assert rule.definition.default_confidence == 0.8
        assert len(rule.spec.patterns) == 1
        assert rule.spec.patterns[0].callee == "eval"

    def test_parse_taint_rule(self):
        data = {
            "id": "TEST-002",
            "name": "Taint Test",
            "severity": "critical",
            "languages": ["python", "javascript"],
            "taint": {
                "sink_types": ["sql_query"],
                "source_types": ["http_param"],
            },
            "message": "Taint from {source} to {sink}",
        }
        rule = _parse_rule(data)
        assert rule.definition.requires_taint_path is True
        assert rule.spec.taint is not None
        assert rule.spec.taint.sink_types == ["sql_query"]
        assert rule.spec.taint.source_types == ["http_param"]

    def test_parse_rule_defaults(self):
        data = {
            "id": "TEST-003",
            "patterns": [{"callee": "test"}],
        }
        rule = _parse_rule(data)
        assert rule.definition.name == "TEST-003"  # defaults to id
        assert rule.definition.severity.value == "medium"  # default
        assert rule.definition.default_confidence == 0.7  # default


class TestYAMLRuleLoading:
    def test_load_from_directory(self):
        if not RULES_DIR.exists():
            pytest.skip("Rules directory not found")
        rules = load_yaml_rules(RULES_DIR)
        assert len(rules) > 0

        rule_ids = [r.definition.id for r in rules]
        assert "AEG-SEC-001" in rule_ids  # hardcoded_secrets
        assert "AEG-CRYPTO-001" in rule_ids  # insecure_crypto
        assert "AEG-SSRF-001" in rule_ids  # ssrf

    def test_load_single_file(self):
        secrets_file = RULES_DIR / "hardcoded_secrets.yml"
        if not secrets_file.exists():
            pytest.skip("Rules file not found")
        rules = load_yaml_rules(secrets_file)
        assert len(rules) == 2  # AEG-SEC-001 and AEG-SEC-002

    def test_load_nonexistent_path(self):
        rules = load_yaml_rules(Path("/nonexistent/path"))
        assert len(rules) == 0

    def test_load_from_yaml_file(self, tmp_path):
        rule_file = tmp_path / "custom.yml"
        rule_file.write_text(
            dedent("""\
            rules:
              - id: CUSTOM-001
                name: Custom Test Rule
                severity: low
                languages: [python]
                patterns:
                  - callee: "print"
                message: "Print statement found at line {line}"
        """)
        )

        rules = load_yaml_rules(rule_file)
        assert len(rules) == 1
        assert rules[0].definition.id == "CUSTOM-001"


class TestYAMLRuleExecution:
    def test_pattern_rule_matches(self, tmp_path):
        """Test that a YAML pattern rule can detect findings."""
        # Create a rule that matches eval() calls
        rule_file = tmp_path / "rules" / "test.yml"
        rule_file.parent.mkdir(parents=True)
        rule_file.write_text(
            dedent("""\
            rules:
              - id: YAML-TEST-001
                name: Eval Usage
                severity: high
                confidence: 0.9
                languages: [python]
                patterns:
                  - callee: "^eval$"
                message: "eval() used at line {line}"
        """)
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)

        engine = ScanEngine(config=config)
        result = engine.scan(FIXTURES / "vulnerable_app.py")

        yaml_findings = [f for f in result.findings if f.rule_id == "YAML-TEST-001"]
        assert len(yaml_findings) > 0

    def test_custom_rules_with_engine(self):
        """Test that YAML rules from the rules/ directory integrate properly."""
        if not RULES_DIR.exists():
            pytest.skip("Rules directory not found")

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(RULES_DIR)

        engine = ScanEngine(config=config)

        # After loading, registry should have built-in + YAML rules
        all_rules = engine.registry.get_all()
        rule_ids = [r.definition.id for r in all_rules]

        # Built-in
        assert "AEG-SQL-001" in rule_ids
        # YAML
        assert "AEG-SEC-001" in rule_ids
        assert "AEG-CRYPTO-001" in rule_ids

    def test_taint_yaml_rule(self, tmp_path):
        """Test taint-based YAML rule."""
        rule_file = tmp_path / "taint_rule.yml"
        rule_file.write_text(
            dedent("""\
            rules:
              - id: YAML-TAINT-001
                name: Custom SQL Taint
                severity: critical
                confidence: 0.95
                languages: [python]
                taint:
                  sink_types: [sql_query]
                  source_types: [http_param]
                message: "Custom taint: {source} -> {sink}"
        """)
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)

        engine = ScanEngine(config=config)
        result = engine.scan(FIXTURES / "vulnerable_app.py")

        yaml_findings = [f for f in result.findings if f.rule_id == "YAML-TAINT-001"]
        assert len(yaml_findings) > 0

    def test_negative_check_respects_function_scope(self, tmp_path):
        rule_file = tmp_path / "negative.yml"
        rule_file.write_text(
            dedent("""\
            rules:
              - id: YAML-NEGATIVE-001
                name: Missing rate limit
                severity: high
                languages: [python]
                patterns:
                  - pattern_type: negative_check
                    match: "def login"
                    must_contain: "rate_limit"
                    scope: function
                message: "Login handler has no rate limit"
        """)
        )
        unsafe = tmp_path / "unsafe.py"
        unsafe.write_text("def login():\n    return authenticate()\n")
        safe = tmp_path / "safe.py"
        safe.write_text("def login():\n    rate_limit()\n    return authenticate()\n")

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        engine = ScanEngine(config=config)

        unsafe_result = engine.scan(unsafe)
        safe_result = engine.scan(safe)

        assert any(f.rule_id == "YAML-NEGATIVE-001" for f in unsafe_result.findings)
        assert not any(f.rule_id == "YAML-NEGATIVE-001" for f in safe_result.findings)

    def test_sequence_pattern_requires_order_and_missing_control(self, tmp_path):
        rule_file = tmp_path / "sequence.yml"
        rule_file.write_text(
            dedent("""\
            rules:
              - id: YAML-SEQUENCE-001
                name: Unsafe read modify write
                severity: high
                languages: [python]
                patterns:
                  - sequence_match:
                      - "load_balance"
                      - "balance -= amount"
                      - "save_balance"
                    max_lines_between: 5
                    missing_match: "with_lock"
                    scope: function
                message: "Read-modify-write without a lock"
        """)
        )
        unsafe = tmp_path / "unsafe.py"
        unsafe.write_text(
            "def debit(amount):\n"
            "    balance = load_balance()\n"
            "    balance -= amount\n"
            "    save_balance(balance)\n"
        )
        safe = tmp_path / "safe.py"
        safe.write_text(
            "def debit(amount):\n"
            "    with_lock()\n"
            "    balance = load_balance()\n"
            "    balance -= amount\n"
            "    save_balance(balance)\n"
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        engine = ScanEngine(config=config)

        assert any(f.rule_id == "YAML-SEQUENCE-001" for f in engine.scan(unsafe).findings)
        assert not any(f.rule_id == "YAML-SEQUENCE-001" for f in engine.scan(safe).findings)

    def test_lexical_taint_pattern_requires_source_before_sink(self, tmp_path):
        rule_file = tmp_path / "lexical-taint.yml"
        rule_file.write_text(
            dedent("""\
            rules:
              - id: YAML-LEXICAL-TAINT-001
                name: Request data reaches command execution
                severity: critical
                languages: [python]
                patterns:
                  - pattern_type: taint
                    source: "request.args"
                    sink: "os.system"
                    sanitizers: ["allowlist"]
                    scope: function
                message: "Lexical source-to-sink candidate"
        """)
        )
        unsafe = tmp_path / "unsafe.py"
        unsafe.write_text(
            "def run(request):\n"
            "    command = request.args.get('command')\n"
            "    return os.system(command)\n"
        )
        safe = tmp_path / "safe.py"
        safe.write_text(
            "def run(request):\n"
            "    command = request.args.get('command')\n"
            "    command = allowlist(command)\n"
            "    return os.system(command)\n"
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        engine = ScanEngine(config=config)

        assert any(f.rule_id == "YAML-LEXICAL-TAINT-001" for f in engine.scan(unsafe).findings)
        assert not any(f.rule_id == "YAML-LEXICAL-TAINT-001" for f in engine.scan(safe).findings)
