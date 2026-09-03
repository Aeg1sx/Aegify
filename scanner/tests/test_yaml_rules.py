"""Tests for the YAML-based custom rule system."""

from pathlib import Path
from textwrap import dedent

import pytest

from aegify.config import AegifyConfig
from aegify.models import EvidenceState, FindingDisposition
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
        assert rule.spec.patterns[0].disposition == FindingDisposition.ADVISORY

    def test_parse_advisory_pattern_and_semantic_detector(self):
        data = {
            "id": "TEST-GATE-001",
            "severity": "high",
            "languages": ["python"],
            "patterns": [{"callee": "save", "disposition": "advisory"}],
            "semantic": {
                "kind": "database_race",
                "read_callee": "find",
                "write_callee": "save",
                "receiver_match": "repo",
                "required_between": r"\+=",
                "defense_match": "transaction",
            },
        }

        rule = _parse_rule(data)

        assert rule.spec.patterns[0].disposition == FindingDisposition.ADVISORY
        assert rule.spec.semantic is not None
        assert rule.spec.semantic.kind == "database_race"

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
    def test_taint_rule_does_not_cross_its_language_boundary(self, tmp_path):
        rule_file = tmp_path / "python-only.yml"
        rule_file.write_text(
            dedent("""\
            rules:
              - id: YAML-PYTHON-ONLY-001
                name: Python-only HTTP sink
                severity: high
                languages: [python]
                cwe_id: 918
                taint:
                  source_types: [http_param, http_body]
                  sink_pattern: "fetch"
                message: "Python-only rule must not evaluate TypeScript"
        """)
        )
        (tmp_path / "keep-rule-active.py").write_text("def identity(value):\n    return value\n")
        (tmp_path / "unsafe.ts").write_text(
            "export async function proxy(request: Request) {\n"
            "  const target = new URL(request.url).searchParams.get('url');\n"
            "  return fetch(target!);\n"
            "}\n"
        )
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)

        findings = ScanEngine(config=config).scan(tmp_path).findings

        assert all(f.rule_id != "YAML-PYTHON-ONLY-001" for f in findings)

    def test_advisory_pattern_is_retained_without_blocking_ci(self, tmp_path):
        rule_file = tmp_path / "advisory.yml"
        rule_file.write_text(
            dedent("""\
            rules:
              - id: YAML-ADVISORY-001
                name: Broad save candidate
                severity: high
                languages: [python]
                patterns:
                  - callee: "save"
                    disposition: advisory
                message: "Review broad save call"
        """)
        )
        target = tmp_path / "app.py"
        target.write_text("def update(value):\n    return repo.save(value)\n")
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)

        findings = ScanEngine(config=config).scan(target).findings
        advisory = next(f for f in findings if f.rule_id == "YAML-ADVISORY-001")

        assert advisory.evidence_state == EvidenceState.CANDIDATE
        assert advisory.disposition == FindingDisposition.ADVISORY
        assert advisory.blocks_ci is False

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
        assert all(f.evidence_state == EvidenceState.REACHABLE for f in yaml_findings)
        assert all(f.disposition == FindingDisposition.BLOCKING for f in yaml_findings)

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

    def test_legacy_pattern_with_args_matches_one_parsed_call(self, tmp_path):
        rule_file = tmp_path / "dynamic-import.yml"
        rule_file.write_text(
            dedent(
                r"""
                rules:
                  - id: YAML-DYNAMIC-IMPORT-001
                    name: Dynamic import from request data
                    severity: critical
                    languages: [python]
                    patterns:
                      - pattern: '__import__\s*\('
                        args_match: 'request\.args'
                    message: "Dynamic request-controlled import"
                """
            ).lstrip()
        )
        unrelated = tmp_path / "unrelated.py"
        unrelated.write_text(
            "from package import (safe_name)\n\n"
            "def read_request(request):\n"
            "    return request.args.get('name')\n"
        )
        unsafe = tmp_path / "unsafe.py"
        unsafe.write_text(
            "def load_plugin(request):\n    return __import__(request.args.get('plugin'))\n"
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        engine = ScanEngine(config=config)

        assert not any(
            finding.rule_id == "YAML-DYNAMIC-IMPORT-001"
            for finding in engine.scan(unrelated).findings
        )
        assert any(
            finding.rule_id == "YAML-DYNAMIC-IMPORT-001" for finding in engine.scan(unsafe).findings
        )

    def test_legacy_dynamic_import_pattern_does_not_match_static_python_import(self, tmp_path):
        rule_file = tmp_path / "dynamic-import.yml"
        rule_file.write_text(
            dedent(
                r"""
                rules:
                  - id: YAML-DYNAMIC-IMPORT-002
                    name: Dynamic import from request data
                    severity: critical
                    languages: [python]
                    patterns:
                      - pattern: 'import\s*\('
                        args_match: 'request\.args'
                    message: "Dynamic request-controlled import"
                """
            ).lstrip()
        )
        static_import = tmp_path / "static_import.py"
        static_import.write_text(
            "from package import (safe_name)\n\n"
            "def read_request(request):\n"
            "    return request.args.get('name')\n"
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        engine = ScanEngine(config=config)

        assert not any(
            finding.rule_id == "YAML-DYNAMIC-IMPORT-002"
            for finding in engine.scan(static_import).findings
        )

    def test_relational_patterns_default_to_function_scope(self, tmp_path):
        rule_file = tmp_path / "relational.yml"
        rule_file.write_text(
            dedent(
                r"""
                rules:
                  - id: YAML-RELATIONAL-001
                    name: Related events in one function
                    severity: high
                    languages: [python]
                    patterns:
                      - multi_match:
                          - 'request\.args'
                          - 'os\.system'
                    message: "Request data and command execution share a function"
                """
            ).lstrip()
        )
        split = tmp_path / "split.py"
        split.write_text(
            "def source(request):\n"
            "    return request.args.get('command')\n\n"
            "def sink(command):\n"
            "    return os.system(command)\n"
        )
        together = tmp_path / "together.py"
        together.write_text(
            "def run(request):\n"
            "    command = request.args.get('command')\n"
            "    return os.system(command)\n"
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        engine = ScanEngine(config=config)

        assert not any(
            finding.rule_id == "YAML-RELATIONAL-001" for finding in engine.scan(split).findings
        )
        assert any(
            finding.rule_id == "YAML-RELATIONAL-001" for finding in engine.scan(together).findings
        )

    def test_call_missing_check_is_evaluated_in_enclosing_function(self, tmp_path):
        rule_file = tmp_path / "guarded-call.yml"
        rule_file.write_text(
            dedent(
                r"""
                rules:
                  - id: YAML-GUARDED-CALL-001
                    name: Sensitive save without authorization
                    severity: high
                    languages: [python]
                    patterns:
                      - callee: '^save$'
                        args_match: 'user'
                        missing_check: 'authorize|is_admin'
                    message: "Sensitive save lacks an authorization check"
                """
            ).lstrip()
        )
        unsafe = tmp_path / "unsafe.py"
        unsafe.write_text("def update(user):\n    return save(user)\n")
        safe = tmp_path / "safe.py"
        safe.write_text("def update(user):\n    authorize(user)\n    return save(user)\n")

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        engine = ScanEngine(config=config)

        assert any(
            finding.rule_id == "YAML-GUARDED-CALL-001" for finding in engine.scan(unsafe).findings
        )
        assert not any(
            finding.rule_id == "YAML-GUARDED-CALL-001" for finding in engine.scan(safe).findings
        )

    def test_full_callee_match_does_not_match_identifier_substrings(self, tmp_path):
        rule_file = tmp_path / "full-callee.yml"
        rule_file.write_text(
            dedent(
                """
                rules:
                  - id: YAML-FULL-CALLEE-001
                    name: Exact sign call
                    severity: medium
                    languages: [python]
                    patterns:
                      - callee: 'sign'
                        callee_match_mode: full
                    message: "Exact sign call"
                """
            ).lstrip()
        )
        target = tmp_path / "calls.py"
        target.write_text("def run(value):\n    _is_assignable(value)\n    return sign(value)\n")

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        findings = [
            finding
            for finding in ScanEngine(config=config).scan(target).findings
            if finding.rule_id == "YAML-FULL-CALLEE-001"
        ]

        assert len(findings) == 1
        assert findings[0].line_start == 3

    def test_args_match_index_limits_matching_to_selected_call_argument(self, tmp_path):
        rule_file = tmp_path / "format-argument.yml"
        rule_file.write_text(
            dedent(
                r"""
                rules:
                  - id: YAML-FORMAT-ARG-001
                    name: User-controlled format string
                    severity: high
                    languages: [python]
                    patterns:
                      - callee: 'logger\.info'
                        args_match: 'request\.args'
                        args_match_index: 0
                    message: "User input is the format string"
                """
            ).lstrip()
        )
        target = tmp_path / "logging_calls.py"
        target.write_text(
            "def log(request):\n"
            "    logger.info('user=%s', request.args.get('user'))\n"
            "    logger.info(request.args.get('format'), 'value')\n"
        )

        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.custom_rules = str(rule_file)
        findings = [
            finding
            for finding in ScanEngine(config=config).scan(target).findings
            if finding.rule_id == "YAML-FORMAT-ARG-001"
        ]

        assert len(findings) == 1
        assert findings[0].line_start == 3
