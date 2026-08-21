"""Integration tests for the scan engine."""

from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.models import ScanStatus, Severity
from aegify.scanner.engine import ScanEngine

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanEngine:
    @pytest.fixture
    def engine(self):
        config = AegifyConfig()
        config.llm.enabled = False  # Don't use LLM in tests
        config.rules.severity_threshold = "low"
        return ScanEngine(config=config)

    def test_scan_vulnerable_file(self, engine):
        result = engine.scan(FIXTURES / "vulnerable_app.py")
        assert result.status == ScanStatus.COMPLETED
        assert result.files_scanned == 1
        assert len(result.findings) > 0

        # Should find SQL injection
        sql_findings = [f for f in result.findings if "SQL" in f.rule_id]
        assert len(sql_findings) > 0

    def test_scan_safe_file_has_fewer_findings(self, engine):
        vulnerable_result = engine.scan(FIXTURES / "vulnerable_app.py")
        safe_result = engine.scan(FIXTURES / "safe_app.py")

        # Safe app should have fewer taint-based findings (high-confidence, critical/high severity)
        vuln_taint = [
            f
            for f in vulnerable_result.findings
            if f.confidence >= 0.7
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.taint_flow is not None
        ]
        safe_taint = [
            f
            for f in safe_result.findings
            if f.confidence >= 0.7
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.taint_flow is not None
        ]

        assert len(safe_taint) <= len(vuln_taint)

    def test_scan_directory(self, engine):
        result = engine.scan(FIXTURES)
        assert result.status == ScanStatus.COMPLETED
        assert result.files_scanned >= 2

    def test_scan_nonexistent_directory(self, engine):
        result = engine.scan(Path("/nonexistent/path"))
        assert result.files_scanned == 0

    def test_severity_threshold_filtering(self):
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "critical"
        engine = ScanEngine(config=config)

        result = engine.scan(FIXTURES / "vulnerable_app.py")
        # Only critical findings should pass
        for finding in result.findings:
            assert finding.severity == Severity.CRITICAL

    def test_findings_sorted_by_severity(self, engine):
        result = engine.scan(FIXTURES / "vulnerable_app.py")
        if len(result.findings) < 2:
            pytest.skip("Not enough findings to test sorting")

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }

        for i in range(len(result.findings) - 1):
            curr = severity_order[result.findings[i].severity]
            next_ = severity_order[result.findings[i + 1].severity]
            assert curr <= next_


class TestScanEngineRules:
    @pytest.fixture
    def engine(self):
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        return ScanEngine(config=config)

    def test_rules_loaded(self, engine):
        rules = engine.registry.get_all()
        assert len(rules) > 0

        rule_ids = [r.definition.id for r in rules]
        assert "AEG-SQL-001" in rule_ids
        assert "AEG-CMD-001" in rule_ids
        assert "AEG-XSS-001" in rule_ids

    def test_disable_rule(self):
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        config.rules.disabled_rules = ["AEG-SQL-001", "AEG-SQL-002"]
        engine = ScanEngine(config=config)

        result = engine.scan(FIXTURES / "vulnerable_app.py")
        sql_findings = [f for f in result.findings if f.rule_id.startswith("AEG-SQL")]
        assert len(sql_findings) == 0


class TestFindingDeduplication:
    def test_fingerprint_stability(self):
        """Same finding data produces same fingerprint."""
        from aegify.models import Finding, Severity

        f1 = Finding(
            rule_id="AEG-SQL-001",
            rule_name="SQL Injection",
            severity=Severity.HIGH,
            confidence=0.9,
            file_path="app.py",
            line_start=10,
            line_end=10,
            code_snippet="cursor.execute(query)",
        )
        f2 = Finding(
            rule_id="AEG-SQL-001",
            rule_name="SQL Injection",
            severity=Severity.HIGH,
            confidence=0.8,
            file_path="app.py",
            line_start=10,
            line_end=10,
            code_snippet="cursor.execute(query)",
        )
        assert f1.fingerprint == f2.fingerprint

    def test_different_findings_different_fingerprint(self):
        from aegify.models import Finding, Severity

        f1 = Finding(
            rule_id="AEG-SQL-001",
            rule_name="SQL Injection",
            severity=Severity.HIGH,
            confidence=0.9,
            file_path="app.py",
            line_start=10,
            line_end=10,
        )
        f2 = Finding(
            rule_id="AEG-XSS-001",
            rule_name="XSS",
            severity=Severity.MEDIUM,
            confidence=0.8,
            file_path="app.py",
            line_start=20,
            line_end=20,
        )
        assert f1.fingerprint != f2.fingerprint

    def test_dedup_in_scan(self):
        """Scan should not produce duplicate fingerprints."""
        config = AegifyConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        engine = ScanEngine(config=config)

        result = engine.scan(FIXTURES / "vulnerable_app.py")
        fingerprints = [f.fingerprint for f in result.findings]
        assert len(fingerprints) == len(set(fingerprints)), "Duplicate findings detected"
