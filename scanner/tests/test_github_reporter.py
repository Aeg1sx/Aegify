"""Tests for GitHub PR comment reporter."""

import pytest

from aegify.models import Finding, FindingDisposition, ScanResult, ScanStatus, Severity
from aegify.reporter.github import GitHubReporter


def _make_finding(**overrides) -> Finding:
    defaults = {
        "rule_id": "AEG-SQL-001",
        "rule_name": "SQL Injection",
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "disposition": FindingDisposition.BLOCKING,
        "file_path": "app.py",
        "line_start": 10,
        "line_end": 10,
        "code_snippet": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
        "message": "Possible SQL injection via string concatenation",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _make_scan_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        status=ScanStatus.COMPLETED,
        findings=findings or [],
        files_scanned=42,
        duration_seconds=3.5,
    )


class TestGitHubReporter:
    @pytest.fixture
    def reporter(self):
        return GitHubReporter()

    def test_generate_comment_with_findings(self, reporter):
        findings = [
            _make_finding(
                severity=Severity.CRITICAL,
                rule_id="AEG-CMD-001",
                rule_name="Command Injection",
            ),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM, rule_id="AEG-XSS-001", rule_name="XSS"),
        ]
        result = _make_scan_result(findings)
        comment = reporter.generate_comment(result)

        assert "Aegify Results" in comment
        assert "CRITICAL" in comment
        assert "HIGH" in comment
        assert "MEDIUM" in comment
        assert "AEG-CMD-001" in comment
        assert "AEG-SQL-001" in comment
        assert "AEG-XSS-001" in comment
        assert "42 files" in comment

    def test_generate_comment_no_findings(self, reporter):
        result = _make_scan_result([])
        comment = reporter.generate_comment(result)

        assert "No security findings" in comment
        assert "42 files" in comment
        assert "3.5s" in comment

    def test_generate_inline_annotations(self, reporter):
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.LOW, line_start=20, line_end=20),
        ]
        annotations = reporter.generate_inline_annotations(findings)

        assert len(annotations) == 2

        critical_ann = annotations[0]
        assert critical_ann["path"] == "app.py"
        assert critical_ann["start_line"] == 10
        assert critical_ann["annotation_level"] == "failure"

        low_ann = annotations[1]
        assert low_ann["annotation_level"] == "warning"
        assert low_ann["start_line"] == 20

    def test_high_advisory_annotation_is_warning(self, reporter):
        finding = _make_finding(disposition=FindingDisposition.ADVISORY)

        annotation = reporter.generate_inline_annotations([finding])[0]

        assert annotation["annotation_level"] == "warning"
        assert "ADVISORY" in annotation["body"]

    def test_summary_table(self, reporter):
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
        ]
        result = _make_scan_result(findings)
        table = reporter._summary_table(result)

        assert "Critical | 1" in table
        assert "High | 2" in table
        assert "**3**" in table

    def test_finding_with_remediation(self, reporter):
        finding = _make_finding(remediation="Use parameterized queries instead.")
        result = _make_scan_result([finding])
        comment = reporter.generate_comment(result)

        assert "Remediation" in comment
        assert "parameterized queries" in comment

    def test_finding_without_snippet(self, reporter):
        finding = _make_finding(code_snippet="")
        text = reporter._format_finding(finding)

        # Should not contain a code block when snippet is empty
        assert "```\n\n```" not in text

    def test_annotation_includes_remediation_in_body(self, reporter):
        finding = _make_finding(remediation="Fix: use prepared statements")
        annotations = reporter.generate_inline_annotations([finding])

        assert "Suggested fix" in annotations[0]["body"]
        assert "prepared statements" in annotations[0]["body"]
