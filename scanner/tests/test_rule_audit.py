"""Tests for executable rule-schema auditing."""

from pathlib import Path

from aegify.rules.audit import audit_rules


def test_audit_reports_unknown_and_non_executable_patterns(tmp_path: Path):
    rules = tmp_path / "rules.yml"
    rules.write_text(
        """
        rules:
          - id: executable
            name: Executable
            severity: high
            languages: [java]
            patterns:
              - callee_match: "execute.*"
                args_match: "request"
          - id: aspirational
            name: Not executable
            severity: medium
            languages: [kotlin]
            patterns:
              - future_match:
                  - one
                  - two
        """
    )
    report = audit_rules(rules)
    assert report.rules == 2
    assert report.loadable_rules == 2
    assert report.executable_rules == 1
    assert report.patterns == 2
    assert report.executable_patterns == 1
    assert report.unsupported_fields["future_match"] == 1
    assert any(issue.code == "no-executable-detector" for issue in report.issues)
    assert any(issue.code == "non-executable-pattern" for issue in report.issues)


def test_audit_only_errors_when_all_declared_languages_are_unsupported(
    tmp_path: Path,
):
    mixed = tmp_path / "mixed.yml"
    mixed.write_text(
        """
id: mixed-language
severity: medium
languages: [java, ruby]
patterns:
  - callee: execute
"""
    )
    unsupported = tmp_path / "unsupported.yml"
    unsupported.write_text(
        """
id: unsupported-language
severity: medium
languages: [ruby]
patterns:
  - callee: execute
"""
    )

    report = audit_rules(tmp_path)
    language_issues = [issue for issue in report.issues if issue.code == "unsupported-language"]

    assert {issue.rule_id: issue.severity for issue in language_issues} == {
        "unsupported-language": "error",
    }
    assert report.deferred_languages == {"ruby": 2}


def test_audit_executable_count_matches_pattern_normalization(tmp_path: Path):
    rules = tmp_path / "normalization.yml"
    rules.write_text(
        """
rules:
  - id: ignored-call-match
    severity: medium
    languages: [java]
    patterns:
      - pattern_type: call
        match: execute
  - id: argument-filter
    severity: medium
    languages: [java]
    patterns:
      - args_match: userInput
  - id: shorthand-regex
    severity: medium
    languages: [java]
    patterns:
      - pattern: 'Runtime\\.getRuntime'
"""
    )

    report = audit_rules(rules)

    assert report.executable_patterns == 2
    assert report.executable_rules == 2
    assert any(
        issue.code == "no-executable-detector" and issue.rule_id == "ignored-call-match"
        for issue in report.issues
    )


def test_audit_accepts_executable_compatibility_patterns(tmp_path: Path):
    rules = tmp_path / "compatibility.yml"
    rules.write_text(
        """
rules:
  - id: negative-check
    severity: high
    languages: [python]
    patterns:
      - pattern_type: negative_check
        match: "@app.route"
        must_contain: "rate_limit"
        scope: function
  - id: sequence-check
    severity: medium
    languages: [java]
    patterns:
      - sequence_match: ["findById", 'save\\(']
        max_lines_between: 10
        missing_match: "authorize"
"""
    )

    report = audit_rules(rules)

    assert report.errors == 0
    assert report.warnings == 0
    assert report.executable_patterns == 2
    assert report.executable_rules == 2


def test_audit_rejects_partially_non_executable_rule(tmp_path: Path):
    rules = tmp_path / "partial.yml"
    rules.write_text(
        """
id: partial
severity: medium
languages: [javascript]
patterns:
  - callee_match: 'helmet\\('
  - missing_header: "Content-Security-Policy"
    context: response_headers
"""
    )

    report = audit_rules(rules)

    assert report.executable_rules == 1
    assert report.executable_patterns == 1
    assert any(
        issue.code == "non-executable-pattern" and issue.pattern_index == 1
        for issue in report.issues
    )


def test_audit_skips_explicitly_disabled_reference_rule(tmp_path: Path):
    rules = tmp_path / "reference.yml"
    rules.write_text(
        """
id: reference-only-ruby
enabled: false
disabled_reason: Ruby parser is not installed
severity: medium
languages: [ruby]
patterns:
  - future_match: ignored
"""
    )

    report = audit_rules(rules)

    assert report.rules == 1
    assert report.disabled_rules == 1
    assert report.errors == 0
    assert report.warnings == 0
