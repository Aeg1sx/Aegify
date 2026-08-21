"""Static validation for the Aegify YAML rule DSL.

The evaluator historically accepted arbitrary dictionaries, which made typoed
or aspirational fields look active while being ignored. This audit makes the
executable subset explicit and is suitable for an open-source CI gate.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from aegify.rules.yaml_rule import LANG_MAP, SEVERITY_MAP, PatternSpec

SUPPORTED_PATTERN_FIELDS = {
    "annotation_match",
    "argument_check",
    "args_exclude",
    "args_match",
    "assignment_match",
    "attribute_match",
    "block_match",
    "block_missing",
    "callee",
    "callee_chain",
    "callee_match",
    "class_context",
    "class_match",
    "condition",
    "config_match",
    "content_match",
    "context",
    "context_check",
    "context_match",
    "decorator_absent",
    "decorator_match",
    "description",
    "entropy_threshold",
    "exclude_context",
    "exclude_match",
    "file_match",
    "flags",
    "import_match",
    "languages",
    "match",
    "max_lines_between",
    "method_match",
    "missing_check",
    "missing_args",
    "missing_annotation",
    "missing_attribute",
    "missing_context",
    "missing_filter",
    "missing_guard",
    "missing_header",
    "missing_match",
    "missing_pattern",
    "missing_sibling",
    "missing_transform",
    "missing_validation",
    "multi_match",
    "multiline",
    "must_contain",
    "negative_match",
    "note",
    "param_type_match",
    "pattern",
    "pattern_type",
    "propagators",
    "receiver",
    "receiver_match",
    "regex_match",
    "sanitizers",
    "scope",
    "sequence_match",
    "sink",
    "source",
    "steps",
    "taint",
    "taint_source",
    "value_match",
    "version_match",
}


class RuleAuditIssue(BaseModel):
    severity: str  # error | warning
    code: str
    message: str
    file_path: str
    rule_id: str = ""
    pattern_index: int | None = None


class RuleAuditReport(BaseModel):
    files: int = 0
    rules: int = 0
    loadable_rules: int = 0
    executable_rules: int = 0
    disabled_rules: int = 0
    patterns: int = 0
    executable_patterns: int = 0
    unsupported_fields: dict[str, int] = Field(default_factory=dict)
    deferred_languages: dict[str, int] = Field(default_factory=dict)
    issues: list[RuleAuditIssue] = Field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == "warning")


def audit_rules(path: Path) -> RuleAuditReport:
    """Audit a rule file or tree without registering or executing the rules."""
    files = [path] if path.is_file() else sorted([*path.rglob("*.yml"), *path.rglob("*.yaml")])
    report = RuleAuditReport(files=len(files))
    unsupported: Counter[str] = Counter()
    deferred_languages: Counter[str] = Counter()
    seen_ids: dict[str, str] = {}

    for file_path in files:
        try:
            data = yaml.safe_load(file_path.read_text())
        except (OSError, yaml.YAMLError) as error:
            _issue(report, "error", "invalid-yaml", str(error), file_path)
            continue
        rule_list = _rule_list(data)
        for rule in rule_list:
            report.rules += 1
            if not isinstance(rule, dict):
                _issue(
                    report,
                    "error",
                    "invalid-rule",
                    "rule must be a mapping",
                    file_path,
                )
                continue
            rule_id = str(rule.get("id") or "")
            if not rule_id:
                _issue(report, "error", "missing-id", "rule id is required", file_path)
            elif rule_id in seen_ids:
                _issue(
                    report,
                    "error",
                    "duplicate-id",
                    f"also defined in {seen_ids[rule_id]}",
                    file_path,
                    rule_id,
                )
            else:
                seen_ids[rule_id] = str(file_path)

            if rule.get("enabled") is False:
                report.disabled_rules += 1
                continue

            severity = str(rule.get("severity", "medium"))
            if severity not in SEVERITY_MAP:
                _issue(
                    report,
                    "error",
                    "invalid-severity",
                    f"unsupported severity: {severity}",
                    file_path,
                    rule_id,
                )
            languages = rule.get("languages") or []
            unknown_languages = [lang for lang in languages if lang not in LANG_MAP]
            deferred_languages.update(map(str, unknown_languages))
            supported_languages = [lang for lang in languages if lang in LANG_MAP]
            language_is_loadable = not languages or bool(supported_languages)
            if language_is_loadable:
                report.loadable_rules += 1
            if unknown_languages and not supported_languages:
                _issue(
                    report,
                    "error",
                    "unsupported-language",
                    f"languages ignored by this build: {', '.join(map(str, unknown_languages))}",
                    file_path,
                    rule_id,
                )

            patterns = rule.get("patterns") or []
            executable_for_rule = bool(rule.get("taint"))
            for index, pattern in enumerate(patterns):
                report.patterns += 1
                if not isinstance(pattern, dict):
                    _issue(
                        report,
                        "error",
                        "invalid-pattern",
                        "pattern must be a mapping",
                        file_path,
                        rule_id,
                        index,
                    )
                    continue
                unknown = set(pattern) - SUPPORTED_PATTERN_FIELDS
                unsupported.update(unknown)
                for field_name in sorted(unknown):
                    _issue(
                        report,
                        "warning",
                        "unsupported-field",
                        f"field is not executed: {field_name}",
                        file_path,
                        rule_id,
                        index,
                    )
                _check_regexes(report, pattern, file_path, rule_id, index)
                if _is_executable_pattern(pattern):
                    executable_for_rule = True
                    report.executable_patterns += 1
                else:
                    _issue(
                        report,
                        "error",
                        "non-executable-pattern",
                        "pattern is accepted by the compatibility schema "
                        "but has no executable detector",
                        file_path,
                        rule_id,
                        index,
                    )

            if not executable_for_rule:
                _issue(
                    report,
                    "error",
                    "no-executable-detector",
                    "rule has neither an executable pattern nor a taint specification",
                    file_path,
                    rule_id,
                )
            elif language_is_loadable:
                report.executable_rules += 1

    report.unsupported_fields = dict(unsupported.most_common())
    report.deferred_languages = dict(deferred_languages.most_common())
    return report


def _is_executable_pattern(pattern: dict[str, Any]) -> bool:
    """Mirror PatternSpec normalization and empty-pattern behavior."""
    return PatternSpec(pattern).is_executable


def _rule_list(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        rules = data.get("rules")
        if isinstance(rules, list):
            return rules
        return [data]
    return []


def _check_regexes(
    report: RuleAuditReport,
    pattern: dict[str, Any],
    file_path: Path,
    rule_id: str,
    index: int,
) -> None:
    scalar_fields = (
        "annotation_match",
        "args_exclude",
        "args_match",
        "assignment_match",
        "attribute_match",
        "block_missing",
        "callee",
        "callee_match",
        "class_context",
        "class_match",
        "config_match",
        "content_match",
        "context",
        "context_check",
        "context_match",
        "decorator_match",
        "exclude_context",
        "exclude_match",
        "file_match",
        "import_match",
        "match",
        "method_match",
        "missing_check",
        "missing_guard",
        "missing_transform",
        "missing_annotation",
        "missing_attribute",
        "missing_context",
        "missing_filter",
        "missing_match",
        "missing_pattern",
        "missing_sibling",
        "missing_validation",
        "must_contain",
        "negative_match",
        "param_type_match",
        "pattern",
        "receiver",
        "receiver_match",
        "regex_match",
        "sink",
        "source",
        "taint_source",
        "value_match",
    )
    values: list[tuple[str, str]] = []
    for field_name in scalar_fields:
        values.extend((field_name, value) for value in _string_values(pattern.get(field_name)))
    for field_name in ("multi_match", "sequence_match", "sanitizers", "missing_args"):
        values.extend((field_name, value) for value in _string_values(pattern.get(field_name)))
    for field_name in ("block_match", "decorator_absent", "taint"):
        nested = pattern.get(field_name)
        if isinstance(nested, dict):
            for nested_name, nested_value in nested.items():
                if nested_name in {
                    "start",
                    "end",
                    "missing",
                    "function_pattern",
                    "expected_decorator",
                    "source",
                    "sink",
                    "missing_sanitizer",
                    "sanitizers",
                }:
                    values.extend(
                        (f"{field_name}.{nested_name}", value)
                        for value in _string_values(nested_value)
                    )
    steps = pattern.get("steps")
    if isinstance(steps, list):
        for step_index, step in enumerate(steps):
            if isinstance(step, dict):
                values.extend(
                    (f"steps[{step_index}].match", value)
                    for value in _string_values(step.get("match"))
                )

    for field_name, value in values:
        try:
            re.compile(value)
        except re.error as error:
            _issue(
                report,
                "error",
                "invalid-regex",
                f"{field_name}: {error}",
                file_path,
                rule_id,
                index,
            )


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    return []


def _issue(
    report: RuleAuditReport,
    severity: str,
    code: str,
    message: str,
    file_path: Path,
    rule_id: str = "",
    pattern_index: int | None = None,
) -> None:
    report.issues.append(
        RuleAuditIssue(
            severity=severity,
            code=code,
            message=message,
            file_path=str(file_path),
            rule_id=rule_id,
            pattern_index=pattern_index,
        )
    )
