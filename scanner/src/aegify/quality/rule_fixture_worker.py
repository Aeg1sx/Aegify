"""Private source-only worker for ``aegify test-rule``; no application execution."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from collections.abc import Hashable
from importlib.metadata import version
from pathlib import Path
from typing import Any, Literal

import yaml

from aegify.models import ScanStatus
from aegify.quality.benchmark import ExpectedFinding, digest_bytes, evaluate_findings
from aegify.quality.rule_fixtures import (
    MAX_INPUT_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_RULE_BYTES,
    FixtureCaseResult,
    FixtureMetrics,
    FixtureReport,
    RuleFixture,
    RuleFixtureSuite,
    canonical_json,
    read_input,
    result_digest,
    strict_json,
)
from aegify.rules.audit import audit_rules
from aegify.rules.base import RuleRegistry
from aegify.rules.yaml_rule import LANG_MAP, YAMLRule, load_yaml_rules
from aegify.scanner.ast_parser import detect_language
from aegify.scanner.engine import ScanEngine
from aegify.worker import implementation_manifest, worker_config

_RULE_FIELDS = {
    "id",
    "name",
    "description",
    "severity",
    "confidence",
    "languages",
    "cwe_id",
    "owasp_category",
    "masvs_category",
    "asvs_category",
    "message",
    "patterns",
    "taint",
    "semantic",
    "defense_patterns",
    "fix_suggestion",
    "references",
    "enabled",
    "disabled_reason",
    "llm_verify_threshold",
}


class RuleInputError(Exception):
    def __init__(self, diagnostics: list[dict[str, Any]]) -> None:
        self.diagnostics = diagnostics
        super().__init__("Rule failed strict validation")


class FixtureYamlLoader(yaml.SafeLoader):
    """Reject aliases, duplicate keys and deeply nested authoring documents."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self.fixture_depth = 0
        self.fixture_nodes = 0

    def compose_node(self, parent: Any, index: Any) -> yaml.Node | None:
        self.fixture_nodes += 1
        if self.check_event(yaml.AliasEvent):
            raise ValueError("rule YAML aliases are unsupported")
        if self.fixture_depth >= 40 or self.fixture_nodes > 20_000:
            raise ValueError("rule YAML complexity limit")
        self.fixture_depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self.fixture_depth -= 1

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("rule mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _load_rule(rule_yaml: str, path: Path, rule_id: str) -> YAMLRule:
    if len(rule_yaml.encode("utf-8")) > MAX_RULE_BYTES:
        raise ValueError("rule size limit")
    data = yaml.load(rule_yaml, Loader=FixtureYamlLoader)
    if isinstance(data, dict) and "rules" in data:
        if set(data) != {"rules"}:
            raise ValueError("unexpected rule container field")
        data = data["rules"]
    if isinstance(data, list):
        if len(data) != 1:
            raise ValueError("one rule required")
        data = data[0]
    if not isinstance(data, dict) or data.get("id") != rule_id:
        raise ValueError("rule identity mismatch")
    if set(data) - _RULE_FIELDS:
        raise RuleInputError(
            [
                {
                    "code": "unsupported_rule_field",
                    "message": "Unsupported rule field; see the rule authoring contract.",
                }
            ]
        )
    for field in ("name", "message"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise RuleInputError(
                [{"code": "missing_rule_metadata", "message": f"A nonempty {field} is required."}]
            )
    confidence = data.get("confidence", 0.7)
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        raise RuleInputError(
            [{"code": "invalid_confidence", "message": "Confidence must be a number from 0 to 1."}]
        )
    languages = data.get("languages")
    if (
        not isinstance(languages, list)
        or not 1 <= len(languages) <= len(LANG_MAP)
        or any(not isinstance(item, str) or item not in LANG_MAP for item in languages)
        or len(set(languages)) != len(languages)
        or data.get("enabled", True) is not True
    ):
        raise ValueError("rule must enable supported languages")
    # The authoritative audit and loader consume exactly the submitted bytes.
    path.write_text(rule_yaml, encoding="utf-8")
    path.chmod(0o400)
    audit = audit_rules(path)
    if (
        audit.errors
        or audit.warnings
        or audit.rules != 1
        or audit.loadable_rules != 1
        or audit.executable_rules != 1
        or audit.disabled_rules
        or audit.patterns > 100
    ):
        diagnostics = [
            {
                "code": issue.code,
                "message": issue.message[:500],
                "pattern_index": issue.pattern_index,
            }
            for issue in audit.issues[:30]
        ]
        raise RuleInputError(
            diagnostics
            or [
                {
                    "code": "invalid_rule_scope",
                    "message": "One enabled, executable rule is required.",
                }
            ]
        )
    rules = load_yaml_rules(path)
    if len(rules) != 1 or rules[0].definition.id != rule_id:
        raise ValueError("rule failed to load")
    return rules[0]


def _run_case(
    case: RuleFixture, rule: YAMLRule, root: Path
) -> tuple[FixtureCaseResult, ScanEngine]:
    root.mkdir(mode=0o700)
    for item in case.files:
        target = root / item.path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(item.content.encode("utf-8"))
        target.chmod(0o400)
    registry = RuleRegistry()
    registry.register(rule)
    config = worker_config()
    config.scan.max_workers = 1
    config.scan.exclude = []
    config.scan.max_file_size_kb = 64
    engine = ScanEngine(config=config, rule_registry=registry)
    previous = Path.cwd()
    issues: set[str] = set()
    paths = {item.path for item in case.files}
    source_digest = digest_bytes(
        canonical_json(
            [item.model_dump() for item in sorted(case.files, key=lambda item: item.path)]
        )
    )
    try:
        os.chdir(root)
        if any(detect_language(Path(path)) is None for path in paths):
            issues.add("unsupported_source")
        result = engine.scan_files(Path("."), [Path(path) for path in sorted(paths)])
        issues.update(gap.code for gap in result.analysis_gaps)
        if result.status != ScanStatus.COMPLETED:
            issues.add("analysis_incomplete")
        if set(result.analyzed_files) != paths or result.files_scanned != len(paths):
            issues.add("source_not_analyzed")
        if result.evaluated_rules != [rule.definition.id]:
            issues.add("rule_not_evaluated")
        if rule.evaluation_limited:
            issues.add("detector_limit_reached")
        for item in case.files:
            if Path(item.path).read_bytes() != item.content.encode("utf-8"):
                issues.add("source_changed")
        if any(
            f.rule_id != rule.definition.id or f.file_path not in paths for f in result.findings
        ):
            issues.add("unexpected_finding_identity")
        comparison = evaluate_findings(
            result.findings,
            [ExpectedFinding(**item.model_dump()) for item in case.expected],
            line_tolerance=0,
            rule_scope=[rule.definition.id],
        )
    finally:
        os.chdir(previous)
    counts = comparison.metrics
    actual = [
        finding.model_dump(
            mode="json",
            include={
                "rule_id",
                "file_path",
                "line_start",
                "line_end",
                "message",
                "severity",
                "evidence_state",
                "disposition",
                "taint_flow",
            },
        )
        for finding in result.findings
    ]
    actual.sort(key=canonical_json)
    mismatch = bool(counts.false_positives or counts.false_negatives)
    return FixtureCaseResult(
        id=case.id,
        status="incomplete" if issues else "failed" if mismatch else "passed",
        source_digest=source_digest,
        duration_seconds=result.duration_seconds,
        files_scanned=result.files_scanned,
        evaluated_rules=result.evaluated_rules,
        issues=sorted(issues),
        parse_diagnostics=[item.model_dump(mode="json") for item in result.parse_diagnostics],
        actual=actual,
        metrics=None
        if issues
        else FixtureMetrics.counts(
            counts.true_positives, counts.false_positives, counts.false_negatives
        ),
        unmatched_actual=comparison.unmatched_actual,
        unmatched_expected=comparison.unmatched_expected,
    ), engine


def evaluate_suite(rule_yaml: str, suite: RuleFixtureSuite, directory: Path) -> FixtureReport:
    """Worker-only evaluation; public callers use the supervised entry point."""
    rule = _load_rule(rule_yaml, directory / "rule.yml", suite.rule_id)
    cases = []
    for index, case in enumerate(suite.cases):
        result, engine = _run_case(case, rule, directory / f"case-{index}")
        cases.append(result)
    positives = sum(bool(case.expected) for case in suite.cases)
    negatives = len(suite.cases) - positives
    issues = []
    if positives < 1:
        issues.append("positive_control_required")
    if negatives < 2:
        issues.append("two_negative_controls_required")
    status: Literal["passed", "failed", "incomplete"]
    if issues or any(case.status == "incomplete" for case in cases):
        status = "incomplete"
    elif any(case.status == "failed" for case in cases):
        status = "failed"
    else:
        status = "passed"
    metrics = None
    if status != "incomplete":
        complete = [case.metrics for case in cases if case.metrics is not None]
        metrics = FixtureMetrics.counts(
            sum(item.true_positives for item in complete),
            sum(item.false_positives for item in complete),
            sum(item.false_negatives for item in complete),
        )
    report = FixtureReport(
        status=status,
        issues=issues,
        suite_id=suite.suite_id,
        rule_id=suite.rule_id,
        positive_cases=positives,
        negative_cases=negatives,
        cases=cases,
        metrics=metrics,
        manifest={
            "contract": "aegify-rule-fixtures/v1",
            "rule_digest": digest_bytes(rule_yaml.encode("utf-8")),
            "suite_digest": digest_bytes(canonical_json(suite.model_dump(mode="json"))),
            **implementation_manifest(engine),
            "config": engine.config.model_dump(mode="json", exclude={"anthropic_api_key"}),
            "engine_version": version("aegify-sast"),
            "python": sys.version.split()[0],
            "line_tolerance": 0,
            "source_execution": False,
            "suite_version": suite.suite_version,
        },
    )
    report.result_digest = result_digest(report)
    return report


def main() -> int:
    logging.disable(logging.CRITICAL)
    try:
        memory_limit = None
        if sys.platform.startswith("linux"):
            import resource

            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            memory_limit = min([2 * 1024**3] + [value for value in (soft, hard) if value >= 0])
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        if len(sys.argv) != 2:
            raise ValueError("worker input required")
        payload = strict_json(read_input(Path(sys.argv[1]), MAX_INPUT_BYTES))
        if not isinstance(payload, dict) or set(payload) != {
            "rule_yaml",
            "suite",
            "timeout_seconds",
        }:
            raise ValueError("invalid worker input")
        if not isinstance(payload["rule_yaml"], str):
            raise ValueError("invalid rule input")
        suite = RuleFixtureSuite.model_validate(payload["suite"])
        with tempfile.TemporaryDirectory(prefix="evaluation-") as directory:
            report = evaluate_suite(payload["rule_yaml"], suite, Path(directory))
        report.manifest["wall_timeout_seconds"] = payload["timeout_seconds"]
        report.manifest["memory_limit_bytes"] = memory_limit
        report.result_digest = result_digest(report)
        raw = canonical_json(report.model_dump(mode="json"))
        if len(raw) > MAX_OUTPUT_BYTES:
            raise ValueError("report size limit")
    except RuleInputError as error:
        raw = canonical_json(
            FixtureReport(
                status="error", issues=["invalid_rule"], diagnostics=error.diagnostics
            ).model_dump()
        )
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        raw = canonical_json(
            FixtureReport(
                status="error",
                issues=["invalid_rule_yaml"],
                diagnostics=[
                    {
                        "code": "invalid_rule_yaml",
                        "message": "Rule YAML could not be parsed.",
                        "line": mark.line + 1 if mark is not None else None,
                    }
                ],
            ).model_dump()
        )
    except Exception:
        # Raw YAML/regex/parser exceptions may include source or worker paths.
        raw = canonical_json(
            FixtureReport(status="error", issues=["rule_or_worker_invalid"]).model_dump()
        )
    sys.stdout.buffer.write(raw + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
