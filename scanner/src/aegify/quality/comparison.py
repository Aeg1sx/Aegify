"""Validate and compare saved OWASP case reports without rerunning applications."""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegify.quality.artifacts import parse_json_object, read_regular_file
from aegify.quality.benchmark import digest_bytes
from aegify.quality.owasp import case_metrics
from aegify.quality.provenance import json_digest

CHANNELS = ("all_candidates", "advisory", "blocking")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_EVALUATION = "owasp-python-exact-case-cwe-v1"
_MATCHING = "Exact relative testcode path and exact CWE; at most one hit per case/channel"
Outcome = Literal["tp", "fp", "fn", "tn", "unscored"]


class CaseOutcomes(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    all_candidates: Outcome
    advisory: Outcome
    blocking: Outcome


class SavedCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    case: str = Field(pattern=r"^BenchmarkTest[0-9]{5,8}$")
    file_path: str
    category: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    cwe: int = Field(ge=1, le=99999)
    positive: bool
    unscored_reason: (
        Literal["analysis_incomplete", "file_not_analyzed", "no_executed_cwe_rule"] | None
    )
    outcomes: CaseOutcomes
    matched_rules: list[str] = Field(max_length=10_000)
    matched_finding_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_identity_and_outcomes(self) -> SavedCase:
        if self.file_path != f"testcode/{self.case}.py":
            raise ValueError("case path does not match its identity")
        if self.matched_rules != sorted(set(self.matched_rules)) or any(
            not re.fullmatch(r"AEG-[A-Z0-9-]+", rule) for rule in self.matched_rules
        ):
            raise ValueError("matched rules must be sorted unique Aegify IDs")
        if self.matched_finding_count < len(self.matched_rules) or bool(self.matched_rules) != bool(
            self.matched_finding_count
        ):
            raise ValueError("matched findings and rules disagree")
        outcomes = self.outcomes.model_dump()
        if self.unscored_reason:
            if set(outcomes.values()) != {"unscored"}:
                raise ValueError("an unscored case must abstain in every channel")
        else:
            if not set(outcomes.values()) <= ({"tp", "fn"} if self.positive else {"fp", "tn"}):
                raise ValueError("case outcomes disagree with the label")
            detected = self.outcomes.all_candidates in {"tp", "fp"}
            if detected != bool(self.matched_rules):
                raise ValueError("case outcome disagrees with matched rules")
            if not detected and any(value in {"tp", "fp"} for value in outcomes.values()):
                raise ValueError("a channel hit requires an all-candidate hit")
        return self


def _csv_cases(material: bytes) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(material.decode("utf-8-sig")), strict=True)
    fields = {
        "case",
        "file_path",
        "category",
        "cwe",
        "positive",
        "unscored_reason",
        "matched_rules",
        "matched_finding_count",
        *CHANNELS,
    }
    if (
        reader.fieldnames is None
        or set(reader.fieldnames) != fields
        or len(reader.fieldnames) != 11
    ):
        raise ValueError("case CSV requires the exact exported columns")
    cases: list[dict[str, Any]] = []
    for row in reader:
        if None in row or None in row.values() or row["positive"] not in {"true", "false"}:
            raise ValueError("malformed case CSV row")
        if not re.fullmatch(r"[1-9][0-9]{0,4}", row["cwe"]) or not re.fullmatch(
            r"0|[1-9][0-9]{0,8}", row["matched_finding_count"]
        ):
            raise ValueError("case CSV counts require decimal integers")
        rules = row["matched_rules"]
        if "|" in rules and ";" in rules:
            raise ValueError("case CSV uses mixed rule separators")
        cases.append(
            {
                "case": row["case"],
                "file_path": row["file_path"],
                "category": row["category"],
                "cwe": int(row["cwe"]),
                "positive": row["positive"] == "true",
                "unscored_reason": row["unscored_reason"] or None,
                "outcomes": {key: row[key] for key in CHANNELS},
                "matched_rules": re.split(r"[|;]", rules) if rules else [],
                "matched_finding_count": int(row["matched_finding_count"]),
            }
        )
        if len(cases) > 50_000:
            raise ValueError("case inventory exceeds 50000 entries")
    return cases


def _same(actual: Any, expected: Any, name: str) -> None:
    # JSON identity distinguishes booleans from counts and keeps null denominators.
    if json_digest(actual) != json_digest(expected):
        raise ValueError(f"report {name} disagrees with case evidence")


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"report {name} must be an object")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"report {name} requires a SHA-256 digest")
    return value


def load_owasp_report(path: Path, cases_csv: Path | None = None) -> dict[str, Any]:
    """Verify internal consistency; digests do not authenticate an outside author."""
    material = read_regular_file(path, limit=32 * 1024 * 1024)
    report = parse_json_object(material)
    if (
        type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
        or report.get("evaluation") != _EVALUATION
        or report.get("language") != "python"
        or report.get("matching") != _MATCHING
    ):
        raise ValueError("comparison requires OWASP Python exact-case/CWE v1 reports")
    rows: Any
    if cases_csv:
        if "cases" in report:
            raise ValueError("provide embedded cases or an explicit CSV, never both")
        rows = _csv_cases(read_regular_file(cases_csv, limit=16 * 1024 * 1024))
    else:
        rows = report.get("cases")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 50_000:
        raise ValueError("comparison requires 1–50000 complete case rows")
    cases = [SavedCase.model_validate(row).model_dump() for row in rows]
    names = [case["case"] for case in cases]
    if names != sorted(set(names)):
        raise ValueError("case identities must be sorted and unique")
    _same(report.get("outcomes_digest"), json_digest(cases), "outcomes_digest")
    positives = sum(case["positive"] for case in cases)
    reasons = Counter(case["unscored_reason"] for case in cases if case["unscored_reason"])
    for name, value in {
        "label_cases": len(cases),
        "positive_labels": positives,
        "negative_labels": len(cases) - positives,
        "scored_case_fraction": (len(cases) - sum(reasons.values())) / len(cases),
        "unscored_reasons": dict(reasons),
    }.items():
        _same(report.get(name), value, name)
    status, gaps = report.get("analysis_status"), report.get("analysis_gaps")
    if (
        not isinstance(status, str)
        or status not in {"completed", "partial", "failed"}
        or not isinstance(gaps, list)
    ):
        raise ValueError("report analysis health is missing or invalid")
    unhealthy = status != "completed" or bool(gaps)
    if any((case["unscored_reason"] == "analysis_incomplete") != unhealthy for case in cases):
        raise ValueError("case abstention disagrees with analysis health")
    _same(report.get("evaluation_complete"), not unhealthy and not reasons, "evaluation_complete")
    metrics: dict[str, Any] = {}
    for channel in CHANNELS:
        metrics[channel] = case_metrics(case["outcomes"][channel] for case in cases)
        metrics[channel]["recall_over_all_positive_labels"] = (
            metrics[channel]["true_positives"] / positives if positives else None
        )
    _same(report.get("metrics"), metrics, "metrics")
    by_cwe = {
        str(cwe): {
            channel: case_metrics(case["outcomes"][channel] for case in cases if case["cwe"] == cwe)
            for channel in CHANNELS
        }
        for cwe in sorted({case["cwe"] for case in cases})
    }
    _same(report.get("by_cwe"), by_cwe, "by_cwe")
    provenance = _object(report.get("provenance"), "provenance")
    for key in ("corpus_digest", "ground_truth_digest", "config_digest"):
        _digest(provenance.get(key), key)
    config = _object(provenance.get("config"), "config")
    # The original v1 runner hashed the default empty API key but omitted it from
    # the serialized public configuration. Preserve that exact legacy contract.
    if "anthropic_api_key" in config:
        raise ValueError("public benchmark configuration must not include provider keys")
    _same(
        provenance["config_digest"],
        json_digest({**config, "anthropic_api_key": ""}),
        "config_digest",
    )
    if (
        provenance.get("llm_enabled") is not False
        or provenance.get("repository_code_executed") is not False
    ):
        raise ValueError("comparison requires source-only, non-LLM report provenance")
    for key in ("requested_python_files", "analyzed_python_files"):
        if type(provenance.get(key)) is not int or not 0 <= provenance[key] <= 50_000:
            raise ValueError("report Python file counts are invalid")
    if provenance["analyzed_python_files"] > provenance["requested_python_files"]:
        raise ValueError("analyzed file count exceeds the requested count")
    if provenance.get("python_parser_execution") != "sequential_scan_files":
        raise ValueError("report parser execution contract is unsupported")
    if provenance.get("workspace_snapshot") != "" or not unhealthy:
        _digest(provenance.get("workspace_snapshot"), "workspace_snapshot")
    if (
        _object(config.get("llm"), "LLM configuration").get("enabled") is not False
        or _object(config.get("storage"), "storage configuration").get("backend") != "memory"
        or _object(config.get("rules"), "rule configuration").get("custom_rules") is not None
    ):
        raise ValueError("configuration disagrees with source-only benchmark execution")
    unscored_findings = _object(report.get("unscored_findings"), "unscored_findings")
    if any(
        key not in {"outside_labeled_case", "unverified_rule_cwe", "different_cwe"}
        or type(value) is not int
        or value < 0
        for key, value in unscored_findings.items()
    ):
        raise ValueError("report unscored observation counts are invalid")
    implementation = _object(provenance.get("implementation"), "implementation")
    for key in (
        "scanner_code_and_modelpacks_digest",
        "bundled_rules_digest",
        "rule_definitions_digest",
    ):
        _digest(implementation.get(key), key)
    for key in (
        "scanner_version",
        "parser_fingerprint",
        "python",
        "system",
        "system_release",
        "machine",
    ):
        if not isinstance(implementation.get(key), str) or not implementation[key]:
            raise ValueError(f"report implementation lacks {key}")
    packages = _object(implementation.get("packages"), "packages")
    if not packages or any(not isinstance(value, str) for value in packages.values()):
        raise ValueError("report package versions are missing or invalid")
    executed = provenance.get("evaluated_rules")
    if not isinstance(executed, list) or not all(isinstance(rule, str) for rule in executed):
        raise ValueError("report executed-rule inventory is missing")
    if executed != sorted(set(executed)):
        raise ValueError("report executed-rule inventory must be sorted and unique")
    by_rule = _object(report.get("by_rule"), "by_rule")
    if len(by_rule) > 10_000 or len(executed) > 10_000:
        raise ValueError("report rule inventory exceeds its bound")
    derived_rules: dict[str, Any] = {}
    for rule, values in by_rule.items():
        values = _object(values, "rule metrics")
        cwe = values.get("cwe")
        if rule not in executed or type(cwe) is not int or str(cwe) not in by_cwe:
            raise ValueError("report per-rule scope disagrees with executed rules or labels")
        derived_rules[rule] = {
            "cwe": cwe,
            **case_metrics(
                "unscored"
                if case["unscored_reason"]
                else ("tp" if case["positive"] else "fp")
                if rule in case["matched_rules"]
                else ("fn" if case["positive"] else "tn")
                for case in cases
                if case["cwe"] == cwe
            ),
        }
    _same(by_rule, derived_rules, "by_rule")
    supported_cwes = {values["cwe"] for values in by_rule.values()}
    for case in cases:
        if (
            not case["unscored_reason"]
            and case["cwe"] not in supported_cwes
            or case["unscored_reason"] == "no_executed_cwe_rule"
            and case["cwe"] in supported_cwes
        ):
            raise ValueError("case coverage disagrees with executed CWE rules")
        for rule in case["matched_rules"]:
            if rule not in by_rule or by_rule[rule]["cwe"] != case["cwe"]:
                raise ValueError("case matched rule is absent from its declared CWE scope")
    return {
        "artifact_digest": digest_bytes(material),
        "report": report,
        "cases": cases,
        "case_identity_digest": json_digest(
            [
                {key: case[key] for key in ("case", "file_path", "category", "cwe", "positive")}
                for case in cases
            ]
        ),
    }


def compare_owasp_reports(
    baseline: dict[str, Any], candidate: dict[str, Any], *, require_identical: bool = False
) -> dict[str, Any]:
    """Separate paired outcome changes, coverage changes and implementation replay."""
    before, after = baseline["report"], candidate["report"]
    left, right = before["provenance"], after["provenance"]
    mismatches = [
        key
        for key in ("corpus_digest", "ground_truth_digest", "config_digest")
        if left[key] != right[key]
    ]
    if baseline["case_identity_digest"] != candidate["case_identity_digest"]:
        mismatches.append("case_identity_digest")
    if mismatches:
        raise ValueError("reports are not comparable: " + ", ".join(mismatches))
    implementation_changes = sorted(
        key
        for key in set(left["implementation"]) | set(right["implementation"])
        if left["implementation"].get(key) != right["implementation"].get(key)
    )
    if left["evaluated_rules"] != right["evaluated_rules"]:
        implementation_changes.append("evaluated_rules")
    pairs = list(zip(baseline["cases"], candidate["cases"], strict=True))
    channels: dict[str, Any] = {}
    for channel in CHANNELS:
        jointly_scored = [
            (a, b) for a, b in pairs if not a["unscored_reason"] and not b["unscored_reason"]
        ]
        before_paired = case_metrics(a["outcomes"][channel] for a, _ in jointly_scored)
        after_paired = case_metrics(b["outcomes"][channel] for _, b in jointly_scored)
        transitions = Counter(
            f"{a['outcomes'][channel]}->{b['outcomes'][channel]}" for a, b in pairs
        )
        regressions = [
            a["case"]
            for a, b in jointly_scored
            if a["outcomes"][channel] in {"tp", "tn"} and b["outcomes"][channel] in {"fn", "fp"}
        ]
        improvements = [
            a["case"]
            for a, b in jointly_scored
            if a["outcomes"][channel] in {"fn", "fp"} and b["outcomes"][channel] in {"tp", "tn"}
        ]
        channels[channel] = {
            "jointly_scored_cases": len(jointly_scored),
            "baseline_paired_metrics": before_paired,
            "candidate_paired_metrics": after_paired,
            "transitions": dict(sorted(transitions.items())),
            "improved_cases": improvements,
            "regressed_cases": regressions,
            "metric_deltas": {
                key: after_paired[key] - before_paired[key]
                if before_paired[key] is not None and after_paired[key] is not None
                else None
                for key in ("precision", "recall", "f1", "accuracy", "false_positive_rate", "mcc")
            },
        }
    coverage_lost = [
        a["case"] for a, b in pairs if not a["unscored_reason"] and b["unscored_reason"]
    ]
    coverage_gained = [
        a["case"] for a, b in pairs if a["unscored_reason"] and not b["unscored_reason"]
    ]
    changes = [
        {
            "case": a["case"],
            "cwe": a["cwe"],
            "positive": a["positive"],
            "baseline": {
                key: a[key]
                for key in ("outcomes", "unscored_reason", "matched_rules", "matched_finding_count")
            },
            "candidate": {
                key: b[key]
                for key in ("outcomes", "unscored_reason", "matched_rules", "matched_finding_count")
            },
        }
        for a, b in pairs
        if a != b
    ]
    identical = (
        not implementation_changes
        and not changes
        and all(
            left.get(key) == right.get(key)
            for key in (
                "requested_python_files",
                "analyzed_python_files",
                "python_parser_execution",
                "workspace_snapshot",
            )
        )
        and all(
            before[key] == after[key]
            for key in ("analysis_status", "analysis_gaps", "unscored_findings")
        )
    )
    regression_free = not coverage_lost and not any(
        channels[key]["regressed_cases"] for key in CHANNELS
    )
    gate_passed = identical if require_identical else regression_free
    complete = before["evaluation_complete"] and after["evaluation_complete"]
    # A diagnostic comparison can be useful while still retaining exit 3.
    exit_code = (
        2
        if "failed" in {before["analysis_status"], after["analysis_status"]}
        else 1
        if not gate_passed
        else 3
        if not complete
        else 0
    )
    return {
        "schema_version": 1,
        "comparison": "owasp-python-paired-v1",
        "mode": "identical" if require_identical else "no_case_regressions",
        "baseline_artifact_digest": baseline["artifact_digest"],
        "candidate_artifact_digest": candidate["artifact_digest"],
        "input_identity": {
            **{key: left[key] for key in ("corpus_digest", "ground_truth_digest", "config_digest")},
            "case_identity_digest": baseline["case_identity_digest"],
        },
        "implementation_changes": implementation_changes,
        "identical_replay": identical,
        "regression_free": regression_free,
        "evaluation_complete": complete,
        "exit_code": exit_code,
        "coverage_lost": coverage_lost,
        "coverage_gained": coverage_gained,
        "baseline_unscored_findings": before["unscored_findings"],
        "candidate_unscored_findings": after["unscored_findings"],
        "channels": channels,
        "changed_cases": changes,
        "limitations": [
            "Internal consistency and paired change only; no independent label adjudication.",
            "Public synthetic cases are not held-out production or live AI evaluation.",
            "Identical replay excludes timing/RSS and does not prove performance equivalence.",
            "Digests identify supplied artifacts; they do not authenticate their authors.",
            "No significance claim or independent-sample assumption for related templates.",
            "A regression-free comparison is not an absolute precision/recall release gate.",
        ],
    }
