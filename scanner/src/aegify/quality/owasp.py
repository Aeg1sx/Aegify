"""Offline, case-level evaluation of OWASP Benchmark Python labels.

The labels describe one intended CWE per case, not every possible issue in a
file. Findings for other CWEs are retained as unscored observations. This is
not the official BenchmarkUtils scorecard implementation.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from aegify.models import Finding, FindingDisposition, ScanResult, ScanStatus

_MAX_LABELS = 50_000
_CHANNELS = ("all_candidates", "advisory", "blocking")


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    category: str
    positive: bool
    cwe: int

    @property
    def file_path(self) -> str:
        return f"testcode/{self.name}.py"


def read_labels(material: bytes) -> list[BenchmarkCase]:
    """Read strict upstream Python CSV labels without importing corpus code."""
    if len(material) > 4 * 1024 * 1024:
        raise ValueError("expected-results CSV exceeds 4 MiB")
    rows = csv.reader(io.StringIO(material.decode("utf-8-sig")), strict=True)
    cases: list[BenchmarkCase] = []
    names: set[str] = set()
    for row in rows:
        if not row or row[0].startswith("#"):
            continue
        if len(row) != 4:
            raise ValueError("expected-results rows require exactly four columns")
        name, category, positive, cwe = (field.strip() for field in row)
        if not re.fullmatch(r"BenchmarkTest[0-9]{5,8}", name):
            raise ValueError("invalid BenchmarkTest case name")
        if name in names:
            raise ValueError(f"duplicate benchmark case: {name}")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", category):
            raise ValueError("invalid benchmark category")
        if positive not in {"true", "false"} or not re.fullmatch(r"[1-9][0-9]{0,4}", cwe):
            raise ValueError("labels require literal true/false and a positive CWE number")
        names.add(name)
        cases.append(BenchmarkCase(name, category, positive == "true", int(cwe)))
        if len(cases) > _MAX_LABELS:
            raise ValueError("expected-results CSV exceeds the case limit")
    if not cases:
        raise ValueError("expected-results CSV contains no cases")
    return sorted(cases, key=lambda case: case.name)


def _relative_path(value: str, root: Path) -> str | None:
    path = PurePosixPath(value.replace("\\", "/"))
    if ".." in path.parts:
        return None
    if path.is_absolute():
        try:
            path = path.relative_to(root.as_posix())
        except ValueError:
            return None
    if not path.parts or ":" in path.parts[0]:
        return None
    return path.as_posix()


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _wilson(successes: int, trials: int) -> list[float] | None:
    if not trials:
        return None
    z = 1.959963984540054
    proportion = successes / trials
    scale = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / scale
    half = z * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials**2))
    return [max(0.0, center - half / scale), min(1.0, center + half / scale)]


def case_metrics(outcomes: Iterable[str]) -> dict[str, Any]:
    """Undefined ratios stay null; unscored cases never become true negatives."""
    counts = Counter(outcomes)
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
    total = tp + fp + fn + tn
    tpr, tnr = _ratio(tp, tp + fn), _ratio(tn, tn + fp)
    mcc_denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "scored_cases": total,
        "unscored_cases": counts["unscored"],
        "precision": _ratio(tp, tp + fp),
        "recall": tpr,
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "accuracy": _ratio(tp + tn, total),
        "false_positive_rate": _ratio(fp, fp + tn),
        "balanced_accuracy": (tpr + tnr) / 2 if tpr is not None and tnr is not None else None,
        "mcc": (tp * tn - fp * fn) / math.sqrt(mcc_denominator) if mcc_denominator else None,
        "precision_wilson_95": _wilson(tp, tp + fp),
        "recall_wilson_95": _wilson(tp, tp + fn),
    }


def _outcome(positive: bool, detected: bool) -> str:
    return ("tp" if positive else "fp") if detected else ("fn" if positive else "tn")


def evaluate_cases(
    result: ScanResult,
    cases: list[BenchmarkCase],
    *,
    target_root: Path,
    rule_cwes: Mapping[str, int | None],
) -> dict[str, Any]:
    """Match exact case paths and exact declared CWEs, once per case/channel.

    Any global analysis gap makes all case outcomes unscored: the current scan
    contract does not attribute every truncation or taint gap to individual cases.
    Missing files and absent executed CWE rules also abstain explicitly.
    """
    root = target_root.resolve()
    if len({case.name for case in cases}) != len(cases) or not cases:
        raise ValueError("case identities must be unique and nonempty")
    by_path = {case.file_path: case for case in cases}
    analyzed = {_relative_path(path, root) for path in result.analyzed_files}
    executed = {
        rule: rule_cwes[rule]
        for rule in result.evaluated_rules
        if rule in rule_cwes and rule_cwes[rule] is not None
    }
    supported_cwes = set(executed.values())
    observations: dict[str, list[Finding]] = defaultdict(list)
    unscored_findings: Counter[str] = Counter()
    complete = result.status == ScanStatus.COMPLETED and not result.analysis_gaps
    for finding in result.findings:
        case = by_path.get(_relative_path(finding.file_path, root) or "")
        if case is None:
            unscored_findings["outside_labeled_case"] += 1
        elif finding.rule_id not in executed or executed[finding.rule_id] != finding.cwe_id:
            unscored_findings["unverified_rule_cwe"] += 1
        elif finding.cwe_id != case.cwe:
            unscored_findings["different_cwe"] += 1
        else:
            observations[case.name].append(finding)

    rows: list[dict[str, Any]] = []
    reasons: Counter[str] = Counter()
    for case in sorted(cases, key=lambda case: case.name):
        reason = (
            "analysis_incomplete"
            if not complete
            else "file_not_analyzed"
            if case.file_path not in analyzed
            else "no_executed_cwe_rule"
            if case.cwe not in supported_cwes
            else None
        )
        if reason:
            reasons[reason] += 1
        matches = observations[case.name]
        detected = {
            "all_candidates": bool(matches),
            "advisory": any(f.disposition == FindingDisposition.ADVISORY for f in matches),
            "blocking": any(f.blocks_ci for f in matches),
        }
        rows.append(
            {
                "case": case.name,
                "file_path": case.file_path,
                "category": case.category,
                "cwe": case.cwe,
                "positive": case.positive,
                "unscored_reason": reason,
                "outcomes": {
                    channel: "unscored" if reason else _outcome(case.positive, detected[channel])
                    for channel in _CHANNELS
                },
                "matched_rules": sorted({f.rule_id for f in matches}),
                "matched_finding_count": len(matches),
            }
        )

    positive_count = sum(case.positive for case in cases)
    metrics: dict[str, Any] = {}
    for channel in _CHANNELS:
        metrics[channel] = case_metrics(row["outcomes"][channel] for row in rows)
        # This denominator retains every positive label, including abstentions.
        metrics[channel]["recall_over_all_positive_labels"] = _ratio(
            metrics[channel]["true_positives"], positive_count
        )
    by_cwe = {
        str(cwe): {
            channel: case_metrics(row["outcomes"][channel] for row in rows if row["cwe"] == cwe)
            for channel in _CHANNELS
        }
        for cwe in sorted({case.cwe for case in cases})
    }
    by_rule = {
        rule: {
            "cwe": cwe,
            **case_metrics(
                "unscored"
                if row["unscored_reason"]
                else _outcome(row["positive"], rule in row["matched_rules"])
                for row in rows
                if row["cwe"] == cwe
            ),
        }
        for rule, cwe in sorted(executed.items())
        if any(case.cwe == cwe for case in cases)
    }
    return {
        "schema_version": 1,
        "evaluation": "owasp-python-exact-case-cwe-v1",
        "language": "python",
        "matching": "Exact relative testcode path and exact CWE; at most one hit per case/channel",
        "label_cases": len(cases),
        "positive_labels": positive_count,
        "negative_labels": len(cases) - positive_count,
        "scored_case_fraction": (len(cases) - sum(reasons.values())) / len(cases),
        "unscored_reasons": dict(sorted(reasons.items())),
        "unscored_findings": dict(sorted(unscored_findings.items())),
        "analysis_status": result.status.value,
        "analysis_gaps": [gap.model_dump() for gap in result.analysis_gaps],
        "metrics": metrics,
        "by_cwe": by_cwe,
        "by_rule": by_rule,
        "cases": rows,
        "limitations": [
            "Public synthetic labels are not held-out or independent real-world validation.",
            "Exact CWE mapping has no implicit parent/child or tool-specific aliases.",
            "Other CWEs in a case and findings outside labeled cases are unscored.",
            "Blocking means engine disposition, not confirmed runtime impact.",
            "Wilson intervals assume independent Bernoulli cases; correlated templates and "
            "deployment shift are not covered.",
            "Per-rule metrics cover all labels for that rule's exact CWE; no rule-specific "
            "framework or variant suitability is inferred.",
        ],
    }


def inventory_python_sources(root: Path) -> tuple[list[Path], str]:
    """Hash the whole corpus, including OpenAPI/config; select Python for parsing."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("benchmark root must be a real directory")
    paths: list[Path] = []
    total = 0
    digest = hashlib.sha256()
    entries: list[Path] = []
    for path in root.rglob("*"):
        if len(entries) >= _MAX_LABELS:
            raise ValueError("benchmark corpus exceeds the entry limit")
        entries.append(path)
    for path in sorted(entries):
        if path.is_symlink():
            raise ValueError("benchmark corpus must not contain symbolic links")
        if path.is_dir():
            continue
        size_limit = (1 if path.suffix == ".py" else 8) * 1024 * 1024
        if not path.is_file() or path.stat().st_size > size_limit:
            raise ValueError("corpus inputs must be bounded regular files")
        material = path.read_bytes()
        total += len(material)
        if total > 256 * 1024 * 1024:
            raise ValueError("benchmark source inventory exceeds byte limits")
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(material).to_bytes(8, "big"))
        digest.update(material)
        if path.suffix == ".py":
            paths.append(path)
    if not paths:
        raise ValueError("benchmark corpus has no Python inputs")
    return paths, f"sha256:{digest.hexdigest()}"
