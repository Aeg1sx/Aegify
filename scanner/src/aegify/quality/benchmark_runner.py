"""Frozen-input execution of the owned finding-location benchmark."""

from __future__ import annotations

import time
from pathlib import Path

from aegify.config import AegifyConfig
from aegify.models import ScanStatus
from aegify.quality.artifacts import parse_json_object, read_regular_file
from aegify.quality.benchmark import (
    BenchmarkReport,
    GroundTruthManifest,
    _path,
    digest_bytes,
    digest_source_tree,
    evaluate_findings,
)
from aegify.quality.provenance import implementation_manifest, json_digest, peak_memory
from aegify.scanner.engine import ScanEngine


def benchmark_root(target: Path) -> Path:
    if target.is_symlink() or not (target.is_dir() or target.is_file()):
        raise ValueError("benchmark target must be a regular file or directory")
    return (target if target.is_dir() else target.parent).resolve()


def run_owned_benchmark(target: Path, ground_truth: Path) -> BenchmarkReport:
    """Analyze static input using trusted defaults and bind every consumed input."""
    started = time.monotonic()
    root = benchmark_root(target)
    target = target.resolve()
    label_bytes = read_regular_file(ground_truth, limit=4 * 1024 * 1024)
    manifest = GroundTruthManifest.model_validate(parse_json_object(label_bytes))
    # A single-file scan can still consume auxiliary inputs beside that file.
    # Bind the complete enclosing directory in both modes.
    source_digest = digest_source_tree(root)
    line_counts: dict[str, int] = {}
    for relative in sorted({item.file_path for item in manifest.expected}):
        source = root / relative
        if target.is_file() and source != target:
            raise ValueError("expected finding is outside the selected file")
        material = read_regular_file(source, limit=8 * 1024 * 1024)
        line_counts[relative] = len(material.splitlines())
    for item in manifest.expected:
        if item.line_start > line_counts[item.file_path]:
            raise ValueError("expected finding line is outside its source file")

    # BaseSettings construction must not read repository YAML or AEGIFY_* env.
    config = AegifyConfig.model_construct()
    config.scan.exclude = []
    config.scan.max_workers = 1
    config.scan.max_file_size_kb = 1024
    config.scan.max_findings_per_rule = 0
    config.scan.max_findings_per_file = 0
    config.rules.severity_threshold = "low"
    config.taint.max_contexts = 50_000
    engine = ScanEngine(config=config)
    effective_config = config.model_dump(mode="json", exclude={"anthropic_api_key"})
    implementation = implementation_manifest(engine)
    result = engine.scan(target)
    if digest_source_tree(root) != source_digest:
        raise ValueError("benchmark corpus changed during analysis")
    if read_regular_file(ground_truth, limit=4 * 1024 * 1024) != label_bytes:
        raise ValueError("benchmark labels changed during analysis")
    if implementation_manifest(engine) != implementation:
        raise ValueError("scanner implementation changed during analysis")
    if config.model_dump(mode="json", exclude={"anthropic_api_key"}) != effective_config:
        raise ValueError("scanner configuration changed during analysis")

    report = evaluate_findings(
        result.findings,
        manifest.expected,
        target_root=root,
        rule_scope=manifest.rule_scope,
        corpus_id=manifest.corpus_id,
        corpus_version=manifest.corpus_version,
        source_digest=source_digest,
        ground_truth_digest=digest_bytes(label_bytes),
    )
    report.analysis_status = result.status
    report.analysis_gaps = result.analysis_gaps
    report.missing_rules = sorted(set(manifest.rule_scope) - set(result.evaluated_rules))
    report.missing_files = sorted(
        {item.file_path for item in manifest.expected}
        - {_path(path, root) for path in result.analyzed_files}
    )
    report.evaluation_complete = (
        result.status == ScanStatus.COMPLETED
        and not result.analysis_gaps
        and not report.missing_rules
        and not report.missing_files
    )
    report.provenance = {
        "implementation": implementation,
        "config": effective_config,
        "target": "." if target.is_dir() else target.name,
        "executed_rules": sorted(result.evaluated_rules),
        "analyzed_files": sorted(_path(path, root) for path in result.analyzed_files),
        "llm_enabled": False,
        "repository_code_executed": False,
    }
    report.provenance["config_digest"] = json_digest(report.provenance["config"])
    # Bind all scoped observations, including duplicate and within-tolerance hits.
    observations = sorted(
        (finding.rule_id, _path(finding.file_path, root), finding.line_start)
        for finding in result.findings
        if finding.rule_id in manifest.rule_scope
    )
    report.outcomes_digest = json_digest(
        {
            "observations": observations,
            "metrics": report.metrics.model_dump(),
            "by_rule": {key: value.model_dump() for key, value in report.by_rule.items()},
            "unmatched_actual": report.unmatched_actual,
            "unmatched_expected": report.unmatched_expected,
            "missing_rules": report.missing_rules,
            "missing_files": report.missing_files,
            "analysis_status": report.analysis_status,
            "analysis_gaps": [gap.model_dump() for gap in report.analysis_gaps],
        }
    )
    report.measurement = {
        "scan_seconds": result.duration_seconds,
        "evaluation_wall_seconds": time.monotonic() - started,
        **peak_memory(),
    }
    return report
