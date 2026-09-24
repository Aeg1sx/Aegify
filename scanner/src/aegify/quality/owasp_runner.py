"""Reproducible static-only OWASP Python benchmark runner."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from aegify.config import AegifyConfig
from aegify.models import ScanStatus
from aegify.quality.owasp import evaluate_cases, inventory_python_sources, read_labels
from aegify.quality.provenance import implementation_manifest, json_digest, peak_memory
from aegify.scanner.engine import ScanEngine


def run_owasp_python(root: Path, expected_results: Path) -> dict[str, Any]:
    """Run local source analysis without corpus configuration, code execution or AI."""
    started = time.monotonic()
    sources, source_digest = inventory_python_sources(root)
    root = root.resolve()
    if expected_results.is_symlink() or not expected_results.is_file():
        raise ValueError("expected-results must be a regular file")
    if expected_results.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("expected-results CSV exceeds 4 MiB")
    label_bytes = expected_results.read_bytes()
    cases = read_labels(label_bytes)
    # Construct trusted defaults without BaseSettings environment resolution.
    # Corpus .aegify.yml, custom rules, external storage and provider keys are unused.
    config = AegifyConfig.model_construct()
    config.scan.languages = ["python"]
    # scan_files preserves repository-qualified ASTs and currently parses serially.
    config.scan.max_workers = 1
    config.scan.max_file_size_kb = 1024
    config.scan.max_findings_per_rule = 0
    config.scan.max_findings_per_file = 0
    config.rules.severity_threshold = "low"
    config.taint.max_contexts = 50_000
    engine = ScanEngine(config=config)
    implementation = implementation_manifest(engine)
    result = engine.scan_files(root, [path.resolve() for path in sources])
    # Bind all source and auxiliary inputs, not just the parsed Python inventory.
    if inventory_python_sources(root)[1] != source_digest:
        raise ValueError("benchmark corpus changed during analysis")
    if expected_results.read_bytes() != label_bytes:
        raise ValueError("benchmark labels changed during analysis")
    if implementation_manifest(engine) != implementation:
        raise ValueError("scanner implementation changed during analysis")
    report = evaluate_cases(
        result,
        cases,
        target_root=root,
        rule_cwes={
            rule.definition.id: rule.definition.cwe_id for rule in engine.registry.get_all()
        },
    )
    report["provenance"] = {
        "corpus_digest": source_digest,
        "ground_truth_digest": "sha256:" + hashlib.sha256(label_bytes).hexdigest(),
        "workspace_snapshot": result.workspace_snapshot,
        "config": config.model_dump(mode="json", exclude={"anthropic_api_key"}),
        "config_digest": json_digest(config.model_dump(mode="json")),
        "implementation": implementation,
        "evaluated_rules": sorted(result.evaluated_rules),
        "requested_python_files": len(sources),
        "analyzed_python_files": result.files_scanned,
        "python_parser_execution": "sequential_scan_files",
        "llm_enabled": False,
        "repository_code_executed": False,
    }
    report["measurement"] = {
        "scan_seconds": result.duration_seconds,
        "evaluation_wall_seconds": time.monotonic() - started,
        **peak_memory(),
    }
    report["outcomes_digest"] = json_digest(report["cases"])
    report["evaluation_complete"] = (
        result.status == ScanStatus.COMPLETED
        and not result.analysis_gaps
        and report["scored_case_fraction"] == 1.0
    )
    return report
