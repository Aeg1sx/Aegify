"""Reproducible static-only OWASP Python benchmark runner."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from dataclasses import asdict
from importlib.metadata import distributions
from pathlib import Path
from typing import Any

from aegify import __version__
from aegify.config import AegifyConfig
from aegify.models import ScanStatus
from aegify.quality.owasp import evaluate_cases, inventory_python_sources, read_labels
from aegify.scanner.ast_parser import parser_fingerprint
from aegify.scanner.engine import ScanEngine


def _json_digest(value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _code_digest(root: Path, suffixes: set[str]) -> str:
    return _json_digest(
        {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts
        }
    )


def _implementation_manifest(engine: ScanEngine) -> dict[str, Any]:
    package = Path(__file__).resolve().parents[1]
    rule_candidates = [
        package / "bundled_rules",
        package.parents[1] / "rules",
        package.parents[2] / "rules",
    ]
    rules = next((candidate for candidate in rule_candidates if candidate.is_dir()), None)
    if rules is None:
        raise ValueError("bundled rule directory is unavailable for provenance")
    return {
        "scanner_version": __version__,
        "scanner_code_and_modelpacks_digest": _code_digest(package, {".py", ".yml", ".yaml"}),
        "bundled_rules_digest": _code_digest(rules, {".yml", ".yaml"}),
        "rule_definitions_digest": _json_digest(
            [
                asdict(rule.definition)
                for rule in sorted(engine.registry.get_all(), key=lambda rule: rule.definition.id)
            ]
        ),
        "parser_fingerprint": parser_fingerprint(),
        "packages": dict(
            sorted(
                (item.metadata["Name"].lower(), item.version)
                for item in distributions()
                if item.metadata["Name"]
            )
        ),
        "python": platform.python_version(),
        "system": platform.system(),
        "system_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
    }


def _peak_memory() -> dict[str, Any]:
    try:
        import resource
    except ImportError:
        return {"peak_rss_self_bytes": None, "peak_rss_children_bytes": None}
    scale = 1 if platform.system() == "Darwin" else 1024
    return {
        "peak_rss_self_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale,
        "peak_rss_children_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * scale,
        "memory_scope": "Process-lifetime high-water marks; separate peaks, not a summed total",
    }


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
    implementation = _implementation_manifest(engine)
    result = engine.scan_files(root, [path.resolve() for path in sources])
    # Bind all source and auxiliary inputs, not just the parsed Python inventory.
    if inventory_python_sources(root)[1] != source_digest:
        raise ValueError("benchmark corpus changed during analysis")
    if expected_results.read_bytes() != label_bytes:
        raise ValueError("benchmark labels changed during analysis")
    if _implementation_manifest(engine) != implementation:
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
        "config_digest": _json_digest(config.model_dump(mode="json")),
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
        **_peak_memory(),
    }
    report["outcomes_digest"] = _json_digest(report["cases"])
    report["evaluation_complete"] = (
        result.status == ScanStatus.COMPLETED
        and not result.analysis_gaps
        and report["scored_case_fraction"] == 1.0
    )
    return report
