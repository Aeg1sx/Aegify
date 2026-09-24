"""Implementation and measurement identity shared by offline evaluations."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import asdict
from importlib.metadata import distributions
from pathlib import Path
from typing import Any

from aegify import __version__
from aegify.scanner.ast_parser import parser_fingerprint
from aegify.scanner.engine import ScanEngine


def json_digest(value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _code_digest(root: Path, suffixes: set[str]) -> str:
    return json_digest(
        {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts
        }
    )


def implementation_manifest(engine: ScanEngine) -> dict[str, Any]:
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
        "rule_definitions_digest": json_digest(
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


def peak_memory() -> dict[str, Any]:
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
