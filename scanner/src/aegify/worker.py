"""Bounded source-snapshot adapter for the shared deterministic ScanEngine.

Repository code, configuration and build scripts are data. This entry point
never imports the target application, installs its dependencies or executes it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from typing import Any

from aegify.config import (
    AegifyConfig,
    ContextConfig,
    LLMConfig,
    ReportingConfig,
    RulesConfig,
    ScanConfig,
    StorageConfig,
    TaintAnalysisConfig,
)
from aegify.models import ScanProgress
from aegify.reporter.sarif import SARIFReporter
from aegify.scanner.ast_parser import parser_fingerprint
from aegify.scanner.engine import ScanEngine

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 100 * 1024 * 1024
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 500 * 1024
MAX_FILES = 1000


def snapshot_digest(payload: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(
        f"aegify-source/v1\n{payload['provider']}\0{payload['repository']}\0"
        f"{payload['commit']}\n".encode()
    )
    for item in sorted(payload["files"], key=lambda item: item["path"].encode("utf-8")):
        digest.update(f"{item['path']}\0{item['sha256']}\n".encode())
    return "sha256:" + digest.hexdigest()


def validate_snapshot(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("Unsupported source snapshot contract")
    if payload.get("provider") not in {"github", "gitlab"}:
        raise ValueError("Invalid source provider")
    repository = payload.get("repository")
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", repository
    ):
        raise ValueError("Invalid repository identity")
    if not isinstance(payload.get("commit"), str) or not re.fullmatch(
        r"[a-fA-F0-9]{40}(?:[a-fA-F0-9]{24})?", payload["commit"]
    ):
        raise ValueError("Immutable commit required")
    files = payload.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise ValueError("Source file count exceeds the worker limit")
    seen: set[str] = set()
    total = 0
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("Invalid source file")
        path, content = item.get("path"), item.get("content")
        if (
            not isinstance(path, str)
            or not path
            or len(path.encode()) > 1024
            or path.startswith("/")
            or "\\" in path
            or ":" in path
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or any(part in {"", ".", "..", ".git"} for part in path.split("/"))
            or PurePosixPath(path).is_absolute()
            or path in seen
            or not isinstance(content, str)
        ):
            raise ValueError("Invalid or duplicate source path")
        seen.add(path)
        data = content.encode("utf-8")
        total += len(data)
        if len(data) > MAX_FILE_BYTES or total > MAX_SOURCE_BYTES:
            raise ValueError("Source bytes exceed the worker limit")
        if hashlib.sha256(data).hexdigest() != item.get("sha256"):
            raise ValueError("Source content digest mismatch")
    if snapshot_digest(payload) != payload.get("sourceDigest"):
        raise ValueError("Source snapshot digest mismatch")
    if not isinstance(payload.get("truncated"), bool):
        raise ValueError("Explicit source coverage required")
    return payload


def worker_config() -> AegifyConfig:
    """Operator contract shared across every job; target configuration is ignored."""
    return AegifyConfig(
        scan=ScanConfig(max_workers=2, max_findings_per_rule=500, max_findings_per_file=200),
        rules=RulesConfig(severity_threshold="low"),
        taint=TaintAnalysisConfig(max_contexts=50_000),
        storage=StorageConfig(backend="memory"),
        reporting=ReportingConfig(),
        context=ContextConfig(),
        llm=LLMConfig(enabled=False),
        anthropic_api_key="",
    )


def implementation_manifest(engine: ScanEngine) -> dict[str, Any]:
    package = Path(__file__).resolve().parent
    implementation = hashlib.sha256()
    for path in sorted(package.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".yml", ".yaml"}:
            implementation.update(path.relative_to(package).as_posix().encode() + b"\0")
            implementation.update(hashlib.sha256(path.read_bytes()).digest())
    rules = [
        {
            "definition": asdict(rule.definition),
            "detection": rule.get_detection_metadata(),
            "rawYaml": getattr(rule, "raw_yaml", ""),
        }
        for rule in sorted(engine.registry.get_all(), key=lambda rule: rule.definition.id)
    ]
    return {
        "engineDigest": "sha256:" + implementation.hexdigest(),
        "rulesDigest": "sha256:"
        + hashlib.sha256(json.dumps(rules, sort_keys=True, default=str).encode()).hexdigest(),
        "parserFingerprint": parser_fingerprint(),
    }


def run_snapshot(payload: dict[str, Any], workspace: Path) -> dict[str, Any]:
    payload = validate_snapshot(payload)
    workspace.mkdir(mode=0o700)
    for item in payload["files"]:
        target = workspace / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("xb") as stream:
            stream.write(item["content"].encode("utf-8"))
        target.chmod(0o400)

    def progress(value: ScanProgress) -> None:
        print(
            json.dumps(
                {
                    "phase": value.phase,
                    "name": value.phase_name[:100],
                    "percent": value.overall_progress,
                }
            ),
            flush=True,
        )

    config = worker_config()
    engine = ScanEngine(config=config, on_progress=progress)
    previous = Path.cwd()
    try:
        # Relative source paths stay stable across worker hosts and retries.
        os.chdir(workspace)
        result = engine.scan(Path("."))
        result.analysis_scope = "files"  # explicitly selected provider snapshot
        if payload["truncated"]:
            result.add_gap(
                "source_fetch_incomplete",
                "fetch",
                "The provider snapshot omitted source files or reached an input limit",
            )
        for item in payload["files"]:
            if hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() != item["sha256"]:
                result.add_gap("source_changed", "snapshot", "Source bytes changed during analysis")
                break
        report = SARIFReporter().generate(result, call_graph=engine._last_call_graph)
    finally:
        os.chdir(previous)
    properties = report["runs"][0]["properties"]
    properties["workerManifest"] = {
        "version": 1,
        "sourceDigest": payload["sourceDigest"],
        "commit": payload["commit"],
        "sourceSelection": "source-and-config",
        "engine": version("aegify-sast"),
        "python": sys.version.split()[0],
        "treeSitter": version("tree-sitter"),
        **implementation_manifest(engine),
        "config": config.model_dump(mode="json", exclude={"anthropic_api_key"}),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("Worker input exceeds the size limit")
        payload = validate_snapshot(json.loads(raw))
        with tempfile.TemporaryDirectory(prefix="aegify-source-") as temporary:
            report = run_snapshot(payload, Path(temporary) / "source")
        encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode()
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ValueError("Worker report exceeds the size limit")
        with args.output.open("xb") as output:
            output.write(encoded)
        return 0
    except Exception:
        # No source, credentials, traceback or operator paths in shared job logs.
        print("Snapshot analysis failed; no report was published.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
