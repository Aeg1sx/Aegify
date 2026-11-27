"""Score source ranges in pinned before/after modules using the installed scanner CLI."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from aegify.config import AegifyConfig
from aegify.models import Language
from aegify.quality.artifacts import read_regular_file, write_report
from aegify.quality.provenance import implementation_manifest, json_digest
from aegify.scanner.engine import ScanEngine

CASES = Path(__file__).with_name("cases.json")
CONFIG = {
    "scan": {"max_workers": 1, "max_findings_per_file": 500, "max_findings_per_rule": 500},
    "rules": {"severity_threshold": "low"},
    "storage": {"backend": "memory"},
    "llm": {"enabled": False},
    "anthropic_api_key": "",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_bytes(cache, module, version, fetch):
    record = module[version]
    relative = "/".join([module["repository"], record["commit"], module["path"]])
    local = cache / relative
    if not local.exists() and fetch:
        with urllib.request.urlopen(
            "https://raw.githubusercontent.com/" + relative, timeout=30
        ) as stream:
            raw = stream.read(record["bytes"] + 1)
        if len(raw) != record["bytes"] or sha(raw) != record["sha256"]:
            raise ValueError(f"Upstream bytes differ for {relative}")
        local.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=local.parent, delete=False) as tmp:
            temp = Path(tmp.name)
            try:
                tmp.write(raw)
                tmp.flush()
                os.replace(temp, local)
            finally:
                temp.unlink(missing_ok=True)
    raw = read_regular_file(local, limit=record["bytes"])
    if len(raw) != record["bytes"] or sha(raw) != record["sha256"]:
        raise ValueError(f"Cached bytes differ for {relative}")
    return raw


def scan_module(raw, module, version, rule_ids, cwe):
    record = module[version]
    with tempfile.TemporaryDirectory(prefix="aegify-tls-review-") as tmp:
        work = Path(tmp)
        root = work / "source"
        source = root / module["path"]
        source.parent.mkdir(parents=True)
        source.write_bytes(raw)
        config = work / "scanner.json"
        config.write_text(json.dumps(CONFIG))
        output = work / "report.json"
        process = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "aegify.cli",
                "scan",
                str(root),
                "--config",
                str(config),
                "--no-llm",
                "--severity",
                "low",
                "--output",
                "json",
                "--output-file",
                str(output),
            ],
            cwd=work,
            env={k: os.environ[k] for k in ("PATH", "LANG", "TMPDIR") if k in os.environ},
            capture_output=True,
            timeout=120,
        )
        if process.returncode not in (0, 1, 3) or not output.is_file():
            raise RuntimeError(
                f"Scanner did not produce a usable report (exit {process.returncode})"
            )
        result = json.loads(read_regular_file(output, limit=32 * 1024 * 1024))
    analyzed = [(s["module_path"], s["source_digest"]) for s in result["analyzed_sources"]]
    if analyzed != [(module["path"], record["sha256"])]:
        raise ValueError(f"Scanner source identity differs for {module['path']}: {analyzed}")
    hits = []
    for finding in result["findings"]:
        if finding.get("cwe_id") != cwe:
            continue
        if (
            finding["provenance"]["module_path"] != module["path"]
            or finding["rule_id"] not in rule_ids
        ):
            raise ValueError("Unexpected finding source or rule identity")
        hits.append(
            {
                "line": finding["line_start"],
                "rule": finding["rule_id"],
                "evidence": finding["evidence_state"],
                "disposition": finding["disposition"],
            }
        )
    missing = sorted(rule_ids - set(result["evaluated_rules"]))
    gaps = sorted({item["code"] for item in result["analysis_gaps"]})
    complete = (
        process.returncode in (0, 1)
        and result["status"] == "completed"
        and result["files_scanned"] == 1
        and not gaps
        and not missing
    )
    return complete, missing, gaps, sorted(hits, key=lambda item: (item["line"], item["rule"]))


def evaluate(cache, split, fetch, cases_path=CASES):
    raw_manifest = cases_path.read_bytes()
    manifest = json.loads(raw_manifest)
    engine = ScanEngine(config=AegifyConfig.model_validate(CONFIG))
    identity = implementation_manifest(engine)
    rule_ids = {
        r.definition.id
        for r in engine.registry.get_all()
        if r.definition.cwe_id == manifest["cwe"] and Language.PYTHON in r.definition.languages
    }
    if not rule_ids:
        raise ValueError("The installed scanner has no Python rule for this CWE.")
    cases, observations = [], []
    for module in manifest["modules"]:
        if split != "all" and module["split"] != split:
            continue
        for version in ("before", "after"):
            raw = source_bytes(cache, module, version, fetch)
            complete, missing, gaps, hits = scan_module(
                raw, module, version, rule_ids, manifest["cwe"]
            )
            scored = set()
            for site in module["sites"]:
                first, last = site[version]
                if not 1 <= first <= last <= len(raw.splitlines()):
                    raise ValueError(f"Invalid label range in {site['id']}")
                matched = [hit for hit in hits if first <= hit["line"] <= last]
                scored.update(hit["line"] for hit in matched)
                outcome = (
                    ("tp" if matched else "fn")
                    if version == "before"
                    else ("fp" if matched else "tn")
                )
                cases.append(
                    {
                        "site": site["id"],
                        "split": module["split"],
                        "version": version,
                        "range": [first, last],
                        "source_sha256": module[version]["sha256"],
                        "hits": matched,
                        "outcome": outcome if complete else "unscored",
                    }
                )
            observations.append(
                {
                    "repository": module["repository"],
                    "path": module["path"],
                    "version": version,
                    "status": "completed" if complete else "partial",
                    "missing_rules": missing,
                    "gaps": gaps,
                    "outside_labels": [hit for hit in hits if hit["line"] not in scored],
                }
            )
    counts = {
        group: {
            key: sum(item["outcome"] == key for item in cases if item["split"] == group)
            for key in ("tp", "fp", "fn", "tn", "unscored")
        }
        for group in sorted({item["split"] for item in cases})
    }
    return {
        "version": 1,
        "corpus": manifest["corpus"],
        "split": split,
        "cwe": manifest["cwe"],
        "manifest_sha256": sha(raw_manifest),
        "evaluator_sha256": sha(Path(__file__).read_bytes()),
        "configuration_digest": json_digest(CONFIG),
        "scored_rules": sorted(rule_ids),
        "implementation": {
            k: identity[k]
            for k in (
                "scanner_version",
                "scanner_code_and_modelpacks_digest",
                "bundled_rules_digest",
                "rule_definitions_digest",
                "parser_fingerprint",
                "python",
            )
        },
        "counts": counts,
        "cases": cases,
        "modules": observations,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        choices=("transport-verification-v1", "python-web-xss-patches-v1"),
        default=CASES.parent.name,
    )
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--split", choices=("development", "evaluation", "all"), default="all")
    parser.add_argument(
        "--fetch", action="store_true", help="Fetch missing hash-pinned upstream modules"
    )
    args = parser.parse_args()
    cache = args.cache.resolve()
    output = args.output.resolve()
    cases_path = CASES.parent.parent / args.corpus / "cases.json"
    if output.is_relative_to(cache) or output in (
        cases_path.resolve(),
        CASES.resolve(),
        Path(__file__).resolve(),
    ):
        parser.error("Choose an output separate from the inputs.")
    report = evaluate(cache, args.split, args.fetch, cases_path)
    write_report(output, json.dumps(report, indent=2))
    print(json.dumps(report["counts"], sort_keys=True))
    totals = list(report["counts"].values())
    raise SystemExit(
        3 if any(c["unscored"] for c in totals) else int(any(c["fp"] or c["fn"] for c in totals))
    )
