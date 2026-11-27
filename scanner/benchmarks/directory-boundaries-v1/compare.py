"""Evaluate frozen, maintainer-documented changes without importing the acquired files."""

import argparse
import ast
import hashlib
import json
import subprocess
import tempfile
import urllib.request
from pathlib import Path

MANIFEST = Path(__file__).with_name("cases.json")


def digest(content):
    return hashlib.sha256(content).hexdigest()


def function_ranges(source):
    ranges = {}

    def visit(node, ancestors):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            ancestors = (*ancestors, node.name)
            ranges[".".join(ancestors)] = (node.lineno, node.end_lineno)
        for child in ast.iter_child_nodes(node):
            visit(child, ancestors)

    visit(ast.parse(source), ())
    return ranges


def source_for(project, version, directory, fetch):
    record = project[version]
    path = directory / project["project"] / version / project["path"]
    if not path.is_file() and fetch:
        url = f"https://raw.githubusercontent.com/{project['repository']}/{record['commit']}/{project['path']}"
        with urllib.request.urlopen(url, timeout=25) as response:
            raw = response.read(1_000_001)
        if len(raw) > 1_000_000 or digest(raw) != record["sha256"]:
            raise ValueError(f"Downloaded source mismatch for {project['project']} {version}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    raw = path.read_bytes()
    if digest(raw) != record["sha256"]:
        raise ValueError(f"Source mismatch for {project['project']} {version}")
    return path, raw


def evaluate(python, sources, fetch):
    code = """
import json
from aegify.quality.provenance import implementation_manifest
from aegify.scanner.engine import ScanEngine
manifest = implementation_manifest(ScanEngine())
print(json.dumps({k: manifest[k] for k in ('scanner_version', 'scanner_code_and_modelpacks_digest',
    'parser_fingerprint', 'rule_definitions_digest', 'bundled_rules_digest')}))
"""
    command = [str(python), "-I"]
    implementation = json.loads(subprocess.check_output([*command, "-c", code], timeout=45))
    manifest = json.loads(MANIFEST.read_bytes())
    rule = manifest["rule_id"]
    cases = []
    with tempfile.TemporaryDirectory(prefix="aegify-directory-reports-") as scratch:
        for project in manifest["projects"]:
            for version in ("before", "after"):
                path, raw = source_for(project, version, sources, fetch)
                bounds = function_ranges(raw)
                with tempfile.TemporaryDirectory(dir=scratch) as run_dir:
                    # Keep adjacent configuration and source outside this scan.
                    sample = Path(run_dir) / path.name
                    sample.write_bytes(raw)
                    output = Path(run_dir) / "scan.json"
                    subprocess.run(
                        [
                            *command,
                            "-m",
                            "aegify.cli",
                            "scan",
                            str(sample),
                            "--no-llm",
                            "-o",
                            "json",
                            "-f",
                            str(output),
                        ],
                        cwd=run_dir,
                        capture_output=True,
                        check=True,
                        timeout=90,
                    )
                    result = json.loads(output.read_bytes())
                    complete = (
                        result["status"] == "completed"
                        and not result["analysis_gaps"]
                        and result["files_scanned"] == 1
                        and rule in result["evaluated_rules"]
                    )
                    analyzed = result["analyzed_sources"]
                    if len(analyzed) != 1 or analyzed[0]["source_digest"] != digest(raw):
                        raise ValueError("Source identity missing or changed")
                    hits = [f for f in result["findings"] if f["rule_id"] == rule]
                    if any(
                        Path(f["file_path"]).name != sample.name
                        or f["disposition"] != "advisory"
                        or f["evidence_state"] != "candidate"
                        or f.get("taint_flow")
                        for f in hits
                    ):
                        raise ValueError("Unexpected path or evidence classification")
                    for check in project["checks"]:
                        start, end = bounds[check["symbol"]]
                        lines = sorted(
                            f["line_start"] for f in hits if start <= f["line_start"] <= end
                        )
                        expected = check["before_lines"] if version == "before" else []
                        cases.append(
                            {
                                "project": project["project"],
                                "version": version,
                                "symbol": check["symbol"],
                                "source_sha256": digest(raw),
                                "expected_lines": expected,
                                "reported_lines": lines,
                                "outside_reviewed_symbol": sum(
                                    not start <= f["line_start"] <= end for f in hits
                                ),
                                "evaluated": complete,
                                "agreed": complete and lines == expected,
                            }
                        )
    return {
        "implementation": implementation,
        "manifest_sha256": digest(MANIFEST.read_bytes()),
        "evaluator_sha256": digest(Path(__file__).read_bytes()),
        "rule_id": rule,
        "cases": cases,
        "complete": all(c["evaluated"] for c in cases),
        "agreed": sum(c["agreed"] for c in cases),
        "comparisons": len(cases),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python", type=Path, help="Python interpreter in the scanner environment")
    parser.add_argument("sources", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Download only missing files from the pinned GitHub commits",
    )
    args = parser.parse_args()
    report = evaluate(args.python.absolute(), args.sources.resolve(), args.fetch)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['agreed']}/{report['comparisons']} matched; complete={report['complete']}.")
    raise SystemExit(
        3 if not report["complete"] else int(report["agreed"] != report["comparisons"])
    )
