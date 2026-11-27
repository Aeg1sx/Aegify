"""Replay published Python label ranges and historical SARIF with one mechanical matcher."""

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote

from aegify.config import AegifyConfig
from aegify.quality.provenance import implementation_manifest, json_digest
from aegify.scanner.engine import ScanEngine

REVISION = "9c114481b130b8755d6a56ff5a9c26c7567ded4e"
SUMMARY = "results/scanner_performance_summary_detection_rates.json"
# Define the accepted CWE family once for both producers. Labels with multiple
# sites count once. The upstream semantic judge uses different criteria.
CLASSES = (
    ("IDOR", {639, 862, 863}),
    ("Weak JWT", {347, 321}),
    ("SQL Injection", {89}),
    ("GraphQL Injection", {943}),
    ("XSS|Cross-Site Scripting", {79}),
    ("Template Injection", {1336}),
    ("Local File Inclusion|Path Traversal", {22, 73, 98}),
    ("SSRF|Server-Side Request Forgery", {918}),
    ("XML External Entity", {611}),
    ("Deserialization", {502}),
    ("Command Injection", {78}),
    ("Hardcoded SSH Credentials", {798}),
)


def git(checkout, *args):
    return subprocess.check_output(["git", "-C", str(checkout), *args])


def blob(checkout, path):
    return git(checkout, "show", f"{REVISION}:{path}")


def recorded_hits(report):
    hits = []
    for run in report["runs"]:
        rules = run["tool"]["driver"].get("rules", [])
        cwes = {
            rule["id"]: {
                int(tag[4:])
                for tag in rule.get("properties", {}).get("tags", [])
                if re.fullmatch(r"CWE-\d+", tag)
            }
            for rule in rules
        }
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                physical = loc["physicalLocation"]
                region = physical["region"]
                hits.append(
                    (
                        unquote(physical["artifactLocation"]["uri"]).removeprefix("./"),
                        region["startLine"],
                        region.get("endLine", region["startLine"]),
                        cwes.get(result["ruleId"], set()),
                    )
                )
    return hits


def matches(hits, locations, cwes):
    return any(
        src == path and start <= hi and end >= lo and tags & cwes
        for src, start, end, tags in hits
        for path, lo, hi in locations
    )


def scan_python(checkout, root, engine):
    paths = [
        p
        for p in git(checkout, "ls-tree", "-r", "--name-only", REVISION, root).decode().splitlines()
        if p.endswith(".py")
    ]
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        files = []
        for name in paths:
            dest = base / name.removeprefix(root)
            dest.parent.mkdir(exist_ok=True, parents=True)
            dest.write_bytes(blob(checkout, name))
            files.append(dest)
        result = engine.scan_files(base, files) if files else None
        if files and (
            result.status != "completed"
            or result.files_scanned != len(files)
            or result.analysis_gaps
        ):
            raise ValueError(f"Incomplete Python coverage in {root}")
        lengths = {p.relative_to(base).as_posix(): len(p.read_bytes().splitlines()) for p in files}
        return lengths, result.findings if result else []


def repaired_controls(checkout, engine):
    sites = [
        ("XBEN-005", "app/main.py", "AEG-A02-001", 14, 17),
        ("XBEN-009", "vulnerable-app/ssti_demo/views.py", "AEG-TMPL-001", 8, 10),
        ("XBEN-024", "app/app.py", "AEG-SSRF-001", 97, 101),
        # Public Flask applications with both source variants in the archive.
        ("XBEN-004", "src/app.py", "AEG-FLASK-XSS-001", 79, 80),
        ("XBEN-008", "src/app.py", "AEG-FLASK-XSS-001", 80, 80),
        ("XBEN-010", "src/app.py", "AEG-FLASK-XSS-001", 81, 81),
        ("XBEN-012", "src/app.py", "AEG-FLASK-XSS-001", 71, 73),
        ("XBEN-013", "src/app.py", "AEG-FLASK-XSS-001", 77, 79),
    ]
    pairs = []
    for case, path, rule, original, patched in sites:
        records = {}
        for tree, line in (("benchmarks", original), ("benchmarks_patched", patched)):
            root = f"{tree}/{case}-24/"
            lengths, findings = scan_python(checkout, root, engine)
            if not 1 <= line <= lengths[path]:
                raise ValueError(f"Invalid paired location in {root}{path}")
            rule_lines = sorted(
                {
                    f.line_start
                    for f in findings
                    if f.rule_id == rule and f.provenance.module_path == path
                }
            )
            records[tree] = {"line": line, "reported": line in rule_lines, "rule_lines": rule_lines}
        pairs.append(dict(case=case, path=path, rule=rule, **records))
    return pairs


def evaluate(checkout):
    summary = json.loads(blob(checkout, SUMMARY))["results"]["zeropath"]
    engine = ScanEngine(
        config=AegifyConfig.model_validate(
            {
                "storage": {"backend": "memory"},
                "llm": {"enabled": False},
                "rules": {"severity_threshold": "low"},
                "scan": {"max_workers": 1},
            }
        )
    )
    identity = implementation_manifest(engine)
    cases = []
    for case in sorted(summary["benchmark_results"]):
        root = f"benchmarks/{case}-24/"
        label = json.loads(blob(checkout, f"rules/{case}-000_vulns.json"))
        peer = recorded_hits(json.loads(blob(checkout, root + "zeropath_raw.sarif")))
        lengths, findings = scan_python(checkout, root, engine)
        ours = [(f.provenance.module_path, f.line_start, f.line_end, {f.cwe_id}) for f in findings]
        for item in label["vulnerabilities"]:
            name = item["vuln_name"]
            groups = [group for pattern, group in CLASSES if re.search(pattern, name, re.I)]
            if len(groups) != 1:
                raise ValueError(f"Unmapped label: {name}")
            sites = [
                (loc["file_path"].removeprefix(root), loc["start_line"], loc["end_line"])
                for loc in item["valid_vulns"]
                if loc["file_path"].endswith(".py")
            ]
            invalid = [
                (path, lo, hi)
                for path, lo, hi in sites
                if not 1 <= lo <= hi <= lengths.get(path, 0)
            ]
            reason = "invalid_upstream_range" if invalid else ("" if sites else "no_python_site")
            cases.append(
                dict(
                    case=case,
                    name=name,
                    cwes=sorted(groups[0]),
                    sites=sites,
                    unscored_reason=reason,
                    aegify=matches(ours, sites, groups[0]) if not reason else None,
                    zeropath=matches(peer, sites, groups[0]) if not reason else None,
                )
            )
    if len(summary["benchmark_results"]) != summary["scanned_benchmarks"]:
        raise ValueError("Upstream application inventory disagrees with the reported count")
    pairs = repaired_controls(checkout, engine)
    if implementation_manifest(engine) != identity:
        raise ValueError("Scanner implementation changed during evaluation")
    return dict(
        revision=REVISION,
        scanner=identity,
        applications=summary["scanned_benchmarks"],
        labels=len(cases),
        scored=sum(not r["unscored_reason"] for r in cases),
        matched={tool: sum(row[tool] is True for row in cases) for tool in ("aegify", "zeropath")},
        outcomes_digest=json_digest(cases),
        cases=cases,
        repaired_controls=pairs,
    )


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("checkout", type=Path)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    report = evaluate(args.checkout)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print({k: report[k] for k in ("applications", "labels", "scored", "matched")})
