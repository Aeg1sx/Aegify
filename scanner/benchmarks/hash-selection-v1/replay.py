"""Replay a frozen, owned source cohort without executing repository code."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-root", type=Path, required=True)
parser.add_argument("--changed-rule", type=Path, required=True)
args = parser.parse_args()
manifest = json.loads(Path(__file__).with_name("self-scan-comparison.json").read_text())
root = args.source_root.resolve()
inventory = manifest["inventory"]
if len(inventory) > 5000:
    raise SystemExit("Source inventory exceeds the replay bound")
asts = []
ast_parser = ASTParser()
for entry in inventory:
    path = (root / entry["path"]).resolve()
    path.relative_to(root)
    if path.stat().st_size > 2 * 1024 * 1024:
        raise SystemExit("Source file exceeds the replay bound")
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        raise SystemExit(f"Source digest mismatch: {entry['path']}")
    asts.append(ast_parser.parse_file(path))
graph = CallGraphBuilder().build(asts)


def matches(rule_path):
    return {
        (finding.rule_id, str(Path(finding.file_path).relative_to(root)), finding.line_start)
        for rule in load_yaml_rules(rule_path)
        if rule.definition.id in {"AEG-A02-002", "AEG-A02-003"}
        for finding in rule.evaluate(asts, graph, [])
    }


baseline = subprocess.check_output(
    ["git", "show", f"{manifest['baseCommit']}:{manifest['ruleFile']}"], cwd=root
)
for content, expected in [
    (baseline, manifest["baselineRuleDigest"]),
    (args.changed_rule.read_bytes(), manifest["changedRuleDigest"]),
]:
    if "sha256:" + hashlib.sha256(content).hexdigest() != expected:
        raise SystemExit("Rule digest mismatch")
with tempfile.TemporaryDirectory(prefix="aegify-hash-replay-") as directory:
    old_rule = Path(directory) / "baseline.yml"
    old_rule.write_bytes(baseline)
    before, after = matches(old_rule), matches(args.changed_rule)
observed = {
    "files": len(asts),
    "baseline": dict(Counter(row[0] for row in before)),
    "changed": dict(Counter(row[0] for row in after)),
    "removed": len(before - after),
    "added": len(after - before),
}
expected_removed = {(row["rule"], row["path"], row["line"]) for row in manifest["removed"]}
if before - after != expected_removed or after - before:
    raise SystemExit("Rule result mismatch")
if observed["baseline"] != manifest["baseline"] or observed["changed"] != manifest["changed"]:
    raise SystemExit("Rule count mismatch")
print(json.dumps(observed, indent=2))
