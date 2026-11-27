"""Compare Aegify SARIF locations with the pinned CodeQL query's selected rows."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("suite", choices=["python", "javascript"])
parser.add_argument("sources", type=Path)
parser.add_argument("sarif", type=Path)
args = parser.parse_args()
suite = json.loads(Path(__file__).with_name("inputs.json").read_text())["suites"][args.suite]

for filename, digest in suite["files"].items():
    if hashlib.sha256((args.sources / filename).read_bytes()).hexdigest() != digest:
        parser.error(f"Input changed: {filename}")

truth = (args.sources / suite["expected"]).read_text()
selected, boundary, _ = truth.partition("\nedges\n")
if not selected.startswith("#select\n") or not boundary:
    parser.error("Expected query selections followed by graph edges")
expected = set()
for line in selected.splitlines()[1:]:
    match = re.match(r"^\| ([^:]+):(\d+):", line)
    if not match:
        parser.error(f"Unrecognized selected row: {line}")
    expected.add((match[1], int(match[2])))

(run,) = json.loads(args.sarif.read_text())["runs"]
props = run["properties"]
if props["analysisStatus"] != "completed" or props["analysisGaps"]:
    parser.error("Incomplete scan")
paths = {src["filePath"]: src["modulePath"] for src in props["analyzedSources"]}
if set(paths.values()) != set(suite["files"]) - {suite["expected"]}:
    parser.error("The report must cover the same source files as the suite")
found = set()
for finding in run["results"]:
    if finding["ruleId"] == "AEG-A03-011":
        where = finding["locations"][0]["physicalLocation"]
        uri = unquote(where["artifactLocation"]["uri"])
        found.add((paths[uri], where["region"]["startLine"]))

print(
    json.dumps(
        {
            "expected": len(expected),
            "matched": sorted(found & expected),
            "missed": sorted(expected - found),
            "extra": sorted(found - expected),
        },
        indent=2,
    )
)
