import assert from "node:assert/strict";
import test from "node:test";
import { codeLanguage, parseEvidenceSteps, snippetStart } from "./code-evidence.ts";
import { boundedInteger, filterQuery, findingFilters } from "./finding-view.ts";
import { entryPath } from "./graph-path.ts";
import { buildFindingReport, fencedCode } from "./finding-report.ts";

test("source context offsets are explicit; legacy context never gets guessed", () => {
  const finding = { codeSnippet: "first\nsecond\nthird", lineStart: 20, lineEnd: 20 };
  assert.equal(snippetStart(finding), null);
  assert.equal(snippetStart({ ...finding, provenance: '{"snippet_start_line":19}' }), 19);
  assert.equal(snippetStart({ ...finding, provenance: '{"snippet_start_line":null}' }), null);
  assert.equal(snippetStart({ ...finding, codeSnippet: "second" }), 20);
  assert.equal(snippetStart({ ...finding, provenance: "broken" }), null);
  assert.equal(codeLanguage(), "text");
  assert.equal(codeLanguage("py"), "python");
});

test("flow parsing fails visibly and bounds malformed artifact data", () => {
  assert.ok(parseEvidenceSteps("not json").warning);
  assert.ok(parseEvidenceSteps("{}").warning);
  assert.deepEqual(parseEvidenceSteps(null), { steps: [], warning: null });
  const flow = parseEvidenceSteps([{ file: "a.py", line: 4, message: "Input" }, null, { file: "b.py", line: -1, message: "Unknown" }]);
  assert.equal(flow.steps.length, 1); assert.ok(flow.warning);
  assert.equal(parseEvidenceSteps(Array(250).fill({ file: "a.py", line: 1, message: "Step" })).steps.length, 200);
});

test("table filters round trip, discard unknown parameters, and bound pagination", () => {
  const filters = findingFilters(new URLSearchParams("severity=critical&page=-5&sort=invalid&history=false&untrusted=1"));
  assert.equal(filters.page, "1"); assert.equal(filters.sort, "newest"); assert.equal(filters.history, "");
  assert.ok(!filterQuery(filters).includes("untrusted"));
  assert.deepEqual(findingFilters(new URLSearchParams(filterQuery(filters))), filters);
  for (const input of ["-1", "NaN", "0", "1.5", "Infinity"]) assert.equal(boundedInteger(input, 50, 100), 50);
  assert.equal(boundedInteger("99999", 50, 100), 100);
});

test("call-path traversal follows direction, tolerates cycles and missing nodes", () => {
  const nodes = [{ id: "entry", nodeType: "entry_point" }, { id: "a", nodeType: "function" }, { id: "sink", nodeType: "sink" }];
  const edges = [{ sourceNodeId: "entry", targetNodeId: "a" }, { sourceNodeId: "a", targetNodeId: "sink" }, { sourceNodeId: "sink", targetNodeId: "a" }, { sourceNodeId: "missing", targetNodeId: "sink" }];
  assert.deepEqual(entryPath(nodes, edges, "sink"), ["entry", "a", "sink"]);
  assert.deepEqual(entryPath(nodes, edges, "missing"), []);
  assert.deepEqual(entryPath(nodes, edges.slice(1), "sink"), []);
  assert.deepEqual(entryPath(nodes, edges, "entry"), ["entry"]);
});

test("reports preserve source, escape metadata and never claim an unrecorded runtime result", () => {
  assert.equal(fencedCode("```\ntext\n```"), "````text\n```\ntext\n```\n````");
  const report = buildFindingReport({ id: "f1", ruleId: "AEG-TEST-001", ruleName: "<tag> [title]", severity: "high", status: "open", evidenceState: "candidate", disposition: "advisory", message: "Needs review", filePath: "a.py", lineStart: 4, lineEnd: 4, codeSnippet: "one\ntwo\nthree", remediation: "Review the source.", scan: { repository: "local", branch: "main", commitSha: "abc" } });
  assert.ok(report.includes("&lt;tag&gt;"));
  assert.ok(report.includes("Static candidate"));
  assert.ok(report.includes("Snippet source offset is unavailable"));
  assert.ok(report.includes("one\ntwo\nthree"));
  assert.ok(!report.includes("Runtime observed"));
});
