import assert from "node:assert/strict";
import test from "node:test";
import { codeLanguage, codePreview, describeFlowMessage, parseEvidenceSteps, snippetStart } from "./code-evidence.ts";
import { boundedInteger, filterQuery, findingFilters } from "./finding-view.ts";
import { entryPath, graphSymbolName } from "./graph-path.ts";
import { buildFindingReport, fencedCode } from "./finding-report.ts";
import { flowLineExcerpt } from "./sarif-evidence.ts";

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
  const step = { file: "legacy.py", line: 11, message: "source: input" };
  assert.deepEqual(parseEvidenceSteps(JSON.stringify([JSON.stringify(step)])), { steps: [step], warning: null });
});

test("source navigation and the code reader share the visible line bounds", () => {
  assert.deepEqual(codePreview(""), { text: "", lines: [], truncated: false });
  assert.deepEqual(codePreview("a\r\nb").lines, ["a", "b"]);
  const output = codePreview("x".repeat(99_999) + "\nnext");
  assert.equal(output.truncated, true);
  assert.equal(output.lines.length, 1);
});

test("flow excerpts retain only a line with a recorded offset", () => {
  const region = { startLine: 8 };
  const contextRegion = { startLine: 7, endLine: 9, snippet: { text: "first\r\n  second\r\nthird" } };
  assert.equal(flowLineExcerpt({ region, contextRegion }), "  second");
  assert.equal(flowLineExcerpt({ region: { ...region, snippet: { text: "  direct" } } }), "  direct");
  assert.equal(flowLineExcerpt({ region: { ...region, snippet: { text: "ambiguous\ncontext" } } }), undefined);
  assert.equal(flowLineExcerpt({ region, contextRegion: { ...contextRegion, startLine: 20 } }), undefined);
  assert.equal(flowLineExcerpt({ region: { ...region, snippet: { text: "a".repeat(4097) } } }), undefined);
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
  assert.equal(graphSymbolName("file:service/mail.py::delivery.open_session(?,?)"), "delivery.open_session");
  assert.equal(graphSymbolName("file:service/Main.kt::send(Message)"), "send(Message)");
  assert.equal(graphSymbolName("<module:services/mail.py>"), "mail.py");
  assert.equal(graphSymbolName("gateway.Dispatch.send"), "gateway.Dispatch.send");
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

test("review queues retain their link identity and reject unknown filters", async () => {
  const { queueConditions, ACTIVE_STATUSES } = await import("./finding-view.ts");
  const now = new Date("2026-11-20T12:00:00Z");
  for (const queue of ["active", "priority", "overdue", "regressed"]) {
    const filters = findingFilters(new URLSearchParams({ queue }));
    assert.equal(findingFilters(new URLSearchParams(filterQuery(filters))).queue, queue);
    assert.deepEqual(queueConditions(queue, now).status, { in: ACTIVE_STATUSES });
    assert.equal(queueConditions(queue, now).isCurrent, true);
  }
  assert.deepEqual(queueConditions("overdue", now).dueAt, { lt: now });
  assert.deepEqual(queueConditions("priority").severity, { in: ["critical", "high"] });
  assert.equal(queueConditions("regressed").baselineState, "regressed");
  assert.equal(findingFilters(new URLSearchParams("queue=constructor")).queue, "");
  assert.deepEqual(queueConditions("constructor"), {});
});

test("configuration reports preserve both declarative locations and omit unrecognized assignments", () => {
  const finding = { id: "storage", ruleId: "AEG-CF-003", ruleName: "Shared storage", severity: "medium", status: "open",
    evidenceState: "candidate", disposition: "advisory", message: "Check the deployment", filePath: "wrangler.toml",
    lineStart: 6, lineEnd: 6, provenance: JSON.stringify({ analysis_kind: "configuration", fidelity: "parsed-settings" }),
    codeSnippet: "", scan: { repository: "fixture", branch: "main", commitSha: "a" } };
  for (const [collection, primary, preview] of [["r2_buckets", "bucket_name", "preview_bucket_name"],
    ["d1_databases", "database_id", "preview_database_id"], ["kv_namespaces", "id", "preview_id"]]) {
    const snippet = `env.dev.${collection}[2].remote = true (line 6), ${preview} (line 5) matches env.production.${collection}[1].${primary} (line 11)`;
    assert.ok(buildFindingReport({ ...finding, codeSnippet: snippet }).includes(snippet));
    const raw = buildFindingReport({ ...finding, codeSnippet: snippet + " · " + primary + " = owned-raw-marker" });
    assert.ok(raw.includes("Parsed settings are unavailable"));
    assert.ok(!raw.includes("owned-raw-marker"));
  }
  for (const [collection, primary] of [["d1_databases", "database_id"], ["queues.producers", "queue"],
    ["kv_namespaces", "id"], ["r2_buckets", "bucket_name"]]) {
    const snippet = `env.blue.previews.${collection}[2].${primary} (line 10) matches env.blue.${collection}[1].${primary} (line 3)`;
    assert.ok(buildFindingReport({ ...finding, codeSnippet: snippet }).includes(snippet));
    for (const invalid of [snippet.replace("matches env.blue.", "matches env.green."), snippet + " = owned-value"]) {
      const report = buildFindingReport({ ...finding, codeSnippet: invalid });
      assert.ok(report.includes("Parsed settings are unavailable") && !report.includes(invalid));
    }
  }
});
test("flow rows retain the recorded message and use readable names for known step types", () => {
  assert.deepEqual(describeFlowMessage("source: request.args"), { label: "Source", value: "request.args" });
  assert.deepEqual(describeFlowMessage("assignment: record: title"), { label: "Assignment", value: "record: title" });
  assert.deepEqual(describeFlowMessage("iteration: char"), { label: "Loop element", value: "char" });
  assert.deepEqual(describeFlowMessage("command-argument: shell command argument"), { label: "Shell command argument", value: "" });
  assert.deepEqual(describeFlowMessage("vendor-step: own evidence"), { label: "", value: "vendor-step: own evidence" });
});

test("exported flow quotes located source and drops withheld or ambiguous excerpts", () => {
  const rows = [
    { file: "labels.py", line: 6, message: "iteration: char", snippet: '    marker = "```"' },
    { file: "env/wrangler.toml", line: 8, message: "setting", snippet: "private-binding" },
    { file: "a.py", line: 2, message: "other", snippet: "line one\nline two" },
    { file: "large.py", line: 9, message: "value", snippet: "x".repeat(4097) },
    { file: "missing.py", line: 0, message: "bad location" },
  ];
  const finding = { id: "flow", ruleId: "PROFILE-LABEL", ruleName: "Label", severity: "low", status: "open",
    evidenceState: "candidate", disposition: "advisory", message: "Review the label", filePath: "a.py",
    lineStart: 2, lineEnd: 2, codeSnippet: "", taintFlow: JSON.stringify(rows), scan: { repository: "", branch: "", commitSha: "" } };
  const text = buildFindingReport(finding);
  assert.ok(text.includes('   ````text\n       marker = "```"\n   ````'));
  assert.ok(text.includes("Some flow steps are invalid") && text.includes("4. large"));
  for (const value of ["private-binding", "line two", "xxx"]) assert.ok(!text.includes(value));
});
