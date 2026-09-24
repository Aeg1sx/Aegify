import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { captureReviewSources, executeSourceTool, parseSourceToolRequest, SOURCE_TOOL_LIMITS, validateReviewSources } from "./ai-source-tools.ts";
import { sourceDigest } from "./source-snapshot.ts";
import { emptySourceSession, finalizeSourceReview, parseSourceResponse, runSourceRequests, saveSourceEvidence, sourceReviewPrompt, validateSavedSourceEvidence } from "./ai-source-review.ts";
import { packSnapshot, reviewSystem, type ReviewResult, type ReviewSnapshot } from "./ai-review-contract.ts";
import { sanitizeLLMSourceText } from "./llm-safety.ts";

const hex = (value: string) => createHash("sha256").update(value).digest("hex");
function catalog(contents: Record<string, string> = { "main.py": "value = normalize(value)\nreturn value\n", "lib/helper.py": "def normalize(value):\n    return str(value)\n" }) {
  const raw = { version: 1 as const, provider: "github", repository: "owned/fixture", commit: "a".repeat(40), truncated: false,
    files: Object.entries(contents).map(([path, content]) => ({ path, content, sha256: hex(content) })) };
  const input = { ...raw, sourceDigest: sourceDigest(raw) };
  return { input, sources: captureReviewSources(input, input) };
}
function snapshot(): ReviewSnapshot {
  return packSnapshot({ version: 2, scanId: "scan", projectId: "project", scanDigest: "owned", mode: "source", includeApiContracts: false,
    system: reviewSystem("source", false, "en"), graphContext: null, findings: [{ id: "finding", evidenceDigest: "owned", data: { filePath: "main.py", lineStart: 1 }, omittedFields: [], apiContractContext: null }], batches: [], sources: catalog().sources });
}
const result: ReviewResult = { findingId: "finding", verdict: "likely_false_positive", confidence: 0.8, reasoning: "Owned static fixture.", remediation: "Review caller constraints.", adjustedSeverity: "low", evidenceFor: [], evidenceAgainst: ["A static guard was read."], evidenceGaps: [] };

test("catalog binds repository, commit, bytes and redacted manifest; no altered source is admitted", () => {
  const { input, sources } = catalog();
  assert.equal(validateReviewSources(sources), sources);
  for (const raw of [undefined, null, { ...input, commit: "b".repeat(40) }, { ...input, files: [...input.files, input.files[0]] },
    { ...input, files: [{ ...input.files[0], content: "changed" }] }, { ...input, files: [{ ...input.files[0], path: "../other.py" }] }]) {
    assert.throws(() => captureReviewSources(raw, input));
  }
  for (const mutate of [() => ({ ...sources, repository: "other/repo" }), () => ({ ...sources, omittedFiles: -1 }),
    () => ({ ...sources, files: [{ ...sources.files[0], content: "changed" }] }), () => ({ ...sources, commit: "" })]) assert.throws(() => validateReviewSources(mutate()));
});

test("credential redaction preserves original source line numbers including multiline credentials", () => {
  const secret = "owned_multiline_credential_123456";
  const raw = `a\nBearer\n${secret}\nb\ntoken=\n${secret}\nc\n-----BEGIN PRIVATE KEY-----\nowned-key-material\n-----END PRIVATE KEY-----\nd`;
  const redacted = sanitizeLLMSourceText(raw);
  assert.equal(redacted.split("\n").length, raw.split("\n").length);
  assert.ok(!redacted.includes(secret)); assert.ok(!redacted.includes("owned-key-material"));
  assert.equal(redacted.split("\n")[10], "d");
  assert.ok(catalog({ "main.py": raw }).sources.files[0].content.includes("REDACTED"));
  const expanded = catalog({ "main.py": "token=a;".repeat(60_000) }).sources;
  assert.ok(Buffer.byteLength(expanded.files[0].content) > SOURCE_TOOL_LIMITS.fileBytes);
  assert.equal(validateReviewSources(expanded), expanded, "Redaction may expand bytes while the complete catalog remains bounded");
});

test("whole-file catalog admission exposes omissions deterministically and prioritizes requested locations", () => {
  const contents = Object.fromEntries(Array.from({ length: 520 }, (_, index) => [`file-${String(index).padStart(3, "0")}.py`, "fixture"]));
  const { input } = catalog(contents);
  const selected = captureReviewSources(input, input, ["file-519.py"]);
  assert.equal(selected.files.length, 512); assert.equal(selected.omittedFiles, 8); assert.equal(selected.truncated, true);
  assert.ok(selected.files.some((file) => file.path === "file-519.py"));
  assert.equal(selected.manifestDigest, captureReviewSources(input, input, ["file-519.py"]).manifestDigest);
});

test("strict source tools expose bounded IDs and citations, never accept shell, paths or regex options", () => {
  const { sources } = catalog(), file = sources.files.find((file) => file.path === "main.py")!;
  const run = (raw: unknown) => executeSourceTool(parseSourceToolRequest(raw), sources, "owned-1", 1);
  const listed = run({ name: "source_list", arguments: { prefix: "lib/" } });
  assert.equal((listed.evidence.files as unknown[]).length, 1);
  const read = run({ name: "source_read", arguments: { file_id: file.id, line_start: 1, line_end: 2 } });
  assert.equal(read.evidence.content, "value = normalize(value)\nreturn value");
  assert.equal((read.evidence.citation as Record<string, unknown>).excerpt_digest, "sha256:" + hex(String(read.evidence.content)));
  assert.equal(run({ name: "source_search", arguments: { query: ".*" } }).evidence.matches instanceof Array, true);
  assert.deepEqual(run({ name: "source_search", arguments: { query: ".*" } }).evidence.matches, []);
  for (const raw of [{ name: "shell", arguments: { command: "fixture" } }, { name: "source_read", arguments: { path: "main.py", line_start: 1, line_end: 2 } },
    { name: "source_search", arguments: { query: "fixture", regex: true } }, { name: "source_read", arguments: { file_id: file.id, line_start: 1, line_end: 201 } }]) assert.throws(() => parseSourceToolRequest(raw));
  assert.equal(run({ name: "source_read", arguments: { file_id: "sha256:" + "0".repeat(64), line_start: 1, line_end: 1 } }).ok, false);
  assert.equal(run({ name: "source_read", arguments: { file_id: file.id, line_start: 99, line_end: 99 } }).ok, false);
});

test("search limits and long lines are explicit; oversized reads never return a cut excerpt", () => {
  const paths = catalog(Object.fromEntries(Array.from({ length: 50 }, (_, index) => [`${"p".repeat(980)}-${index}.py`, "fixture"]))).sources;
  const listed = executeSourceTool(parseSourceToolRequest({ name: "source_list", arguments: {} }), paths, "list", 1);
  assert.equal(listed.ok, true); assert.equal(listed.truncated, true); assert.ok(Number(listed.evidence.next_offset) > 0);
  assert.ok(Buffer.byteLength(JSON.stringify(listed.evidence)) <= SOURCE_TOOL_LIMITS.outputBytes);
  const { sources } = catalog({ "main.py": "hit ".repeat(500) + "\n" + "hit\n".repeat(30) });
  const search = executeSourceTool(parseSourceToolRequest({ name: "source_search", arguments: { query: "hit" } }), sources, "search", 1);
  assert.equal(search.truncated, true); assert.equal(search.evidence.omitted_long_lines, 1); assert.equal((search.evidence.matches as unknown[]).length, 20);
  const long = catalog({ "main.py": "x".repeat(17_000) }).sources;
  const read = executeSourceTool(parseSourceToolRequest({ name: "source_read", arguments: { file_id: long.files[0].id, line_start: 1, line_end: 1 } }), long, "read", 1);
  assert.equal(read.ok, false); assert.deepEqual(read.evidence, {});
});

test("only executor-issued citations support final results and the finding location must be covered", () => {
  const snap = snapshot(), session = emptySourceSession();
  const helper = snap.sources!.files.find((file) => file.path === "lib/helper.py")!;
  session.spans = runSourceRequests(snap, session, [{ name: "source_read", arguments: { file_id: helper.id, line_start: 1, line_end: 2 } }]);
  session.roundIndex++;
  const otherCitation = (session.spans[0].evidence.citation as { citation_id: string }).citation_id;
  const ungrounded = finalizeSourceReview(snap, ["finding"], session, { results: [result], citationIds: { finding: [otherCitation] } });
  assert.equal(ungrounded.results[0].verdict, "needs_review"); assert.equal(ungrounded.results[0].confidence, 0);
  assert.throws(() => finalizeSourceReview(snap, ["finding"], session, { results: [result], citationIds: { finding: ["sha256:" + "f".repeat(64)] } }));
  const main = snap.sources!.files.find((file) => file.path === "main.py")!;
  session.spans.push(...runSourceRequests(snap, session, [{ name: "source_read", arguments: { file_id: main.id, line_start: 1, line_end: 2 } }])); session.roundIndex++;
  const mainCitation = (session.spans[1].evidence.citation as { citation_id: string }).citation_id;
  const grounded = finalizeSourceReview(snap, ["finding"], session, { results: [result], citationIds: { finding: [mainCitation, otherCitation] } });
  assert.equal(grounded.results[0].verdict, "likely_false_positive");
  const saved = saveSourceEvidence(snap, session, grounded.citationIds.finding, "owned-model", "sha256:" + "1".repeat(64), 100);
  validateSavedSourceEvidence(saved);
  const changed = structuredClone(saved); changed.tools_used[0].evidence.content = "changed";
  assert.throws(() => validateSavedSourceEvidence(changed));
});

test("round, tool, prompt and evidence ceilings are enforced before further source disclosure", () => {
  const snap = snapshot(), session = emptySourceSession(), request = parseSourceToolRequest({ name: "source_list", arguments: {} });
  assert.throws(() => runSourceRequests(snap, { ...session, roundIndex: 3 }, [request]));
  assert.throws(() => runSourceRequests(snap, session, Array.from({ length: 9 }, () => request)));
  assert.throws(() => sourceReviewPrompt({ ...snap, system: "x".repeat(180_000) }, ["finding"], session));
  const large = catalog({ "main.py": "x".repeat(16_000) }).sources;
  const read = parseSourceToolRequest({ name: "source_read", arguments: { file_id: large.files[0].id, line_start: 1, line_end: 1 } });
  assert.throws(() => runSourceRequests({ ...snap, sources: large }, session, Array.from({ length: 8 }, () => read)), /evidence budget/);
  assert.equal(JSON.parse(sourceReviewPrompt(snap, ["finding"], { ...session, roundIndex: 3 })).source_progress.final_required, true);
  const response = JSON.stringify({ kind: "review", reviews: [{ ...result, citationIds: [] }] });
  assert.equal(parseSourceResponse(response, ["finding"]).kind, "review");
  for (const raw of [response.replace('"finding"', '"invented"'), JSON.stringify({ kind: "tools", requests: [] }), JSON.stringify({ kind: "tools", requests: [request], extra: true }), "[]", "not json"])
    assert.throws(() => parseSourceResponse(raw, ["finding"]));
  assert.equal(SOURCE_TOOL_LIMITS.calls, 8);
});
