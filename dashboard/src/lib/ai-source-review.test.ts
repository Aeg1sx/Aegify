import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { captureReviewSources, executeSourceTool, parseSourceToolRequest, SOURCE_TOOL_LIMITS, validateReviewSources } from "./ai-source-tools.ts";
import { sourceDigest } from "./source-snapshot.ts";
import { emptySourceSession, finalizeSourceReview, parseSourceResponse, runSourceRequests, saveSourceEvidence, sourceReviewPrompt, validateSavedSourceEvidence } from "./ai-source-review.ts";
import { batchPrompt, packSnapshot, reviewSystem, type ReviewResult, type ReviewSnapshot } from "./ai-review-contract.ts";
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

test("Wrangler manifests stay out of model source tools and restored catalogs", () => {
  const { sources } = catalog({
    "wrangler.json": "owned-config-marker", "apps/api/wrangler.jsonc": "owned-config-marker",
    "work/wrangler.toml": "owned-config-marker", "main.py": "value = 2",
  });
  assert.deepEqual(sources.files.map((file) => file.path), ["main.py"]);
  assert.equal(sources.omittedFiles, 3);
  assert.equal(sources.truncated, true);
  assert.ok(!JSON.stringify(sources).includes("owned-config-marker"));
  assert.equal(validateReviewSources(sources), sources);
  assert.throws(() => validateReviewSources({ ...sources, files: [{ ...sources.files[0], path: "old/wrangler.toml" }] }), /withheld/);
});

test("quick, deep and source prompts withhold raw configuration in older finding records", () => {
  const marker = "owned-private-configuration-value";
  const review = snapshot();
  const item = { ...review.findings[0], data: { filePath: "app/wrangler.toml", lineStart: 7, ruleId: "EXT-001",
    codeSnippet: 'PASSWORD = "' + marker + '"', message: marker, defenseContext: marker }, apiContractContext: marker };
  for (const mode of ["quick", "deep", "source"] as const) {
    const prompt = batchPrompt({ ...review, mode, findings: [item], graphContext: { data: marker, omitted: 0 } }, [item.id]);
    assert.ok(!prompt.includes(marker));
    const record = JSON.parse(prompt).findings[0];
    assert.equal(record.data.lineStart, 7);
    assert.ok(record.omittedFields.includes("codeSnippet"));
    assert.ok(record.omittedFields.includes("message"));
    assert.equal(record.apiContractContext, null);
    assert.equal(JSON.parse(prompt).graphContext, null);
  }
  const storage = "env.qa.d1_databases[1].remote = true (line 8), preview_database_id (line 7) matches default.d1_databases[0].database_id (line 4)";
  const preview = "default.previews.queues.producers[0].queue (line 8) matches env.qa.queues.producers[1].queue (line 6)";
  for (const unsafe of [storage + "\n", storage.replace("preview_database_id", marker),
    storage.replace("default.d1_databases", "default.kv_namespaces"), storage.replace("preview_database_id", "id"),
    preview.replace("default.previews", "env.sibling.previews"), preview.replace(".queue (line", ".bucket_name (line"),
    preview.replaceAll("queues.producers", "queuesXproducers"), preview + " · " + marker]) {
    const record = { ...item, data: { ...item.data, codeSnippet: unsafe } };
    assert.equal(JSON.parse(batchPrompt({ ...review, findings: [record] }, [record.id])).findings[0].data.codeSnippet, undefined);
  }
  for (const safe of ["env.staging.vars.PASSWORD = [withheld]", "default.previews.vars.SIGNING_KEY = [withheld]",
    "default: workers_dev = false (line 4), preview_urls = true (line 6)", storage, preview]) {
    const record = { ...item, data: { ...item.data, codeSnippet: safe } };
    for (const mode of ["quick", "deep", "source"] as const) {
      const retained = JSON.parse(batchPrompt({ ...review, mode, findings: [record] }, [record.id])).findings[0];
      assert.equal(retained.data.codeSnippet, safe);
      assert.ok(!JSON.stringify(retained).includes(marker));
    }
  }
});

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

test("signing key masks bind to the original file bytes and survive catalog recovery", () => {
  const key = "owned-marker-for-review";
  const source = `from jose import jwt\r\nmaterial = """${key}\r\nsecond-part"""\r\ndef issue(data): return jwt.encode(data, material, algorithm="HS256")\r\n`;
  const { input } = catalog({ "auth.py": source, "app.py": "def ready(): return True" });
  const expected = source.replace(/\r\n/g, "\n").split("\n");
  expected.fill("[REDACTED_SIGNING_KEY]", 1, 3);
  const proof = { ranges: [[2, 3]], sha256: hex(expected.join("\n")) };
  const masks = { [hex(source)]: proof };
  const captured = captureReviewSources(input, input, [], masks);
  assert.equal(captured.omittedFiles, 0);
  const restored = validateReviewSources(JSON.parse(JSON.stringify(captured)));
  const auth = restored.files.find((file) => file.path === "auth.py")!;
  assert.equal(auth.content, expected.join("\n"));
  assert.equal(auth.sourceDigest, "sha256:" + hex(source));
  assert.ok(!JSON.stringify(restored).includes(key));
  assert.throws(() => validateReviewSources({ ...restored, files: [{ ...auth, signingKeyReview: undefined }] }));
  for (const bad of [undefined, {}, { [hex(source)]: { ...proof, ranges: [[3, 3]] } }]) {
    const unavailable = captureReviewSources(input, input, [], bad);
    assert.equal(unavailable.omittedFiles, 1);
    assert.equal(unavailable.unverifiedSigningKeyFiles, 1);
    assert.deepEqual(unavailable.files.map((file) => file.path), ["app.py"]);
  }
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

test("source verdicts require contiguous cited coverage, matching snapshot bytes and directional evidence", () => {
  const snap = snapshot();
  snap.sources = catalog({ "main.py": "first\nmiddle\nlast\n" }).sources;
  snap.findings[0].data.lineEnd = 3;
  const session = emptySourceSession();
  const read = (line: number) => {
    const request = parseSourceToolRequest({ name: "source_read", arguments: {
      file_id: snap.sources!.files[0].id, line_start: line, line_end: line,
    } });
    const [span] = runSourceRequests(snap, session, [request]);
    session.spans.push(span);
    return (span.evidence.citation as { citation_id: string }).citation_id;
  };
  const citations = [read(3), read(1)];
  const finalize = (row = result) => finalizeSourceReview(snap, ["finding"], session, {
    results: [row], citationIds: { finding: citations },
  }).results[0];
  assert.equal(finalize().verdict, "needs_review");
  citations.push(read(2));
  assert.equal(finalize().verdict, "likely_false_positive");
  assert.equal(finalize({ ...result, evidenceAgainst: [" "] }).verdict, "needs_review");
  assert.equal(finalize({ ...result, verdict: "likely_true_positive" }).verdict, "needs_review");
  snap.sources = catalog({ "main.py": "first\nchanged\nlast\n" }).sources;
  assert.throws(() => finalize());
});

test("a positive flow review requires citations for the recorded origin and the reported location", () => {
  const snap = snapshot();
  snap.findings[0].data.taintFlow = JSON.stringify([{ file: "lib/helper.py", line: 2, message: "source: value" }]);
  const session = emptySourceSession();
  const requests = ["main.py", "lib/helper.py"].map((path) => parseSourceToolRequest({
    name: "source_read", arguments: { file_id: snap.sources!.files.find((f) => f.path === path)!.id, line_start: 1, line_end: 2 },
  }));
  session.spans = runSourceRequests(snap, session, requests);
  const ids = session.spans.map((s) => (s.evidence.citation as { citation_id: string }).citation_id);
  const positive = { ...result, verdict: "likely_true_positive" as const, evidenceFor: ["Recorded input reaches the operation."] };
  const finalize = (citations: string[]) => finalizeSourceReview(snap, ["finding"], session, {
    results: [positive], citationIds: { finding: citations },
  }).results[0];
  assert.equal(finalize(ids.slice(0, 1)).verdict, "needs_review");
  assert.equal(finalize(ids.slice(1)).verdict, "needs_review");
  assert.equal(finalize(ids).verdict, "likely_true_positive");
});
