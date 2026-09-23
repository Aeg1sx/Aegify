import assert from "node:assert/strict";
import test from "node:test";
import { normalizeAIReviewEvidence } from "./ai-review-evidence.ts";

const sha = "sha256:" + "a".repeat(64);
const citation = { citation_id: sha, request_id: "tool-2", repository_id: "service", path: "src/app.py", source_digest: sha, excerpt_digest: sha, line_start: 2, line_end: 2 };

test("source excerpts require the matching tool, request and citation", () => {
  const view = normalizeAIReviewEvidence({
    citations: [citation],
    tools_used: [{ tool: "source_read", request_id: "tool-2", ok: true, round: 2, evidence: { citation, content: "    return name" } }],
    trace: { model_calls: 3, prompt_bytes: 4000, source_manifest: sha, stop_reason: "final_review" },
  });
  assert.equal(view.references[0].excerpt, "    return name");
  assert.equal(view.modelCalls, 3);
  assert.equal(view.tools[0].round, 2);
  for (const tool of ["other_tool", "source_search"]) {
    const mismatch = normalizeAIReviewEvidence({ citations: [citation], tools_used: [{ tool, request_id: "tool-2", evidence: { citation, content: "unrelated" } }] });
    assert.equal(mismatch.references[0].excerpt, "");
  }
  const failed = normalizeAIReviewEvidence({ citations: [citation], tools_used: [{ tool: "source_read", request_id: "tool-2", ok: false, evidence: { citation, content: "not returned" } }] });
  assert.equal(failed.references[0].excerpt, "");
});

test("malformed and oversized imported AI evidence stays bounded and legacy data works", () => {
  const view = normalizeAIReviewEvidence({
    citations: [null, [], { ...citation, line_end: -1 }, { ...citation, source_digest: "invalid" }],
    tools_used: Array.from({ length: 100 }, () => ({ tool: "source_read", duration_ms: Infinity, arguments: { query: "x".repeat(1_000_000), nested: { huge: "x".repeat(1_000_000) } } })),
    trace: { model_calls: -8, stop_reason: "x".repeat(1000) },
  });
  assert.deepEqual(view.references, []);
  assert.equal(view.tools.length, 20);
  assert.ok(view.tools[0].arguments.length < 1000);
  assert.equal(view.tools[0].durationMs, 0);
  assert.equal(view.modelCalls, 0);
  assert.equal(view.stopReason.length, 64);
  assert.deepEqual(normalizeAIReviewEvidence({ verdict: "needs_review" }).tools, []);
});

test("source search retains only the cited match and preserves failed or cached tool states", () => {
  const view = normalizeAIReviewEvidence({ citations: [citation], tools_used: [
    { tool: "source_search", request_id: "tool-2", cached: true, evidence: { matches: [{ citation, content: "matched line" }, { citation: { citation_id: "other" }, content: "unrelated" }] } },
    { tool: "source_read", request_id: "tool-3", ok: false, truncated: true, summary: "Evidence limit" },
  ] });
  assert.equal(view.references[0].excerpt, "matched line");
  assert.equal(view.tools[0].cached, true);
  assert.equal(view.tools[1].ok, false);
  assert.equal(view.tools[1].truncated, true);
});
