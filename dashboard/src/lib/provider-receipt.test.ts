import assert from "node:assert/strict";
import test from "node:test";
import { callProviderDetailed, ProviderCallError } from "./provider-receipt.ts";
import { publicProviderRequest } from "./public-https.ts";
import { parseReviewResults } from "./ai-review-contract.ts";
import type { ProviderConfig } from "./provider-client.ts";

const config: ProviderConfig = { enabled: true, provider: "anthropic", model: "owned-model", customEndpoint: "", customHeaders: {}, anthropicApiKey: "owned-placeholder", openaiApiKey: "owned-placeholder", googleApiKey: "owned-placeholder" };
const bodies: Record<string, Record<string, unknown>> = {
  anthropic: { stop_reason: "end_turn", content: [{ type: "text", text: "[]" }], usage: { input_tokens: 100, output_tokens: 20, cache_read_input_tokens: 30, cache_creation_input_tokens: 40 } },
  google: { candidates: [{ finishReason: "STOP", content: { parts: [{ thought: true, text: "private reasoning" }, { text: "[]" }] } }], usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 20, thoughtsTokenCount: 15, cachedContentTokenCount: 30, totalTokenCount: 135 } },
  "openai-responses": { status: "completed", output: [{ type: "reasoning", summary: [] }, { type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: "[]" }] }], usage: { input_tokens: 100, output_tokens: 20, total_tokens: 120, input_tokens_details: { cached_tokens: 30 }, output_tokens_details: { reasoning_tokens: 10 } } },
  openai: { choices: [{ finish_reason: "stop", message: { role: "assistant", content: "[]" } }], usage: { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120, prompt_tokens_details: { cached_tokens: 30 } } },
};

test("four provider receipts preserve native cache/reasoning counters without inventing costs or usage", async () => {
  for (const [provider, body] of Object.entries(bodies)) {
    const response = await callProviderDetailed({ ...config, provider }, "owned system", "owned user", new AbortController().signal, async () => ({ status: 200, text: JSON.stringify(body) }));
    assert.equal(response.text, "[]"); assert.equal(response.receipt.costUsd, null); assert.equal(response.receipt.completion, "completed");
    assert.ok(response.receipt.reportedUsage); assert.ok(!JSON.stringify(response.receipt).includes("private reasoning")); assert.match(response.receipt.responseDigest!, /^sha256:/);
    const noUsage = { ...body, usage: undefined, usageMetadata: undefined };
    const missing = await callProviderDetailed({ ...config, provider }, "owned", "owned", new AbortController().signal, async () => ({ status: 200, text: JSON.stringify(noUsage) }));
    assert.equal(missing.receipt.reportedUsage, null);
  }
  const anthropic = await callProviderDetailed(config, "owned", "owned", new AbortController().signal, async () => ({ status: 200, text: JSON.stringify(bodies.anthropic) }));
  assert.deepEqual(anthropic.receipt.reportedUsage, { input_tokens: 100, output_tokens: 20, cache_creation_input_tokens: 40, cache_read_input_tokens: 30 });
});

test("truncation, refusals, tool requests and missing completion signals cannot masquerade as reviews", async () => {
  const cases: Array<[string, unknown]> = [
    ["anthropic", { ...bodies.anthropic, stop_reason: "max_tokens" }],
    ["anthropic", { ...bodies.anthropic, stop_reason: "refusal" }],
    ["anthropic", { ...bodies.anthropic, stop_reason: undefined }],
    ["anthropic", { ...bodies.anthropic, content: [{ type: "tool_use", name: "unrequested" }, { type: "text", text: "[]" }] }],
    ["google", { candidates: [{ finishReason: "MAX_TOKENS", content: { parts: [{ text: "[]" }] } }] }],
    ["google", { ...bodies.google, promptFeedback: { blockReason: "SAFETY" } }],
    ["openai-responses", { ...bodies["openai-responses"], status: "incomplete" }],
    ["openai-responses", { ...bodies["openai-responses"], output: [{ type: "message", role: "assistant", status: "completed", content: [{ type: "refusal", refusal: "private refusal" }] }] }],
    ["openai", { choices: [{ finish_reason: "length", message: { content: "[]" } }] }],
    ["openai", { choices: [{ finish_reason: "stop", message: { content: "[]", tool_calls: [{ function: "unrequested" }] } }] }],
  ];
  for (const [provider, body] of cases) await assert.rejects(callProviderDetailed({ ...config, provider }, "owned", "owned", new AbortController().signal, async () => ({ status: 200, text: JSON.stringify(body) })), (error: unknown) => error instanceof ProviderCallError && error.receipt.completion !== "completed" && !error.message.includes("private refusal"));
});

test("receipt errors redact provider bodies and unknown failures never claim zero cost", async () => {
  let calls = 0;
  await assert.rejects(callProviderDetailed(config, "owned", "owned", new AbortController().signal, async () => { calls++; throw new Error("private-credential"); }), (error: unknown) => error instanceof ProviderCallError && error.receipt.outcome === "unknown" && error.receipt.costUsd === null && !error.message.includes("private-credential"));
  assert.equal(calls, 1);
  await assert.rejects(callProviderDetailed(config, "owned", "owned", new AbortController().signal, async () => ({ status: 401, text: "private-credential" })), (error: unknown) => error instanceof ProviderCallError && !JSON.stringify(error.receipt).includes("private-credential"));
  const signal = AbortSignal.abort();
  await assert.rejects(publicProviderRequest({ url: "https://api.example.invalid/v1/messages", headers: {}, body: "{}", timeoutMs: 1000, signal }));
});

test("review parser rejects ambiguous or unbounded outputs and does not invent missing verdicts", () => {
  const valid = { findingId: "owned", verdict: "needs_review", confidence: 0.5, reasoning: "Static only", remediation: "Review", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["No runtime evidence"] };
  assert.equal(parseReviewResults(JSON.stringify([valid]), ["owned"])[0].verdict, "needs_review");
  for (const value of [[{ ...valid, verdict: "confirmed" }], [{ ...valid, confidence: 2 }], [{ ...valid, reasoning: null }], [{ ...valid, evidenceFor: [null] }], [{ ...valid, workflowStatus: "fixed" }], [valid, valid]]) assert.throws(() => parseReviewResults(JSON.stringify(value), ["owned"]));
  assert.throws(() => parseReviewResults("```json\n[]\n```", ["owned"]));
  assert.deepEqual(parseReviewResults("[]", ["owned"]), []);
});
