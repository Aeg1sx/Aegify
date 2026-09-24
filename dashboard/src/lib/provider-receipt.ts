import { createHash } from "node:crypto";
import { buildProviderRequest, providerText, type ProviderConfig } from "./provider-client.ts";
import type { ProviderProtocol } from "./provider-catalog.ts";
import { publicProviderRequest, type ProviderTransport } from "./public-https.ts";

export function sha256(value: string): string { return "sha256:" + createHash("sha256").update(value, "utf8").digest("hex"); }
function object(value: unknown): Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function list(value: unknown): Record<string, unknown>[] { return Array.isArray(value) ? value.map(object) : []; }
function identifier(value: unknown): string | null { return typeof value === "string" && /^[A-Za-z0-9._:/-]{1,200}$/.test(value) ? value : null; }

export interface ProviderReceipt {
  version: 1;
  provider: string;
  requestedModel: string;
  returnedModel: string | null;
  responseId: string | null;
  requestDigest: string;
  responseDigest: string | null;
  outcome: "received" | "unknown";
  completion: "completed" | "incomplete" | "refused" | "invalid" | "unknown";
  stopReason: string | null;
  httpStatus: number | null;
  startedAt: string;
  finishedAt: string;
  // Provider-native names preserve cache/reasoning semantics; missing is never zero.
  reportedUsage: Record<string, number> | null;
  costUsd: null;
}

export class ProviderCallError extends Error {
  code: string;
  receipt: ProviderReceipt;
  constructor(code: string, receipt: ProviderReceipt) {
    super("AI provider call did not produce a complete review (" + code + "). No automatic retry was made.");
    this.code = code; this.receipt = receipt;
  }
}

function usage(protocol: string, data: Record<string, unknown>): Record<string, number> | null {
  const native = object(protocol === "google" ? data.usageMetadata : data.usage);
  const fields = protocol === "anthropic"
    ? ["input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "cache_creation.ephemeral_5m_input_tokens", "cache_creation.ephemeral_1h_input_tokens"]
    : protocol === "google"
      ? ["promptTokenCount", "candidatesTokenCount", "cachedContentTokenCount", "thoughtsTokenCount", "totalTokenCount", "toolUsePromptTokenCount"]
      : protocol === "openai-responses"
        ? ["input_tokens", "output_tokens", "total_tokens", "input_tokens_details.cached_tokens", "input_tokens_details.cache_write_tokens", "output_tokens_details.reasoning_tokens"]
        : ["prompt_tokens", "completion_tokens", "total_tokens", "prompt_tokens_details.cached_tokens", "prompt_tokens_details.cache_write_tokens", "completion_tokens_details.reasoning_tokens"];
  const counters: Record<string, number> = {};
  for (const field of fields) {
    const value = field.split(".").reduce<unknown>((parent, key) => object(parent)[key], native);
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) counters[field] = value;
  }
  return Object.keys(counters).length ? counters : null;
}

function completion(protocol: string, data: Record<string, unknown>): Pick<ProviderReceipt, "completion" | "stopReason"> {
  if (data.error) return { completion: "invalid", stopReason: null };
  if (protocol === "anthropic") {
    const reason = identifier(data.stop_reason);
    if (reason === "refusal") return { completion: "refused", stopReason: reason };
    const unexpected = list(data.content).some((item) => !["text", "thinking", "redacted_thinking"].includes(String(item.type)));
    return { completion: reason === "end_turn" && !unexpected ? "completed" : "incomplete", stopReason: reason };
  }
  if (protocol === "google") {
    const candidates = list(data.candidates);
    const candidate = candidates[0] || {};
    const reason = identifier(candidate.finishReason);
    const blocked = Boolean(object(data.promptFeedback).blockReason) || ["SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"].includes(reason || "");
    const unexpected = list(object(candidate.content).parts).some((part) => Object.keys(part).some((key) => !["text", "thought", "thoughtSignature"].includes(key)));
    return { completion: blocked ? "refused" : reason === "STOP" && candidates.length === 1 && !unexpected ? "completed" : "incomplete", stopReason: reason };
  }
  if (protocol === "openai-responses") {
    const output = list(data.output);
    if (output.some((item) => list(item.content).some((content) => content.type === "refusal"))) return { completion: "refused", stopReason: "refusal" };
    const valid = data.status === "completed" && !data.incomplete_details && output.length > 0 && output.every((item) => item.type === "reasoning" || (item.type === "message" && item.status === "completed" && item.role === "assistant" && list(item.content).every((content) => content.type === "output_text")));
    return { completion: valid ? "completed" : "incomplete", stopReason: identifier(data.status) };
  }
  const choices = list(data.choices);
  const choice = choices[0] || {};
  const message = object(choice.message);
  const reason = identifier(choice.finish_reason);
  if (message.refusal || reason === "content_filter") return { completion: "refused", stopReason: reason };
  return { completion: choices.length === 1 && reason === "stop" && !message.function_call && !list(message.tool_calls).length ? "completed" : "incomplete", stopReason: reason };
}

/** One dispatch, bounded transport, no redirects/retries or hidden continuation calls. */
export async function callProviderDetailed(config: ProviderConfig, system: string, user: string, signal: AbortSignal, transport: ProviderTransport = publicProviderRequest) {
  const request = buildProviderRequest(config, system, user);
  const receipt: ProviderReceipt = {
    version: 1, provider: config.provider, requestedModel: config.model, returnedModel: null, responseId: null,
    requestDigest: sha256(JSON.stringify({ url: request.url, body: request.body })), responseDigest: null,
    outcome: "unknown", completion: "unknown", stopReason: null, httpStatus: null,
    startedAt: new Date().toISOString(), finishedAt: "", reportedUsage: null, costUsd: null,
  };
  let response;
  try { signal.throwIfAborted(); response = await transport({ ...request, signal }); }
  catch { receipt.finishedAt = new Date().toISOString(); throw new ProviderCallError(signal.aborted ? "request_interrupted" : "transport_unknown", receipt); }
  receipt.finishedAt = new Date().toISOString(); receipt.outcome = "received"; receipt.httpStatus = response.status;
  // A digest is useful for correlation without retaining provider error bodies or source.
  if (Buffer.byteLength(response.text) > 2 * 1024 * 1024) throw new ProviderCallError("response_too_large", receipt);
  receipt.responseDigest = sha256(response.text);
  if (response.status < 200 || response.status >= 300) throw new ProviderCallError("provider_http_error", receipt);
  let data: Record<string, unknown>;
  try { data = object(JSON.parse(response.text)); }
  catch { throw new ProviderCallError("invalid_provider_json", receipt); }
  Object.assign(receipt, completion(config.provider, data));
  receipt.reportedUsage = usage(config.provider, data);
  receipt.returnedModel = identifier(config.provider === "google" ? data.modelVersion : data.model);
  receipt.responseId = identifier(config.provider === "google" ? data.responseId : data.id);
  if (receipt.completion !== "completed") throw new ProviderCallError("provider_" + receipt.completion, receipt);
  const text = providerText(config.provider as ProviderProtocol, data);
  if (!text.trim()) { receipt.completion = "invalid"; throw new ProviderCallError("empty_provider_text", receipt); }
  return { text, receipt };
}
