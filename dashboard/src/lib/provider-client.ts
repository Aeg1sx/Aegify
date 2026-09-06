import { providerProtocol, providerUrl, type ProviderProtocol } from "./provider-catalog.ts";
import { extractAnthropicText, sanitizeLLMText } from "./llm-safety.ts";
import { validateCustomHeaders, validateEndpointUrl } from "./url-validator.ts";
import { publicProviderRequest, type ProviderHttpRequest, type ProviderTransport } from "./public-https.ts";

export interface ProviderConfig {
  enabled: boolean; provider: string; model: string; customEndpoint: string; customHeaders: Record<string, string>;
  anthropicApiKey: string; openaiApiKey: string; googleApiKey?: string;
  maxOutputTokens?: number; timeoutSeconds?: number; chatTokenParameter?: string;
}
export function buildProviderRequest(config: ProviderConfig, system: string, user: string, outputLimit?: number): ProviderHttpRequest {
  if (!config.enabled) throw new Error("AI review is not enabled. Configure it in Settings.");
  if (!providerProtocol(config.provider)) throw new Error("Unsupported provider protocol.");
  if (!config.model.trim()) throw new Error("Configure an explicit model ID in Settings.");
  const url = providerUrl(config.provider, config.customEndpoint, config.model);
  const valid = validateEndpointUrl(url); if (!valid.valid) throw new Error(valid.error);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.provider === "anthropic") headers["anthropic-version"] = "2023-06-01";
  if (!config.customEndpoint) {
    const key = config.provider === "anthropic" ? config.anthropicApiKey : config.provider === "google" ? config.googleApiKey : config.openaiApiKey;
    if (!key) throw new Error("The selected provider API key is not configured.");
    headers[config.provider === "anthropic" ? "x-api-key" : config.provider === "google" ? "x-goog-api-key" : "Authorization"] = ["anthropic", "google"].includes(config.provider) ? key : "Bearer " + key;
  }
  const extra = config.customHeaders;
  if (!extra || typeof extra !== "object" || Array.isArray(extra) || Object.keys(extra).length > 20 || Object.values(extra).some((value) => typeof value !== "string")) throw new Error("Custom headers must be a bounded object of strings.");
  const headerValidation = validateCustomHeaders(extra); if (!headerValidation.valid) throw new Error(headerValidation.error);
  for (const [key, value] of Object.entries(extra)) {
    if (!/^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$/.test(key)) throw new Error("Invalid custom header name.");
    const existing = Object.keys(headers).find((name) => name.toLowerCase() === key.toLowerCase());
    if (existing) delete headers[existing];
    headers[key] = value;
  }
  const configuredLimit = config.maxOutputTokens ?? 4096;
  const max = outputLimit ? Math.min(outputLimit, configuredLimit) : configuredLimit;
  if (!Number.isInteger(max) || max < 1 || max > 32768) throw new Error("Output token limit must be between 1 and 32768.");
  const timeout = config.timeoutSeconds ?? 60;
  if (!Number.isInteger(timeout) || timeout < 5 || timeout > 300) throw new Error("Timeout must be between 5 and 300 seconds.");
  const input = sanitizeLLMText(user, 200_000);
  let body: Record<string, unknown>;
  if (config.provider === "anthropic") body = { model: config.model, max_tokens: max, system, messages: [{ role: "user", content: input }] };
  else if (config.provider === "google") body = { systemInstruction: { parts: [{ text: system }] }, contents: [{ role: "user", parts: [{ text: input }] }], generationConfig: { maxOutputTokens: max } };
  else if (config.provider === "openai-responses") body = { model: config.model, instructions: system, input, max_output_tokens: max, store: false };
  else {
    const tokenParameter = config.chatTokenParameter || "max_tokens";
    if (!["max_tokens", "max_completion_tokens"].includes(tokenParameter)) throw new Error("Unsupported Chat Completions token parameter.");
    body = { model: config.model, [tokenParameter]: max, messages: [{ role: "system", content: system }, { role: "user", content: input }] };
  }
  return { url, headers, body: JSON.stringify(body), timeoutMs: timeout * 1000 };
}
function object(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function list(value: unknown): unknown[] { return Array.isArray(value) ? value : []; }
export function providerText(protocol: ProviderProtocol, value: unknown): string {
  const data = object(value);
  if (protocol === "anthropic") return extractAnthropicText(data);
  if (protocol === "google") return list(object(object(list(data.candidates)[0]).content).parts).filter((part) => object(part).thought !== true).map((part) => typeof object(part).text === "string" ? object(part).text : "").join("");
  if (protocol === "openai-responses") {
    if (data.status && data.status !== "completed") throw new Error("The provider response did not complete. Review token limits and provider status.");
    return list(data.output).filter((item) => object(item).type === "message").flatMap((item) => list(object(item).content)).filter((item) => object(item).type === "output_text").map((item) => typeof object(item).text === "string" ? object(item).text : "").join("\n");
  }
  const content = object(object(list(data.choices)[0]).message).content;
  return typeof content === "string" ? content : "";
}
export async function callProvider(config: ProviderConfig, system: string, user: string, outputLimit?: number, transport: ProviderTransport = publicProviderRequest): Promise<string> {
  const request = buildProviderRequest(config, system, user, outputLimit);
  const response = await transport(request);
  // Provider error bodies may echo request credentials or source. Never forward them to clients/logs.
  if (response.status < 200 || response.status >= 300) throw new Error("Provider request failed (HTTP " + response.status + "). Check the saved endpoint, model, credentials, and account limits.");
  if (Buffer.byteLength(response.text) > 2 * 1024 * 1024) throw new Error("Provider response exceeds 2 MiB.");
  let data: unknown; try { data = JSON.parse(response.text); } catch { throw new Error("Provider returned invalid JSON."); }
  const text = providerText(config.provider as ProviderProtocol, data);
  if (!text.trim()) throw new Error("Provider returned no text. Check model support, safety filters, and output token limits.");
  return text;
}
