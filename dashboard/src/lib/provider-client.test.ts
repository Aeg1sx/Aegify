import assert from "node:assert/strict";
import test from "node:test";
import { buildProviderRequest, callProvider, providerText, type ProviderConfig } from "./provider-client.ts";
import { providerUrl } from "./provider-catalog.ts";
import { publicProviderAddress } from "./public-https.ts";

const config: ProviderConfig = { enabled: true, provider: "anthropic", model: "test-model", customEndpoint: "", customHeaders: {}, anthropicApiKey: "synthetic-anthropic-key", openaiApiKey: "synthetic-openai-key", googleApiKey: "synthetic-google-key", maxOutputTokens: 4096, timeoutSeconds: 60 };

test("provider URL normalization accepts origin, API base, and full operation paths", () => {
  for (const endpoint of ["https://api.example", "https://api.example/v1", "https://api.example/v1/", "https://api.example/v1/chat/completions"]) assert.equal(providerUrl("openai", endpoint, "test"), "https://api.example/v1/chat/completions");
  assert.equal(providerUrl("openai", "https://openrouter.ai/api/v1", "vendor/model"), "https://openrouter.ai/api/v1/chat/completions");
  assert.equal(providerUrl("openai", "https://resource.openai.azure.com/openai/v1", "deployment"), "https://resource.openai.azure.com/openai/v1/chat/completions");
  assert.equal(providerUrl("google", "", "models/test-model"), "https://generativelanguage.googleapis.com/v1beta/models/test-model:generateContent");
  assert.equal(providerUrl("anthropic", "https://api.example/v1", "test"), "https://api.example/v1/messages");
  assert.equal(providerUrl("openai-responses", "", "test"), "https://api.openai.com/v1/responses");
  assert.throws(() => providerUrl("openai", "https://api.example?api-key=private", "test"));
});

test("native protocols use their own envelopes and never forward a default key to custom hosts", () => {
  const anthropic = buildProviderRequest(config, "system", "user");
  assert.equal(anthropic.headers["x-api-key"], config.anthropicApiKey); assert.equal(JSON.parse(anthropic.body).system, "system");
  const gemini = buildProviderRequest({ ...config, provider: "google" }, "system", "user");
  assert.equal(gemini.headers["x-goog-api-key"], config.googleApiKey); assert.equal(JSON.parse(gemini.body).contents[0].parts[0].text, "user");
  const responses = buildProviderRequest({ ...config, provider: "openai-responses" }, "system", "user");
  assert.equal(JSON.parse(responses.body).store, false); assert.equal(JSON.parse(responses.body).instructions, "system");
  const chat = buildProviderRequest({ ...config, provider: "openai", chatTokenParameter: "max_completion_tokens" }, "system", "user");
  assert.equal(JSON.parse(chat.body).max_completion_tokens, 4096);
  for (const protocol of ["anthropic", "openai", "openai-responses", "google"]) {
    const custom = buildProviderRequest({ ...config, provider: protocol, customEndpoint: "https://gateway.example/v1", customHeaders: { Authorization: "Bearer dedicated-gateway-key" } }, "system", "user");
    assert.ok(!JSON.stringify(custom).includes("synthetic-")); assert.equal(custom.headers.Authorization, "Bearer dedicated-gateway-key");
  }
  assert.throws(() => buildProviderRequest({ ...config, customEndpoint: "https://127.0.0.1" }, "system", "user"));
  assert.throws(() => buildProviderRequest({ ...config, customHeaders: { Cookie: "session=value" } }, "system", "user"));
});

test("response normalization ignores tool calls and thinking; incomplete/empty responses fail", async () => {
  assert.equal(providerText("google", { candidates: [{ content: { parts: [{ thought: true, text: "hidden" }, { text: "visible" }] } }] }), "visible");
  assert.equal(providerText("openai-responses", { status: "completed", output: [{ type: "function_call", arguments: "never execute" }, { type: "message", content: [{ type: "output_text", text: "visible" }] }] }), "visible");
  assert.throws(() => providerText("openai-responses", { status: "incomplete" }));
  await assert.rejects(() => callProvider(config, "system", "user", undefined, async () => ({ status: 400, text: "echoed-private-credential" })), (error: Error) => !error.message.includes("private"));
  await assert.rejects(() => callProvider(config, "system", "user", undefined, async () => ({ status: 200, text: "{}" })), /no text/);
  await assert.rejects(() => callProvider(config, "system", "user", undefined, async () => ({ status: 200, text: "x".repeat(2 * 1024 * 1024 + 1) })), /2 MiB/);
  assert.equal(await callProvider(config, "system", "user", 128, async (request) => { assert.equal(JSON.parse(request.body).max_tokens, 128); return { status: 200, text: JSON.stringify({ content: [{ type: "text", text: "ok" }] }) }; }), "ok");
});

test("provider network policy rejects private, reserved, mapped, and documentation addresses", () => {
  for (const address of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.1.1", "192.168.1.1", "203.0.113.1", "::1", "::ffff:127.0.0.1", "fd01::1", "fe80::1", "2001:db8::1", "2002:7f00:1::"]) assert.equal(publicProviderAddress(address), false, address);
  assert.equal(publicProviderAddress("8.8.8.8"), true);
  assert.equal(publicProviderAddress("2606:4700:4700::1111"), true);
});
