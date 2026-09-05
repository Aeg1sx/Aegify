export const PROVIDER_PROTOCOLS = [
  ["anthropic", "Anthropic Messages"],
  ["openai", "OpenAI Chat Completions"],
  ["openai-responses", "OpenAI Responses"],
  ["google", "Google Gemini"],
] as const;
export type ProviderProtocol = typeof PROVIDER_PROTOCOLS[number][0];
export const PROVIDER_PRESETS = [
  { id: "anthropic", name: "Anthropic", protocol: "anthropic", endpoint: "", tokenParameter: "max_tokens", hint: "Uses the stored Anthropic key on the official API only." },
  { id: "openai", name: "OpenAI · Responses", protocol: "openai-responses", endpoint: "", tokenParameter: "max_completion_tokens", hint: "Uses the stored OpenAI key. Responses are requested with store: false." },
  { id: "openai-chat", name: "OpenAI · Chat", protocol: "openai", endpoint: "", tokenParameter: "max_completion_tokens", hint: "Chat Completions protocol with an explicitly selected model ID." },
  { id: "gemini", name: "Google Gemini", protocol: "google", endpoint: "", tokenParameter: "max_tokens", hint: "Native generateContent requests with the stored Google API key." },
  { id: "azure", name: "Azure OpenAI", protocol: "openai", endpoint: "https://YOUR-RESOURCE.openai.azure.com/openai/v1", tokenParameter: "max_completion_tokens", hint: "Replace YOUR-RESOURCE, enter your deployment name as Model ID, and set an api-key custom header. Uses the Azure v1 API." },
  { id: "openrouter", name: "OpenRouter", protocol: "openai", endpoint: "https://openrouter.ai/api/v1", tokenParameter: "max_tokens", hint: "Use a provider/model ID and a dedicated Authorization: Bearer header." },
  { id: "groq", name: "Groq", protocol: "openai", endpoint: "https://api.groq.com/openai/v1", tokenParameter: "max_tokens", hint: "Use a model available to your Groq account and a dedicated Authorization: Bearer header." },
  { id: "compatible", name: "Custom HTTPS gateway", protocol: "openai", endpoint: "https://YOUR-GATEWAY.example/v1", tokenParameter: "max_tokens", hint: "Enter your HTTPS API base or full operation URL. Private/loopback addresses and redirects are blocked. Supply a dedicated credential in custom headers." },
] as const;
export function providerProtocol(value: string): value is ProviderProtocol { return PROVIDER_PROTOCOLS.some(([id]) => id === value); }

/** Accept base paths and complete operation URLs without appending a second /v1. */
export function providerUrl(protocol: ProviderProtocol, endpoint: string, model: string): string {
  const defaults = { anthropic: "https://api.anthropic.com", openai: "https://api.openai.com", "openai-responses": "https://api.openai.com", google: "https://generativelanguage.googleapis.com" };
  const url = new URL(endpoint || defaults[protocol]);
  if (url.search || url.hash || url.username || url.password) throw new Error("Provider URLs must not contain credentials, query strings, or fragments. Use custom headers for authentication.");
  let path = url.pathname.replace(/\/+$/, "");
  if (protocol === "google") {
    const name = model.replace(/^models\//, "");
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(name)) throw new Error("Use a Gemini model ID, optionally prefixed with models/.");
    if (!path.endsWith(":generateContent")) {
      if (!path) path = "/v1beta";
      path += "/models/" + encodeURIComponent(name) + ":generateContent";
    }
  } else {
    const operation = protocol === "anthropic" ? "/messages" : protocol === "openai-responses" ? "/responses" : "/chat/completions";
    if (!path.endsWith(operation)) path = (path || "/v1") + operation;
  }
  url.pathname = path;
  return url.toString();
}
