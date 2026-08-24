const SENSITIVE_KEY = /token|secret|password|authorization|api[_-]?key/i;
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const DESTRUCTIVE_TEMPLATE = /(?:\b(?:rm\s+-rf|drop\s+(?:database|table)|truncate\s+table|shutdown|reboot|mkfs|dd\s+if=|nc\s+-e|bash\s+-i|169\.254\.169\.254|(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash))\b|\/etc\/shadow)/i;

export function sanitizeLLMText(value: unknown, limit = 20_000): string {
  if (typeof value !== "string") return "";
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer [REDACTED]")
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED_AWS_KEY]")
    .replace(/\b(?:sk-ant-|sk-proj-|sk-)[A-Za-z0-9_-]{16,}\b/g, "[REDACTED_API_KEY]")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/\bAIza[A-Za-z0-9_-]{20,}\b/g, "[REDACTED_GOOGLE_KEY]")
    .replace(/\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .slice(0, limit);
}

export function sanitizeLLMStrings(value: unknown, limit = 100): string[] {
  return Array.isArray(value)
    ? value
        .filter((item): item is string => typeof item === "string")
        .slice(0, limit)
        .map((item) => sanitizeLLMText(item, 4_000))
    : [];
}

export function sanitizeProofTemplate(value: unknown): string {
  const sanitized = sanitizeLLMText(value);
  return DESTRUCTIVE_TEMPLATE.test(sanitized)
    ? "[BLOCKED_UNSAFE_TEMPLATE]"
    : sanitized;
}

function sanitizeValue(value: unknown, depth: number): unknown {
  if (depth > 8) return "[TRUNCATED]";
  if (typeof value === "string") return sanitizeLLMText(value);
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => sanitizeValue(item, depth + 1));
  if (!value || typeof value !== "object") return null;

  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value).slice(0, 100)) {
    if (DANGEROUS_KEYS.has(key)) continue;
    result[key] = SENSITIVE_KEY.test(key) ? "[REDACTED]" : sanitizeValue(item, depth + 1);
  }
  return result;
}

export function sanitizeLLMRecord(value: unknown): Record<string, unknown> {
  const sanitized = sanitizeValue(value, 0);
  return sanitized && typeof sanitized === "object" && !Array.isArray(sanitized)
    ? sanitized as Record<string, unknown>
    : {};
}

export function extractAnthropicText(value: unknown): string {
  if (!value || typeof value !== "object") return "";
  const content = (value as { content?: unknown }).content;
  if (!Array.isArray(content)) return "";
  const block = content.find((item) => {
    return item && typeof item === "object" &&
      (item as { type?: unknown }).type === "text" &&
      typeof (item as { text?: unknown }).text === "string";
  }) as { text?: string } | undefined;
  return block?.text || "";
}

export function buildLLMRequestHeaders(
  provider: "anthropic" | "openai",
  apiKey: string,
  customEndpoint: boolean,
  customHeaders: Record<string, string> = {},
): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (!customEndpoint && provider === "anthropic") {
    headers["anthropic-version"] = "2023-06-01";
    if (apiKey) headers["x-api-key"] = apiKey;
  }
  if (!customEndpoint && provider === "openai" && apiKey) {
    headers.Authorization = `Bearer ${apiKey}`;
  }
  return { ...headers, ...customHeaders };
}
