import { authOrigin, type AuthEnvironment } from "./auth-policy.ts";

export function sameAuthOrigin(request: Request, environment: AuthEnvironment): boolean {
  const origin = authOrigin(environment);
  return Boolean(origin && request.headers.get("origin") === origin && request.headers.get("sec-fetch-site") !== "cross-site");
}
export async function readAuthBody(request: Request, maxBytes = 8192): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json") || !request.body) return null;
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let length = 0; let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxBytes) { await reader.cancel(); return null; }
      text += decoder.decode(value, { stream: true });
    }
    const value: unknown = JSON.parse(text + decoder.decode());
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; } finally { reader.releaseLock(); }
}
