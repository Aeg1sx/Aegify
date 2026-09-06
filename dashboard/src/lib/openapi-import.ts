import type { PrismaClient } from "@prisma/client";
import { publicProviderRequest, type ProviderTransport } from "./public-https.ts";
import { parseApiContract, reconcileContract, SPEC_MAX_BYTES, type ApiContract } from "./openapi-contract.ts";
import { authOrigin } from "./auth-policy.ts";

export function specMutationOriginAllowed(request: Request, environment: Record<string, string | undefined>): boolean {
  if (request.headers.get("sec-fetch-site") === "cross-site") return false;
  const origin = request.headers.get("origin");
  if (!origin) return false;
  if (environment.AUTH_URL) return origin === authOrigin(environment);
  if (environment.NODE_ENV === "production") return false;
  // Next dev may normalize the internal request URL to localhost. Check the
  // browser-controlled Origin against Host, and allow only loopback preview.
  try {
    const parsed = new URL(origin);
    return ["http:", "https:"].includes(parsed.protocol) && ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname) && parsed.origin === origin && parsed.host === request.headers.get("host");
  } catch { return false; }
}

export function specUrl(value: unknown): string {
  if (typeof value !== "string" || value.length > 2000) throw new Error("Enter a raw specification HTTPS URL.");
  let url: URL; try { url = new URL(value); } catch { throw new Error("Invalid specification URL."); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) throw new Error("Use HTTPS without credentials, query parameters, or fragments. Upload private specifications as files.");
  return url.href;
}
export async function fetchApiContract(url: string, transport: ProviderTransport = publicProviderRequest): Promise<{ source: string; contract: ApiContract }> {
  const safeUrl = specUrl(url);
  const response = await transport({ url: safeUrl, method: "GET", headers: { Accept: "application/json, application/yaml, text/yaml, text/plain" }, body: "", timeoutMs: 10_000 });
  if (response.status < 200 || response.status >= 300) throw new Error("Specification fetch failed (HTTP " + response.status + "). Redirects and authenticated URLs are not supported; use a file upload.");
  return { source: safeUrl, contract: parseApiContract(response.text) };
}
export async function readSpecBody(request: Request, limit = SPEC_MAX_BYTES): Promise<ArrayBuffer> {
  if (Number(request.headers.get("content-length")) > limit) throw new Error("Specification request exceeds the size limit.");
  const reader = request.body?.getReader(); if (!reader) throw new Error("A specification is required.");
  const chunks: Uint8Array[] = []; let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) { await reader.cancel(); throw new Error("Specification request exceeds the size limit."); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(bytes); let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result.buffer;
}
export async function contractRepositoryIds(db: PrismaClient, scanId: string) {
  const [endpoints, findings] = await Promise.all([
    db.endpoint.findMany({ where: { scanId }, distinct: ["repositoryId"], select: { repositoryId: true } }),
    db.finding.findMany({ where: { scanId }, distinct: ["repositoryId"], select: { repositoryId: true } }),
  ]);
  const ids = [...new Set([...endpoints, ...findings].map((item) => item.repositoryId))].sort();
  return ids.length ? ids : [""];
}
export async function importApiContract(db: PrismaClient, input: { scanId: string; repositoryId: string; sourceType: string; sourceName: string; sourceUrl: string; contract: ApiContract }) {
  const { scanId, repositoryId, contract } = input;
  return db.$transaction(async (tx) => {
    const existing = await tx.apiSpecification.findUnique({ where: { scanId_repositoryId_contentHash: { scanId, repositoryId, contentHash: contract.digest } } });
    if (existing) return { id: existing.id, imported: 0, duplicate: true };
    if (await tx.apiSpecification.count({ where: { scanId, repositoryId } }) >= 30) throw new Error("This scan/repository already contains 30 specification snapshots. Start a new scan for a new snapshot.");
    const spec = await tx.apiSpecification.create({ data: { scanId, repositoryId, sourceType: input.sourceType, sourceName: input.sourceName, sourceUrl: input.sourceUrl, contentHash: contract.digest, title: contract.title, apiVersion: contract.apiVersion, specVersion: contract.version, contract: JSON.stringify(contract), operationCount: contract.operations.length } });
    const endpoints = await tx.endpoint.findMany({ where: { scanId, repositoryId }, select: { path: true, method: true } });
    const keys = new Set(endpoints.map((endpoint) => endpoint.method + ":" + endpoint.path));
    let imported = 0;
    for (const operation of contract.operations) for (const path of operation.resolvedPaths) {
      const key = operation.method + ":" + path; if (keys.has(key)) continue;
      keys.add(key);
      await tx.endpoint.create({ data: { scanId, repositoryId, path, method: operation.method, filePath: "openapi:" + spec.id, framework: "OpenAPI", handlerFunction: operation.operationId || operation.method + " " + operation.path,
        // Documentation does not prove that authentication exists in the implementation.
        authRequired: false, parameters: JSON.stringify(operation.parameters.map((parameter) => ({ name: parameter.name, location: parameter.location, paramType: typeof parameter.schema.type === "string" ? parameter.schema.type : "", required: parameter.required }))),
      } }); imported++;
    }
    return { id: spec.id, imported, duplicate: false };
  }, { timeout: 30_000 });
}
export async function inspectApiContract(db: PrismaClient, scanId: string, repositoryId: string, contract: ApiContract) {
  const endpoints = await db.endpoint.findMany({ where: { scanId, repositoryId }, select: { id: true, path: true, method: true, framework: true, filePath: true, lineStart: true, lineEnd: true, authRequired: true } });
  return reconcileContract(contract, endpoints);
}
