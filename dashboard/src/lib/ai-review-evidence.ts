/** Bounded display model for imported scanner-side AI evidence. */
export interface SourceReferenceView {
  id: string;
  requestId: string;
  repository: string;
  path: string;
  lineStart: number;
  lineEnd: number;
  sourceDigest: string;
  excerptDigest: string;
  excerpt: string;
}

export interface ToolSpanView {
  requestId: string;
  name: string;
  ok: boolean;
  truncated: boolean;
  cached: boolean;
  round: number;
  durationMs: number;
  summary: string;
  arguments: string;
  inputDigest: string;
  outputDigest: string;
}

export interface AIReviewEvidenceView {
  references: SourceReferenceView[];
  tools: ToolSpanView[];
  model: string;
  modelCalls: number;
  promptBytes: number;
  stopReason: string;
  sourceManifest: string;
  promptDigest: string;
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function text(value: unknown, limit = 1024): string {
  return typeof value === "string" ? value.slice(0, limit) : "";
}

function boundedNumber(value: unknown, max = 1_000_000): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.max(0, Math.min(value, max)) : 0;
}

function digest(value: unknown): string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value) ? value : "";
}

function argumentPreview(value: unknown): string {
  const source = record(value);
  const output: Record<string, unknown> = {};
  for (const key in source) {
    if (!Object.hasOwn(source, key)) continue;
    if (Object.keys(output).length >= 20) break;
    const item = source[key];
    output[key.slice(0, 128)] = typeof item === "string" ? item.slice(0, 512)
      : typeof item === "number" || typeof item === "boolean" || item === null ? item : "[structured value]";
  }
  return JSON.stringify(output, null, 2);
}

export function normalizeAIReviewEvidence(value: Record<string, unknown>): AIReviewEvidenceView {
  const rawTools = Array.isArray(value.tools_used) ? value.tools_used.slice(0, 20).map(record) : [];
  const tools = rawTools.map((item): ToolSpanView => ({
    requestId: text(item.request_id, 128),
    name: text(item.tool, 64),
    ok: item.ok !== false,
    truncated: item.truncated === true,
    cached: item.cached === true,
    round: Math.floor(boundedNumber(item.round, 8)),
    durationMs: boundedNumber(item.duration_ms, 900_000),
    summary: text(item.summary, 1000),
    arguments: argumentPreview(item.arguments),
    inputDigest: digest(item.input_digest),
    outputDigest: digest(item.output_digest),
  }));
  const references: SourceReferenceView[] = [];
  const rawReferences = Array.isArray(value.citations) ? value.citations.slice(0, 100) : [];
  for (const raw of rawReferences) {
    const item = record(raw);
    const id = digest(item.citation_id);
    const sourceDigest = digest(item.source_digest);
    const excerptDigest = digest(item.excerpt_digest);
    const start = item.line_start, end = item.line_end;
    if (!id || !sourceDigest || !excerptDigest || !Number.isInteger(start) || !Number.isInteger(end)
      || typeof start !== "number" || typeof end !== "number" || start < 1 || end < start || end - start >= 200) continue;
    const requestId = text(item.request_id, 128);
    const tool = rawTools.find((tool) => tool.request_id === requestId && tool.ok !== false);
    const evidence = record(tool?.evidence);
    let excerpt = "";
    if (tool?.tool === "source_read" && record(evidence.citation).citation_id === id) {
      excerpt = text(evidence.content, 16_384);
    } else if (tool?.tool === "source_search" && Array.isArray(evidence.matches)) {
      const match = evidence.matches.slice(0, 20).map(record)
        .find((match) => record(match.citation).citation_id === id);
      excerpt = text(match?.content, 1024);
    }
    references.push({ id, requestId, repository: text(item.repository_id, 256), path: text(item.path),
      lineStart: start, lineEnd: end, sourceDigest, excerptDigest, excerpt });
  }
  const trace = record(value.trace);
  return {
    references, tools, model: text(value.model, 256),
    modelCalls: Math.floor(boundedNumber(trace.model_calls, 9)),
    promptBytes: Math.floor(boundedNumber(trace.prompt_bytes, 2_000_000)),
    stopReason: text(trace.stop_reason, 64), sourceManifest: digest(trace.source_manifest),
    promptDigest: digest(value.prompt_digest),
  };
}
