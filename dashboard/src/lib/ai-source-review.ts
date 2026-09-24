/** Strict source-review protocol and replayable, bounded evidence. */
import { batchPrompt, parseReviewResults, REVIEW_LIMITS, ReviewContractError, type ReviewResult, type ReviewSnapshot } from "./ai-review-contract.ts";
import { executeSourceTool, parseSourceToolRequest, SOURCE_TOOL_LIMITS, sourceCatalogSummary, type SourceCitation, type SourceToolRequest, type SourceToolSpan } from "./ai-source-tools.ts";
import { sha256 } from "./provider-receipt.ts";

export interface SourceSession { roundIndex: number; spans: SourceToolSpan[]; previousDigest: string; promptBytes: number }
export const emptySourceSession = (): SourceSession => ({ roundIndex: 0, spans: [], previousDigest: "", promptBytes: 0 });
export interface SourceFinal { results: ReviewResult[]; citationIds: Record<string, string[]> }
export interface SavedSourceEvidence {
  version: 1;
  catalog: ReturnType<typeof sourceCatalogSummary>;
  model: string;
  prompt_digest: string;
  citations: Array<SourceCitation & { request_id: string }>;
  tools_used: SourceToolSpan[];
  trace: { model_calls: number; prompt_bytes: number; stop_reason: "final_review"; source_manifest: string };
}
const bytes = (value: unknown) => Buffer.byteLength(JSON.stringify(value));
export class SourceBudgetError extends ReviewContractError {}
function fail(): never { throw new ReviewContractError("Source review schema or evidence does not match its version."); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fail();
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, fields: string[]) {
  if (Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) fail();
}

export function sourceReviewPrompt(snapshot: ReviewSnapshot, ids: string[], session: SourceSession): string {
  const user = JSON.stringify({ ...JSON.parse(batchPrompt(snapshot, ids)), source_progress: {
    round: session.roundIndex + 1, rounds_limit: SOURCE_TOOL_LIMITS.rounds,
    tools_remaining: SOURCE_TOOL_LIMITS.calls - session.spans.length,
    final_required: session.roundIndex >= SOURCE_TOOL_LIMITS.rounds - 1 || session.spans.length >= SOURCE_TOOL_LIMITS.calls,
    tool_results: session.spans,
  } });
  if (Buffer.byteLength(snapshot.system) + Buffer.byteLength(user) > REVIEW_LIMITS.promptBytes) throw new SourceBudgetError("Source review prompt exceeds its limit.");
  return user;
}

export function parseSourceResponse(text: string, ids: string[]): { kind: "tools"; requests: SourceToolRequest[] } | ({ kind: "review" } & SourceFinal) {
  let value: Record<string, unknown>;
  try { value = record(JSON.parse(text)); } catch { return fail(); }
  if (value.kind === "tools") {
    exact(value, ["kind", "requests"]);
    if (!Array.isArray(value.requests) || !value.requests.length || value.requests.length > SOURCE_TOOL_LIMITS.calls) return fail();
    try { return { kind: "tools", requests: value.requests.map(parseSourceToolRequest) }; } catch { return fail(); }
  }
  if (value.kind !== "review") return fail();
  exact(value, ["kind", "reviews"]);
  if (!Array.isArray(value.reviews) || value.reviews.length > ids.length) return fail();
  const citationIds: Record<string, string[]> = Object.create(null);
  const plain = value.reviews.map((raw) => {
    const item = record(raw), { citationIds: citations, ...result } = item;
    if (typeof result.findingId !== "string" || !Array.isArray(citations) || citations.length > 16
      || citations.some((id) => typeof id !== "string" || !/^sha256:[a-f0-9]{64}$/.test(id)) || new Set(citations).size !== citations.length) return fail();
    citationIds[result.findingId] = citations;
    return result;
  });
  return { kind: "review", results: parseReviewResults(JSON.stringify(plain), ids), citationIds };
}

/** Called only after lease, project, source and call binding are rechecked. */
export function runSourceRequests(snapshot: ReviewSnapshot, session: SourceSession, requests: SourceToolRequest[]): SourceToolSpan[] {
  if (!snapshot.sources || session.roundIndex >= SOURCE_TOOL_LIMITS.rounds - 1 || !requests.length
    || session.spans.length + requests.length > SOURCE_TOOL_LIMITS.calls) throw new SourceBudgetError("Source tool or round budget exhausted. A final review was required.");
  const spans = requests.map((request, index) => executeSourceTool(request, snapshot.sources!, `source-${session.spans.length + index + 1}`, session.roundIndex + 1));
  if (bytes([...session.spans, ...spans]) > SOURCE_TOOL_LIMITS.totalEvidenceBytes) throw new SourceBudgetError("Source evidence budget exhausted.");
  return spans;
}

function citationsFrom(spans: SourceToolSpan[]) {
  const citations = new Map<string, SourceCitation & { request_id: string }>();
  for (const span of spans) {
    if (!span.ok) continue;
    const matches = span.tool === "source_read" ? [span.evidence] : span.tool === "source_search" ? span.evidence.matches : [];
    if (!Array.isArray(matches)) return fail();
    for (const raw of matches) {
      const match = record(raw), citation = record(match.citation);
      exact(citation, ["citation_id", "repository_id", "path", "line_start", "line_end", "source_digest", "excerpt_digest"]);
      const { citation_id: id, ...identity } = citation;
      if (typeof match.content !== "string" || Buffer.byteLength(match.content) > SOURCE_TOOL_LIMITS.readBytes
        || typeof id !== "string" || sha256(JSON.stringify(identity)) !== id || sha256(match.content) !== citation.excerpt_digest
        || typeof citation.repository_id !== "string" || typeof citation.path !== "string"
        || typeof citation.source_digest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(citation.source_digest)
        || typeof citation.line_start !== "number" || !Number.isSafeInteger(citation.line_start) || citation.line_start < 1
        || typeof citation.line_end !== "number" || !Number.isSafeInteger(citation.line_end) || citation.line_end < citation.line_start
        || citation.line_end - citation.line_start >= SOURCE_TOOL_LIMITS.readLines) return fail();
      citations.set(id, { ...citation as unknown as SourceCitation, request_id: span.request_id });
    }
  }
  return citations;
}

export function finalizeSourceReview(snapshot: ReviewSnapshot, ids: string[], session: SourceSession, final: SourceFinal): SourceFinal {
  if (!snapshot.sources) return fail();
  const parsed = parseSourceResponse(JSON.stringify({ kind: "review", reviews: final.results.map((result) => ({ ...result, citationIds: final.citationIds[result.findingId] })) }), ids);
  if (parsed.kind !== "review") return fail();
  const available = citationsFrom(session.spans);
  for (const result of parsed.results) {
    const citations = parsed.citationIds[result.findingId].map((id) => available.get(id) || fail());
    const finding = snapshot.findings.find((finding) => finding.id === result.findingId)!;
    const covered = citations.some((citation) => citation.repository_id === snapshot.sources!.repository
      && citation.path === finding.data.filePath && typeof finding.data.lineStart === "number"
      && citation.line_start <= finding.data.lineStart && citation.line_end >= finding.data.lineStart);
    if (result.verdict !== "needs_review" && !covered) {
      result.verdict = "needs_review"; result.confidence = 0; result.adjustedSeverity = null;
      result.evidenceGaps = ["The source tools did not provide a cited read covering this finding location.", ...result.evidenceGaps].slice(0, 20);
    }
  }
  return { results: parsed.results, citationIds: parsed.citationIds };
}

export function saveSourceEvidence(snapshot: ReviewSnapshot, session: SourceSession, ids: string[], model: string, promptDigest: string, currentPromptBytes: number): SavedSourceEvidence {
  if (!snapshot.sources) return fail();
  const available = citationsFrom(session.spans);
  return { version: 1, catalog: sourceCatalogSummary(snapshot.sources), model, prompt_digest: promptDigest,
    citations: ids.map((id) => available.get(id) || fail()), tools_used: session.spans,
    trace: { model_calls: session.roundIndex + 1, prompt_bytes: session.promptBytes + currentPromptBytes, stop_reason: "final_review", source_manifest: snapshot.sources.manifestDigest } };
}

/** Retained excerpts remain independently checkable after the full input expires. */
export function validateSavedSourceEvidence(raw: SavedSourceEvidence): void {
  if (!raw || raw.version !== 1 || bytes(raw) > SOURCE_TOOL_LIMITS.totalEvidenceBytes + 20_000 || !Array.isArray(raw.tools_used)
    || raw.tools_used.length > SOURCE_TOOL_LIMITS.calls || !Array.isArray(raw.citations) || raw.citations.length > 16
    || raw.catalog?.manifestDigest !== raw.trace?.source_manifest || !/^sha256:[a-f0-9]{64}$/.test(raw.trace?.source_manifest)
    || !Number.isInteger(raw.trace.model_calls) || raw.trace.model_calls < 1 || raw.trace.model_calls > SOURCE_TOOL_LIMITS.rounds) return fail();
  for (const span of raw.tools_used) {
    const request = parseSourceToolRequest({ name: span.tool, arguments: span.arguments });
    if (span.input_digest !== sha256(JSON.stringify(request)) || span.output_digest !== sha256(JSON.stringify({ evidence: span.evidence, error: span.error, truncated: span.truncated }))) return fail();
  }
  const available = citationsFrom(raw.tools_used);
  for (const citation of raw.citations) {
    if (citation.repository_id !== raw.catalog.repository || JSON.stringify(available.get(citation.citation_id)) !== JSON.stringify(citation)) return fail();
  }
}
