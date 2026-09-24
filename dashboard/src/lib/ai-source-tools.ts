/** Bounded navigation over an admitted immutable source snapshot. No filesystem or network tools. */
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { sanitizeLLMSourceText } from "./llm-safety.ts";
import { sourceDigest, type SourceSnapshot } from "./source-snapshot.ts";

export const SOURCE_TOOL_LIMITS = {
  files: 512, catalogBytes: 2_500_000, fileBytes: 512_000, snapshotBytes: 64 * 1024 * 1024,
  findings: 25, batchFindings: 5, calls: 8, rounds: 4, outputBytes: 24_000, totalEvidenceBytes: 120_000,
  readLines: 200, readBytes: 16_384, searchMatches: 20, listFiles: 50,
} as const;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const HASH = /^[a-f0-9]{64}$/;
const sha = (value: string) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const bytes = (value: unknown) => {
  try { const encoded = JSON.stringify(value); return typeof encoded === "string" ? Buffer.byteLength(encoded) : Infinity; }
  catch { return Infinity; }
};
export class SourceToolError extends Error {}

export interface ReviewSourceFile {
  id: string; path: string; sourceDigest: string; contentDigest: string; content: string; lineCount: number;
}
export interface ReviewSourceCatalog {
  version: 1; repository: string; commit: string; sourceDigest: string; manifestDigest: string;
  truncated: boolean; omittedFiles: number; files: ReviewSourceFile[];
}
export interface SourceCitation {
  citation_id: string; repository_id: string; path: string; line_start: number; line_end: number;
  source_digest: string; excerpt_digest: string;
}
export interface SourceToolRequest {
  name: "source_list" | "source_read" | "source_search";
  arguments: Record<string, string | number>;
}
export interface SourceToolSpan {
  request_id: string; tool: SourceToolRequest["name"]; arguments: SourceToolRequest["arguments"];
  ok: boolean; error: string; truncated: boolean; cached: boolean; round: number;
  duration_ms: number; input_digest: string; output_digest: string;
  summary: string; evidence: Record<string, unknown>;
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new SourceToolError("Expected an object");
  return value as Record<string, unknown>;
}
function text(value: unknown, maximum: number, minimum = 1): string {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || /[\u0000\r]/.test(value)) throw new SourceToolError("Invalid bounded text");
  return value;
}
function integer(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new SourceToolError("Invalid bounded number");
  return value;
}
function safePath(value: unknown): string {
  const path = text(value, 1024);
  if (path.startsWith("/") || path.includes("\\") || /[\u0000-\u001f\u007f:]/.test(path) || path.split("/").some((part) => !part || part === "." || part === ".." || part === ".git")) throw new SourceToolError("Invalid source path");
  return path;
}
function fields(value: Record<string, unknown>, allowed: string[], required: string[] = allowed) {
  if (Object.keys(value).some((key) => !allowed.includes(key)) || required.some((key) => !Object.hasOwn(value, key))) throw new SourceToolError("Unexpected fields");
}

function manifest(catalog: Omit<ReviewSourceCatalog, "manifestDigest"> | ReviewSourceCatalog): string {
  return sha(JSON.stringify({ version: catalog.version, repository: catalog.repository, commit: catalog.commit,
    sourceDigest: catalog.sourceDigest, truncated: catalog.truncated, omittedFiles: catalog.omittedFiles,
    files: catalog.files.map(({ id, path, sourceDigest, contentDigest, lineCount }) => ({ id, path, sourceDigest, contentDigest, lineCount })) }));
}

export function captureReviewSources(raw: unknown, expected: { repository: string; commit: string; sourceDigest: string }, preferredPaths: string[] = []): ReviewSourceCatalog {
  if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/.test(expected.repository) || expected.repository.length > 256) throw new SourceToolError("Invalid repository identity");
  if (bytes(raw) > SOURCE_TOOL_LIMITS.snapshotBytes) throw new SourceToolError("Stored source snapshot exceeds its limit");
  const value = object(raw);
  if (value.version !== 1 || value.repository !== expected.repository || value.commit !== expected.commit || value.sourceDigest !== expected.sourceDigest
    || typeof value.provider !== "string" || !["github", "gitlab"].includes(value.provider) || typeof value.truncated !== "boolean"
    || !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i.test(expected.commit) || !DIGEST.test(expected.sourceDigest)
    || !Array.isArray(value.files) || value.files.length > 1000) throw new SourceToolError("Stored source identity mismatch");
  const seen = new Set<string>();
  let totalBytes = 0;
  const files = value.files.map((item) => {
    const file = object(item), path = safePath(file.path);
    if (seen.has(path) || typeof file.content !== "string" || typeof file.sha256 !== "string" || !HASH.test(file.sha256)) throw new SourceToolError("Invalid source entry");
    seen.add(path);
    const length = Buffer.byteLength(file.content); totalBytes += length;
    if (length > SOURCE_TOOL_LIMITS.fileBytes || totalBytes > 10 * 1024 * 1024 || sha(file.content) !== `sha256:${file.sha256}`) throw new SourceToolError("Source bytes do not match the manifest");
    return { path, content: file.content, sha256: file.sha256 };
  });
  const original: SourceSnapshot = { version: 1, repository: expected.repository, commit: expected.commit, sourceDigest: expected.sourceDigest,
    provider: value.provider, truncated: value.truncated, files };
  if (sourceDigest(original) !== expected.sourceDigest) throw new SourceToolError("Source manifest mismatch");
  const preferred = new Set(preferredPaths);
  files.sort((a, b) => Number(preferred.has(b.path)) - Number(preferred.has(a.path)) || Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const selected: ReviewSourceFile[] = [];
  let selectedBytes = 0;
  for (const file of files) {
    const content = sanitizeLLMSourceText(file.content);
    const entry = { id: sha(`${expected.repository}\0${file.path}\0${file.sha256}`), path: file.path,
      sourceDigest: `sha256:${file.sha256}`, contentDigest: sha(content), content, lineCount: content.split("\n").length };
    const size = bytes(entry);
    if (selected.length >= SOURCE_TOOL_LIMITS.files || selectedBytes + size > SOURCE_TOOL_LIMITS.catalogBytes) continue;
    selected.push(entry); selectedBytes += size;
  }
  selected.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  const catalog: ReviewSourceCatalog = { version: 1, repository: expected.repository, commit: expected.commit, sourceDigest: expected.sourceDigest,
    manifestDigest: "", truncated: value.truncated || selected.length < files.length, omittedFiles: files.length - selected.length, files: selected };
  catalog.manifestDigest = manifest(catalog);
  return catalog;
}

export function validateReviewSources(value: ReviewSourceCatalog): ReviewSourceCatalog {
  if (!value || value.version !== 1 || typeof value.repository !== "string" || value.repository.length > 256
    || !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/.test(value.repository)
    || typeof value.commit !== "string" || !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i.test(value.commit)
    || !DIGEST.test(value.sourceDigest) || !DIGEST.test(value.manifestDigest)
    || !Array.isArray(value.files) || value.files.length > SOURCE_TOOL_LIMITS.files || bytes(value) > SOURCE_TOOL_LIMITS.catalogBytes + 8192
    || !Number.isSafeInteger(value.omittedFiles) || value.omittedFiles < 0 || value.omittedFiles > 1000
    || typeof value.truncated !== "boolean" || (value.omittedFiles > 0 && !value.truncated)) throw new SourceToolError("Invalid source catalog");
  const paths = new Set<string>(), ids = new Set<string>();
  for (const file of value.files) {
    object(file);
    safePath(file.path);
    if (paths.has(file.path) || ids.has(file.id) || !DIGEST.test(file.id) || !DIGEST.test(file.sourceDigest)
      || file.id !== sha(`${value.repository}\0${file.path}\0${file.sourceDigest.slice(7)}`)
      || typeof file.content !== "string" || Buffer.byteLength(file.content) > SOURCE_TOOL_LIMITS.catalogBytes
      || file.contentDigest !== sha(file.content) || file.lineCount !== file.content.split("\n").length) throw new SourceToolError("Invalid source catalog entry");
    paths.add(file.path); ids.add(file.id);
  }
  if (manifest(value) !== value.manifestDigest) throw new SourceToolError("Source catalog digest mismatch");
  return value;
}

export function sourceCatalogSummary(catalog: ReviewSourceCatalog) {
  return { repository: catalog.repository, commit: catalog.commit, sourceDigest: catalog.sourceDigest,
    manifestDigest: catalog.manifestDigest, files: catalog.files.length, truncated: catalog.truncated, omittedFiles: catalog.omittedFiles };
}
export function sourceLocation(catalog: ReviewSourceCatalog, path: string) {
  const file = catalog.files.find((entry) => entry.path === path);
  return file ? fileMetadata(file) : null;
}
function fileMetadata({ id, path, sourceDigest, lineCount }: ReviewSourceFile) { return { file_id: id, path, source_digest: sourceDigest, line_count: lineCount }; }

export const SOURCE_TOOL_SPECS = [
  { name: "source_list", description: "List admitted source paths and executor-issued file IDs. Optional prefix and offset; no file contents.", arguments: { prefix: "optional path prefix", offset: "optional integer 0..512" } },
  { name: "source_read", description: "Read redacted source lines from one admitted file. Returns a source citation.", arguments: { file_id: "ID from finding_source or source_list", line_start: "positive integer", line_end: "inclusive; at most 200 lines" } },
  { name: "source_search", description: "Literal text search in admitted source, optionally one file. Returns bounded one-line citations; no regular expressions.", arguments: { query: "1..256 characters", file_id: "optional admitted file ID" } },
] as const;

export function parseSourceToolRequest(raw: unknown): SourceToolRequest {
  if (bytes(raw) > 2048) throw new SourceToolError("Tool arguments exceed the limit");
  const request = object(raw); fields(request, ["name", "arguments"]);
  const args = object(request.arguments);
  if (request.name === "source_list") {
    fields(args, ["prefix", "offset"], []);
    return { name: request.name, arguments: { prefix: args.prefix === undefined ? "" : text(args.prefix, 256, 0), offset: args.offset === undefined ? 0 : integer(args.offset, 0, SOURCE_TOOL_LIMITS.files) } };
  }
  if (request.name === "source_read") {
    fields(args, ["file_id", "line_start", "line_end"]);
    const id = text(args.file_id, 71), start = integer(args.line_start, 1, 1_000_000), end = integer(args.line_end, start, start + SOURCE_TOOL_LIMITS.readLines - 1);
    if (!DIGEST.test(id)) throw new SourceToolError("Invalid source file ID");
    return { name: request.name, arguments: { file_id: id, line_start: start, line_end: end } };
  }
  if (request.name === "source_search") {
    fields(args, ["query", "file_id"], ["query"]);
    const query = text(args.query, 256);
    if (query.includes("\n")) throw new SourceToolError("Search one line at a time");
    const id = args.file_id === undefined ? undefined : text(args.file_id, 71);
    if (id !== undefined && !DIGEST.test(id)) throw new SourceToolError("Invalid source file ID");
    return { name: request.name, arguments: { query, ...(id ? { file_id: id } : {}) } };
  }
  throw new SourceToolError("Tool is not in the source navigation allowlist");
}

function cite(catalog: ReviewSourceCatalog, file: ReviewSourceFile, start: number, end: number, content: string): SourceCitation {
  const value = { repository_id: catalog.repository, path: file.path, line_start: start, line_end: end,
    source_digest: file.sourceDigest, excerpt_digest: sha(content) };
  return { citation_id: sha(JSON.stringify(value)), ...value };
}

/** Requests use IDs from the frozen catalog; arbitrary paths are never opened. */
export function executeSourceTool(request: SourceToolRequest, catalog: ReviewSourceCatalog, requestId: string, round: number): SourceToolSpan {
  const started = performance.now();
  let evidence: Record<string, unknown> = {}, error = "", truncated = false;
  try {
    request = parseSourceToolRequest(request);
    const args = request.arguments;
    if (request.name === "source_list") {
      const selected = catalog.files.filter((file) => file.path.startsWith(String(args.prefix)));
      const offset = Number(args.offset), files = selected.slice(offset, offset + SOURCE_TOOL_LIMITS.listFiles).map(fileMetadata);
      // Pack complete path records, so long paths cannot make a list page unusable.
      while (files.length && bytes(files) > SOURCE_TOOL_LIMITS.outputBytes - 256) files.pop();
      const next = offset + files.length < selected.length ? offset + files.length : null;
      truncated = next !== null;
      evidence = { files, total: selected.length, next_offset: next };
    } else {
      const files = args.file_id ? catalog.files.filter((file) => file.id === args.file_id) : catalog.files;
      if (args.file_id && !files.length) throw new SourceToolError("File is not in this source snapshot");
      if (request.name === "source_read") {
        const file = files[0], start = Number(args.line_start), end = Number(args.line_end);
        if (!file || start > file.lineCount || end > file.lineCount) throw new SourceToolError("Source range is outside the file");
        const content = file.content.split("\n").slice(start - 1, end).join("\n");
        if (Buffer.byteLength(content) > SOURCE_TOOL_LIMITS.readBytes) throw new SourceToolError("Read fewer source lines; this excerpt exceeds the byte limit");
        evidence = { content, citation: cite(catalog, file, start, end, content) };
      } else {
        const matches: Array<{ content: string; citation: SourceCitation }> = [];
        let outputBytes = 0, omittedLongLines = 0;
        search: for (const file of files) {
          const lines = file.content.split("\n");
          for (let index = 0; index < lines.length; index++) {
            const content = lines[index];
            if (!content.includes(String(args.query))) continue;
            if (Buffer.byteLength(content) > 1024) { omittedLongLines++; continue; }
            const match = { content, citation: cite(catalog, file, index + 1, index + 1, content) };
            if (matches.length >= SOURCE_TOOL_LIMITS.searchMatches || outputBytes + bytes(match) > SOURCE_TOOL_LIMITS.readBytes) { truncated = true; break search; }
            matches.push(match); outputBytes += bytes(match);
          }
        }
        truncated ||= omittedLongLines > 0;
        evidence = { matches, omitted_long_lines: omittedLongLines };
      }
    }
    if (bytes(evidence) > SOURCE_TOOL_LIMITS.outputBytes) throw new SourceToolError("Tool result exceeds the byte limit");
  } catch (failure) {
    error = failure instanceof SourceToolError ? failure.message : "Source navigation failed";
    evidence = {};
  }
  return { request_id: requestId, tool: request.name, arguments: request.arguments,
    ok: !error, error, truncated, cached: false, round, duration_ms: Math.max(0, performance.now() - started),
    input_digest: sha(JSON.stringify(request)), output_digest: sha(JSON.stringify({ evidence, error, truncated })),
    summary: error || `${request.name}: source evidence retained`, evidence };
}
