import { createHash } from "node:crypto";

import { sanitizeLLMText } from "./llm-safety.ts";

const RULE_ID = /^REPO-[A-Z0-9][A-Z0-9-]{1,63}$/;
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const MAX_FINDINGS_PER_BATCH = 200;
const LINE_TOLERANCE = 3;

export interface RepoSourceFile {
  path: string;
  content: string;
}

export interface EvidenceBoundRepoFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: number;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  message: string;
  cweId?: number;
  owaspCategory?: string;
  remediation?: string;
  sourceDigest: string;
  snippetDigest: string;
  evidenceId: string;
}

export interface RejectedRepoFinding {
  index: number;
  reason: string;
}

export interface RepoFindingBindingResult {
  findings: EvidenceBoundRepoFinding[];
  rejected: RejectedRepoFinding[];
  truncated: boolean;
}

export function canReconcileRepoFindingAbsence(
  scannedRef: string,
  defaultBranch: string,
  incomplete: boolean,
): boolean {
  return !incomplete && scannedRef === defaultBranch;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function extractJsonArray(raw: string): unknown[] | null {
  let value = raw.trim();
  const block = value.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (block) value = block[1].trim();
  if (!value.startsWith("[")) {
    const first = value.indexOf("[");
    const last = value.lastIndexOf("]");
    if (first !== -1 && last > first) value = value.slice(first, last + 1);
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function occurrences(source: string, snippet: string): number[] {
  const matches: number[] = [];
  let offset = 0;
  while (matches.length < 100) {
    const index = source.indexOf(snippet, offset);
    if (index === -1) break;
    matches.push(index);
    offset = index + Math.max(snippet.length, 1);
  }
  return matches;
}

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < offset; index++) {
    if (source.charCodeAt(index) === 10) line++;
  }
  return line;
}

function finiteConfidence(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(value, 1));
}

function integer(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

function reject(index: number, reason: string): RejectedRepoFinding {
  return { index, reason };
}

export function bindRepoFindingsToSource(
  raw: string,
  files: RepoSourceFile[],
): RepoFindingBindingResult {
  const parsed = extractJsonArray(raw);
  if (!parsed) {
    return {
      findings: [],
      rejected: [reject(-1, "model output was not a JSON array")],
      truncated: false,
    };
  }

  const fileByPath = new Map(files.map((file) => [file.path, file]));
  const findings: EvidenceBoundRepoFinding[] = [];
  const rejected: RejectedRepoFinding[] = [];
  const bounded = parsed.slice(0, MAX_FINDINGS_PER_BATCH);

  for (const [index, value] of bounded.entries()) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      rejected.push(reject(index, "finding must be an object"));
      continue;
    }
    const candidate = value as Record<string, unknown>;
    const ruleId = typeof candidate.ruleId === "string" ? candidate.ruleId.trim() : "";
    if (!RULE_ID.test(ruleId)) {
      rejected.push(reject(index, "ruleId must match REPO-[A-Z0-9-]"));
      continue;
    }

    const filePath = typeof candidate.filePath === "string" ? candidate.filePath.trim() : "";
    const file = fileByPath.get(filePath);
    if (!file) {
      rejected.push(reject(index, "filePath is not in the fetched source batch"));
      continue;
    }

    const claimedLine = integer(candidate.lineStart);
    if (claimedLine === null || claimedLine < 1) {
      rejected.push(reject(index, "lineStart must be a positive integer"));
      continue;
    }

    const snippet = sanitizeLLMText(candidate.codeSnippet, 20_000).trim();
    if (!snippet) {
      rejected.push(reject(index, "an exact non-empty codeSnippet is required"));
      continue;
    }
    const sanitizedSource = sanitizeLLMText(file.content, file.content.length + 1_024);
    const locations = occurrences(sanitizedSource, snippet)
      .map((offset) => ({ offset, line: lineAt(sanitizedSource, offset) }))
      .sort((left, right) => {
        const distance = Math.abs(left.line - claimedLine) - Math.abs(right.line - claimedLine);
        return distance || left.line - right.line;
      });
    if (locations.length === 0) {
      rejected.push(reject(index, "codeSnippet is not present in the fetched source file"));
      continue;
    }
    const best = locations[0];
    const bestDistance = Math.abs(best.line - claimedLine);
    if (bestDistance > LINE_TOLERANCE) {
      rejected.push(reject(index, "lineStart does not identify the exact source snippet"));
      continue;
    }
    if (
      locations.length > 1 &&
      Math.abs(locations[1].line - claimedLine) === bestDistance
    ) {
      rejected.push(reject(index, "codeSnippet location is ambiguous"));
      continue;
    }

    const ruleName = sanitizeLLMText(candidate.ruleName, 500).trim();
    const message = sanitizeLLMText(candidate.message, 4_000).trim();
    const severity = typeof candidate.severity === "string"
      ? candidate.severity.toLowerCase()
      : "";
    if (!ruleName || !message || !SEVERITIES.has(severity)) {
      rejected.push(reject(index, "ruleName, message, and a valid severity are required"));
      continue;
    }

    const lineStart = best.line;
    const lineEnd = lineStart + (snippet.match(/\n/g)?.length ?? 0);
    const sourceDigest = `sha256:${sha256(file.content)}`;
    const snippetDigest = `sha256:${sha256(snippet)}`;
    const identity = [ruleId, filePath, lineStart, lineEnd, sourceDigest, snippetDigest].join("\0");
    const cweId = integer(candidate.cweId);

    findings.push({
      ruleId,
      ruleName,
      severity,
      confidence: finiteConfidence(candidate.confidence),
      filePath,
      lineStart,
      lineEnd,
      codeSnippet: snippet,
      message,
      ...(cweId !== null && cweId > 0 && cweId <= 10_000 ? { cweId } : {}),
      ...(typeof candidate.owaspCategory === "string"
        ? { owaspCategory: sanitizeLLMText(candidate.owaspCategory, 100) }
        : {}),
      ...(typeof candidate.remediation === "string"
        ? { remediation: sanitizeLLMText(candidate.remediation, 12_000) }
        : {}),
      sourceDigest,
      snippetDigest,
      evidenceId: `ai:${sha256(identity).slice(0, 32)}`,
    });
  }

  return {
    findings,
    rejected,
    truncated: parsed.length > MAX_FINDINGS_PER_BATCH,
  };
}
