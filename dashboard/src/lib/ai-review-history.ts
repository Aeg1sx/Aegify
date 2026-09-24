import type { LlmJob, LlmReview, PrismaClient } from "@prisma/client";
import { AccessDenied, authorizeResource, type AccessPrincipal } from "./project-access.ts";
import { decrypt, encryptMany } from "./crypto.ts";
import { findingEvidenceDigest, parseReviewResults, reviewFindingSelect, type FrozenFinding, type ReviewResult } from "./ai-review-contract.ts";
import { sha256 } from "./provider-receipt.ts";
import { validateSavedSourceEvidence, type SavedSourceEvidence } from "./ai-source-review.ts";

export const REVIEW_HISTORY_VERSION = 1;
const MAX_RECORD_BYTES = 2 * 1024 * 1024;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
export type ReviewPublication = "published" | "human_decision_preserved";
export interface SavedReview {
  version: 1;
  id: string;
  jobId: string;
  callId: string;
  scanId: string;
  projectId: string;
  batchIndex: number;
  ordinal: number;
  publication: ReviewPublication;
  provider: string;
  model: string;
  mode: string;
  inputDigest: string;
  scanDigest: string;
  promptDigest: string;
  responseDigest: string;
  createdAt: string;
  finding: FrozenFinding;
  result: ReviewResult;
  sourceEvidence?: SavedSourceEvidence;
}

function displayMetadata(finding: FrozenFinding) {
  let metadataTruncated = false;
  const text = (key: string, maximum: number) => {
    const value = typeof finding.data[key] === "string" ? finding.data[key] as string : "";
    if (value.length > maximum) metadataTruncated = true;
    return value.slice(0, maximum);
  };
  const ruleId = text("ruleId", 128), ruleName = text("ruleName", 512), filePath = text("filePath", 4096);
  const severity = ["critical", "high", "medium", "low"].includes(String(finding.data.severity)) ? String(finding.data.severity) : "unknown";
  const lineStart = typeof finding.data.lineStart === "number" && Number.isSafeInteger(finding.data.lineStart) && finding.data.lineStart > 0 ? finding.data.lineStart : 1;
  return { ruleId, ruleName, severity, filePath, lineStart, metadataTruncated };
}

/** Encrypt once per bounded result batch; no key or raw response is retained. */
export function prepareReviewHistory(records: SavedReview[], encryptionSecret?: string) {
  const payloads = records.map((record) => {
    const text = JSON.stringify(record);
    if (Buffer.byteLength(text) > MAX_RECORD_BYTES) throw new Error("Review history record exceeds its limit.");
    return text;
  });
  const ciphertexts = records.length ? encryptMany(payloads, encryptionSecret) : [];
  return records.map((record, index) => ({
    id: record.id, jobId: record.jobId, callId: record.callId, findingId: record.finding.id,
    batchIndex: record.batchIndex, ordinal: record.ordinal, publication: record.publication,
    ...displayMetadata(record.finding), verdict: record.result.verdict, confidence: record.result.confidence,
    evidenceDigest: record.finding.evidenceDigest, payloadDigest: sha256(payloads[index]),
    payloadCiphertext: ciphertexts[index], createdAt: new Date(record.createdAt),
  }));
}

const summarySelect = {
  id: true, jobId: true, callId: true, findingId: true, batchIndex: true, ordinal: true,
  publication: true, ruleId: true, ruleName: true, severity: true, filePath: true, lineStart: true,
  metadataTruncated: true, verdict: true, confidence: true, evidenceDigest: true, payloadDigest: true, createdAt: true,
} as const;

async function authorizedJob(db: PrismaClient, access: AccessPrincipal, jobId: string) {
  await authorizeResource(db, access, "llmJob", jobId, "viewer");
  const job = await db.llmJob.findUnique({ where: { id: jobId }, select: {
    id: true, scanId: true, projectId: true, inputDigest: true, provider: true, model: true, mode: true,
    historyVersion: true, status: true, reviewedCount: true, totalFindings: true,
    scan: { select: { projectId: true } }, _count: { select: { reviews: true } },
  } });
  if (!job || (job.projectId && job.projectId !== job.scan.projectId) || (job._count.reviews > 0 && !job.projectId)) throw new AccessDenied();
  return job;
}

export function parseHistoryPage(query: URLSearchParams) {
  if ([...query.keys()].some((key) => !["limit", "cursor"].includes(key)) || query.getAll("limit").length > 1 || query.getAll("cursor").length > 1) throw new AccessDenied(400, "Use one limit and cursor.");
  const raw = query.get("limit") ?? "20";
  if (!/^\d{1,2}$/.test(raw) || Number(raw) < 1 || Number(raw) > 20) throw new AccessDenied(400, "History limit must be 1–20.");
  const cursor = query.get("cursor");
  if (cursor !== null && !ID.test(cursor)) throw new AccessDenied(400, "Invalid history cursor.");
  return { limit: Number(raw), cursor };
}

export async function listReviewHistory(db: PrismaClient, access: AccessPrincipal, jobId: string, query = new URLSearchParams()) {
  const job = await authorizedJob(db, access, jobId);
  const { limit, cursor } = parseHistoryPage(query);
  if (cursor && !await db.llmReview.findFirst({ where: { id: cursor, jobId }, select: { id: true } })) throw new AccessDenied(400, "Cursor does not belong to this review.");
  const [rows, groups] = await Promise.all([
    db.llmReview.findMany({ where: { jobId }, orderBy: [{ batchIndex: "asc" }, { ordinal: "asc" }, { id: "asc" }], take: limit + 1, ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}), select: summarySelect }),
    db.llmReview.groupBy({ by: ["publication", "verdict"], where: { jobId }, _count: { _all: true } }),
  ]);
  const count = (key: "publication" | "verdict", value: string) => groups.filter((group) => group[key] === value).reduce((sum, group) => sum + group._count._all, 0);
  const published = count("publication", "published");
  const saved = groups.reduce((sum, group) => sum + group._count._all, 0);
  return {
    jobId, historyVersion: job.historyVersion, status: job.status,
    totalFindings: job.totalFindings, saved,
    published, preservedHumanDecisions: count("publication", "human_decision_preserved"),
    missingReviewHistory: Math.max(0, job.reviewedCount - (job.historyVersion >= 1 ? saved : published)),
    verdicts: { likely_true_positive: count("verdict", "likely_true_positive"), likely_false_positive: count("verdict", "likely_false_positive"), needs_review: count("verdict", "needs_review") },
    reviews: rows.slice(0, limit), nextCursor: rows.length > limit ? rows[limit - 1].id : null,
  };
}

function verifiedPayload(row: LlmReview, job: Pick<LlmJob, "id" | "scanId" | "projectId" | "inputDigest" | "provider" | "model" | "mode">, call: { jobId: string; batchIndex: number; status: string; promptDigest: string; responseDigest: string }): SavedReview {
  try {
    if (row.payloadCiphertext.length > MAX_RECORD_BYTES * 2 + 128) throw new Error();
    const text = decrypt(row.payloadCiphertext);
    if (Buffer.byteLength(text) > MAX_RECORD_BYTES || sha256(text) !== row.payloadDigest) throw new Error();
    const record = JSON.parse(text) as SavedReview;
    if (record.version !== REVIEW_HISTORY_VERSION || record.id !== row.id || record.jobId !== job.id || row.jobId !== job.id || call.jobId !== job.id || record.callId !== row.callId || record.batchIndex !== row.batchIndex || call.batchIndex !== row.batchIndex || record.ordinal !== row.ordinal || record.publication !== row.publication || record.scanId !== job.scanId || record.projectId !== job.projectId || record.inputDigest !== job.inputDigest || record.provider !== job.provider || record.model !== job.model || record.mode !== job.mode || record.promptDigest !== call.promptDigest || record.responseDigest !== call.responseDigest || call.status !== "completed" || record.createdAt !== row.createdAt.toISOString()) throw new Error();
    if (record.finding.id !== row.findingId || record.finding.evidenceDigest !== row.evidenceDigest || record.result.findingId !== row.findingId || record.result.verdict !== row.verdict || record.result.confidence !== row.confidence) throw new Error();
    const metadata = displayMetadata(record.finding);
    if (Object.entries(metadata).some(([key, value]) => row[key as keyof LlmReview] !== value)) throw new Error();
    parseReviewResults(JSON.stringify([record.result]), [row.findingId]);
    if ((record.mode === "source") !== Boolean(record.sourceEvidence)) throw new Error();
    if (record.sourceEvidence) {
      validateSavedSourceEvidence(record.sourceEvidence);
      if (record.sourceEvidence.prompt_digest !== call.promptDigest || record.sourceEvidence.model !== job.model) throw new Error();
    }
    return record;
  } catch {
    throw new AccessDenied(409, "Saved review could not be verified. Check the installation encryption key and retained record integrity.");
  }
}

export async function readReviewHistory(db: PrismaClient, access: AccessPrincipal, jobId: string, reviewId: string) {
  const job = await authorizedJob(db, access, jobId);
  if (!ID.test(reviewId)) throw new AccessDenied();
  const row = await db.llmReview.findFirst({ where: { id: reviewId, jobId }, include: { call: { select: { jobId: true, batchIndex: true, status: true, promptDigest: true, responseDigest: true } } } });
  if (!row) throw new AccessDenied();
  const record = verifiedPayload(row, job, row.call);
  const finding = await db.finding.findFirst({ where: { id: row.findingId, scanId: job.scanId }, select: { ...reviewFindingSelect, status: true, aiReviewStatus: true, llmAnalysis: true } });
  let currentHistoryId: unknown = null;
  if (finding?.llmAnalysis && finding.llmAnalysis.length <= MAX_RECORD_BYTES) { try { currentHistoryId = JSON.parse(finding.llmAnalysis)?.historyId; } catch { /* Unverified legacy projection. */ } }
  return {
    record, payloadDigest: row.payloadDigest,
    current: finding ? { findingId: finding.id, status: finding.status, aiReviewStatus: finding.aiReviewStatus,
      state: findingEvidenceDigest(finding) !== row.evidenceDigest ? "source_changed" : currentHistoryId === row.id ? "current" : "superseded" } : null,
  };
}
