import { randomUUID } from "node:crypto";
import type { LlmJob, Prisma, PrismaClient } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { AccessDenied, authorizeProject, resolvePrincipal, type AccessPrincipal } from "./project-access.ts";
import { writeTransaction } from "./database-runtime.ts";
import { encrypt, decrypt } from "./crypto.ts";
import { getLLMConfig } from "./settings.ts";
import { buildProviderRequest } from "./provider-client.ts";
import { sha256, type ProviderReceipt } from "./provider-receipt.ts";
import { contractReviewInput, findingContractContext } from "./openapi-context.ts";
import { sanitizeLLMText } from "./llm-safety.ts";
import { batchPrompt, findingEvidenceDigest, freezeFinding, packSnapshot, promptDigest, REVIEW_LIMITS, REVIEW_VERSION, SOURCE_REVIEW_VERSION, ReviewContractError, reviewFindingSelect, reviewSystem, scanEvidenceDigest, type ReviewMode, type ReviewResult, type ReviewSnapshot } from "./ai-review-contract.ts";
import { llmJobTerminalStatus } from "./llm-job-state.ts";
import { prepareReviewHistory, REVIEW_HISTORY_VERSION, type SavedReview } from "./ai-review-history.ts";
import { captureReviewSources, SOURCE_TOOL_LIMITS, type SourceToolRequest } from "./ai-source-tools.ts";
import { finalizeSourceReview, runSourceRequests, saveSourceEvidence, sourceReviewPrompt } from "./ai-source-review.ts";
import { loadSourceSession, prepareSourceContinuation } from "./llm-source-journal.ts";

export const AI_LEASE_MS = 120_000;
export const AI_DEADLINE_MS = 30 * 60_000;
export const llmJobMetadata = {
  id: true, scanId: true, projectId: true, mode: true, status: true, totalFindings: true,
  reviewedCount: true, falsePositives: true, currentBatch: true, totalBatches: true,
  errorMessage: true, errorCode: true, errorCount: true, createdAt: true, startedAt: true, completedAt: true,
  contractVersion: true, historyVersion: true, provider: true, model: true, inputDigest: true, attempts: true, maxAttempts: true,
  maxCalls: true, callsStarted: true, promptBytes: true, outputTokensReserved: true, heartbeatAt: true, deadlineAt: true,
} as const;
export const llmCallMetadata = { id: true, batchIndex: true, roundIndex: true, responseKind: true, continuationDigest: true, status: true, promptDigest: true, responseDigest: true, receipt: true, errorCode: true, startedAt: true, completedAt: true } as const;
export const aiMessages: Record<string, string> = {
  queued: "Waiting for an AI review worker",
  authorization_lost: "Review permission, project admission or project binding changed",
  configuration_changed: "AI settings changed after enqueue; start a new review explicitly",
  input_invalid: "The stored review input could not be verified",
  source_changed: "Source evidence changed; previous suggestions were preserved",
  deadline_exceeded: "Review exceeded its 30 minute queue and execution budget",
  attempts_exhausted: "Local recovery attempts exhausted; start a new review explicitly",
  provider_outcome_unknown: "Provider outcome and charges may be unknown. No automatic retry was made",
  provider_failed: "Provider did not return a complete review. Inspect the call receipt before retrying",
  invalid_review: "Provider response did not match the review schema; no results from that batch were published",
  partial_review: "Some findings were not reviewed; inspect the batch history",
  cancelled: "Review cancelled. An already dispatched provider request may still incur charges",
  publication_failed: "Review publication failed; inspect the call receipt before retrying",
  budget_exceeded: "Review exceeded its stored call, prompt or output reservation budget",
};
export class AiJobError extends Error { code: string; constructor(code: string) { super(aiMessages[code] || "AI review stopped"); this.code = code; } }
export class AiLeaseLost extends Error {}

type Config = Awaited<ReturnType<typeof getLLMConfig>>;
export function reviewConfigDigest(config: Config): string {
  // Keep this private: it binds credentials without persisting another copy of them.
  return sha256(JSON.stringify({ ...config, customHeaders: Object.fromEntries(Object.entries(config.customHeaders).sort(([a], [b]) => a.localeCompare(b))) }));
}

async function authorizeJob(tx: Prisma.TransactionClient, job: LlmJob, env: AuthEnvironment) {
  if (!job.projectId || !job.requestedBy) throw new AiJobError("authorization_lost");
  try {
    const access = await resolvePrincipal(tx, job.requestedBy, env);
    const project = await authorizeProject(tx, access, job.projectId, "maintainer");
    const scan = await tx.scan.findUnique({ where: { id: job.scanId } });
    if (project.archived || !scan || scan.projectId !== job.projectId || !["completed", "partial"].includes(scan.status)) throw new AccessDenied();
    return scan;
  } catch (error) { if (error instanceof AccessDenied) throw new AiJobError("authorization_lost"); throw error; }
}

async function checkedConfig(tx: Prisma.TransactionClient, job: LlmJob): Promise<Config> {
  const config = await getLLMConfig(tx);
  try { if (!config.enabled || reviewConfigDigest(config) !== job.configDigest) throw new Error(); }
  catch { throw new AiJobError("configuration_changed"); }
  return config;
}

export async function enqueueLlmJob(db: PrismaClient, access: AccessPrincipal, scanId: string, mode: ReviewMode, includeApiContracts: boolean, env: AuthEnvironment, findingIds?: string[]) {
  if (!access.userId) throw new AccessDenied(401, "Sign in before queuing an AI review.");
  if (!["quick", "deep", "source"].includes(mode) || (findingIds !== undefined && (mode !== "source" || !Array.isArray(findingIds) || !findingIds.length
    || findingIds.length > SOURCE_TOOL_LIMITS.findings || new Set(findingIds).size !== findingIds.length || findingIds.some((id) => typeof id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(id))))) throw new AccessDenied(400, "Source review accepts 1–25 distinct finding IDs from this scan.");
  return writeTransaction(db, async (tx) => {
    const principal = await resolvePrincipal(tx, access.userId!, env);
    const scan = await tx.scan.findUnique({ where: { id: scanId } });
    if (!scan?.projectId) throw new AccessDenied(409, "Assign this scan to a project before reviewing.");
    const project = await authorizeProject(tx, principal, scan.projectId, "maintainer");
    if (project.archived || !["completed", "partial"].includes(scan.status)) throw new AccessDenied(409, "Review requires a completed or partial scan in an active project.");
    const existing = await tx.llmJob.findUnique({ where: { activeKey: scanId }, select: llmJobMetadata });
    if (existing) return { ...existing, alreadyQueued: true };
    if (await tx.llmJob.count({ where: { status: { in: ["pending", "running"] } } }) >= 50 || await tx.llmJob.count({ where: { projectId: scan.projectId, status: { in: ["pending", "running"] } } }) >= 2) throw new AccessDenied(429, "The AI review queue is full (two active jobs per project, 50 per workspace).");
    const config = await getLLMConfig(tx);
    try { buildProviderRequest(config, "Validate configuration only", "No network request is made"); }
    catch { throw new AccessDenied(409, "Configure an enabled AI provider, explicit model and valid limits in Settings first."); }
    const findings = await tx.finding.findMany({ where: { scanId, ...(findingIds ? { id: { in: findingIds } } : {}) }, orderBy: [{ severity: "asc" }, { id: "asc" }], take: (mode === "source" ? SOURCE_TOOL_LIMITS.findings : REVIEW_LIMITS.findings) + 1, select: reviewFindingSelect });
    if (mode === "source" && (findings.length > SOURCE_TOOL_LIMITS.findings || (findingIds && findings.length !== findingIds.length))) throw new AccessDenied(400, "Select at most 25 findings that belong to this scan for source review.");
    if (!findings.length || findings.length > REVIEW_LIMITS.findings) throw new AccessDenied(400, "Review supports scans with 1–1000 findings.");
    let graphContext: ReviewSnapshot["graphContext"] = null;
    if (mode !== "quick") {
      const nodes = await tx.callGraphNode.findMany({ where: { scanId }, orderBy: { id: "asc" }, take: 100, select: { qualifiedName: true, filePath: true, lineStart: true, nodeType: true } });
      const edges = await tx.callGraphEdge.findMany({ where: { scanId }, orderBy: { id: "asc" }, take: 100, select: { callSiteLine: true, sourceNode: { select: { qualifiedName: true } }, targetNode: { select: { qualifiedName: true } } } });
      const total = await tx.callGraphNode.count({ where: { scanId } }) + await tx.callGraphEdge.count({ where: { scanId } });
      // Whole graph records fit the context budget; no cut JSON or implied complete graph.
      while (Buffer.byteLength(JSON.stringify({ nodes, edges })) > 20_000 && (edges.length || nodes.length)) { if (edges.length) edges.pop(); else nodes.pop(); }
      graphContext = { data: sanitizeLLMText(JSON.stringify({ nodes, edges }), 30_000), omitted: total - nodes.length - edges.length };
    }
    const frozen = [];
    for (const finding of findings) frozen.push(freezeFinding(finding, includeApiContracts ? contractReviewInput(await findingContractContext(tx, finding)) : null));
    let sources: ReviewSnapshot["sources"];
    if (mode === "source") {
      const sourceJob = await tx.scanJob.findUnique({ where: { scanId } });
      if (!sourceJob?.sourceCiphertext || sourceJob.projectId !== scan.projectId || !["completed", "partial"].includes(sourceJob.status)) throw new AccessDenied(409, "No retained repository source is available. CI report uploads contain findings only; run a connected repository scan or use an excerpt review.");
      try {
        if (sourceJob.commitSha !== scan.commitSha || sourceJob.ownerSlug !== scan.repository || sourceJob.sourceCiphertext.length > SOURCE_TOOL_LIMITS.snapshotBytes * 2 + 128) throw new Error();
        const result = JSON.parse(sourceJob.resultManifest);
        if (result.sourceDigest !== sourceJob.sourceDigest || result.commit !== sourceJob.commitSha) throw new Error();
        const raw = JSON.parse(decrypt(sourceJob.sourceCiphertext));
        if (raw.provider !== sourceJob.provider) throw new Error();
        sources = captureReviewSources(raw, { repository: scan.repository, commit: scan.commitSha, sourceDigest: sourceJob.sourceDigest }, findings.map((finding) => finding.filePath));
        // A dashboard repository scan has one namespace. Never guess across repositories or normalize arbitrary paths.
        if (findings.some((finding) => finding.repositoryId && finding.repositoryId !== sources!.repository)) throw new Error();
      } catch { throw new AccessDenied(409, "Retained source identity could not be verified for this scan. Run a new repository scan."); }
    }
    const version = sources ? SOURCE_REVIEW_VERSION : REVIEW_VERSION;
    const snapshot = packSnapshot({ version, scanId, projectId: scan.projectId, scanDigest: scanEvidenceDigest(scan), mode, includeApiContracts,
      system: reviewSystem(mode, includeApiContracts, config.language), graphContext, findings: frozen, batches: [], ...(sources ? { sources } : {}) });
    const input = JSON.stringify(snapshot);
    const job = await tx.llmJob.create({ data: {
      scanId, projectId: scan.projectId, requestedBy: access.userId!, activeKey: scanId, mode,
      contractVersion: version, historyVersion: REVIEW_HISTORY_VERSION, provider: config.provider, model: config.model, configDigest: reviewConfigDigest(config),
      inputDigest: sha256(input), inputCiphertext: encrypt(input), totalFindings: findings.length, totalBatches: snapshot.batches.length,
      maxCalls: REVIEW_LIMITS.calls, deadlineAt: new Date(Date.now() + AI_DEADLINE_MS),
      events: { create: { code: "queued", message: aiMessages.queued, details: JSON.stringify({ inputDigest: sha256(input), findings: findings.length, batches: snapshot.batches.length, graphOmitted: graphContext?.omitted || 0, truncatedFindings: frozen.filter((item) => item.omittedFields.length).length,
        ...(sources ? { sourceManifest: sources.manifestDigest, sourceFiles: sources.files.length, sourceTruncated: sources.truncated, sourceFilesOmitted: sources.omittedFiles } : {}) }) } },
    }, select: llmJobMetadata });
    await tx.auditEvent.create({ data: { projectId: scan.projectId, actorId: access.userId!, action: "ai.review.queued", targetId: job.id, details: JSON.stringify({ inputDigest: job.inputDigest, model: config.model, provider: config.provider }) } });
    return { ...job, alreadyQueued: false };
  }, { timeout: 30_000 });
}

export function loadReviewSnapshot(job: LlmJob): ReviewSnapshot {
  try {
    if (![REVIEW_VERSION, SOURCE_REVIEW_VERSION].includes(job.contractVersion) || !job.inputCiphertext || job.inputCiphertext.length > REVIEW_LIMITS.snapshotBytes * 2 + 128) throw new Error();
    const input = decrypt(job.inputCiphertext);
    if (sha256(input) !== job.inputDigest) throw new Error();
    const snapshot = JSON.parse(input) as ReviewSnapshot;
    if (snapshot.version !== job.contractVersion || snapshot.scanId !== job.scanId || snapshot.projectId !== job.projectId || snapshot.mode !== job.mode || snapshot.findings.length !== job.totalFindings || snapshot.batches.length !== job.totalBatches) throw new Error();
    const originalBatches = JSON.stringify(snapshot.batches);
    if (JSON.stringify(packSnapshot(snapshot).batches) !== originalBatches) throw new Error();
    return snapshot;
  } catch { throw new AiJobError("input_invalid"); }
}

async function terminate(tx: Prisma.TransactionClient, job: LlmJob, code: string, now: Date, cancelled = false) {
  const status = cancelled ? "cancelled" : job.reviewedCount > 0 ? "partial" : "failed";
  await tx.llmCall.updateMany({ where: { jobId: job.id, status: "dispatched" }, data: { status: "unknown", errorCode: "provider_outcome_unknown" } });
  await tx.llmJob.update({ where: { id: job.id }, data: { status, activeKey: null, leaseToken: null, leaseExpiresAt: null, completedAt: now, errorCode: code, errorMessage: aiMessages[code] || aiMessages.publication_failed, ...(cancelled ? { cancelRequestedAt: now } : {}) } });
  await tx.llmJobEvent.create({ data: { jobId: job.id, code, message: aiMessages[code] || aiMessages.publication_failed } });
  await tx.auditEvent.create({ data: { projectId: job.projectId, actorId: job.workerId || job.requestedBy || "worker", action: "ai.review." + status, targetId: job.id, details: JSON.stringify({ code }) } });
}

export async function claimLlmJob(db: PrismaClient, workerId: string, env: AuthEnvironment, now = new Date()): Promise<LlmJob | null> {
  return writeTransaction(db, async (tx) => {
    for (let skipped = 0; skipped < 50; skipped++) {
      const job = await tx.llmJob.findFirst({ where: { OR: [{ status: "pending" }, { status: "running", leaseExpiresAt: { lte: now } }, { status: "running", leaseExpiresAt: null }] }, orderBy: [{ createdAt: "asc" }, { id: "asc" }] });
      if (!job) return null;
      let code = "";
      if (await tx.llmCall.count({ where: { jobId: job.id, status: { in: ["dispatched", "unknown"] } } })) code = "provider_outcome_unknown";
      else if (await tx.llmCall.count({ where: { jobId: job.id, batchIndex: { gte: job.currentBatch }, NOT: { status: "completed", responseKind: "tools", batchIndex: job.currentBatch } } })) code = "provider_failed";
      else if (!job.deadlineAt || job.deadlineAt <= now) code = "deadline_exceeded";
      else if (job.attempts >= job.maxAttempts) code = "attempts_exhausted";
      if (!code) {
        try {
          await authorizeJob(tx, job, env); await checkedConfig(tx, job);
          const snapshot = loadReviewSnapshot(job);
          const calls = await tx.llmCall.findMany({ where: { jobId: job.id, batchIndex: job.currentBatch }, orderBy: { roundIndex: "asc" } });
          if (snapshot.sources) loadSourceSession(job, snapshot, job.currentBatch, calls);
          else if (calls.length) throw new AiJobError("provider_failed");
        } catch (error) { if (!(error instanceof AiJobError) && !(error instanceof ReviewContractError)) throw error; code = error instanceof AiJobError ? error.code : "input_invalid"; }
      }
      if (code) { await terminate(tx, job, code, now); continue; }
      const claimed = await tx.llmJob.update({ where: { id: job.id }, data: { status: "running", startedAt: job.startedAt || now, attempts: { increment: 1 }, leaseToken: randomUUID(), workerId, leaseExpiresAt: new Date(now.getTime() + AI_LEASE_MS), heartbeatAt: now } });
      await tx.llmJobEvent.create({ data: { jobId: job.id, code: job.attempts ? "recovered" : "claimed", message: job.attempts ? "Worker recovered local progress without replaying provider calls" : "Worker claimed the review", details: JSON.stringify({ attempt: claimed.attempts }) } });
      return claimed;
    }
    return null;
  }, { timeout: 30_000 });
}

export async function assertLlmLease(tx: Prisma.TransactionClient, job: Pick<LlmJob, "id" | "leaseToken">, env: AuthEnvironment, now = new Date()) {
  if (!job.leaseToken) throw new AiLeaseLost("No AI worker lease.");
  const current = await tx.llmJob.findFirst({ where: { id: job.id, leaseToken: job.leaseToken, status: "running", cancelRequestedAt: null, leaseExpiresAt: { gt: now } } });
  if (!current) throw new AiLeaseLost("AI worker lease expired or was replaced.");
  if (!current.deadlineAt || current.deadlineAt <= now) throw new AiJobError("deadline_exceeded");
  const scan = await authorizeJob(tx, current, env);
  const config = await checkedConfig(tx, current);
  return { current, scan, config };
}

export async function heartbeatLlmJob(db: PrismaClient, job: LlmJob, env: AuthEnvironment) {
  await writeTransaction(db, async (tx) => {
    await assertLlmLease(tx, job, env);
    const now = new Date();
    await tx.llmJob.update({ where: { id: job.id }, data: { heartbeatAt: now, leaseExpiresAt: new Date(now.getTime() + AI_LEASE_MS) } });
  });
}

export async function startLlmCall(db: PrismaClient, job: LlmJob, snapshot: ReviewSnapshot, batchIndex: number, env: AuthEnvironment) {
  return writeTransaction(db, async (tx) => {
    const { current, config, scan } = await assertLlmLease(tx, job, env);
    if (scanEvidenceDigest(scan) !== snapshot.scanDigest) throw new AiJobError("source_changed");
    const ids = snapshot.batches[batchIndex];
    if (!ids || current.currentBatch !== batchIndex) throw new AiLeaseLost("Batch out of sequence.");
    const prior = await tx.llmCall.findMany({ where: { jobId: job.id, batchIndex }, orderBy: { roundIndex: "asc" } });
    if (prior.some((call) => call.status !== "completed" || call.responseKind !== "tools") || (!snapshot.sources && prior.length)) throw new AiLeaseLost("Batch already dispatched.");
    const sourceSession = snapshot.sources ? loadSourceSession(current, snapshot, batchIndex, prior) : undefined;
    for (const id of ids) {
      const finding = await tx.finding.findUnique({ where: { id }, select: reviewFindingSelect });
      if (!finding || findingEvidenceDigest(finding) !== snapshot.findings.find((item) => item.id === id)?.evidenceDigest) throw new AiJobError("source_changed");
    }
    const user = sourceSession ? sourceReviewPrompt(snapshot, ids, sourceSession) : batchPrompt(snapshot, ids);
    const bytes = Buffer.byteLength(snapshot.system) + Buffer.byteLength(user);
    if (bytes > REVIEW_LIMITS.promptBytes || current.callsStarted >= Math.min(current.maxCalls, REVIEW_LIMITS.calls) || current.promptBytes + bytes > REVIEW_LIMITS.totalPromptBytes || current.outputTokensReserved + config.maxOutputTokens > REVIEW_LIMITS.outputTokens) throw new AiJobError("budget_exceeded");
    buildProviderRequest(config, snapshot.system, user);
    const digest = promptDigest(snapshot.system, user);
    const call = await tx.llmCall.create({ data: { jobId: job.id, batchIndex, roundIndex: sourceSession?.roundIndex || 0, leaseToken: job.leaseToken!, promptDigest: digest } });
    await tx.llmJob.update({ where: { id: job.id }, data: { callsStarted: { increment: 1 }, promptBytes: { increment: bytes }, outputTokensReserved: { increment: config.maxOutputTokens } } });
    await tx.llmJobEvent.create({ data: { jobId: job.id, code: "call_dispatched", message: "Provider dispatch reserved; an interrupted call will not be automatically replayed", details: JSON.stringify({ batchIndex, roundIndex: call.roundIndex, promptDigest: digest, promptBytes: bytes, outputTokensReserved: config.maxOutputTokens }) } });
    return { callId: call.id, config, user, sourceSession };
  }, { timeout: 10_000 });
}

export async function completeLlmToolTurn(db: PrismaClient, job: LlmJob, snapshot: ReviewSnapshot, batchIndex: number, callId: string, requests: SourceToolRequest[], receipt: ProviderReceipt, env: AuthEnvironment) {
  await writeTransaction(db, async (tx) => {
    const { current, scan } = await assertLlmLease(tx, job, env);
    if (scanEvidenceDigest(scan) !== snapshot.scanDigest) throw new AiJobError("source_changed");
    const call = await tx.llmCall.findFirst({ where: { id: callId, jobId: job.id, batchIndex, leaseToken: job.leaseToken!, status: "dispatched" } });
    if (!snapshot.sources || !call || current.currentBatch !== batchIndex || receipt.completion !== "completed" || receipt.outcome !== "received" || !receipt.responseDigest) throw new AiLeaseLost("Tool turn no longer publishable.");
    const prior = await tx.llmCall.findMany({ where: { jobId: job.id, batchIndex, id: { not: callId } }, orderBy: { roundIndex: "asc" } });
    const session = loadSourceSession(current, snapshot, batchIndex, prior);
    if (call.roundIndex !== session.roundIndex || call.promptDigest !== promptDigest(snapshot.system, sourceReviewPrompt(snapshot, snapshot.batches[batchIndex], session))) throw new AiJobError("input_invalid");
    const spans = runSourceRequests(snapshot, session, requests);
    const continuation = prepareSourceContinuation(current, snapshot, call, session, requests, spans, receipt.responseDigest);
    await tx.llmCall.update({ where: { id: callId }, data: { status: "completed", responseKind: "tools", ...continuation, responseDigest: receipt.responseDigest, receipt: JSON.stringify(receipt), completedAt: new Date() } });
    await tx.llmJobEvent.create({ data: { jobId: job.id, code: "source_tools_completed", message: "Source tool evidence saved; the next model turn can resume without replaying this call", details: JSON.stringify({ callId, batchIndex, roundIndex: call.roundIndex, sourceManifest: snapshot.sources.manifestDigest, continuationDigest: continuation.continuationDigest,
      tools: spans.map((span) => ({ name: span.tool, ok: span.ok, truncated: span.truncated, inputDigest: span.input_digest, outputDigest: span.output_digest })), toolsRemaining: SOURCE_TOOL_LIMITS.calls - session.spans.length - spans.length }) } });
  }, { timeout: 10_000 });
}

export async function publishLlmBatch(db: PrismaClient, job: LlmJob, snapshot: ReviewSnapshot, batchIndex: number, callId: string, results: ReviewResult[], receipt: ProviderReceipt, env: AuthEnvironment, citationIds?: Record<string, string[]>) {
  await writeTransaction(db, async (tx) => {
    const { current, scan } = await assertLlmLease(tx, job, env);
    if (scanEvidenceDigest(scan) !== snapshot.scanDigest) throw new AiJobError("source_changed");
    const call = await tx.llmCall.findFirst({ where: { id: callId, jobId: job.id, batchIndex, leaseToken: job.leaseToken!, status: "dispatched" } });
    if (!call || current.currentBatch !== batchIndex || receipt.completion !== "completed") throw new AiLeaseLost("Batch no longer publishable.");
    const sourceSession = snapshot.sources ? loadSourceSession(current, snapshot, batchIndex,
      await tx.llmCall.findMany({ where: { jobId: job.id, batchIndex, id: { not: callId } }, orderBy: { roundIndex: "asc" } })) : undefined;
    let currentPromptBytes = 0;
    if (sourceSession) {
      const user = sourceReviewPrompt(snapshot, snapshot.batches[batchIndex], sourceSession);
      if (call.roundIndex !== sourceSession.roundIndex || call.promptDigest !== promptDigest(snapshot.system, user) || !citationIds) throw new AiJobError("input_invalid");
      results = finalizeSourceReview(snapshot, snapshot.batches[batchIndex], sourceSession, { results, citationIds }).results;
      currentPromptBytes = Buffer.byteLength(snapshot.system) + Buffer.byteLength(user);
    } else if (citationIds || call.roundIndex !== 0) throw new AiJobError("input_invalid");
    const now = new Date();
    let protectedDecisions = 0;
    let suggestedFalsePositives = 0;
    const history: SavedReview[] = [];
    const expected = snapshot.batches[batchIndex];
    if (new Set(results.map((result) => result.findingId)).size !== results.length) throw new AiJobError("invalid_review");
    for (const id of expected) {
      const finding = await tx.finding.findUnique({ where: { id }, select: reviewFindingSelect });
      if (!finding || findingEvidenceDigest(finding) !== snapshot.findings.find((item) => item.id === id)?.evidenceDigest) throw new AiJobError("source_changed");
    }
    for (const result of results) {
      const frozen = snapshot.findings.find((finding) => finding.id === result.findingId);
      const finding = await tx.finding.findUnique({ where: { id: result.findingId }, select: { ...reviewFindingSelect, aiReviewStatus: true } });
      if (!snapshot.batches[batchIndex].includes(result.findingId) || !frozen || !finding || findingEvidenceDigest(finding) !== frozen.evidenceDigest) throw new AiJobError("source_changed");
      const preserved = ["accepted", "rejected"].includes(finding.aiReviewStatus);
      const historyId = randomUUID();
      const sourceEvidence = sourceSession ? saveSourceEvidence(snapshot, sourceSession, citationIds![result.findingId], job.model, call.promptDigest, currentPromptBytes) : undefined;
      history.push({ version: REVIEW_HISTORY_VERSION, id: historyId, jobId: job.id, callId,
        scanId: job.scanId, projectId: job.projectId!, batchIndex, ordinal: history.length,
        publication: preserved ? "human_decision_preserved" : "published", provider: job.provider, model: job.model,
        mode: job.mode, inputDigest: job.inputDigest, scanDigest: snapshot.scanDigest, promptDigest: call.promptDigest,
        responseDigest: receipt.responseDigest || "", createdAt: now.toISOString(), finding: frozen, result, ...(sourceEvidence ? { sourceEvidence } : {}) });
      if (result.verdict === "likely_false_positive" && (!preserved || current.historyVersion >= 1)) suggestedFalsePositives++;
      if (preserved) { protectedDecisions++; continue; }
      await tx.finding.update({ where: { id: finding.id }, data: {
        aiVerdict: result.verdict, aiConfidence: result.confidence, aiReviewStatus: "suggested",
        llmAnalysis: JSON.stringify({ ...result, isFalsePositive: result.verdict === "likely_false_positive", mode: snapshot.mode,
          producer: "aegify.dashboard.ai-finding-review", contractVersion: snapshot.version, jobId: job.id, callId, historyId,
          provider: job.provider, model: job.model, inputDigest: job.inputDigest, evidenceDigest: frozen.evidenceDigest,
          promptDigest: call.promptDigest, responseDigest: receipt.responseDigest, reviewedAt: now.toISOString(),
          apiContractContextRequested: snapshot.includeApiContracts, apiContractContext: frozen.apiContractContext, omittedFields: frozen.omittedFields, graphRecordsOmitted: snapshot.graphContext?.omitted || 0,
          ...(sourceEvidence ? { sourceReview: { manifestDigest: sourceEvidence.catalog.manifestDigest, toolCalls: sourceEvidence.tools_used.length, citations: sourceEvidence.citations.length } } : {}) }),
      } });
    }
    if (history.length) await tx.llmReview.createMany({ data: prepareReviewHistory(history) });
    const publishedCount = results.length - protectedDecisions;
    // New jobs count every retained review, including one withheld to preserve
    // a human decision. Legacy jobs retain their earlier publication counters.
    const reviewedDelta = current.historyVersion >= 1 ? results.length : publishedCount;
    const missing = snapshot.batches[batchIndex].length - reviewedDelta;
    const reviewedCount = current.reviewedCount + reviewedDelta;
    const errorCount = current.errorCount + missing;
    const status = batchIndex + 1 === snapshot.batches.length ? llmJobTerminalStatus(current.totalFindings, reviewedCount, errorCount) : "running";
    await tx.llmCall.update({ where: { id: call.id }, data: { status: "completed", responseDigest: receipt.responseDigest || "", receipt: JSON.stringify(receipt), completedAt: now } });
    await tx.llmJob.update({ where: { id: job.id }, data: { currentBatch: batchIndex + 1, reviewedCount, errorCount,
      falsePositives: current.falsePositives + suggestedFalsePositives,
      status, ...(status !== "running" ? { activeKey: null, leaseToken: null, leaseExpiresAt: null, completedAt: now, errorCode: errorCount ? "partial_review" : "", errorMessage: errorCount ? aiMessages.partial_review : "" } : {}) } });
    await tx.llmJobEvent.create({ data: { jobId: job.id, code: "batch_published", message: "AI reviews saved; human workflow decisions preserved", details: JSON.stringify({ batchIndex, reviewed: reviewedDelta, published: publishedCount, saved: history.length, omitted: missing, protectedDecisions, callId, status }) } });
    await tx.auditEvent.create({ data: { projectId: job.projectId, actorId: job.requestedBy!, action: "ai.review.batch_published", targetId: job.id, details: JSON.stringify({ callId, reviewed: reviewedDelta, published: publishedCount, saved: history.length, omitted: missing, protectedDecisions }) } });
  }, { timeout: 10_000 });
}

/** A late worker may append only its own receipt, never suggestions or job state. */
export async function recordDiscardedLlmCall(db: PrismaClient, job: LlmJob, callId: string, code: string, receipt?: ProviderReceipt) {
  await writeTransaction(db, async (tx) => {
    const changed = await tx.llmCall.updateMany({ where: { id: callId, jobId: job.id, leaseToken: job.leaseToken!, status: { in: ["dispatched", "unknown"] }, completedAt: null }, data: {
      status: receipt?.outcome === "received" ? "discarded" : "unknown", errorCode: code, responseDigest: receipt?.responseDigest || "", receipt: JSON.stringify(receipt || {}), completedAt: new Date(),
    } });
    if (changed.count) await tx.llmJobEvent.create({ data: { jobId: job.id, code: "call_discarded", message: "Call receipt retained without publishing suggestions or retrying", details: JSON.stringify({ callId, code, outcome: receipt?.outcome || "unknown" }) } });
  });
}

export async function failLlmJob(db: PrismaClient, job: LlmJob, code: string) {
  await writeTransaction(db, async (tx) => {
    const current = await tx.llmJob.findFirst({ where: { id: job.id, leaseToken: job.leaseToken, status: "running", leaseExpiresAt: { gt: new Date() } } });
    if (current) await terminate(tx, current, code in aiMessages ? code : "publication_failed", new Date());
  });
}

export async function cancelLlmJob(db: PrismaClient, access: AccessPrincipal, id: string, env: AuthEnvironment) {
  await writeTransaction(db, async (tx) => {
    const job = await tx.llmJob.findUnique({ where: { id } });
    if (!job?.projectId) throw new AccessDenied();
    const principal = await resolvePrincipal(tx, access.userId || undefined, env);
    await authorizeProject(tx, principal, job.projectId, "maintainer");
    if (!["pending", "running"].includes(job.status)) return;
    await terminate(tx, job, "cancelled", new Date(), true);
    await tx.auditEvent.create({ data: { projectId: job.projectId, actorId: principal.userId || "development", action: "ai.review.cancel_requested", targetId: id } });
  });
}

/** Full inputs and recovery evidence share a seven-day TTL; selected history excerpts remain. */
export async function expireLlmInputs(db: PrismaClient, now = new Date()) {
  const where = { completedAt: { lt: new Date(now.getTime() - 7 * 86_400_000) }, status: { in: ["completed", "partial", "failed", "cancelled"] } };
  return writeTransaction(db, async (tx) => {
    const calls = await tx.llmCall.updateMany({ where: { job: where, continuationCiphertext: { not: null } }, data: { continuationCiphertext: null } });
    const jobs = await tx.llmJob.updateMany({ where: { ...where, inputCiphertext: { not: null } }, data: { inputCiphertext: null } });
    return { jobs: jobs.count, calls: calls.count };
  });
}
