import type { LlmJob, PrismaClient } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import type { ProviderTransport } from "./public-https.ts";
import { callProviderDetailed, ProviderCallError, type ProviderReceipt } from "./provider-receipt.ts";
import { parseReviewResults, ReviewContractError } from "./ai-review-contract.ts";
import { AiJobError, AiLeaseLost, claimLlmJob, completeLlmToolTurn, failLlmJob, heartbeatLlmJob, loadReviewSnapshot, publishLlmBatch, recordDiscardedLlmCall, startLlmCall } from "./llm-jobs.ts";
import { parseSourceResponse, SourceBudgetError } from "./ai-source-review.ts";

export async function runClaimedLlmJob(db: PrismaClient, job: LlmJob, env: AuthEnvironment, stopping: AbortSignal, options: { transport?: ProviderTransport; heartbeatMs?: number } = {}) {
  const interrupted = new AbortController();
  const remaining = Math.max(1, (job.deadlineAt?.getTime() || 0) - Date.now());
  const deadline = AbortSignal.timeout(remaining);
  const signal = AbortSignal.any([stopping, interrupted.signal, deadline]);
  let heartbeatFailure: unknown;
  let pendingHeartbeat: Promise<void> | null = null;
  const pulse = setInterval(() => {
    if (pendingHeartbeat || signal.aborted) return;
    pendingHeartbeat = heartbeatLlmJob(db, job, env).catch((error) => { heartbeatFailure = error; interrupted.abort(); }).finally(() => { pendingHeartbeat = null; });
  }, options.heartbeatMs ?? 10_000);
  let callId: string | undefined;
  let receipt: ProviderReceipt | undefined;
  try {
    const snapshot = loadReviewSnapshot(job);
    for (let batchIndex = job.currentBatch; batchIndex < snapshot.batches.length; batchIndex++) {
      let published = false;
      while (!published) {
        signal.throwIfAborted();
        const started = await startLlmCall(db, job, snapshot, batchIndex, env);
        callId = started.callId;
        const response = await callProviderDetailed(started.config, snapshot.system, started.user, signal, options.transport);
        receipt = response.receipt;
        signal.throwIfAborted();
        if (snapshot.sources) {
          const turn = parseSourceResponse(response.text, snapshot.batches[batchIndex]);
          if (turn.kind === "tools") await completeLlmToolTurn(db, job, snapshot, batchIndex, callId, turn.requests, receipt, env);
          else {
            await publishLlmBatch(db, job, snapshot, batchIndex, callId, turn.results, receipt, env, turn.citationIds);
            published = true;
          }
        } else {
          const results = parseReviewResults(response.text, snapshot.batches[batchIndex]);
          await publishLlmBatch(db, job, snapshot, batchIndex, callId, results, receipt, env);
          published = true;
        }
        callId = undefined; receipt = undefined;
      }
    }
  } catch (error) {
    if (error instanceof ProviderCallError) receipt = error.receipt;
    const cause = heartbeatFailure || error;
    const code = cause instanceof AiJobError ? cause.code
      : deadline.aborted ? "deadline_exceeded"
        : cause instanceof SourceBudgetError ? "budget_exceeded"
          : cause instanceof ReviewContractError ? "invalid_review"
            : error instanceof ProviderCallError ? error.receipt.outcome === "unknown" ? "provider_outcome_unknown" : "provider_failed"
              : signal.aborted && callId ? "provider_outcome_unknown" : "publication_failed";
    if (callId) await recordDiscardedLlmCall(db, job, callId, error instanceof ProviderCallError ? error.code : code, receipt);
    // Shutdown before dispatch is recoverable. Dispatched calls are never replayed.
    if (!(stopping.aborted && !callId) && !(cause instanceof AiLeaseLost)) await failLlmJob(db, job, code);
  } finally {
    clearInterval(pulse);
    await pendingHeartbeat;
  }
}

export async function runLlmWorkerOnce(db: PrismaClient, workerId: string, env: AuthEnvironment, stopping: AbortSignal, options: { transport?: ProviderTransport; heartbeatMs?: number } = {}): Promise<boolean> {
  if (stopping.aborted) return false;
  const job = await claimLlmJob(db, workerId, env);
  if (!job) return false;
  await runClaimedLlmJob(db, job, env, stopping, options);
  return true;
}
