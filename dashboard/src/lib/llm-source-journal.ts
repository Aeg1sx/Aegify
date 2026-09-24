import type { LlmCall, LlmJob } from "@prisma/client";
import { decrypt, encrypt } from "./crypto.ts";
import { promptDigest, ReviewContractError, type ReviewSnapshot } from "./ai-review-contract.ts";
import { emptySourceSession, runSourceRequests, sourceReviewPrompt, type SourceSession } from "./ai-source-review.ts";
import { SOURCE_TOOL_LIMITS, type SourceToolRequest, type SourceToolSpan } from "./ai-source-tools.ts";
import { sha256 } from "./provider-receipt.ts";

const MAX_JOURNAL_BYTES = SOURCE_TOOL_LIMITS.totalEvidenceBytes + 16_384;
interface Continuation {
  version: 1; jobId: string; inputDigest: string; batchIndex: number; roundIndex: number;
  sourceManifest: string; previousDigest: string; promptDigest: string; responseDigest: string;
  requests: SourceToolRequest[]; spans: SourceToolSpan[];
}

/** No raw model narrative or credentials in the continuation; source evidence is encrypted. */
export function prepareSourceContinuation(job: LlmJob, snapshot: ReviewSnapshot, call: LlmCall, session: SourceSession, requests: SourceToolRequest[], spans: SourceToolSpan[], responseDigest: string) {
  const record: Continuation = { version: 1, jobId: job.id, inputDigest: job.inputDigest, batchIndex: call.batchIndex, roundIndex: call.roundIndex,
    sourceManifest: snapshot.sources!.manifestDigest, previousDigest: session.previousDigest, promptDigest: call.promptDigest, responseDigest, requests, spans };
  const text = JSON.stringify(record);
  if (Buffer.byteLength(text) > MAX_JOURNAL_BYTES) throw new ReviewContractError("Source continuation exceeds its limit.");
  return { continuationDigest: sha256(text), continuationCiphertext: encrypt(text) };
}

/** Only completed, receipt-bound tool turns may be recovered. Never reissue a model call. */
export function loadSourceSession(job: LlmJob, snapshot: ReviewSnapshot, batchIndex: number, calls: LlmCall[]): SourceSession {
  try {
    if (!snapshot.sources || calls.length >= SOURCE_TOOL_LIMITS.rounds) throw new Error();
    const session = emptySourceSession();
    for (const call of calls) {
      if (call.jobId !== job.id || call.batchIndex !== batchIndex || call.roundIndex !== session.roundIndex || call.status !== "completed"
        || call.responseKind !== "tools" || !call.continuationCiphertext || call.continuationCiphertext.length > MAX_JOURNAL_BYTES * 2 + 128
        || !/^sha256:[a-f0-9]{64}$/.test(call.responseDigest)) throw new Error();
      const receipt = JSON.parse(call.receipt);
      if (receipt.completion !== "completed" || receipt.outcome !== "received" || receipt.responseDigest !== call.responseDigest) throw new Error();
      const text = decrypt(call.continuationCiphertext);
      if (Buffer.byteLength(text) > MAX_JOURNAL_BYTES || sha256(text) !== call.continuationDigest) throw new Error();
      const record = JSON.parse(text) as Continuation;
      const user = sourceReviewPrompt(snapshot, snapshot.batches[batchIndex], session);
      if (record.version !== 1 || record.jobId !== job.id || record.inputDigest !== job.inputDigest || record.batchIndex !== batchIndex
        || record.roundIndex !== session.roundIndex || record.sourceManifest !== snapshot.sources.manifestDigest || record.previousDigest !== session.previousDigest
        || record.promptDigest !== call.promptDigest || record.responseDigest !== call.responseDigest || call.promptDigest !== promptDigest(snapshot.system, user)
        || !Array.isArray(record.requests) || !Array.isArray(record.spans) || record.requests.length !== record.spans.length) throw new Error();
      const replayed = runSourceRequests(snapshot, session, record.requests);
      for (let index = 0; index < replayed.length; index++) {
        const stored = record.spans[index];
        if (!stored || !Number.isFinite(stored.duration_ms) || stored.duration_ms < 0 || stored.duration_ms > 900_000
          || JSON.stringify({ ...stored, duration_ms: 0 }) !== JSON.stringify({ ...replayed[index], duration_ms: 0 })) throw new Error();
      }
      session.spans.push(...record.spans); session.roundIndex++;
      session.previousDigest = call.continuationDigest;
      session.promptBytes += Buffer.byteLength(snapshot.system) + Buffer.byteLength(user);
    }
    return session;
  } catch { throw new ReviewContractError("Stored source continuation could not be verified."); }
}
