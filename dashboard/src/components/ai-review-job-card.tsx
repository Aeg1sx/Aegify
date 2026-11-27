"use client";

import { Button } from "./ui/button";
import { isLlmJobTerminal } from "@/lib/llm-job-state";
import { phaseLabels, type JobObservation } from "@/lib/job-observation";

export interface AiReviewJob {
  id: string; scanId: string; mode: string; status: string; totalFindings: number;
  reviewedCount: number; falsePositives: number; currentBatch: number; totalBatches: number;
  errorMessage: string; createdAt: string; startedAt: string | null; completedAt: string | null;
  scan?: { id: string; repository: string; branch: string };
  contractVersion?: number; historyVersion?: number; provider?: string; model?: string; inputDigest?: string;
  callsStarted?: number; maxCalls?: number; outputTokensReserved?: number; promptBytes?: number;
  workerReady?: boolean; heartbeatAt?: string | null; deadlineAt?: string | null;
  observation?: JobObservation | null; attempts?: number; maxAttempts?: number;
  permissions?: { canCancel: boolean };
  calls?: Array<{ id: string; batchIndex: number; roundIndex?: number; responseKind?: string; status: string; errorCode: string; receipt: string; promptDigest: string; responseDigest: string }>;
  events?: Array<{ id: string; code: string; message: string; details: string; createdAt: string }>;
}

export function AiReviewJobCard({ job, onCancel, cancelling }: { job: AiReviewJob; onCancel: () => void; cancelling: boolean }) {
  const terminal = isLlmJobTerminal(job.status);
  const percent = job.totalFindings ? Math.round(job.reviewedCount / job.totalFindings * 100) : 0;
  const calls = job.calls || [];
  const events = job.events || [];
  const phase = job.observation ? phaseLabels[job.observation.phase] : job.status.replaceAll("_", " ");
  return <section id="review-run" tabIndex={-1} aria-label="AI review job" className="workbench-panel scroll-mt-4">
    <header className="workbench-heading">
      <div className="min-w-0"><h2 className="text-lg font-semibold tracking-tight">Run status</h2><p className="mt-1 break-all text-xs text-muted-foreground">{job.scan?.repository || "Scan review"} · {job.mode}</p></div>
      <span className="text-sm font-medium">{phase}</span>
    </header>
    <div className="space-y-4 px-4 py-4 text-sm sm:px-5">
      <div role="status" aria-atomic="true">
        <span className="sr-only">{phase}. </span>
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <p><strong className="tabular-nums">{job.reviewedCount}/{job.totalFindings}</strong> {job.historyVersion ? "reviews saved" : "suggestions published"}</p>
          <p className="text-xs text-muted-foreground">{job.currentBatch}/{job.totalBatches} batches saved</p>
        </div>
        <progress aria-label="Findings reviewed" className="mt-2 block h-1.5 w-full accent-primary" value={percent} max={100} />
      </div>
      {job.observation?.phase === "recovery_pending" && <p className="border-l-2 border-input pl-3 leading-6">The worker lease {job.observation.at ? <>ended at <time dateTime={job.observation.at}>{new Date(job.observation.at).toLocaleString()}</time></> : "is missing"}. The next worker will check saved batches and provider calls.</p>}
      {job.observation?.phase === "deadline_reached" && <p className="border-l-2 border-input pl-3 leading-6">The review budget has expired. A worker will record the final outcome.</p>}
      {job.workerReady === false && !terminal && <p className="text-muted-foreground">No recent AI worker heartbeat. Check the AI worker service.</p>}
      {job.errorMessage && <p role="alert" className="break-words text-destructive">{job.errorMessage}</p>}
      <dl className="flex flex-wrap gap-x-8 gap-y-2 text-xs">
        <div><dt className="text-muted-foreground">Provider / model</dt><dd className="mt-1 break-all">{job.provider || "Legacy record"} / {job.model || "Not recorded"}</dd></div>
        <div><dt className="text-muted-foreground">Calls started</dt><dd className="mt-1 tabular-nums">{job.callsStarted ?? "Unknown"} / {job.maxCalls ?? "Unknown"}</dd></div>
        {job.attempts !== undefined && <div><dt className="text-muted-foreground">Worker attempts</dt><dd className="mt-1 tabular-nums">{job.attempts} of {job.maxAttempts}</dd></div>}
      </dl>
      {(job.reviewedCount > 0 || (!terminal && job.permissions?.canCancel)) && <div className="flex flex-wrap items-center gap-x-4">
        {job.reviewedCount > 0 && <a className="inline-flex min-h-11 items-center font-medium text-primary underline underline-offset-4" href="#review-results">View saved results</a>}
        {!terminal && job.permissions?.canCancel && <><Button variant="outline" onClick={onCancel} disabled={cancelling}>{cancelling ? "Cancelling…" : "Cancel review"}</Button><p className="py-1 text-xs text-muted-foreground">Dispatched requests may still incur provider charges.</p></>}
      </div>}
    </div>
    <div className="divide-y border-t px-4 text-sm sm:px-5">
      <details><summary className="cursor-pointer py-3.5 font-medium">Budget and timing</summary>
        {job.mode === "source" && <p className="mb-3 text-xs leading-5 text-muted-foreground">Source investigation uses the stored scan snapshot. The worker can resume completed turns. An interrupted provider request with an unknown outcome needs operator review.</p>}
        <dl className="grid gap-3 pb-4 text-xs sm:grid-cols-2">
          <div><dt className="text-muted-foreground">Output token reservation</dt><dd>{job.outputTokensReserved?.toLocaleString() ?? "Unknown"}</dd></div>
          <div><dt className="text-muted-foreground">Cost</dt><dd>Unknown — check provider billing</dd></div>
          {job.deadlineAt && <div><dt className="text-muted-foreground">Queue and execution deadline</dt><dd><time dateTime={job.deadlineAt}>{new Date(job.deadlineAt).toLocaleString()}</time></dd></div>}
          {job.heartbeatAt && <div><dt className="text-muted-foreground">Last worker heartbeat</dt><dd><time dateTime={job.heartbeatAt}>{new Date(job.heartbeatAt).toLocaleString()}</time></dd></div>}
          {job.inputDigest && <div className="sm:col-span-2"><dt className="text-muted-foreground">Input digest</dt><dd className="mt-1 break-all font-mono">{job.inputDigest}</dd></div>}
        </dl>
      </details>
      {calls.length > 0 && <details><summary className="cursor-pointer py-3.5 font-medium">Provider calls ({calls.length})</summary><ol className="mb-3 divide-y border-y">
        {calls.map((call) => {
          let receipt: { reportedUsage?: Record<string, number> | null; outcome?: string; completion?: string; stopReason?: string; requestDigest?: string } = {};
          try { receipt = JSON.parse(call.receipt) || {}; } catch { /* Some legacy calls have no saved receipt. */ }
          return <li key={call.id} className="py-3 text-xs">
            <p className="font-semibold">Batch {call.batchIndex + 1}{job.mode === "source" ? ` · Turn ${(call.roundIndex ?? 0) + 1} · ${call.responseKind === "tools" ? "Source tools" : "Review"}` : ""} · {call.status}{call.errorCode ? " · " + call.errorCode : ""}</p>
            <p className="mt-1 text-muted-foreground">Outcome · {receipt.outcome || "unknown"} / Completion · {receipt.completion || "unknown"}{receipt.stopReason ? " · " + receipt.stopReason : ""}</p>
            <details><summary className="w-fit cursor-pointer py-2.5">Usage and receipt</summary>
              <p className="text-muted-foreground">The provider reports its own token counters. Cache and reasoning usage may overlap.</p>
              {receipt.reportedUsage ? <dl className="mt-2 space-y-1">{Object.entries(receipt.reportedUsage).map(([key, value]) => <div key={key} className="flex flex-wrap justify-between gap-2"><dt className="break-all font-mono">{key}</dt><dd>{value.toLocaleString()}</dd></div>)}</dl> : <p className="mt-2">Usage not reported</p>}
              <dl className="mt-3 space-y-2 break-all font-mono"><div><dt>Request digest</dt><dd>{receipt.requestDigest || "Not recorded"}</dd></div><div><dt>Prompt digest</dt><dd>{call.promptDigest}</dd></div><div><dt>Response digest</dt><dd>{call.responseDigest || "Unknown"}</dd></div></dl>
            </details>
          </li>;
        })}
      </ol></details>}
      {events.length > 0 && <details><summary className="cursor-pointer py-3.5 font-medium">Run events ({events.length})</summary><ol className="mb-4 space-y-3 text-xs">
        {events.map((event) => <li key={event.id} className="border-l-2 pl-3"><p><time dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleString()}</time> · {event.code}</p><p className="mt-1 text-muted-foreground">{event.message}</p><details><summary className="w-fit cursor-pointer py-2">Details</summary><pre className="whitespace-pre-wrap break-all">{event.details}</pre></details></li>)}
      </ol></details>}
    </div>
  </section>;
}
