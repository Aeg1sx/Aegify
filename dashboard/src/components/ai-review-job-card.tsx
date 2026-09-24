"use client";

import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { isLlmJobTerminal } from "@/lib/llm-job-state";

export interface AiReviewJob {
  id: string; scanId: string; mode: string; status: string; totalFindings: number;
  reviewedCount: number; falsePositives: number; currentBatch: number; totalBatches: number;
  errorMessage: string; createdAt: string; startedAt: string | null; completedAt: string | null;
  scan?: { id: string; repository: string; branch: string };
  contractVersion?: number; historyVersion?: number; provider?: string; model?: string; inputDigest?: string;
  callsStarted?: number; maxCalls?: number; outputTokensReserved?: number; promptBytes?: number;
  workerReady?: boolean; heartbeatAt?: string | null; deadlineAt?: string | null;
  permissions?: { canCancel: boolean };
  calls?: Array<{ id: string; batchIndex: number; roundIndex?: number; responseKind?: string; status: string; errorCode: string; receipt: string; promptDigest: string; responseDigest: string }>;
  events?: Array<{ id: string; code: string; message: string; details: string; createdAt: string }>;
}

export function AiReviewJobCard({ job, onCancel, cancelling }: { job: AiReviewJob; onCancel: () => void; cancelling: boolean }) {
  const terminal = isLlmJobTerminal(job.status);
  const percent = job.totalFindings ? Math.round(job.reviewedCount / job.totalFindings * 100) : 0;
  return <Card aria-label="AI review job">
    <CardHeader><CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
      <span>{job.scan?.repository || "Scan review"} · {job.mode}</span><Badge variant="outline" className="capitalize">{job.status}</Badge>
    </CardTitle></CardHeader>
    <CardContent className="space-y-4 text-sm">
      <div role="status" aria-live="polite">
        <p>{job.reviewedCount}/{job.totalFindings} {job.historyVersion ? "reviews saved" : "suggestions published"} · {job.currentBatch}/{job.totalBatches} batches saved</p>
        <progress aria-label="Findings reviewed" className="mt-2 h-2 w-full" value={percent} max={100} />
      </div>
      {job.workerReady === false && !terminal && <p className="text-amber-700 dark:text-amber-300">No AI worker heartbeat. The job is stored; ask an operator to start the AI worker before the deadline.</p>}
      {job.errorMessage && <p className="text-destructive">{job.errorMessage}</p>}
      {job.mode === "source" && <p className="text-xs text-muted-foreground">Source investigation · reads only the frozen source admitted for this scan. Completed source turns are recoverable; interrupted provider requests are never automatically replayed. Review suggestions require human triage.</p>}
      <dl className="grid gap-3 text-xs sm:grid-cols-2">
        <div><dt className="text-muted-foreground">Provider / model</dt><dd className="break-all">{job.provider || "Legacy record"} / {job.model || "Not recorded"}</dd></div>
        <div><dt className="text-muted-foreground">Calls started / limit</dt><dd>{job.callsStarted ?? "Unknown"} / {job.maxCalls ?? "Unknown"}</dd></div>
        <div><dt className="text-muted-foreground">Output tokens reserved (ceiling)</dt><dd>{job.outputTokensReserved?.toLocaleString() ?? "Unknown"}</dd></div>
        <div><dt className="text-muted-foreground">Cost</dt><dd>Unknown — check provider billing</dd></div>
        {job.deadlineAt && <div><dt className="text-muted-foreground">Queue and execution deadline</dt><dd>{new Date(job.deadlineAt).toLocaleString()}</dd></div>}
        {job.heartbeatAt && <div><dt className="text-muted-foreground">Last job heartbeat</dt><dd>{new Date(job.heartbeatAt).toLocaleString()}</dd></div>}
      </dl>
      {job.inputDigest && <details><summary className="cursor-pointer text-xs">Input identity</summary><p className="mt-2 break-all font-mono text-xs">{job.inputDigest}</p></details>}
      {!terminal && job.permissions?.canCancel && <div className="space-y-2"><Button variant="outline" onClick={onCancel} disabled={cancelling}>{cancelling ? "Cancelling…" : "Cancel review"}</Button><p className="text-xs text-muted-foreground">Cancellation stops publication and local requests. A dispatched request may still incur provider charges.</p></div>}
      {Boolean(job.calls?.length) && <details open><summary className="cursor-pointer font-medium">Provider calls ({job.calls!.length})</summary><div className="mt-3 space-y-2">
        {job.calls!.map((call) => {
          let receipt: { reportedUsage?: Record<string, number> | null; outcome?: string; completion?: string; stopReason?: string; responseId?: string; requestDigest?: string } = {};
          try { receipt = JSON.parse(call.receipt); } catch { /* Legacy receipt remains unknown. */ }
          return <div key={call.id} className="rounded-md border p-3 text-xs">
            <p className="font-medium">Batch {call.batchIndex + 1}{job.mode === "source" ? ` · Turn ${(call.roundIndex ?? 0) + 1} · ${call.responseKind === "tools" ? "Source tools" : "Review"}` : ""} · {call.status}{call.errorCode ? " · " + call.errorCode : ""}</p>
            <p className="mt-1 text-muted-foreground">Outcome: {receipt.outcome || "unknown"} · Completion: {receipt.completion || "unknown"}{receipt.stopReason ? " · " + receipt.stopReason : ""}</p>
            <details className="mt-2"><summary className="cursor-pointer">Usage and receipt</summary>
              <p className="mt-2 text-muted-foreground">Provider-reported token counters retain their native names. Cache and reasoning counters may overlap other counters; do not add them together.</p>
              {receipt.reportedUsage ? <dl className="mt-2 space-y-1">{Object.entries(receipt.reportedUsage).map(([key, value]) => <div key={key} className="flex flex-wrap justify-between gap-2"><dt className="break-all font-mono">{key}</dt><dd>{value.toLocaleString()}</dd></div>)}</dl> : <p className="mt-2">Usage not reported</p>}
              <dl className="mt-3 space-y-2 break-all font-mono"><div><dt>Request digest</dt><dd>{receipt.requestDigest || "Not recorded"}</dd></div><div><dt>Prompt digest</dt><dd>{call.promptDigest}</dd></div><div><dt>Response digest</dt><dd>{call.responseDigest || "Unknown"}</dd></div></dl>
            </details>
          </div>;
        })}
      </div></details>}
      {Boolean(job.events?.length) && <details><summary className="cursor-pointer font-medium">Job history ({job.events!.length})</summary><ol className="mt-3 space-y-3 text-xs">{job.events!.map((event) => <li key={event.id} className="border-l-2 pl-3"><p><time>{new Date(event.createdAt).toLocaleString()}</time> · {event.code}</p><p className="mt-1 text-muted-foreground">{event.message}</p><details className="mt-1"><summary className="cursor-pointer">Details</summary><pre className="mt-2 whitespace-pre-wrap break-all">{event.details}</pre></details></li>)}</ol></details>}
    </CardContent>
  </Card>;
}
