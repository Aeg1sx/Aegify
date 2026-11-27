"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { phaseLabels, type JobObservation } from "@/lib/job-observation";

interface JobState {
  job: {
    id: string;
    status: string;
    attempts: number;
    maxAttempts: number;
    commitSha: string;
    sourceDigest: string;
    resultDigest: string;
    errorCode: string;
    heartbeatAt: string | null;
  } | null;
  events: Array<{ id: number; code: string; message: string; createdAt: string }>;
  scan: { progressPhaseName: string; progressPercent: number; progressMessage: string };
  observation: JobObservation | null;
  nextBefore: number | null;
  canManage: boolean;
  workerAvailable: boolean;
}
function Timestamp({ value }: { value: string }) {
  return (
    <time dateTime={value}>
      {new Date(value).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })}
    </time>
  );
}
export function ScanJobPanel({ scanId, onFinished }: { scanId: string; onFinished: () => void }) {
  const router = useRouter();
  const [state, setState] = useState<JobState | null>(null);
  const [before, setBefore] = useState<number | null>(null);
  const [loadedBefore, setLoadedBefore] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const actionRequest = useRef<AbortController | null>(null);
  const notified = useRef("");
  useEffect(() => () => actionRequest.current?.abort(), []);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const query = new URLSearchParams({ order: "recent" });
        if (before !== null) query.set("before", String(before));
        const response = await fetch(`/api/scans/${scanId}/job?` + query, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("Could not load scan activity.");
        const data: JobState = await response.json();
        if (controller.signal.aborted) return;
        setState(data);
        setLoadedBefore(before);
        setError("");
        if (!data.job) return;
        if (["queued", "running"].includes(data.job.status)) timer = setTimeout(poll, 2000);
        else if (notified.current !== data.job.id + data.job.status) {
          notified.current = data.job.id + data.job.status;
          onFinished();
        }
      } catch (reason) {
        if (controller.signal.aborted) return;
        setError(reason instanceof Error ? reason.message : "Could not load scan activity.");
        timer = setTimeout(poll, 5000);
      }
    }
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [scanId, onFinished, refresh, before]);

  async function act(action: "cancel" | "retry") {
    if (busy) return;
    const controller = new AbortController();
    actionRequest.current = controller;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`/api/scans/${scanId}/job`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
        signal: controller.signal,
      });
      const result = await response.json();
      if (controller.signal.aborted) return;
      if (!response.ok) throw new Error(result.error || "Could not update the scan.");
      if (action === "retry") router.push(`/scans/${result.scanId}`);
      else setRefresh((value) => value + 1);
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(reason instanceof Error ? reason.message : "Could not update the scan.");
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  if (!state?.job)
    return error ? (
      <p role="alert" className="text-sm text-destructive">
        {error}
      </p>
    ) : !state ? (
      <p role="status" className="text-sm text-muted-foreground">
        Loading scan activity…
      </p>
    ) : null;
  const { job, observation, scan } = state;
  const phase = observation?.phase;
  const inProgress = phase === "working" || phase === "retrying";
  const status = observation
    ? phaseLabels[observation.phase]
    : job.status[0].toUpperCase() + job.status.slice(1);
  const percent = Math.round(Math.min(1, Math.max(0, scan.progressPercent)) * 100);
  return (
    <section aria-label="Source scan job" className="workbench-panel min-w-0">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3 sm:px-5">
        <div>
          <h2 className="text-sm text-muted-foreground">Source scan</h2>
          <p role="status" aria-atomic="true" className="mt-1 text-lg font-semibold">
            {status}
          </p>
        </div>
        {state.canManage && (
          <div className="flex flex-wrap gap-2">
            {observation && (
              <Button variant="outline" className="min-h-11" disabled={busy} onClick={() => act("cancel")}>
                Cancel scan
              </Button>
            )}
            {["failed", "cancelled", "partial"].includes(job.status) && (
              <Button variant="outline" className="min-h-11" disabled={busy} onClick={() => act("retry")}>
                Retry {job.commitSha ? "same commit" : "scan"}
              </Button>
            )}
          </div>
        )}
      </header>
      <div className="space-y-4 px-4 py-4 text-sm sm:px-5">
        {phase === "recovery_pending" ? (
          <p>
            The previous worker’s lease{" "}
            {observation?.at ? (
              <>
                ended at <Timestamp value={observation.at} />
              </>
            ) : (
              "is missing"
            )}
            . The next worker will check this scan.
          </p>
        ) : phase === "retry_scheduled" || phase === "retry_ready" ? (
          <p>
            The previous attempt stopped.{" "}
            {observation?.at && (
              <>
                Eligible for another attempt at <Timestamp value={observation.at} />.
              </>
            )}
          </p>
        ) : (
          scan.progressMessage && phase !== "waiting" && <p>{scan.progressMessage}</p>
        )}
        {observation && !state.workerAvailable && (
          <p className="border-l-2 border-input pl-3 text-muted-foreground">
            No recent scan worker heartbeat. Check the worker service.
          </p>
        )}
        {inProgress && scan.progressPhaseName !== "starting" && (
          <div>
            <div className="mb-1 flex justify-between gap-2 text-xs">
              <span>{scan.progressPhaseName}</span>
              <span className="tabular-nums">{percent}%</span>
            </div>
            <progress
              className="block h-2 w-full accent-primary"
              max={100}
              value={percent}
              aria-label="Scan progress"
            />
          </div>
        )}
        <dl className="flex flex-wrap gap-x-8 gap-y-2 text-xs">
          <div>
            <dt className="text-muted-foreground">Attempts used</dt>
            <dd className="mt-1 tabular-nums">
              {job.attempts} of {job.maxAttempts}
            </dd>
          </div>
          {job.commitSha && (
            <div>
              <dt className="text-muted-foreground">Pinned commit</dt>
              <dd className="mt-1 font-mono">{job.commitSha.slice(0, 12)}</dd>
            </div>
          )}
          {job.heartbeatAt && (
            <div>
              <dt className="text-muted-foreground">Job heartbeat</dt>
              <dd className="mt-1">
                <Timestamp value={job.heartbeatAt} />
              </dd>
            </div>
          )}
        </dl>
        {error && (
          <p role="alert" className="text-destructive">
            {error}
          </p>
        )}
        <details className="group border-t">
          <summary className="min-h-11 cursor-pointer py-3 text-sm font-medium">
            Activity and evidence
            {observation && before === null && state.events[0] && (
              <span className="mt-2 block break-words pl-4 text-xs font-normal leading-5 text-muted-foreground group-open:hidden">
                <Timestamp value={state.events[0].createdAt} /> · {state.events[0].message}
              </span>
            )}
          </summary>
          {state.events.length > 0 && (
            <ol className="divide-y" aria-label="Scan activity">
              {state.events.map((event) => (
                <li
                  key={event.id}
                  className="grid items-baseline gap-1 py-2 text-xs sm:grid-cols-[10rem_minmax(0,1fr)]"
                >
                  <span className="tabular-nums text-muted-foreground">
                    <Timestamp value={event.createdAt} />
                  </span>
                  <span className="break-words">{event.message}</span>
                </li>
              ))}
            </ol>
          )}
          <div className="flex flex-wrap gap-2">
            {before !== null && (
              <Button variant="outline" className="min-h-11" onClick={() => setBefore(null)}>
                Latest activity
              </Button>
            )}
            {state.nextBefore !== null && (
              <Button
                variant="outline"
                className="min-h-11"
                disabled={loadedBefore !== before}
                onClick={() => setBefore(state.nextBefore)}
              >
                Earlier activity
              </Button>
            )}
          </div>
          {job.sourceDigest && (
            <p className="mt-3 break-all text-xs text-muted-foreground">
              Source snapshot <code>{job.sourceDigest}</code>
            </p>
          )}
          {job.resultDigest && (
            <p className="mt-2 break-all text-xs text-muted-foreground">
              Report digest <code>{job.resultDigest}</code>
            </p>
          )}
        </details>
      </div>
    </section>
  );
}
