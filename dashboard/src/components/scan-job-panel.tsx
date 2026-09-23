"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface JobState {
  job: { id: string; status: string; attempts: number; maxAttempts: number; commitSha: string; sourceDigest: string; resultDigest: string; errorCode: string; heartbeatAt: string | null } | null;
  events: Array<{ id: number; code: string; message: string; createdAt: string }>;
  scan: { progressPhaseName: string; progressPercent: number; progressMessage: string };
  canManage: boolean;
  workerAvailable: boolean;
}

export function ScanJobPanel({ scanId, onFinished }: { scanId: string; onFinished: () => void }) {
  const router = useRouter();
  const [state, setState] = useState<JobState | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const response = await fetch(`/api/scans/${scanId}/job`, { cache: "no-store" });
        if (!response.ok) throw new Error("Could not load scan progress.");
        const data: JobState = await response.json();
        if (!active) return;
        setState(data); setError("");
        if (data.job && ["queued", "running"].includes(data.job.status)) timer = setTimeout(poll, 2000);
        else if (data.job) onFinished();
      } catch (error) {
        if (!active) return;
        setError(error instanceof Error ? error.message : "Could not load scan progress.");
        timer = setTimeout(poll, 5000);
      }
    }
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [scanId, onFinished, refresh]);

  async function act(action: "cancel" | "retry") {
    setBusy(true); setError("");
    try {
      const response = await fetch(`/api/scans/${scanId}/job`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Could not update the job.");
      if (action === "retry") router.push(`/scans/${result.scanId}`);
      else setRefresh((value) => value + 1);
    } catch (error) { setError(error instanceof Error ? error.message : "Could not update the job."); }
    finally { setBusy(false); }
  }
  if (!state?.job) return error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null;
  const job = state.job;
  const running = ["queued", "running"].includes(job.status);
  const percent = Math.round(Math.min(1, Math.max(0, state.scan.progressPercent)) * 100);
  return <Card>
    <CardHeader className="flex-row items-center justify-between gap-3">
      <CardTitle className="text-base">Source scan · {job.status}</CardTitle>
      {state.canManage && <div className="flex gap-2">
        {running && <Button size="sm" variant="outline" disabled={busy} onClick={() => act("cancel")}>Cancel scan</Button>}
        {["failed", "cancelled", "partial"].includes(job.status) && <Button size="sm" variant="outline" disabled={busy} onClick={() => act("retry")}>Retry {job.commitSha ? "same commit" : "scan"}</Button>}
      </div>}
    </CardHeader>
    <CardContent className="space-y-4 text-sm">
      <div role="status">
        <p>{state.scan.progressMessage || state.scan.progressPhaseName}</p>
        <p className="mt-1 text-muted-foreground">Attempt {job.attempts} of {job.maxAttempts}{job.commitSha && <> · Commit <code>{job.commitSha.slice(0, 12)}</code></>}</p>
        {running && !state.workerAvailable && <p className="mt-2 text-amber-700 dark:text-amber-300">Waiting for an available worker. The queued job is saved; an administrator can check the worker service.</p>}
      </div>
      {running && <div><progress className="h-2 w-full" max={100} value={percent} aria-label="Scan progress" /><span className="text-xs text-muted-foreground">{percent}%</span></div>}
      {error && <p role="alert" className="text-destructive">{error}</p>}
      <details open={running}>
        <summary className="cursor-pointer font-medium">Activity and evidence</summary>
        <ol className="mt-3 max-h-56 space-y-2 overflow-auto" aria-label="Scan activity">
          {state.events.map((event) => <li key={event.id} className="flex gap-3"><time className="shrink-0 text-muted-foreground" dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleTimeString()}</time><span>{event.message}</span></li>)}
        </ol>
        {job.sourceDigest && <p className="mt-3 break-all text-xs text-muted-foreground">Source snapshot: <code>{job.sourceDigest}</code></p>}
        {job.resultDigest && <p className="mt-2 break-all text-xs text-muted-foreground">Report: <code>{job.resultDigest}</code></p>}
      </details>
    </CardContent>
  </Card>;
}
