"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Button } from "@/components/ui/button";
import { isLlmJobTerminal } from "@/lib/llm-job-state";
import { AiReviewJobCard, type AiReviewJob } from "@/components/ai-review-job-card";
import { AiReviewHistory } from "@/components/ai-review-history";
import { SourceReviewPicker } from "@/components/source-review-picker";
import { CheckCircle, AlertCircle, Clock, Loader2 } from "lucide-react";

interface Project {
  id: string;
  name: string;
  scanCount: number;
  accessRole: string;
}

interface ScanOption {
  id: string;
  repository: string;
  projectId: string | null;
  branch: string;
  scanType: string;
  status: string;
  createdAt: string;
  findingsCount: number;
  _count: { findings: number; graphNodes: number };
}

type LlmJob = AiReviewJob;

const runTime = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

const reviewModes = [
  { id: "quick", title: "Quick Review", compact: "Quick", detail: "Review findings and remediation from the scan artifact." },
  { id: "deep", title: "Deep Analysis", compact: "Deep", detail: "Include the call graph to trace findings across functions." },
  { id: "source", title: "Source Investigation", compact: "Source", detail: "Read the retained repository snapshot and cite the lines supporting each verdict." },
] as const;

export default function LLMScanPage() {
  const [mode, setMode] = useState<"quick" | "deep" | "source">("quick");
  const selectedMethod = reviewModes.find((item) => item.id === mode) ?? reviewModes[0];
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const [includeApiContracts, setIncludeApiContracts] = useState(false);
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<ScanOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanning, setScanning] = useState(false);
  const [activeJob, setActiveJob] = useState<LlmJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [jobHistory, setJobHistory] = useState<LlmJob[] | null>(null);
  const [historyError, setHistoryError] = useState(false);
  const [inspectedJob, setInspectedJob] = useState<LlmJob | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [workerReady, setWorkerReady] = useState<boolean | null>(null);
  const inspection = useRef(0);
  const resultsTarget = useRef<HTMLDivElement>(null);
  const displayedJob = inspectedJob || activeJob;
  const activeJobId = activeJob?.id;
  const selectedScan = scans.find((scan) => scan.id === selectedScanId);
  const canStart = Boolean(selectedScan?.projectId && projects.some((project) => project.id === selectedScan.projectId && ["admin", "maintainer"].includes(project.accessRole)));

  useEffect(() => {
    const controller = new AbortController();
    async function loadInputs() {
      try {
        const params = new URLSearchParams({ limit: "50" });
        if (selectedProjectId) params.set("projectId", selectedProjectId);
        const [projectResponse, scanResponse] = await Promise.all([
          fetch("/api/projects", { signal: controller.signal }),
          fetch("/api/scans?" + params, { signal: controller.signal }),
        ]);
        if (!projectResponse.ok || !scanResponse.ok) throw new Error();
        const [projectData, scanData] = await Promise.all([projectResponse.json(), scanResponse.json()]);
        if (controller.signal.aborted) return;
        setProjects(projectData.projects);
        setScans(scanData.scans.filter((scan: ScanOption) =>
          ["completed", "partial"].includes(scan.status) && scan._count.findings > 0));
        setLoadError("");
      } catch {
        if (!controller.signal.aborted) setLoadError("Project and scan records could not be loaded.");
      } finally {
        if (!controller.signal.aborted) setLoadingScans(false);
      }
    }
    void loadInputs();
    return () => controller.abort();
  }, [selectedProjectId, attempt]);

  const fetchHistory = useCallback(() => {
    fetch("/api/llm-jobs?limit=10").then(async (response) => {
      if (!response.ok) throw new Error();
      const data = await response.json();
      setJobHistory(data.jobs); setWorkerReady(data.workerReady); setHistoryError(false);
    }).catch(() => { setWorkerReady(null); setHistoryError(true); });
  }, []);

  useEffect(() => {
    fetchHistory();
    const controller = new AbortController();
    fetch("/api/llm-jobs?active=true&limit=1", { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error();
        const data = await response.json();
        if (!controller.signal.aborted && data.jobs?.[0]) {
          setActiveJob(data.jobs[0]); setScanning(true);
        }
      }).catch(() => { if (!controller.signal.aborted) setError("Active review status is unavailable."); });
    return () => controller.abort();
  }, [fetchHistory]);

  // Poll active job for progress
  useEffect(() => {
    if (!activeJobId) return;
    const controller = new AbortController();

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/llm-jobs/${activeJobId}`, { signal: controller.signal, cache: "no-store" });
        if (controller.signal.aborted) return;
        if (!res.ok) { setError("Review status is unavailable. Check your project access."); setActiveJob(null); setScanning(false); return; }
        const job: LlmJob = await res.json();
        if (controller.signal.aborted) return;

        setActiveJob(job);
        setInspectedJob((current) => current?.id === job.id ? job : current);

        if (isLlmJobTerminal(job.status)) {
          setScanning(false);
          setActiveJob(null);
          setInspectedJob((current) => !current || current.id === job.id ? job : current);
          fetchHistory();

          if (job.status === "completed" || job.status === "partial") {
            if (job.status === "partial") {
              setError(job.errorMessage || "Review completed with unresolved batches");
            }
          } else {
            setError(job.errorMessage || "Review failed");
          }
        }
      } catch {
        // Keep polling
      }
    }, 2000);

    return () => { controller.abort(); clearInterval(interval); };
  }, [activeJobId, fetchHistory]);

  const startReview = async () => {
    if (scanning || loadingScans || !selectedScanId || !canStart) return;
    inspection.current++;

    setScanning(true);
    setInspectedJob(null);
    setError(null);

    try {
      const res = await fetch("/api/llm-jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId: selectedScanId, mode, includeApiContracts, ...(mode === "source" ? { findingIds: selectedFindingIds } : {}) }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Review failed");
        setScanning(false);
        return;
      }

      setActiveJob(data);
      requestAnimationFrame(() => document.getElementById("review-run")?.focus());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Review failed");
      setScanning(false);
    }
  };

  const inspectJob = async (id: string) => {
    const sequence = ++inspection.current;
    setError(null);
    try {
      const response = await fetch(`/api/llm-jobs/${id}`, { cache: "no-store" });
      if (!response.ok) throw new Error("Could not load this review.");
      const job: LlmJob = await response.json();
      if (sequence !== inspection.current) return;
      setInspectedJob(job);
      requestAnimationFrame(() => {
        if (sequence !== inspection.current) return;
        resultsTarget.current?.focus({ preventScroll: true });
        resultsTarget.current?.scrollIntoView({ block: "start" });
      });
      if (!isLlmJobTerminal(job.status)) { setActiveJob(job); setScanning(true); }
    } catch (failure) {
      if (sequence === inspection.current) { setInspectedJob(null); setError(failure instanceof Error ? failure.message : "Could not load review."); }
    }
  };

  const cancelReview = async () => {
    if (!activeJob || cancelling) return;
    setCancelling(true);
    try {
      const response = await fetch(`/api/llm-jobs/${activeJob.id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "cancel" }) });
      const data = await response.json(); if (!response.ok) throw new Error(data.error || "Cancellation failed.");
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Cancellation failed."); }
    finally { setCancelling(false); }
  };

  return (
    <div className="review-desk space-y-6">
      <header className="workspace-masthead flex flex-wrap items-center justify-between gap-x-4">
        <h1 className="workbench-title">AI reviews</h1>
        {!!jobHistory?.length && <a className="review-history-jump" href="#recent-review-runs">Recent runs</a>}
      </header>

      {loadError && <div role="alert" className="flex items-center justify-between gap-3 rounded-md border p-3 text-sm">{loadError}<Button variant="outline" onClick={() => { setLoadingScans(true); setAttempt(attempt + 1); }}>Retry</Button></div>}

      <div className="review-columns">
        <section aria-label="New review" className="min-w-0">
          <h2 className="review-section-title">New review</h2>
          {/* Firefox otherwise restores dynamic disabled/checked state before hydration. */}
          <form className="space-y-5 pt-4" autoComplete="off" onSubmit={(event) => {
            event.preventDefault();
            void startReview();
          }}>
            <div className="review-input-pair">
              <div className="grid min-w-0 gap-1.5">
                <label htmlFor="review-project" className="text-sm font-medium">
                  Project
                </label>
                <select
                  id="review-project"
                  value={selectedProjectId}
                  onChange={(e) => {
                    if (e.target.value === selectedProjectId) return;
                    setSelectedProjectId(e.target.value);
                    setSelectedScanId("");
                    setSelectedFindingIds([]);
                    setScans([]);
                    setLoadingScans(true);
                  }}
                  className="h-11 w-full min-w-0 rounded-md border border-input bg-card px-3 text-sm"
                >
                  <option value="">All projects</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.scanCount} scans)
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid min-w-0 gap-1.5">
                <label htmlFor="review-scan" className="text-sm font-medium">
                  Scan
                </label>
                <select
                  id="review-scan"
                  value={selectedScanId}
                  onChange={(e) => { setSelectedScanId(e.target.value); setSelectedFindingIds([]); }}
                  className="h-11 w-full min-w-0 rounded-md border border-input bg-card px-3 text-sm"
                  disabled={loadingScans}
                >
                  <option value="">
                    {loadingScans ? "Loading scans..." : "Select a scan..."}
                  </option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.repository || s.id.slice(0, 8)} - {new Date(s.createdAt).toLocaleDateString()} ({s._count.findings} findings{s._count.graphNodes > 0 ? `, ${s._count.graphNodes} graph nodes` : ""})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <fieldset>
              <legend className="text-sm font-medium">Review method</legend>
              <div className="mt-1 grid grid-cols-3 border-b sm:flex sm:gap-x-6">
                {reviewModes.map(({ id, title, compact }) =>
                  <button key={id} type="button" aria-label={title} aria-pressed={id === mode} aria-describedby="method-detail" onClick={() => setMode(id)}
                    className="min-h-11 border-b-2 border-transparent text-sm text-muted-foreground hover:text-foreground aria-pressed:border-primary aria-pressed:font-semibold aria-pressed:text-primary">
                    <span className="sm:hidden">{compact}</span><span className="hidden sm:inline">{title}</span>
                  </button>)}
              </div>
              <p id="method-detail" className="mt-2 text-sm leading-6 text-muted-foreground">{selectedMethod.detail}</p>
            </fieldset>
            {mode === "source" && selectedScanId && <SourceReviewPicker key={selectedScanId} scanId={selectedScanId} selected={selectedFindingIds} onChange={setSelectedFindingIds} disabled={scanning} />}
            <details className="border-y text-sm">
              <summary className="w-fit cursor-pointer py-3 font-medium">Review options and limits{includeApiContracts && <span className="ml-2 text-xs text-primary">API context on</span>}</summary>
              <div className="space-y-3 pb-4">
                <label className="flex min-h-11 items-start gap-3 text-sm leading-6">
                  <input type="checkbox" className="mt-1.5" checked={includeApiContracts} disabled={scanning} onChange={(event) => setIncludeApiContracts(event.target.checked)} />
                  <span><span className="block font-medium">Include API contract context</span><span className="text-muted-foreground">Include matching OpenAPI or Swagger requirements in the input sent to the provider.</span></span>
                </label>
                <p className="max-w-prose text-xs leading-5 text-muted-foreground">Each run uses a fixed snapshot and up to 20 model calls. {mode === "source" ? "Select up to 25 findings. Each batch can use four model turns and eight source requests. Source investigation requires a retained repository snapshot." : "Excerpt reviews support up to 1,000 findings."} Usage appears in the run receipt when the provider returns it. Check provider billing for the final cost.</p>
              </div>
            </details>
            {workerReady === false && !activeJob && <p role="status" className="flex items-start gap-2 text-sm text-muted-foreground"><Clock aria-hidden className="mt-0.5 size-4 shrink-0" />No AI worker is online. Queued reviews expire after 30 minutes.</p>}
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
              <Button
                type="submit"
                disabled={scanning || loadingScans || !selectedScanId || !canStart || (mode === "source" && !selectedFindingIds.length)}
                className="flex min-h-11 items-center gap-2"
              >
                {scanning ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Reviewing...
                  </>
                ) : (
                  "Start " + selectedMethod.title
                )}
              </Button>
              <p className="text-xs leading-5 text-muted-foreground">{mode === "source" ? "Sends redacted source excerpts to the configured provider." : "Sends scan evidence to the configured provider."} Provider charges may apply.</p>
              {selectedScanId && !canStart && <p className="text-xs text-muted-foreground">An active project and maintainer access are required to start reviews.</p>}
            </div>
          </form>
        </section>
        <section aria-label="Review runs" className="review-run-index">
          <h2 className="review-section-title scroll-mt-4" id="recent-review-runs" tabIndex={-1}>Recent runs</h2>
          {historyError ? <p role="alert" className="flex items-center gap-3 text-sm">Could not refresh recent runs. <button type="button" className="min-h-11 text-primary underline" onClick={fetchHistory}>Retry</button></p>
            : !jobHistory?.length && <p role="status" className="py-4 text-sm text-muted-foreground">{jobHistory ? "No reviews recorded yet." : "Loading recent runs…"}</p>}
          <ul className="divide-y" aria-label="Recent review records">
            {jobHistory?.map((job) => <li key={job.id} data-review-job={job.id}>
              <button id={"run-row-" + job.id} type="button" onClick={() => void inspectJob(job.id)} aria-pressed={displayedJob?.id === job.id}
                className="review-run-row">
                {job.status === "completed" ? <CheckCircle aria-hidden className="mt-0.5 size-4 text-[var(--status-fixed)]" /> : isLlmJobTerminal(job.status)
                  ? <AlertCircle aria-hidden className="mt-0.5 size-4 text-muted-foreground" /> : <Loader2 aria-hidden className="mt-0.5 size-4 animate-spin text-primary" />}
                <span className="min-w-0">
                  <span className="block wrap-anywhere text-sm font-semibold">{job.scan?.repository || job.scanId.slice(0, 8)}</span>
                  <span className="mt-1 flex flex-wrap gap-x-2 text-xs leading-5 text-muted-foreground">
                    <span>{reviewModes.find((item) => item.id === job.mode)?.title ?? job.mode}</span><span>{job.reviewedCount}/{job.totalFindings} reviewed</span>
                    {job.falsePositives > 0 && <span>{job.falsePositives} suggested false positives</span>}
                  </span>
                  {job.errorMessage && (job.status === "partial" || job.status === "failed") && <span className="mt-1 block wrap-anywhere text-xs leading-5 text-muted-foreground">{job.errorMessage}</span>}
                </span>
                <span className="text-right text-xs leading-5">
                  <span className="block font-medium capitalize">{job.status}</span>
                  <time dateTime={job.createdAt} title={new Date(job.createdAt).toLocaleString()} className="text-muted-foreground">{runTime.format(new Date(job.createdAt))}</time>
                </span>
              </button>
            </li>)}
          </ul>
        </section>
      </div>

      {/* Active Job Progress */}
      {activeJob && inspectedJob && activeJob.id !== inspectedJob.id && <Button variant="outline" onClick={() => setInspectedJob(null)}>Show active review</Button>}
      {displayedJob && <AiReviewJobCard key={displayedJob.id} job={displayedJob} onCancel={() => void cancelReview()} cancelling={cancelling} />}

      {/* Error */}
      {error && (
        <div role="alert" className="flex items-center gap-2 text-sm px-3 py-2 rounded-md bg-destructive/10 text-destructive">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {displayedJob && <div ref={resultsTarget} id="review-results" tabIndex={-1} aria-label="Results of the selected run" className="scroll-mt-4">
        {jobHistory?.some((job) => job.id === displayedJob.id) && <button type="button" className="mb-1 min-h-11 text-sm text-primary underline underline-offset-4" onClick={() => document.getElementById("run-row-" + displayedJob.id)?.focus()}>Back to recent runs</button>}
        <AiReviewHistory key={displayedJob.id} job={displayedJob} />
      </div>}
    </div>
  );
}
