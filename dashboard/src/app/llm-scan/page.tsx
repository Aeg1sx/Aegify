"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { isLlmJobTerminal } from "@/lib/llm-job-state";
import { AiReviewJobCard, type AiReviewJob } from "@/components/ai-review-job-card";
import { AiReviewHistory } from "@/components/ai-review-history";
import { SourceReviewPicker } from "@/components/source-review-picker";
import {
  Bot,
  Zap,
  Search,
  Loader2,
  CheckCircle,
  AlertCircle,
  FolderKanban,
  ScanSearch,
  Clock,
  History,
} from "lucide-react";

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

export default function LLMScanPage() {
  const [mode, setMode] = useState<"quick" | "deep" | "source">("quick");
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
  const [jobHistory, setJobHistory] = useState<LlmJob[]>([]);
  const [inspectedJob, setInspectedJob] = useState<LlmJob | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [workerReady, setWorkerReady] = useState<boolean | null>(null);
  const inspection = useRef(0);
  const displayedJob = inspectedJob || activeJob;
  const activeJobId = activeJob?.id;
  const selectedScan = scans.find((scan) => scan.id === selectedScanId);
  const canStart = Boolean(selectedScan?.projectId && projects.some((project) => project.id === selectedScan.projectId && ["admin", "maintainer"].includes(project.accessRole)));

  // Fetch projects
  useEffect(() => {
    fetch("/api/projects")
      .then((r) => r.json())
      .then((data) => setProjects(data.projects || []))
      .catch(() => {});
  }, []);

  // Fetch scans when project changes
  useEffect(() => {
    const controller = new AbortController();
    const url = selectedProjectId
      ? `/api/scans?projectId=${encodeURIComponent(selectedProjectId)}&limit=50`
      : "/api/scans?limit=50";
    fetch(url, { signal: controller.signal })
      .then((r) => r.json())
      .then((data) => {
        if (controller.signal.aborted) return;
        const scanList = (data.scans || []).filter(
          (s: ScanOption) => ["completed", "partial"].includes(s.status) && s._count.findings > 0
        );
        setScans(scanList);
      })
      .catch(() => {})
      .finally(() => {
        if (!controller.signal.aborted) setLoadingScans(false);
      });
    return () => controller.abort();
  }, [selectedProjectId]);

  // Fetch job history
  const fetchHistory = useCallback(() => {
    fetch("/api/llm-jobs?limit=10")
      .then((r) => r.json())
      .then((data) => { setJobHistory(data.jobs || []); setWorkerReady(data.workerReady === true); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Check for active job on mount
  useEffect(() => {
    fetch("/api/llm-jobs?active=true&limit=1")
      .then((r) => r.json())
      .then((data) => {
        const job = data.jobs?.[0];
        if (job) {
          setActiveJob(job);
          setScanning(true);
        }
      })
      .catch(() => {});
  }, []);

  // Poll active job for progress
  useEffect(() => {
    if (!activeJobId) return;
    const controller = new AbortController();

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/llm-jobs/${activeJobId}`, { signal: controller.signal, cache: "no-store" });
        if (controller.signal.aborted) return;
        if (!res.ok) { setError("Review status is unavailable; check your project access."); setActiveJob(null); setScanning(false); return; }
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
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold">LLM Security Review</h1>
        <p className="text-muted-foreground">
          AI-powered review of existing scan findings for false positive detection and remediation guidance
        </p>
      </div>

      {workerReady === false && !activeJob && <p role="status" className="rounded-md border p-3 text-sm text-muted-foreground">No AI worker is online. New reviews are stored with a 30 minute deadline.</p>}

      {/* Mode Selector */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={() => setMode("quick")}
          className={`p-4 rounded-lg border text-left transition-colors ${
            mode === "quick"
              ? "border-primary bg-primary/5"
              : "border-border hover:border-muted-foreground/30"
          }`}
        >
          <div className="flex items-center gap-3 mb-2">
            <Zap className={`h-5 w-5 ${mode === "quick" ? "text-primary" : "text-muted-foreground"}`} />
            <span className="font-medium">Quick Review</span>
            <Badge variant="outline" className="text-xs">Fast</Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            Reviews findings for false positives and suggests remediation. Best for triaging large finding sets.
          </p>
        </button>

        <button
          onClick={() => setMode("deep")}
          className={`p-4 rounded-lg border text-left transition-colors ${
            mode === "deep"
              ? "border-primary bg-primary/5"
              : "border-border hover:border-muted-foreground/30"
          }`}
        >
          <div className="flex items-center gap-3 mb-2">
            <Search className={`h-5 w-5 ${mode === "deep" ? "text-primary" : "text-muted-foreground"}`} />
            <span className="font-medium">Deep Analysis</span>
            <Badge variant="outline" className="text-xs">Thorough</Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            Uses call graph context to assess cross-function evidence and identify explicit evidence gaps.
          </p>
        </button>
        <button onClick={() => setMode("source")} className={`p-4 rounded-lg border text-left transition-colors ${mode === "source" ? "border-primary bg-primary/5" : "border-border hover:border-muted-foreground/30"}`}>
          <div className="flex items-center gap-3 mb-2"><Bot className={`h-5 w-5 ${mode === "source" ? "text-primary" : "text-muted-foreground"}`} /><span className="font-medium">Source Investigation</span></div>
          <p className="text-sm text-muted-foreground">An agent reads and searches the scan’s retained source, follows relevant context and cites the lines it used. Requires a connected repository scan with retained source.</p>
        </button>
      </div>

      {/* Project + Scan Selector */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <ScanSearch className="h-4 w-4" />
            Select Scan to Review
          </CardTitle>
        </CardHeader>
        {/* Firefox otherwise restores dynamic disabled/checked state before hydration. */}
        <form autoComplete="off" onSubmit={(event) => {
          event.preventDefault();
          void startReview();
        }}>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="review-project" className="text-xs font-medium text-muted-foreground flex items-center gap-1">
                <FolderKanban className="h-3 w-3" />
                Filter by project
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
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="">All projects</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.scanCount} scans)
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <label htmlFor="review-scan" className="text-xs font-medium text-muted-foreground flex items-center gap-1">
                <ScanSearch className="h-3 w-3" />
                Scan
              </label>
              <select
                id="review-scan"
                value={selectedScanId}
                onChange={(e) => { setSelectedScanId(e.target.value); setSelectedFindingIds([]); }}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
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

          {mode === "source" && selectedScanId && <SourceReviewPicker key={selectedScanId} scanId={selectedScanId} selected={selectedFindingIds} onChange={setSelectedFindingIds} disabled={scanning} />}
          <label className="flex items-start gap-3 rounded-md border p-3 text-xs leading-6">
            <input type="checkbox" className="mt-1.5" checked={includeApiContracts} disabled={scanning} onChange={(event) => setIncludeApiContracts(event.target.checked)} />
            <span><span className="block font-medium">Include API contract context</span><span className="text-muted-foreground">Send bounded, matching OpenAPI/Swagger requirements to the configured AI provider for defensive review. Documentation does not prove enforcement or resolve findings automatically. Off by default.</span></span>
          </label>
          <p className="text-xs text-muted-foreground">Each review uses a fixed snapshot and at most 20 model calls. {mode === "source" ? "Source investigation supports 25 selected findings, four model turns and eight source requests per batch. Redacted source excerpts are sent to your configured provider and retained with the result. CI report uploads alone do not include full source." : "Excerpt reviews support up to 1000 findings."} Provider usage is recorded when available. Costs require provider billing confirmation. Starting another review can incur new charges.</p>
          <div className="flex items-center gap-3">
            <Button
              type="submit"
              disabled={scanning || loadingScans || !selectedScanId || !canStart || (mode === "source" && !selectedFindingIds.length)}
              className="flex items-center gap-2"
            >
              {scanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Reviewing...
                </>
              ) : (
                <>
                  <Bot className="h-4 w-4" />
                  Start {mode === "quick" ? "Quick Review" : mode === "source" ? "Source Investigation" : "Deep Analysis"}
                </>
              )}
            </Button>
            {selectedScanId && !canStart && <p className="text-xs text-muted-foreground">An active project and maintainer access are required to start reviews.</p>}
          </div>
        </CardContent>
        </form>
      </Card>

      {/* Active Job Progress */}
      {activeJob && inspectedJob && activeJob.id !== inspectedJob.id && <Button variant="outline" onClick={() => setInspectedJob(null)}>Show active review</Button>}
      {displayedJob && <AiReviewJobCard job={displayedJob} onCancel={() => void cancelReview()} cancelling={cancelling} />}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 text-sm px-3 py-2 rounded-md bg-destructive/10 text-destructive">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {displayedJob && <AiReviewHistory key={displayedJob.id} job={displayedJob} />}

      {/* Job History */}
      {jobHistory.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <History className="h-4 w-4" />
              Job History
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {jobHistory.map((job) => (
                <div
                  key={job.id}
                  data-review-job={job.id}
                  className="flex items-center gap-3 p-2.5 rounded-md border border-border text-sm"
                >
                  <div className="flex-shrink-0">
                    {job.status === "completed" ? (
                      <CheckCircle className="h-4 w-4 text-[var(--status-fixed)]" />
                    ) : isLlmJobTerminal(job.status) ? (
                      <AlertCircle className="h-4 w-4 text-destructive" />
                    ) : (
                      <Loader2 className="h-4 w-4 animate-spin text-primary" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium truncate">
                        {job.scan?.repository || job.scanId.slice(0, 8)}
                      </span>
                      <Badge variant="outline" className="text-[10px] capitalize">{job.mode}</Badge>
                      <Badge
                        variant="outline"
                        className={`text-[10px] capitalize ${
                          job.status === "completed"
                            ? "text-[var(--status-fixed)]"
                            : isLlmJobTerminal(job.status)
                            ? "text-destructive"
                            : "text-primary"
                        }`}
                      >
                        {job.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                      <span>{job.reviewedCount}/{job.totalFindings} reviewed</span>
                      {job.falsePositives > 0 && (
                        <span>{job.falsePositives} suggested FPs</span>
                      )}
                      {job.errorMessage && isLlmJobTerminal(job.status) && (
                        <span className="text-destructive truncate">{job.errorMessage}</span>
                      )}
                    </div>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => void inspectJob(job.id)}>Details</Button>
                  <div className="flex-shrink-0 text-xs text-muted-foreground flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(job.createdAt).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
