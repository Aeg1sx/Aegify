"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { isLlmJobTerminal } from "@/lib/llm-job-state";
import { AiReviewJobCard, type AiReviewJob } from "@/components/ai-review-job-card";
import {
  Bot,
  Zap,
  Search,
  Loader2,
  CheckCircle,
  AlertCircle,
  FolderKanban,
  ScanSearch,
  ShieldCheck,
  ShieldAlert,
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

interface ScanResult {
  scan: {
    id: string;
    scanType: string;
    status: string;
    filesScanned: number;
    createdAt: string;
  };
  findings: Array<{
    id: string;
    ruleId: string;
    ruleName: string;
    severity: string;
    status: string;
    message: string;
    filePath: string;
    lineStart: number;
    confidence: number;
    remediation: string | null;
    llmAnalysis: string | null;
  }>;
  summary: {
    total: number;
    bySeverity: Record<string, number>;
  };
}

interface LLMAnalysis {
  jobId?: string;
  verdict?: "likely_true_positive" | "likely_false_positive" | "needs_review";
  isFalsePositive: boolean;
  confidence: number;
  reasoning: string;
  remediation: string;
  adjustedSeverity?: string;
}

type LlmJob = AiReviewJob;

export default function LLMScanPage() {
  const [mode, setMode] = useState<"quick" | "deep">("quick");
  const [includeApiContracts, setIncludeApiContracts] = useState(false);
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<ScanOption[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanning, setScanning] = useState(false);
  const [activeJob, setActiveJob] = useState<LlmJob | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [jobHistory, setJobHistory] = useState<LlmJob[]>([]);
  const [inspectedJob, setInspectedJob] = useState<LlmJob | null>(null);
  const [resultJob, setResultJob] = useState<LlmJob | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [workerReady, setWorkerReady] = useState<boolean | null>(null);
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
    if (!activeJob) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/llm-jobs/${activeJob.id}`);
        if (!res.ok) { setError("Review status is unavailable; check your project access."); setActiveJob(null); setScanning(false); return; }
        const job: LlmJob = await res.json();

        setActiveJob(job);

        if (isLlmJobTerminal(job.status)) {
          setScanning(false);
          setActiveJob(null);
          setInspectedJob(job);
          fetchHistory();

          if (job.status === "completed" || job.status === "partial") {
            const scanRes = await fetch(`/api/llm-scan/${job.scanId}`);
            const scanData = await scanRes.json();
            setResult(scanData);
            setResultJob(job);
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

    return () => clearInterval(interval);
  }, [activeJob, fetchHistory]);

  const startReview = async () => {
    if (scanning || loadingScans || !selectedScanId || !canStart) return;

    setScanning(true);
    setResult(null);
    setResultJob(null);
    setInspectedJob(null);
    setError(null);

    try {
      const res = await fetch("/api/llm-jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId: selectedScanId, mode, includeApiContracts }),
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
    try {
      const response = await fetch(`/api/llm-jobs/${id}`);
      if (!response.ok) throw new Error("Could not load this review.");
      const job: LlmJob = await response.json(); setInspectedJob(job);
      if (!isLlmJobTerminal(job.status)) { setActiveJob(job); setScanning(true); }
      else if (job.reviewedCount) {
        const findings = await fetch(`/api/llm-scan/${job.scanId}`);
        if (!findings.ok) throw new Error("Could not load review findings.");
        setResult(await findings.json()); setResultJob(job);
      } else { setResult(null); setResultJob(null); }
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Could not load review."); }
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

  const parseLLMAnalysis = (raw: string | null): LLMAnalysis | null => {
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  };

  const reviewedFindings = result?.findings.filter((f) => f.llmAnalysis && (!resultJob?.contractVersion || parseLLMAnalysis(f.llmAnalysis)?.jobId === resultJob.id)) || [];
  const falsePositives = reviewedFindings.filter((f) => {
    const a = parseLLMAnalysis(f.llmAnalysis);
    return a?.verdict === "likely_false_positive" ||
      (!a?.verdict && a?.isFalsePositive === true);
  });
  const truePositives = reviewedFindings.filter((f) => {
    const a = parseLLMAnalysis(f.llmAnalysis);
    return a?.verdict === "likely_true_positive";
  });

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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                onChange={(e) => setSelectedScanId(e.target.value)}
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

          <label className="flex items-start gap-3 rounded-md border p-3 text-xs leading-6">
            <input type="checkbox" className="mt-1.5" checked={includeApiContracts} disabled={scanning} onChange={(event) => setIncludeApiContracts(event.target.checked)} />
            <span><span className="block font-medium">Include API contract context</span><span className="text-muted-foreground">Send bounded, matching OpenAPI/Swagger requirements to the configured AI provider for defensive review. Documentation does not prove enforcement or resolve findings automatically. Off by default.</span></span>
          </label>
          <p className="text-xs text-muted-foreground">Each review sends a fixed snapshot to the configured provider: at most 20 calls and 1000 findings. Provider usage is recorded when available. Costs require provider billing confirmation. Starting another review can incur new charges.</p>
          <div className="flex items-center gap-3">
            <Button
              type="submit"
              disabled={scanning || loadingScans || !selectedScanId || !canStart}
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
                  Start {mode === "quick" ? "Quick Review" : "Deep Analysis"}
                </>
              )}
            </Button>
            {selectedScanId && !canStart && <p className="text-xs text-muted-foreground">An active project and maintainer access are required to start reviews.</p>}
          </div>
        </CardContent>
        </form>
      </Card>

      {/* Active Job Progress */}
      {(activeJob || inspectedJob) && <AiReviewJobCard job={(activeJob || inspectedJob)!} onCancel={() => void cancelReview()} cancelling={cancelling} />}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 text-sm px-3 py-2 rounded-md bg-destructive/10 text-destructive">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Summary */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                {result.scan.status === "completed" ? (
                  <CheckCircle className="h-4 w-4 text-[var(--status-fixed)]" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-[var(--status-open)]" />
                )}
                Review Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
                <div>
                  <p className="text-xs text-muted-foreground">Source Scan</p>
                  <p className="text-sm font-medium capitalize">{result.scan.status}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Total Findings</p>
                  <p className="text-sm font-medium">{result.summary.total}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Reviewed</p>
                  <p className="text-sm font-medium">{reviewedFindings.length}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <ShieldCheck className="h-3 w-3" /> Suggested FPs
                  </p>
                  <p className="text-sm font-medium text-[var(--status-false-positive)]">
                    {falsePositives.length}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <ShieldAlert className="h-3 w-3" /> Suggested TPs
                  </p>
                  <p className="text-sm font-medium text-[var(--status-open)]">
                    {truePositives.length}
                  </p>
                </div>
              </div>

              {/* Severity breakdown */}
              {result.summary.total > 0 && (
                <div className="flex items-center gap-3 text-xs">
                  {Object.entries(result.summary.bySeverity).map(([sev, count]) => (
                    <div key={sev} className="flex items-center gap-1">
                      <SeverityBadge severity={sev} />
                      <span className="text-muted-foreground">{count}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Reviewed findings */}
          {reviewedFindings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">
                  Reviewed Findings ({reviewedFindings.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {reviewedFindings.map((f) => {
                  const analysis = parseLLMAnalysis(f.llmAnalysis);
                  return (
                    <Link
                      key={f.id}
                      href={`/findings/${f.id}`}
                      className="block p-3 rounded-md border border-border hover:bg-accent/30 transition-colors"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={f.severity} />
                        <StatusBadge status={f.status} />
                        {(analysis?.verdict === "likely_false_positive" ||
                          (!analysis?.verdict && analysis?.isFalsePositive)) && (
                          <Badge variant="outline" className="text-xs bg-[var(--status-false-positive-bg)] text-[var(--status-false-positive)]">
                            FP
                          </Badge>
                        )}
                        <span className="text-xs font-mono text-muted-foreground">
                          {f.ruleId}
                        </span>
                        <span className="text-xs text-muted-foreground ml-auto">
                          {analysis ? `${(analysis.confidence * 100).toFixed(0)}% model estimate` : ""}
                        </span>
                      </div>
                      <p className="text-sm font-medium mb-1">{f.ruleName}</p>
                      {analysis?.reasoning && (
                        <p className="text-xs text-muted-foreground line-clamp-2 mb-1">
                          {analysis.reasoning}
                        </p>
                      )}
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <span className="font-mono">{f.filePath}:{f.lineStart}</span>
                      </div>
                      {analysis?.remediation &&
                        analysis.verdict !== "likely_false_positive" &&
                        !(!analysis.verdict && analysis.isFalsePositive) && (
                        <p className="text-xs mt-2 text-[var(--status-fixed)] line-clamp-2">
                          Fix: {analysis.remediation}
                        </p>
                      )}
                    </Link>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {/* Unreviewed findings */}
          {result.findings.length > reviewedFindings.length && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm text-muted-foreground">
                  Unreviewed Findings ({result.findings.length - reviewedFindings.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  {result.findings.length - reviewedFindings.length} findings have no current suggestion from this job. Suggestions from other jobs and accepted decisions are not counted here. Inspect the call history before starting another paid review.
                </p>
              </CardContent>
            </Card>
          )}

          {result.findings.length === 0 && result.scan.status === "completed" && (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
              <CheckCircle className="h-10 w-10 mb-3 text-[var(--status-fixed)]" />
              <p className="font-medium">No findings in this scan</p>
              <p className="text-xs mt-1">Select a scan with findings to review.</p>
            </div>
          )}
        </div>
      )}

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
