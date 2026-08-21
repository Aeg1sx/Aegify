"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
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
}

interface ScanOption {
  id: string;
  repository: string;
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
  isFalsePositive: boolean;
  confidence: number;
  reasoning: string;
  remediation: string;
  adjustedSeverity?: string;
}

interface LlmJob {
  id: string;
  scanId: string;
  mode: string;
  status: string;
  totalFindings: number;
  reviewedCount: number;
  falsePositives: number;
  currentBatch: number;
  totalBatches: number;
  errorMessage: string;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  scan: { id: string; repository: string; branch: string };
}

export default function LLMScanPage() {
  const [mode, setMode] = useState<"quick" | "deep">("quick");
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

  // Fetch projects
  useEffect(() => {
    fetch("/api/projects")
      .then((r) => r.json())
      .then((data) => setProjects(data.projects || []))
      .catch(() => {});
  }, []);

  // Fetch scans when project changes
  useEffect(() => {
    const url = selectedProjectId
      ? `/api/scans?projectId=${selectedProjectId}&limit=50`
      : "/api/scans?limit=50";
    fetch(url)
      .then((r) => r.json())
      .then((data) => {
        const scanList = (data.scans || []).filter(
          (s: ScanOption) => s.status === "completed" && s._count.findings > 0
        );
        setScans(scanList);
      })
      .catch(() => {})
      .finally(() => setLoadingScans(false));
  }, [selectedProjectId]);

  // Fetch job history
  const fetchHistory = useCallback(() => {
    fetch("/api/llm-jobs?limit=10")
      .then((r) => r.json())
      .then((data) => setJobHistory(data.jobs || []))
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
        const job: LlmJob = await res.json();

        setActiveJob(job);

        if (job.status === "completed" || job.status === "failed") {
          setScanning(false);
          setActiveJob(null);
          fetchHistory();

          // Fetch final results for display
          if (job.status === "completed") {
            const scanRes = await fetch(`/api/llm-scan/${job.scanId}`);
            const scanData = await scanRes.json();
            setResult(scanData);
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
    if (!selectedScanId) return;

    setScanning(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch("/api/llm-jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId: selectedScanId, mode }),
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

  const parseLLMAnalysis = (raw: string | null): LLMAnalysis | null => {
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  };

  const reviewedFindings = result?.findings.filter((f) => f.llmAnalysis) || [];
  const falsePositives = reviewedFindings.filter((f) => {
    const a = parseLLMAnalysis(f.llmAnalysis);
    return a?.isFalsePositive;
  });
  const truePositives = reviewedFindings.filter((f) => {
    const a = parseLLMAnalysis(f.llmAnalysis);
    return a && !a.isFalsePositive;
  });

  const jobPercent =
    activeJob && activeJob.totalFindings > 0
      ? Math.round((activeJob.reviewedCount / activeJob.totalFindings) * 100)
      : 0;

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold">LLM Security Review</h1>
        <p className="text-muted-foreground">
          AI-powered review of existing scan findings for false positive detection and remediation guidance
        </p>
      </div>

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
            Uses call graph context for cross-function analysis. Can discover additional vulnerabilities missed by SAST.
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
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground flex items-center gap-1">
                <FolderKanban className="h-3 w-3" />
                Project (optional)
              </label>
              <select
                value={selectedProjectId}
                onChange={(e) => {
                  setSelectedProjectId(e.target.value);
                  setSelectedScanId("");
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
              <label className="text-xs font-medium text-muted-foreground flex items-center gap-1">
                <ScanSearch className="h-3 w-3" />
                Scan
              </label>
              <select
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

          <div className="flex items-center gap-3">
            <Button
              onClick={startReview}
              disabled={scanning || !selectedScanId}
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
          </div>
        </CardContent>
      </Card>

      {/* Active Job Progress */}
      {activeJob && (
        <Card className="border-primary/30">
          <CardContent className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
                Reviewing {activeJob.scan?.repository || "scan"}
                <Badge variant="outline" className="text-xs capitalize">{activeJob.mode}</Badge>
              </div>
              <span className="text-sm font-mono text-muted-foreground">{jobPercent}%</span>
            </div>
            <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all duration-500"
                style={{ width: `${Math.max(jobPercent, 2)}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>
                Batch {activeJob.currentBatch}/{activeJob.totalBatches} — {activeJob.reviewedCount}/{activeJob.totalFindings} findings
              </span>
              <span className="capitalize">{activeJob.status}</span>
            </div>
          </CardContent>
        </Card>
      )}

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
                  <p className="text-xs text-muted-foreground">Status</p>
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
                    <ShieldCheck className="h-3 w-3" /> False Positives
                  </p>
                  <p className="text-sm font-medium text-[var(--status-false-positive)]">
                    {falsePositives.length}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <ShieldAlert className="h-3 w-3" /> True Positives
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
                        {analysis?.isFalsePositive && (
                          <Badge variant="outline" className="text-xs bg-[var(--status-false-positive-bg)] text-[var(--status-false-positive)]">
                            FP
                          </Badge>
                        )}
                        <span className="text-xs font-mono text-muted-foreground">
                          {f.ruleId}
                        </span>
                        <span className="text-xs text-muted-foreground ml-auto">
                          {analysis ? `${(analysis.confidence * 100).toFixed(0)}% confidence` : ""}
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
                      {analysis?.remediation && !analysis.isFalsePositive && (
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
                  {result.findings.length - reviewedFindings.length} findings were not reviewed by the LLM. Run the review again to cover more findings.
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
                    ) : job.status === "failed" ? (
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
                            : job.status === "failed"
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
                        <span>{job.falsePositives} FPs</span>
                      )}
                      {job.errorMessage && job.status === "failed" && (
                        <span className="text-destructive truncate">{job.errorMessage}</span>
                      )}
                    </div>
                  </div>
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
