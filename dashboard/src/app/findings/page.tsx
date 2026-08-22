"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import {
  Search,
  FileCode,
  AlertTriangle,
  Bot,
  Loader2,
  CheckSquare,
  Square,
  X,
  CheckCircle,
  AlertCircle,
} from "lucide-react";

interface Finding {
  id: string;
  scanId: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: number;
  evidenceState: string;
  disposition: string;
  status: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  message: string;
  cweId: number | null;
  owaspCategory: string | null;
  llmAnalysis: string | null;
  createdAt: string;
}

interface RuleOption {
  id: string;
  name: string;
  findingCount: number;
}

interface BatchResult {
  success: boolean;
  data?: {
    analysis: string;
    remediation: string;
    riskAssessment: string;
    confidence: number;
  };
  error?: string;
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "text-[var(--severity-critical)]",
  HIGH: "text-[var(--severity-high)]",
  MEDIUM: "text-[var(--severity-medium)]",
  LOW: "text-[var(--severity-low)]",
  FALSE_POSITIVE: "text-[var(--status-fixed)]",
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [language, setLanguage] = useState("");
  const [page, setPage] = useState(1);
  const [rules, setRules] = useState<RuleOption[]>([]);
  const [languages, setLanguages] = useState<string[]>([]);
  const [projectId, setProjectId] = useState("");
  const [source, setSource] = useState("");
  const [disposition, setDisposition] = useState("");
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>([]);

  // Multi-select state
  const [selectMode, setSelectMode] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Batch analysis state
  const [batchAnalyzing, setBatchAnalyzing] = useState(false);
  const [batchProgress, setBatchProgress] = useState("");
  const [batchResults, setBatchResults] = useState<Record<string, BatchResult> | null>(null);
  const [batchSummary, setBatchSummary] = useState<{ total: number; success: number; failed: number } | null>(null);

  useEffect(() => {
    fetch("/api/rules")
      .then((r) => r.json())
      .then((data) => setRules(data.rules || []));
    fetch("/api/projects")
      .then((r) => r.json())
      .then((data) => setProjects(data.projects || []));
  }, []);

  useEffect(() => {
    fetch("/api/findings/languages")
      .then((r) => r.json())
      .then((data) => setLanguages(data.languages || []))
      .catch(() => {});
  }, []);

  const fetchFindings = useCallback(() => {
    const params = new URLSearchParams();
    params.set("page", page.toString());
    params.set("limit", "50");
    if (search) params.set("search", search);
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (ruleId) params.set("ruleId", ruleId);
    if (language) params.set("language", language);
    if (projectId) params.set("projectId", projectId);
    if (source) params.set("source", source);
    if (disposition) params.set("disposition", disposition);

    fetch(`/api/findings?${params}`)
      .then((r) => r.json())
      .then((data) => {
        setFindings(data.findings);
        setTotal(data.total);
      })
      .finally(() => setLoading(false));
  }, [page, search, severity, status, ruleId, language, projectId, source, disposition]);

  useEffect(() => {
    const timer = setTimeout(fetchFindings, 300);
    return () => clearTimeout(timer);
  }, [fetchFindings]);

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selected.size === findings.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(findings.map((f) => f.id)));
    }
  };

  const cancelSelect = () => {
    setSelectMode(false);
    setSelected(new Set());
    setBatchResults(null);
    setBatchSummary(null);
  };

  const runBatchAnalysis = async () => {
    if (selected.size === 0) return;
    setBatchAnalyzing(true);
    setBatchResults(null);
    setBatchSummary(null);
    setBatchProgress("");

    const allIds = [...selected];
    const CHUNK_SIZE = 20;
    const chunks: string[][] = [];
    for (let i = 0; i < allIds.length; i += CHUNK_SIZE) {
      chunks.push(allIds.slice(i, i + CHUNK_SIZE));
    }

    const allResults: Record<string, BatchResult> = {};
    let totalSuccess = 0;
    let totalFailed = 0;

    try {
      for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        setBatchProgress(`${i * CHUNK_SIZE + 1}-${Math.min((i + 1) * CHUNK_SIZE, allIds.length)} / ${allIds.length}`);

        try {
          const res = await fetch("/api/findings/analyze-batch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ids: chunk }),
          });
          const data = await res.json();

          if (res.ok && data.results) {
            Object.assign(allResults, data.results);
            totalSuccess += data.summary?.success || 0;
            totalFailed += data.summary?.failed || 0;

            // Update local findings incrementally
            setFindings((prev) =>
              prev.map((f) => {
                const result = data.results?.[f.id];
                if (result?.success && result.data) {
                  return { ...f, llmAnalysis: JSON.stringify(result.data) };
                }
                return f;
              })
            );
          } else {
            totalFailed += chunk.length;
            for (const id of chunk) {
              allResults[id] = { success: false, error: data.error || "Request failed" };
            }
          }
        } catch {
          totalFailed += chunk.length;
          for (const id of chunk) {
            allResults[id] = { success: false, error: "Network error" };
          }
        }

        // Update summary progressively
        setBatchSummary({ total: allIds.length, success: totalSuccess, failed: totalFailed });
      }

      setBatchResults(allResults);
      setBatchSummary({ total: allIds.length, success: totalSuccess, failed: totalFailed });
    } finally {
      setBatchAnalyzing(false);
      setBatchProgress("");
    }
  };

  const totalPages = Math.ceil(total / 50);

  const getLlmBadge = (finding: Finding) => {
    if (!finding.llmAnalysis) return null;
    try {
      const parsed = JSON.parse(finding.llmAnalysis);
      return parsed.riskAssessment as string;
    } catch {
      return null;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Findings</h1>
        <p className="text-muted-foreground">All security findings across scans</p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by message, file, or rule..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>
        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm"
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="triaged">Triaged</option>
          <option value="false_positive">False Positive</option>
          <option value="fixed">Fixed</option>
        </select>
        <select
          value={ruleId}
          onChange={(e) => {
            setRuleId(e.target.value);
            setPage(1);
          }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm max-w-[200px]"
        >
          <option value="">All rules</option>
          {rules.map((r) => (
            <option key={r.id} value={r.id}>
              {r.id} ({r.findingCount})
            </option>
          ))}
        </select>
        <select
          value={language}
          onChange={(e) => {
            setLanguage(e.target.value);
            setPage(1);
          }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm"
        >
          <option value="">All languages</option>
          {languages.map((lang) => (
            <option key={lang} value={lang}>
              {lang}
            </option>
          ))}
        </select>
        <select
          value={projectId}
          onChange={(e) => {
            setProjectId(e.target.value);
            setPage(1);
          }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm max-w-[180px]"
        >
          <option value="">All projects</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <select
          value={source}
          onChange={(e) => {
            setSource(e.target.value);
            setPage(1);
          }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm"
        >
          <option value="">All sources</option>
          <option value="sast">SAST</option>
          <option value="llm">LLM</option>
        </select>
        <select
          value={disposition}
          onChange={(e) => {
            setDisposition(e.target.value);
            setPage(1);
          }}
          className="h-9 rounded-md border border-input bg-background px-3 text-sm"
        >
          <option value="">All gates</option>
          <option value="blocking">Blocking</option>
          <option value="advisory">Advisory</option>
        </select>
      </div>

      {/* Batch analysis summary */}
      {batchSummary && (
        <div
          className={`flex items-center gap-2 text-sm px-4 py-3 rounded-md ${
            batchSummary.failed === 0
              ? "bg-[var(--status-fixed-bg)] text-[var(--status-fixed)]"
              : batchSummary.success === 0
                ? "bg-[var(--status-open-bg)] text-[var(--status-open)]"
                : "bg-[var(--status-triaged-bg)] text-[var(--status-triaged)]"
          }`}
        >
          {batchSummary.failed === 0 ? (
            <CheckCircle className="h-4 w-4" />
          ) : (
            <AlertCircle className="h-4 w-4" />
          )}
          {batchAnalyzing ? "Analyzing" : "Batch analysis complete"}: {batchSummary.success}/{batchSummary.total} succeeded
          {batchSummary.failed > 0 && `, ${batchSummary.failed} failed`}
        </div>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              {total} findings
            </CardTitle>
            <div className="flex items-center gap-2">
              {selectMode ? (
                <>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={selectAll}
                  >
                    {selected.size === findings.length ? "Deselect All" : "Select All"}
                  </Button>
                  <Button
                    variant="default"
                    size="sm"
                    onClick={runBatchAnalysis}
                    disabled={selected.size === 0 || batchAnalyzing}
                  >
                    {batchAnalyzing ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                    ) : (
                      <Bot className="h-4 w-4 mr-1" />
                    )}
                    {batchProgress ? `Analyzing ${batchProgress}` : `Analyze ${selected.size > 0 ? `(${selected.size})` : ""}`}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={cancelSelect}>
                    <X className="h-4 w-4" />
                  </Button>
                </>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSelectMode(true)}
                >
                  <Bot className="h-4 w-4 mr-1" />
                  Batch Analyze
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-pulse text-muted-foreground">Loading...</div>
            </div>
          ) : findings.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              No findings match your filters
            </div>
          ) : (
            <div className="space-y-2">
              {findings.map((finding) => {
                const isSelected = selected.has(finding.id);
                const llmRisk = getLlmBadge(finding);
                const batchResult = batchResults?.[finding.id];

                return (
                  <div
                    key={finding.id}
                    className={`flex items-start gap-3 p-3 rounded-md border transition-colors ${
                      isSelected
                        ? "border-primary bg-primary/5"
                        : "border-border hover:bg-accent/30"
                    }`}
                  >
                    {selectMode && (
                      <button
                        onClick={() => toggleSelect(finding.id)}
                        className="mt-1 shrink-0 text-muted-foreground hover:text-foreground"
                      >
                        {isSelected ? (
                          <CheckSquare className="h-4 w-4 text-primary" />
                        ) : (
                          <Square className="h-4 w-4" />
                        )}
                      </button>
                    )}
                    <Link
                      href={`/findings/${finding.id}`}
                      className="flex-1 min-w-0"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <SeverityBadge severity={finding.severity} />
                            <StatusBadge status={finding.status} />
                            <span
                              className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                                finding.disposition === "advisory"
                                  ? "bg-amber-500/10 text-amber-600"
                                  : "bg-red-500/10 text-red-600"
                              }`}
                            >
                              {finding.disposition}
                            </span>
                            <span className="text-[10px] uppercase text-muted-foreground">
                              {finding.evidenceState}
                            </span>
                            <span className="text-xs font-mono text-muted-foreground">
                              {finding.ruleId}
                            </span>
                            {finding.cweId && (
                              <span className="text-xs text-muted-foreground">
                                CWE-{finding.cweId}
                              </span>
                            )}
                            {finding.owaspCategory && (
                              <span className="text-xs text-muted-foreground">
                                {finding.owaspCategory}
                              </span>
                            )}
                            {llmRisk && (
                              <span
                                className={`text-xs font-bold flex items-center gap-1 ${
                                  RISK_COLORS[llmRisk] || "text-muted-foreground"
                                }`}
                              >
                                <Bot className="h-3 w-3" />
                                {llmRisk}
                              </span>
                            )}
                            {batchResult && !batchResult.success && (
                              <span className="text-xs text-[var(--status-open)] flex items-center gap-1">
                                <AlertCircle className="h-3 w-3" />
                                Failed
                              </span>
                            )}
                          </div>
                          <p className="text-sm truncate">{finding.message}</p>
                          <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                            <FileCode className="h-3 w-3" />
                            <span className="font-mono">
                              {finding.filePath}:{finding.lineStart}
                            </span>
                          </div>
                        </div>
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {(finding.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </Link>
                  </div>
                );
              })}
            </div>
          )}

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 mt-6">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 rounded-md border text-sm disabled:opacity-50"
              >
                Previous
              </button>
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="px-3 py-1 rounded-md border text-sm disabled:opacity-50"
              >
                Next
              </button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
