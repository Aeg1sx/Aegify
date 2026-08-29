"use client";

import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import dynamic from "next/dynamic";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Separator } from "@/components/ui/separator";
import {
  ArrowLeft,
  FileCode,
  GitBranch,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Bot,
  Loader2,
  AlertCircle,
  Network,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Focus,
  Search,
} from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { AIEvidencePanel, type AIReviewView } from "@/components/finding/ai-evidence-panel";
import {
  FindingLifecyclePanel,
  type FindingIdentityView,
} from "@/components/finding/finding-lifecycle-panel";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
});

interface TaintStep {
  file: string;
  line: number;
  message: string;
}

interface BatchReviewAnalysis {
  isFalsePositive: boolean;
  confidence: number;
  reasoning: string;
  remediation: string;
  adjustedSeverity?: string;
  mode?: string;
  reviewedAt?: string;
}

interface GraphNode {
  id: string;
  qualifiedName: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  nodeType: string;
  hasFinding: boolean;
  findingSeverity: string | null;
  isFindingNode?: boolean;
  x?: number;
  y?: number;
}

interface GraphEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  callSiteLine: number;
}

interface FindingDetail {
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
  codeSnippet: string;
  message: string;
  cweId: number | null;
  owaspCategory: string | null;
  taintFlow: string | null;
  callChain: string | null;
  remediation: string | null;
  llmAnalysis: string | null;
  evidenceId: string;
  repositoryId: string;
  modulePath: string;
  provenance: string;
  fingerprint: string;
  baselineState: string;
  aiVerdict: string;
  aiConfidence: number | null;
  aiReviewStatus: string;
  aiProof: string;
  createdAt: string;
  identity: FindingIdentityView | null;
  scan: {
    id: string;
    repository: string;
    branch: string;
    commitSha: string;
    workspaceSnapshot: string;
  };
}

interface EvidenceProvenance {
  producer?: string;
  producer_version?: string;
  analysis_kind?: string;
  fidelity?: string;
  rule_digest?: string;
}

const NODE_COLORS: Record<string, string> = {
  entry_point: "#22c55e",
  sink: "#ef4444",
  module: "#6366f1",
  function: "#64748b",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#2563eb",
};

function normalizeAIReview(value: Record<string, unknown>): AIReviewView {
  const proof = value.proof && typeof value.proof === "object"
    ? value.proof as Record<string, unknown> : {};
  const stringArray = (item: unknown) => Array.isArray(item)
    ? item.filter((entry): entry is string => typeof entry === "string") : [];
  const rawVerdict = String(value.verdict || "needs_review");
  const verdict = ["likely_true_positive", "likely_false_positive", "needs_review"].includes(rawVerdict)
    ? rawVerdict as AIReviewView["verdict"] : "needs_review";
  const rawConfidence = typeof value.confidence === "number" && Number.isFinite(value.confidence)
    ? value.confidence : 0;
  return {
    verdict,
    analysis: typeof value.analysis === "string" ? value.analysis : String(value.reasoning || ""),
    remediation: typeof value.remediation === "string"
      ? value.remediation : String(value.remediation_summary || ""),
    riskAssessment: typeof value.riskAssessment === "string"
      ? value.riskAssessment : String(value.risk_assessment || ""),
    confidence: Math.max(0, Math.min(rawConfidence, 1)),
    evidenceFor: stringArray(value.evidenceFor ?? value.evidence_for),
    evidenceAgainst: stringArray(value.evidenceAgainst ?? value.evidence_against),
    evidenceGaps: stringArray(value.evidenceGaps ?? value.evidence_gaps),
    attackScenario: typeof value.attackScenario === "string" ? value.attackScenario : String(value.attack_scenario || ""),
    fixedCode: typeof value.fixedCode === "string" ? value.fixedCode : String(value.fixed_code || ""),
    remediationSteps: stringArray(value.remediationSteps ?? value.remediation_steps),
    proof: {
      safety: String(proof.safety || "owned_fixture_only"),
      requiresApproval: true,
      preconditions: stringArray(proof.preconditions),
      requestTemplate: String(proof.requestTemplate ?? proof.request_template ?? ""),
      payloadTemplate: String(proof.payloadTemplate ?? proof.payload_template ?? ""),
      expectedSignal: String(proof.expectedSignal ?? proof.expected_signal ?? ""),
      negativeControl: String(proof.negativeControl ?? proof.negative_control ?? ""),
      harnessPlan: proof.harnessPlan && typeof proof.harnessPlan === "object"
        ? proof.harnessPlan as Record<string, unknown> : {},
    },
  };
}

export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [showTaintFlow, setShowTaintFlow] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [triageReason, setTriageReason] = useState("");
  const [triageExpiresAt, setTriageExpiresAt] = useState("");
  const [triageError, setTriageError] = useState("");

  // LLM analysis state
  const [analyzing, setAnalyzing] = useState(false);
  const [llmResult, setLlmResult] = useState<AIReviewView | null>(null);
  const [batchResult, setBatchResult] = useState<BatchReviewAnalysis | null>(null);
  const [llmError, setLlmError] = useState<string | null>(null);
  const [analysisLang, setAnalysisLang] = useState("en");

  // Per-finding call graph state
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [graphCapped, setGraphCapped] = useState(false);
  const [showGraph, setShowGraph] = useState(false);
  const [graphLoading, setGraphLoading] = useState(false);
  const [selectedGraphNode, setSelectedGraphNode] = useState<GraphNode | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [graphQuery, setGraphQuery] = useState("");
  const [graphType, setGraphType] = useState("all");
  const [focusEvidencePath, setFocusEvidencePath] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 600, height: 500 });

  useEffect(() => {
    fetch(`/api/findings/${params.id}`)
      .then((r) => r.json())
      .then((data) => {
        setFinding(data);
        setTriageReason(data.identity?.triageReason || "");
        setTriageExpiresAt(data.identity?.triageExpiresAt?.slice(0, 10) || "");
        // Load saved LLM analysis (two possible formats)
        if (data.llmAnalysis) {
          try {
            const parsed = JSON.parse(data.llmAnalysis);
            if (parsed && typeof parsed === "object" && (
              parsed.analysis || parsed.reasoning || parsed.verdict || parsed.proof
            )) {
              // Structured evidence-bound review format
              setLlmResult(normalizeAIReview(parsed));
            } else if (parsed && typeof parsed === "object" && "isFalsePositive" in parsed) {
              // Batch review format
              setBatchResult(parsed);
            }
          } catch {
            // ignore
          }
        }
      })
      .finally(() => setLoading(false));
  }, [params.id]);

  // Observe container size for graph
  useEffect(() => {
    if (!containerRef.current) return;
    const obs = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setDimensions({
          width: entry.contentRect.width,
          height: 500,
        });
      }
    });
    obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, [showGraph]);

  const updateStatus = async (newStatus: string) => {
    if (!finding) return;
    setUpdating(true);
    setTriageError("");
    try {
      const res = await fetch(`/api/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: newStatus,
          reason: triageReason,
          expiresAt: triageExpiresAt || null,
        }),
      });
      if (res.ok) {
        const refreshed = await fetch(`/api/findings/${finding.id}`).then((response) => response.json());
        setFinding(refreshed);
      } else {
        const error = await res.json();
        setTriageError(error.error || "Triage update failed");
      }
    } catch (error) {
      setTriageError(error instanceof Error ? error.message : "Triage update failed");
    } finally {
      setUpdating(false);
    }
  };

  const runAnalysis = async () => {
    if (!finding) return;
    setAnalyzing(true);
    setLlmError(null);
    try {
      const res = await fetch(`/api/findings/${finding.id}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ language: analysisLang }),
      });
      const data = await res.json();
      if (!res.ok) {
        setLlmError(data.error || "Analysis failed");
        return;
      }
      setLlmResult(normalizeAIReview(data));
    } catch (err) {
      setLlmError(err instanceof Error ? err.message : "Network error");
    } finally {
      setAnalyzing(false);
    }
  };

  const loadGraph = async () => {
    if (!finding) return;
    setGraphLoading(true);
    try {
      const res = await fetch(`/api/findings/${finding.id}/graph`);
      const data = await res.json();
      setGraphNodes(data.nodes || []);
      setGraphEdges(data.edges || []);
      setGraphCapped(!!data.capped);
      setShowGraph(true);
    } finally {
      setGraphLoading(false);
    }
  };

  const graphData = useMemo(() => {
    if (graphNodes.length === 0) return { nodes: [], links: [] };
    const query = graphQuery.trim().toLowerCase();
    const findingNodeId = graphNodes.find((node) => node.isFindingNode)?.id;
    const pathNeighbors = new Set<string>();
    if (findingNodeId) {
      for (const edge of graphEdges) {
        if (edge.sourceNodeId === findingNodeId) pathNeighbors.add(edge.targetNodeId);
        if (edge.targetNodeId === findingNodeId) pathNeighbors.add(edge.sourceNodeId);
      }
    }
    const visibleNodes = graphNodes.filter((node) => {
      if (graphType !== "all" && node.nodeType !== graphType) return false;
      if (query && !`${node.qualifiedName} ${node.filePath}`.toLowerCase().includes(query)) return false;
      if (focusEvidencePath && !(
        node.isFindingNode || node.nodeType === "entry_point" || node.nodeType === "sink" ||
        pathNeighbors.has(node.id)
      )) return false;
      return true;
    });
    const visibleIds = new Set(visibleNodes.map((node) => node.id));
    return {
      nodes: visibleNodes.map((n) => ({ ...n })),
      links: graphEdges.filter((edge) =>
        visibleIds.has(edge.sourceNodeId) && visibleIds.has(edge.targetNodeId)
      ).map((e) => ({
        source: e.sourceNodeId,
        target: e.targetNodeId,
        callSiteLine: e.callSiteLine,
      })),
    };
  }, [graphNodes, graphEdges, graphQuery, graphType, focusEvidencePath]);

  // Adaptive physics: more spacing for small graphs, tighter for large
  const graphPhysics = useMemo(() => {
    const n = graphNodes.length;
    if (n <= 10) {
      return { charge: -500, linkDist: 160, alphaDecay: 0.015, velocityDecay: 0.2 };
    }
    if (n <= 25) {
      return { charge: -350, linkDist: 130, alphaDecay: 0.02, velocityDecay: 0.25 };
    }
    if (n <= 60) {
      return { charge: -220, linkDist: 100, alphaDecay: 0.03, velocityDecay: 0.3 };
    }
    if (n <= 150) {
      return { charge: -140, linkDist: 70, alphaDecay: 0.04, velocityDecay: 0.35 };
    }
    return { charge: -80, linkDist: 50, alphaDecay: 0.06, velocityDecay: 0.4 };
  }, [graphNodes.length]);

  // Set of node IDs directly connected to the finding node
  const findingNeighborIds = useMemo(() => {
    const findingNode = graphNodes.find((n) => n.isFindingNode);
    if (!findingNode) return new Set<string>();
    const neighbors = new Set<string>();
    for (const e of graphEdges) {
      if (e.sourceNodeId === findingNode.id) neighbors.add(e.targetNodeId);
      if (e.targetNodeId === findingNode.id) neighbors.add(e.sourceNodeId);
    }
    return neighbors;
  }, [graphNodes, graphEdges]);

  // Apply d3 force configuration when physics or graph data changes
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = fg as any;
    if (g.d3Force) {
      const charge = g.d3Force("charge");
      if (charge?.strength) charge.strength(graphPhysics.charge);
      const link = g.d3Force("link");
      if (link?.distance) link.distance(graphPhysics.linkDist);
      g.d3ReheatSimulation?.();
    }
  }, [graphPhysics]);

  const getNodeLabel = useCallback((qualifiedName: string): string => {
    // Module names: <module:path/to/file.py> → file.py
    const moduleMatch = qualifiedName.match(/^<module:(.+)>$/);
    if (moduleMatch) {
      const parts = moduleMatch[1].split("/");
      return parts[parts.length - 1];
    }
    // Anonymous functions
    if (qualifiedName === "<anonymous>") return "(anonymous)";
    // Class.method or simple names - keep last 2 parts
    const parts = qualifiedName.split(".");
    if (parts.length <= 2) return qualifiedName;
    return parts.slice(-2).join(".");
  }, []);

  const nodeCanvasObject = useCallback(
    (node: GraphNode & { x?: number; y?: number }, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      const isHovered = node.id === hoveredNodeId;
      const isNeighbor = findingNeighborIds.has(node.id);
      const isEntryPoint = node.nodeType === "entry_point";

      // Tiered node sizes: finding > entry/neighbor > regular
      let r: number;
      if (node.isFindingNode) r = 12;
      else if (isEntryPoint || isHovered) r = 8;
      else if (isNeighbor) r = 7;
      else r = 5;

      // Node color
      let color = NODE_COLORS[node.nodeType] || NODE_COLORS.function;
      if (node.isFindingNode) {
        color = SEVERITY_COLORS[finding?.severity || ""] || "#ef4444";
      } else if (node.hasFinding && node.findingSeverity) {
        color = SEVERITY_COLORS[node.findingSeverity] || color;
      }

      // Dim distant nodes when not zoomed in
      const isImportant = node.isFindingNode || isEntryPoint || isNeighbor || isHovered;
      const nodeAlpha = isImportant ? 1.0 : 0.55;

      ctx.globalAlpha = nodeAlpha;

      // Draw glow ring for finding node
      if (node.isFindingNode) {
        ctx.beginPath();
        ctx.arc(x, y, r + 4, 0, 2 * Math.PI);
        ctx.strokeStyle = color;
        ctx.lineWidth = 2.5;
        ctx.setLineDash([3, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      // Hover highlight ring
      if (isHovered && !node.isFindingNode) {
        ctx.beginPath();
        ctx.arc(x, y, r + 3, 0, 2 * Math.PI);
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Draw node shape
      if (node.nodeType === "module") {
        const s = r * 0.85;
        ctx.fillStyle = color;
        ctx.fillRect(x - s, y - s, s * 2, s * 2);
      } else {
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
      }

      ctx.globalAlpha = 1.0;

      // --- Label logic: smart visibility based on zoom & importance ---
      // Tiers: finding always, hovered always, neighbors at medium zoom, all at high zoom
      const showLabel =
        node.isFindingNode ||
        isHovered ||
        (isNeighbor && globalScale > 0.8) ||
        (isEntryPoint && globalScale > 0.8) ||
        globalScale > 2.0;

      if (!showLabel) return;

      let label = getNodeLabel(node.qualifiedName);
      // Truncate long labels (except hovered / finding)
      const maxLen = (isHovered || node.isFindingNode) ? 30 : 18;
      if (label.length > maxLen) label = label.slice(0, maxLen - 1) + "\u2026";

      // Font size in graph-space, clamped for readability
      const baseFontSize = node.isFindingNode ? 4.5 : isHovered ? 4 : 3.5;
      const screenPx = baseFontSize * globalScale;
      const clampedPx = Math.min(16, Math.max(7, screenPx));
      const fontSize = clampedPx / globalScale;

      const fontWeight = node.isFindingNode || isHovered ? "bold" : "normal";
      ctx.font = `${fontWeight} ${fontSize}px monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";

      const textY = y + r + 2;
      const textMetrics = ctx.measureText(label);
      const textW = textMetrics.width;
      const textH = fontSize;
      const padX = 2;
      const padY = 1;

      // Background pill for readability
      const isDark = document.documentElement.classList.contains("dark");
      ctx.fillStyle = isDark ? "rgba(15, 23, 42, 0.75)" : "rgba(255, 255, 255, 0.8)";
      const pillX = x - textW / 2 - padX;
      const pillW = textW + padX * 2;
      const pillH = textH + padY * 2;
      const pillY = textY - padY;
      const cr = Math.min((pillH) / 2, 3);
      ctx.beginPath();
      ctx.moveTo(pillX + cr, pillY);
      ctx.lineTo(pillX + pillW - cr, pillY);
      ctx.arcTo(pillX + pillW, pillY, pillX + pillW, pillY + cr, cr);
      ctx.lineTo(pillX + pillW, pillY + pillH - cr);
      ctx.arcTo(pillX + pillW, pillY + pillH, pillX + pillW - cr, pillY + pillH, cr);
      ctx.lineTo(pillX + cr, pillY + pillH);
      ctx.arcTo(pillX, pillY + pillH, pillX, pillY + pillH - cr, cr);
      ctx.lineTo(pillX, pillY + cr);
      ctx.arcTo(pillX, pillY, pillX + cr, pillY, cr);
      ctx.closePath();
      ctx.fill();

      // Label fade for non-important nodes
      const labelAlpha = (node.isFindingNode || isHovered) ? 0.95 : isNeighbor ? 0.85 : 0.7;
      ctx.fillStyle = isDark
        ? `rgba(226, 232, 240, ${labelAlpha})`
        : `rgba(30, 41, 59, ${labelAlpha})`;
      ctx.fillText(label, x, textY);
    },
    [finding?.severity, getNodeLabel, hoveredNodeId, findingNeighborIds]
  );

  const nodePointerAreaPaint = useCallback(
    (node: GraphNode & { x?: number; y?: number }, color: string, ctx: CanvasRenderingContext2D) => {
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      const r = node.isFindingNode ? 14 : 10;
      ctx.beginPath();
      ctx.arc(x, y, r, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
    },
    []
  );

  if (loading || !finding) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  let taintSteps: TaintStep[] = [];
  try {
    const parsed = finding.taintFlow ? JSON.parse(finding.taintFlow) : [];
    taintSteps = Array.isArray(parsed) ? parsed : [];
  } catch {
    taintSteps = [];
  }
  let evidenceProvenance: EvidenceProvenance = {};
  try {
    evidenceProvenance = finding.provenance
      ? JSON.parse(finding.provenance)
      : {};
  } catch {
    evidenceProvenance = {};
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-start gap-3">
        <button
          type="button"
          onClick={() => router.back()}
          className="text-muted-foreground hover:text-foreground mt-1"
          aria-label="Back to findings"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
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
          </div>
          <h1 className="text-xl font-bold">{finding.ruleName}</h1>
          <p className="text-muted-foreground mt-1">{finding.message}</p>
        </div>
      </div>

      <Card>
        <CardContent className="space-y-3 py-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-muted-foreground mr-2">Triage:</span>
            {["open", "triaged", "confirmed", "in_progress", "false_positive", "accepted_risk", "fixed"].map((s) => (
              <Button
                key={s}
                variant={finding.status === s ? "default" : "outline"}
                size="sm"
                onClick={() => updateStatus(s)}
                disabled={updating || finding.status === s}
              >
                {s === "false_positive"
                  ? "False Positive"
                  : s === "accepted_risk"
                  ? "Accepted Risk"
                  : s === "in_progress"
                  ? "In Progress"
                  : s.charAt(0).toUpperCase() + s.slice(1)}
              </Button>
            ))}
          </div>
          <div className="grid gap-2 md:grid-cols-[1fr_180px]">
            <input
              value={triageReason}
              onChange={(event) => setTriageReason(event.target.value)}
              placeholder="Decision rationale (required for false positive / accepted risk)"
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            />
            <input
              type="date"
              value={triageExpiresAt}
              onChange={(event) => setTriageExpiresAt(event.target.value)}
              aria-label="Triage expiry"
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            />
          </div>
          {triageError && <p className="text-xs text-destructive">{triageError}</p>}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <FileCode className="h-4 w-4" />
                Location
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="font-mono text-sm">
                <div className="text-muted-foreground mb-2 text-xs">
                  {finding.filePath}:{finding.lineStart}-{finding.lineEnd}
                </div>
                <CodeHighlight
                  code={finding.codeSnippet}
                  language={finding.filePath?.split(".").pop()}
                  lineStart={finding.lineStart}
                />
              </div>
            </CardContent>
          </Card>

          {taintSteps.length > 0 && (
            <Card>
              <CardHeader>
                <button
                  onClick={() => setShowTaintFlow(!showTaintFlow)}
                  className="flex items-center gap-2 w-full text-left"
                >
                  <CardTitle className="text-sm flex items-center gap-2">
                    <GitBranch className="h-4 w-4" />
                    Taint Flow ({taintSteps.length} steps)
                  </CardTitle>
                  {showTaintFlow ? (
                    <ChevronDown className="h-4 w-4 ml-auto" />
                  ) : (
                    <ChevronRight className="h-4 w-4 ml-auto" />
                  )}
                </button>
              </CardHeader>
              {showTaintFlow && (
                <CardContent>
                  <div className="space-y-0">
                    {taintSteps.map((step, i) => (
                      <div key={i} className="flex items-start gap-3">
                        <div className="flex flex-col items-center">
                          <div className="w-2 h-2 rounded-full bg-primary mt-2" />
                          {i < taintSteps.length - 1 && (
                            <div className="w-px h-8 bg-border" />
                          )}
                        </div>
                        <div className="pb-4">
                          <p className="text-sm">{step.message}</p>
                          <p className="text-xs font-mono text-muted-foreground">
                            {step.file}:{step.line}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {/* Per-finding Call Graph */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Network className="h-4 w-4" />
                  Call Graph Context
                </CardTitle>
                {!showGraph ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={loadGraph}
                    disabled={graphLoading}
                  >
                    {graphLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                    ) : (
                      <Network className="h-4 w-4 mr-1" />
                    )}
                    Load Graph
                  </Button>
                ) : (
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => graphRef.current?.zoom(1.5, 300)}
                      aria-label="Zoom in"
                    >
                      <ZoomIn className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => graphRef.current?.zoom(0.67, 300)}
                      aria-label="Zoom out"
                    >
                      <ZoomOut className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => graphRef.current?.zoomToFit(400, 40)}
                      aria-label="Fit graph to view"
                    >
                      <Maximize2 className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {!showGraph && !graphLoading && (
                <p className="text-sm text-muted-foreground">
                  View the call graph centered on this finding to understand caller/callee relationships.
                </p>
              )}
              {showGraph && graphNodes.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  No call graph data available for this finding.
                </p>
              )}
              {showGraph && graphNodes.length > 0 && (
                <div className="space-y-2">
                  <div className="grid gap-2 rounded-lg border bg-muted/30 p-2 md:grid-cols-[1fr_150px_auto]">
                    <label className="relative">
                      <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                      <input
                        value={graphQuery}
                        onChange={(event) => setGraphQuery(event.target.value)}
                        placeholder="Search symbol or file"
                        aria-label="Search graph symbols or files"
                        className="h-8 w-full rounded-md border bg-background pl-8 pr-2 text-xs"
                      />
                    </label>
                    <select
                      value={graphType}
                      onChange={(event) => setGraphType(event.target.value)}
                      className="h-8 rounded-md border bg-background px-2 text-xs"
                      aria-label="Filter graph by node type"
                    >
                      <option value="all">All node types</option>
                      <option value="entry_point">Entry points</option>
                      <option value="sink">Sinks</option>
                      <option value="module">Modules</option>
                      <option value="function">Functions</option>
                    </select>
                    <Button
                      size="sm"
                      variant={focusEvidencePath ? "default" : "outline"}
                      onClick={() => setFocusEvidencePath((value) => !value)}
                      className="h-8 gap-1 text-xs"
                    >
                      <Focus className="h-3.5 w-3.5" />Evidence path
                    </Button>
                  </div>
                <div ref={containerRef} className="relative rounded-md border border-border overflow-hidden bg-muted">
                  <ForceGraph2D
                    ref={graphRef as React.MutableRefObject<never>}
                    graphData={graphData}
                    nodeId="id"
                    width={dimensions.width}
                    height={dimensions.height}
                    backgroundColor="transparent"
                    nodeCanvasObject={nodeCanvasObject as never}
                    nodePointerAreaPaint={nodePointerAreaPaint as never}
                    onNodeClick={((node: GraphNode) => setSelectedGraphNode(node)) as never}
                    onNodeHover={((node: GraphNode | null) => setHoveredNodeId(node?.id ?? null)) as never}
                    linkColor={((link: { source: GraphNode; target: GraphNode }) => {
                      if (!hoveredNodeId) return "rgba(100,116,139,0.3)";
                      const s = typeof link.source === "object" ? link.source.id : link.source;
                      const t = typeof link.target === "object" ? link.target.id : link.target;
                      if (s === hoveredNodeId || t === hoveredNodeId) return "rgba(100,116,139,0.8)";
                      return "rgba(100,116,139,0.15)";
                    }) as never}
                    linkWidth={((link: { source: GraphNode; target: GraphNode }) => {
                      if (!hoveredNodeId) return 1.2;
                      const s = typeof link.source === "object" ? link.source.id : link.source;
                      const t = typeof link.target === "object" ? link.target.id : link.target;
                      if (s === hoveredNodeId || t === hoveredNodeId) return 2.5;
                      return 0.6;
                    }) as never}
                    linkDirectionalArrowLength={5}
                    linkDirectionalArrowRelPos={1}
                    d3AlphaDecay={graphPhysics.alphaDecay}
                    d3VelocityDecay={graphPhysics.velocityDecay}
                    warmupTicks={50}
                    cooldownTicks={150}
                    onEngineStop={() => graphRef.current?.zoomToFit(400, 60)}
                  />
                  {selectedGraphNode && (
                    <div className="absolute top-2 right-2 bg-background/90 backdrop-blur rounded-md p-2 text-xs space-y-1 max-w-[200px] border border-border">
                      <p className="font-mono font-semibold break-all">{selectedGraphNode.qualifiedName}</p>
                      <p className="text-muted-foreground">{selectedGraphNode.filePath}:{selectedGraphNode.lineStart}</p>
                      <p className="capitalize text-muted-foreground">{selectedGraphNode.nodeType.replace("_", " ")}</p>
                    </div>
                  )}
                  <div className="flex items-center gap-4 px-3 py-2 text-xs text-muted-foreground border-t border-border bg-background/50">
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
                      Finding
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-green-500 inline-block" />
                      Entry Point
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-red-400 inline-block" />
                      Sink
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 inline-block" />
                      Module
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-slate-500 inline-block" />
                      Function
                    </span>
                    <span className="ml-auto">
                      {graphData.nodes.length}/{graphNodes.length} nodes, {graphData.links.length} edges
                      {graphCapped && <span className="text-amber-500 ml-1">(truncated)</span>}
                    </span>
                  </div>
                </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* LLM Analysis */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Bot className="h-4 w-4" />
                  AI Analysis
                </CardTitle>
                <div className="flex items-center gap-2">
                  <select
                    value={analysisLang}
                    onChange={(e) => setAnalysisLang(e.target.value)}
                    className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                  >
                    <option value="en">English</option>
                    <option value="ko">한국어</option>
                    <option value="ja">日本語</option>
                    <option value="zh">中文</option>
                  </select>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={runAnalysis}
                    disabled={analyzing}
                  >
                    {analyzing ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                    ) : (
                      <Bot className="h-4 w-4 mr-1" />
                    )}
                    {llmResult ? "Re-analyze" : "Analyze with LLM"}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {llmError && (
                <div className="flex items-start gap-2 p-3 rounded-md bg-destructive/10 text-destructive text-sm mb-4">
                  <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{llmError}</span>
                </div>
              )}

              {analyzing && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Analyzing finding with LLM...
                </div>
              )}

              {/* Batch review result (from LLM Scan page) */}
              {batchResult && !llmResult && (
                <div className="space-y-3 mb-4 p-3 rounded-md border border-border bg-muted/30">
                  <div className="flex items-center gap-2 text-sm">
                    <span className="font-medium">Batch Review Result</span>
                    <span
                      className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                        batchResult.isFalsePositive
                          ? "bg-[var(--status-false-positive-bg)] text-[var(--status-fixed)]"
                          : "bg-destructive/10 text-destructive"
                      }`}
                    >
                      {batchResult.isFalsePositive ? "False Positive" : "True Positive"}
                    </span>
                    {batchResult.adjustedSeverity && (
                      <SeverityBadge severity={batchResult.adjustedSeverity} />
                    )}
                    <span className="text-xs text-muted-foreground ml-auto">
                      {(batchResult.confidence * 100).toFixed(0)}% confidence
                      {batchResult.mode && ` \u00B7 ${batchResult.mode} mode`}
                    </span>
                  </div>
                  {batchResult.reasoning && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Reasoning</p>
                      <p className="text-sm">{batchResult.reasoning}</p>
                    </div>
                  )}
                  {batchResult.remediation && !batchResult.isFalsePositive && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">Remediation</p>
                      <p className="text-sm">{batchResult.remediation}</p>
                    </div>
                  )}
                  {batchResult.reviewedAt && (
                    <p className="text-[10px] text-muted-foreground">
                      Reviewed: {new Date(batchResult.reviewedAt).toLocaleString()}
                    </p>
                  )}
                </div>
              )}

              {!llmResult && !batchResult && !analyzing && !llmError && (
                <p className="text-sm text-muted-foreground">
                  Use AI to get detailed vulnerability analysis, risk assessment, and remediation guidance.
                  Configure your LLM provider in Settings first.
                </p>
              )}

              {llmResult && (
                <AIEvidencePanel
                  review={llmResult}
                  language={finding.filePath.split(".").pop()}
                />
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Finding lifecycle</CardTitle>
            </CardHeader>
            <CardContent>
              <FindingLifecyclePanel
                baselineState={finding.baselineState}
                identity={finding.identity}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <p className="text-xs text-muted-foreground">Confidence</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex-1 h-2 rounded-full bg-muted">
                    <div
                      className="h-2 rounded-full bg-primary"
                      style={{ width: `${finding.confidence * 100}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono">
                    {(finding.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>

              <Separator />

              {finding.cweId && (
                <div>
                  <p className="text-xs text-muted-foreground">CWE</p>
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${finding.cweId}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline flex items-center gap-1"
                  >
                    CWE-{finding.cweId}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              )}

              {finding.owaspCategory && (
                <div>
                  <p className="text-xs text-muted-foreground">OWASP</p>
                  <p className="text-sm">{finding.owaspCategory}</p>
                </div>
              )}

              <Separator />

              <div>
                <p className="text-xs text-muted-foreground">Scan</p>
                <Link
                  href={`/scans/${finding.scanId}`}
                  className="text-sm text-primary hover:underline"
                >
                  {finding.scan.repository || finding.scanId.slice(0, 8)}
                </Link>
              </div>

              {finding.scan.commitSha && (
                <div>
                  <p className="text-xs text-muted-foreground">Commit</p>
                  <p className="text-sm font-mono">
                    {finding.scan.commitSha.slice(0, 7)}
                  </p>
                </div>
              )}

              <div>
                <p className="text-xs text-muted-foreground">Rule</p>
                <Link
                  href={`/rules/${finding.ruleId}`}
                  className="text-sm text-primary hover:underline font-mono"
                >
                  {finding.ruleId}
                </Link>
              </div>

              {(finding.repositoryId || finding.modulePath) && (
                <div>
                  <p className="text-xs text-muted-foreground">Evidence location</p>
                  <p className="text-sm font-mono break-all">
                    {[finding.repositoryId, finding.modulePath]
                      .filter(Boolean)
                      .join(":")}
                  </p>
                </div>
              )}

              {finding.evidenceId && (
                <div>
                  <p className="text-xs text-muted-foreground">Evidence ID</p>
                  <p className="text-sm font-mono break-all">{finding.evidenceId}</p>
                </div>
              )}

              {finding.scan.workspaceSnapshot && (
                <div>
                  <p className="text-xs text-muted-foreground">Workspace snapshot</p>
                  <p
                    className="text-sm font-mono break-all"
                    title={finding.scan.workspaceSnapshot}
                  >
                    {finding.scan.workspaceSnapshot.slice(0, 23)}…
                  </p>
                </div>
              )}

              {evidenceProvenance.producer && (
                <div>
                  <p className="text-xs text-muted-foreground">Evidence producer</p>
                  <p className="text-sm font-mono break-all">
                    {evidenceProvenance.producer}
                    {evidenceProvenance.producer_version
                      ? `@${evidenceProvenance.producer_version}`
                      : ""}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {[
                      evidenceProvenance.analysis_kind,
                      evidenceProvenance.fidelity,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </p>
                </div>
              )}

              <Separator />

              <div>
                <p className="text-xs text-muted-foreground">Full Call Graph</p>
                <Link
                  href={`/graph/${finding.scanId}`}
                  className="text-sm text-primary hover:underline flex items-center gap-1"
                >
                  View scan graph
                  <ExternalLink className="h-3 w-3" />
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
