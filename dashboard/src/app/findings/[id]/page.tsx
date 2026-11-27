"use client";

import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { useParams, useSearchParams } from "next/navigation";
import dynamic from "next/dynamic";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { findingStatusOptions, StatusBadge } from "@/components/status-badge";
import {
  ArrowLeft,
  ArrowDown,
  ArrowUpRight,
  Download,
  ExternalLink,
  Loader2,
  AlertCircle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Focus,
  Search,
  TicketCheck,
} from "lucide-react";
import { EvidenceWorkbench } from "@/components/finding/evidence-workbench";
import { EVIDENCE_LABELS, isConfigurationEvidence } from "@/lib/code-evidence";
import { isWranglerManifest } from "@/lib/configuration-evidence";
import { filterQuery, findingFilters } from "@/lib/finding-view";
import { ApiContractPanel, type ApiContractContextView } from "@/components/finding/api-contract-panel";
import { AIEvidencePanel, type AIReviewView } from "@/components/finding/ai-evidence-panel";
import { normalizeAIReviewEvidence } from "@/lib/ai-review-evidence";
import {
  FindingLifecyclePanel,
  type FindingIdentityView,
} from "@/components/finding/finding-lifecycle-panel";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
});

interface BatchReviewAnalysis {
  isFalsePositive: boolean;
  confidence: number | null;
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
  isCurrent: boolean;
  permissions?: { canTriage: boolean };
  workflow?: {
    version: string; scope: "identity" | "observation"; needsReview: boolean;
    status: string; owner: string; dueAt: string | null; priority: string; tags: string;
    ticketKey: string; ticketUrl: string; reason: string; expiresAt: string | null;
  };
  apiContractContext?: ApiContractContextView[];
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
  owner: string;
  dueAt: string | null;
  priority: string;
  tags: string;
  ticketProvider: string;
  ticketKey: string;
  ticketUrl: string;
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
    sourceEvidence: normalizeAIReviewEvidence(value),
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

function assignmentTags(value: string | undefined): string | null {
  try {
    const items: unknown = JSON.parse(value || "[]");
    return Array.isArray(items) && items.every((item) => typeof item === "string") ? items.join(", ") : null;
  } catch { return null; }
}

function WorkflowError({ message, busy, reload }: { message: string; busy: boolean; reload: () => void }) {
  return <div role="alert" className="mt-3 space-y-2 text-sm">
    <p className="text-destructive">{message}</p>
    <p className="text-muted-foreground">Reloading replaces unsaved triage and assignment drafts.</p>
    <Button type="button" size="sm" variant="outline" className="min-h-11" disabled={busy} onClick={reload}>Reload latest</Button>
  </div>;
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  return <FindingDetailRecord key={id} id={id} />;
}

function FindingDetailRecord({ id }: { id: string }) {
  const search = useSearchParams();
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [updating, setUpdating] = useState(false);
  const [triageStatus, setTriageStatus] = useState("");
  const [triageReason, setTriageReason] = useState("");
  const [triageVersion, setTriageVersion] = useState("");
  const [managementVersion, setManagementVersion] = useState("");
  const [triageExpiresAt, setTriageExpiresAt] = useState("");
  const [triageError, setTriageError] = useState("");
  const [triageNotice, setTriageNotice] = useState("");
  const [assignmentNotice, setAssignmentNotice] = useState("");
  const [assignmentError, setAssignmentError] = useState("");
  const [owner, setOwner] = useState("");
  const [dueAt, setDueAt] = useState("");
  const [priority, setPriority] = useState("");
  const [tags, setTags] = useState("");
  const [jiraCreating, setJiraCreating] = useState(false);

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
  const [graphError, setGraphError] = useState(false);
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
    const controller = new AbortController();
    fetch(`/api/findings/${id}`, { signal: controller.signal })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok || !data.scan) throw new Error(data.error || "Unable to load finding.");
        return data;
      })
      .then((data) => {
        if (controller.signal.aborted) return;
        setLoadError("");
        setFinding(data);
        const workflow = data.workflow || data;
        setTriageStatus(workflow.status);
        setTriageVersion(workflow.version || "");
        setManagementVersion(workflow.version || "");
        setTriageReason(workflow.reason || data.identity?.triageReason || "");
        setTriageExpiresAt(workflow.expiresAt?.slice(0, 10) || "");
        setOwner(workflow.owner || "");
        setDueAt(workflow.dueAt?.slice(0, 10) || "");
        setPriority(workflow.priority || "");
        setTags(assignmentTags(workflow.tags) ?? "");
        // Load saved LLM analysis (two possible formats)
        if (data.llmAnalysis) {
          try {
            const parsed = JSON.parse(data.llmAnalysis);
            if (parsed && typeof parsed === "object") {
              if (typeof parsed.isFalsePositive === "boolean" && !parsed.verdict && !parsed.analysis && !parsed.proof) {
                setBatchResult({
                  isFalsePositive: parsed.isFalsePositive,
                  confidence: typeof parsed.confidence === "number" && parsed.confidence >= 0 && parsed.confidence <= 1 ? parsed.confidence : null,
                  reasoning: typeof parsed.reasoning === "string" ? parsed.reasoning : "",
                  remediation: typeof parsed.remediation === "string" ? parsed.remediation : "",
                  adjustedSeverity: typeof parsed.adjustedSeverity === "string" ? parsed.adjustedSeverity : undefined,
                  mode: typeof parsed.mode === "string" ? parsed.mode : undefined,
                  reviewedAt: typeof parsed.reviewedAt === "string" && Number.isFinite(Date.parse(parsed.reviewedAt)) ? parsed.reviewedAt : undefined,
                });
              } else if (parsed.analysis || parsed.reasoning || parsed.verdict || parsed.proof) {
                setLlmResult(normalizeAIReview(parsed));
              }
            }
          } catch {
            // ignore
          }
        }
      })
      .catch((error) => { if (!controller.signal.aborted) setLoadError(error instanceof Error ? error.message : "Unable to load finding."); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [id]);

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

  const refreshWorkflow = async (saved: "all" | "triage" | "management" | "ticket" = "all") => {
    if (!finding) return;
    const response = await fetch(`/api/findings/${finding.id}`);
    const data = await response.json();
    if (!response.ok || !data.scan) throw new Error(data.error || "Unable to reload finding.");
    setFinding(data);
    const workflow = data.workflow || data;
    const before = finding.workflow;
    const previousTags = assignmentTags(before?.tags) ?? "";
    const untouchedTriage = triageVersion === before?.version && triageStatus === before.status && triageReason === before.reason
      && triageExpiresAt === (before.expiresAt?.slice(0, 10) || "");
    const untouchedManagement = managementVersion === before?.version && owner === before.owner
      && dueAt === (before.dueAt?.slice(0, 10) || "") && priority === before.priority && tags === previousTags;
    if (saved === "all" || saved === "triage" || untouchedTriage) {
      setTriageStatus(workflow.status);
      setTriageReason(workflow.reason || "");
      setTriageExpiresAt(workflow.expiresAt?.slice(0, 10) || "");
      setTriageVersion(workflow.version || "");
    }
    if (saved === "all" || saved === "management" || untouchedManagement) {
      setOwner(workflow.owner || "");
      setDueAt(workflow.dueAt?.slice(0, 10) || "");
      setPriority(workflow.priority || "");
      setTags(assignmentTags(workflow.tags) ?? "");
      setManagementVersion(workflow.version || "");
    }
    setTriageError("");
  };

  const saveTriage = async () => {
    if (!finding?.permissions?.canTriage) return;
    setUpdating(true);
    setTriageError("");
    setTriageNotice("");
    try {
      const res = await fetch(`/api/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: triageStatus,
          expectedVersion: triageVersion,
          reason: triageReason,
          expiresAt: triageExpiresAt || null,
        }),
      });
      if (res.ok) {
        await refreshWorkflow("triage");
        setTriageNotice("Decision saved.");
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

  const saveManagement = async () => {
    if (!finding?.permissions?.canTriage) return;
    setUpdating(true);
    setAssignmentError("");
    setAssignmentNotice("");
    try {
      const response = await fetch(`/api/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner,
          expectedVersion: managementVersion,
          resolveWorkflowReview: finding.workflow?.needsReview || false,
          dueAt: dueAt || null,
          priority,
          tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Management update failed");
      await refreshWorkflow("management");
      setAssignmentNotice("Assignment saved.");
    } catch (error) {
      setAssignmentError(error instanceof Error ? error.message : "Management update failed");
    } finally {
      setUpdating(false);
    }
  };

  const createJiraTicket = async () => {
    if (!finding?.permissions?.canTriage) return;
    setJiraCreating(true);
    setAssignmentError("");
    setAssignmentNotice("");
    try {
      const response = await fetch(`/api/findings/${finding.id}/jira`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Jira ticket creation failed");
      await refreshWorkflow("ticket");
    } catch (error) {
      setAssignmentError(error instanceof Error ? error.message : "Jira ticket creation failed");
    } finally {
      setJiraCreating(false);
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
    if (!finding || graphLoading) return;
    setGraphLoading(true);
    setGraphError(false);
    try {
      const res = await fetch(`/api/findings/${finding.id}/graph`);
      if (!res.ok) throw new Error("Graph request failed");
      const data = await res.json();
      if (!Array.isArray(data?.nodes) || !Array.isArray(data.edges)) throw new Error("Incomplete graph");
      setGraphNodes(data.nodes);
      setGraphEdges(data.edges);
      setGraphCapped(!!data.capped);
      setShowGraph(true);
    } catch {
      setGraphError(true);
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

  if (loadError || (!loading && !finding)) return <div className="workbench-panel space-y-4 p-6"><p role="alert">{loadError || "Finding not found."}</p><Link href="/findings" className="text-sm text-primary">Back to findings →</Link></div>;
  if (loading || !finding) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  let evidenceProvenance: EvidenceProvenance = {};
  try {
    evidenceProvenance = finding.provenance
      ? JSON.parse(finding.provenance)
      : {};
  } catch {
    evidenceProvenance = {};
  }

  const configuration = isConfigurationEvidence(finding.provenance);
  const reasonRequired = triageStatus === "false_positive" || triageStatus === "accepted_risk";
  const mayTriage = Boolean(finding.permissions?.canTriage);
  const canEditTriage = mayTriage && !updating;
  const listQuery = search.size ? "?" + filterQuery(findingFilters(new URLSearchParams(search.toString()))) : "";
  const assignment = finding.workflow ?? finding;
  const savedTags = assignmentTags(assignment.tags);
  const reloadWorkflow = async () => {
    setUpdating(true);
    try {
      await refreshWorkflow();
      setTriageNotice("");
      setAssignmentNotice("");
      setTriageError("");
      setAssignmentError("");
    } finally {
      setUpdating(false);
    }
  };
  return (
    <div className="space-y-6">
      <header>
        <div className="finding-record-tools no-print">
          <Link href={"/findings" + listQuery} aria-label="Back to findings">
            <ArrowLeft aria-hidden className="size-4" />Findings
          </Link>
          <div className="flex items-center gap-x-3 sm:gap-x-5">
            <Link href={`/findings/${finding.id}/report`} aria-label="Open finding report">
              Report<ArrowUpRight aria-hidden className="size-3.5" />
            </Link>
            <a href={`/api/findings/${finding.id}/report`} aria-label="Download Markdown">
              <Download aria-hidden className="size-3.5" />Markdown
            </a>
          </div>
        </div>
        <div className="space-y-3 py-4 sm:py-5">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            <SeverityBadge severity={finding.severity} />
            <Link href={`/rules/${encodeURIComponent(finding.ruleId)}`} className="min-w-0 break-all font-mono text-primary hover:underline">{finding.ruleId}</Link>
          </div>
          <h1 className="workbench-title max-w-4xl break-words">{finding.ruleName}</h1>
          <p className="max-w-3xl text-sm leading-6 text-muted-foreground">{finding.message}</p>
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <StatusBadge status={finding.workflow?.status || finding.status} />
          <span className="border-l pl-3">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified evidence"}</span>
          {finding.disposition && <span className="capitalize">{finding.disposition}</span>}
          <a href="#triage-heading" className="ml-auto inline-flex min-h-11 items-center gap-1 text-sm font-medium text-primary hover:underline xl:hidden">Triage<ArrowDown aria-hidden className="size-3.5" /></a>
        </div>
      </header>

      <div className="finding-review">
      <EvidenceWorkbench key={finding.id} finding={{ ...finding, owner: finding.workflow?.owner ?? finding.owner }} />

      <section className="finding-decision" aria-labelledby="triage-heading">
        <h2 id="triage-heading" tabIndex={-1} className="scroll-mt-4 text-lg font-semibold tracking-tight">Triage decision</h2>
        {!finding.isCurrent && finding.workflow?.scope === "identity" && <p className="mt-3 text-sm text-muted-foreground">This earlier scan recorded {finding.status.replaceAll("_", " ")} with {finding.owner || "no assigned owner"}. The decision below applies to the current issue.</p>}
        {mayTriage ? <form className="mt-4 space-y-4" onChange={() => setTriageNotice("")} onSubmit={(event) => { event.preventDefault(); void saveTriage(); }}>
          <div className="finding-decision-fields">
            <label className="grid gap-1.5 text-sm font-medium">Status
              <select aria-label="Triage status" className="workbench-select min-h-11 w-full font-normal" disabled={!canEditTriage} value={triageStatus} onChange={(event) => setTriageStatus(event.target.value)}>
                {findingStatusOptions.map(({ value, label }) => <option key={value} value={value}>{label}</option>)}
              </select>
            </label>
            {finding.workflow?.scope === "identity" && <label className="grid gap-1.5 text-sm font-medium">Expiry date
              <input type="date" aria-label="Triage expiry" className="workbench-select min-h-11 w-full min-w-0 font-normal" disabled={!canEditTriage} value={triageExpiresAt} onChange={(event) => setTriageExpiresAt(event.target.value)} />
            </label>}
          </div>
          <label className="grid max-w-3xl gap-1.5 text-sm font-medium">Decision rationale{reasonRequired ? " (required)" : ""}
            <textarea aria-label="Triage rationale" className="min-h-16 w-full resize-y rounded-md border border-input bg-card px-3 py-2 text-base font-normal sm:text-sm" disabled={!canEditTriage} required={reasonRequired} maxLength={4000} rows={2} value={triageReason} onChange={(event) => setTriageReason(event.target.value)} />
          </label>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" className="min-h-11" disabled={!canEditTriage}>Save decision</Button>
            <span role="status" className="text-sm text-muted-foreground">{triageNotice}</span>
          </div>
          {triageError && <WorkflowError message={triageError} busy={updating} reload={() => reloadWorkflow().catch((error) => setTriageError(error instanceof Error ? error.message : "Unable to reload finding."))} />}
        </form> : <>
          <p className="mt-1 text-xs text-muted-foreground">Read-only access</p>
          <dl className="saved-workflow mt-4 grid gap-4">
            <div><dt>Status</dt><dd><StatusBadge status={assignment.status} /></dd></div>
            <div><dt>Decision rationale</dt><dd className="whitespace-pre-wrap">{finding.workflow?.reason || finding.identity?.triageReason || "No rationale recorded"}</dd></div>
            {finding.workflow?.expiresAt && <div><dt>Expires</dt><dd><time dateTime={finding.workflow.expiresAt}>{finding.workflow.expiresAt.slice(0, 10)}</time></dd></div>}
          </dl>
        </>}
      </section>
      </div>

      <section className="finding-assignment" aria-labelledby="assignment-heading">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 id="assignment-heading" className="text-lg font-semibold tracking-tight">Assignment</h2>
            {assignment.ticketUrl ? (
              <a href={assignment.ticketUrl} target="_blank" rel="noreferrer" className="inline-flex min-h-11 items-center gap-1.5 text-sm text-primary hover:underline">
                <TicketCheck aria-hidden className="size-4" />{assignment.ticketKey || "Open Jira ticket"}<ExternalLink aria-hidden className="size-3.5" />
              </a>
            ) : mayTriage && (
              <Button variant="ghost" size="sm" className="min-h-11 text-primary" onClick={createJiraTicket} disabled={!canEditTriage || jiraCreating}>
                {jiraCreating ? <Loader2 aria-hidden className="size-4 animate-spin" /> : <TicketCheck aria-hidden className="size-4" />}
                Create Jira ticket
              </Button>
            )}
          </div>
          {finding.workflow?.needsReview && <p role="status" className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">Historical assignments need review.{mayTriage && " Check the previous scans before saving the current owner and delivery details."}</p>}
          {mayTriage ? <form onChange={() => setAssignmentNotice("")} onSubmit={(event) => { event.preventDefault(); void saveManagement(); }}>
            <div className="assignment-fields">
              <label>Owner or team<input value={owner} disabled={!canEditTriage} maxLength={200} onChange={(event) => setOwner(event.target.value)} aria-label="Finding owner" /></label>
              <label>Priority<select value={priority} disabled={!canEditTriage} onChange={(event) => setPriority(event.target.value)} aria-label="Remediation priority">
                <option value="">Unspecified</option><option value="p0">P0</option><option value="p1">P1</option><option value="p2">P2</option><option value="p3">P3</option>
              </select></label>
              <label>Due date<input type="date" value={dueAt} disabled={!canEditTriage} onChange={(event) => setDueAt(event.target.value)} aria-label="Remediation due date" /></label>
              <label>Tags <span className="sr-only" id="tag-format">Separate tags with commas.</span><input value={tags} disabled={!canEditTriage} placeholder="api, auth" onChange={(event) => setTags(event.target.value)} aria-label="Finding tags" aria-describedby="tag-format" /></label>
              <Button type="submit" variant="outline" className="min-h-11 justify-self-start" disabled={!canEditTriage || jiraCreating}>{finding.workflow?.needsReview ? "Save reviewed assignment" : "Save assignment"}</Button>
            </div>
            <p aria-live="polite" className="mt-2 text-sm text-muted-foreground empty:mt-0">{assignmentNotice}</p>
            {assignmentError && <WorkflowError message={assignmentError} busy={updating || jiraCreating} reload={() => reloadWorkflow().catch((error) => setAssignmentError(error instanceof Error ? error.message : "Unable to reload finding."))} />}
          </form> : <dl className="saved-workflow grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <div><dt>Owner or team</dt><dd>{assignment.owner || "Unassigned"}</dd></div>
            <div><dt>Priority</dt><dd>{assignment.priority?.toUpperCase() || "Unspecified"}</dd></div>
            <div><dt>Due date</dt><dd>{assignment.dueAt ? <time dateTime={assignment.dueAt}>{assignment.dueAt.slice(0, 10)}</time> : "No due date"}</dd></div>
            <div><dt>Tags</dt><dd>{savedTags === null ? "Unavailable" : savedTags || "None"}</dd></div>
          </dl>}
      </section>

      <div className="finding-support">
        <div className="finding-analysis" data-expanded={Boolean((showGraph && graphNodes.length) || llmResult || batchResult)}>
          {!configuration && <ApiContractPanel contexts={finding.apiContractContext || []} scanId={finding.scanId} />}
          {!configuration && <section aria-labelledby="nearby-calls-heading">
            <header className="finding-section-heading">
              <h2 id="nearby-calls-heading">Nearby calls</h2>
              <button type="button" className="finding-action" aria-controls="nearby-calls" aria-expanded={showGraph}
                onClick={() => showGraph ? setShowGraph(false) : void loadGraph()} aria-disabled={graphLoading}>
                {graphLoading ? "Loading calls…" : showGraph ? "Hide calls" : graphError ? "Retry calls" : "Load calls"}
              </button>
            </header>
            {graphError && <p role="alert" className="mt-2 text-sm text-destructive">Nearby calls could not be loaded.</p>}
            <div id="nearby-calls" hidden={!showGraph}>
              {showGraph && graphNodes.length === 0 && (
                <p role="status" className="mt-3 text-sm text-muted-foreground">No call graph nodes recorded for this file.</p>
              )}
              {showGraph && graphNodes.length > 0 && (
                <div className="space-y-2">
                  <div className="graph-zoom mt-2 flex w-fit" role="group" aria-label="Graph zoom">
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
                  <div className="flex flex-wrap items-center gap-2 border-y border-border py-2">
                    <label className="relative min-w-0 flex-[1_1_12rem]">
                      <Search aria-hidden className="absolute left-3 top-3.5 size-4 text-muted-foreground" />
                      <input
                        value={graphQuery}
                        onChange={(event) => setGraphQuery(event.target.value)}
                        placeholder="Search symbol or file"
                        aria-label="Search graph symbols or files"
                        className="workbench-select min-h-11 w-full pl-9 text-sm"
                      />
                    </label>
                    <select
                      value={graphType}
                      onChange={(event) => setGraphType(event.target.value)}
                      className="workbench-select min-h-11 max-w-full text-sm"
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
                      aria-pressed={focusEvidencePath}
                      className="min-h-11 gap-1 text-sm"
                    >
                      <Focus className="h-3.5 w-3.5" />Evidence path
                    </Button>
                  </div>
                <div ref={containerRef} className="relative min-w-0 overflow-hidden border border-border bg-card">
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
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-xs text-muted-foreground border-t border-border">
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
            </div>
            <Link href={`/graph/${finding.scanId}`} className="finding-action">Full scan graph<ArrowUpRight aria-hidden className="size-3.5" /></Link>
          </section>}

          <section aria-labelledby="model-review-heading">
            <header className="finding-section-heading">
              <h2 id="model-review-heading">Model review</h2>
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <select
                  aria-label="Review language"
                  value={analysisLang}
                  onChange={(event) => setAnalysisLang(event.target.value)}
                  className="workbench-select min-h-11"
                >
                  <option value="en">English</option>
                  <option value="ko">한국어</option>
                  <option value="ja">日本語</option>
                  <option value="zh">中文</option>
                </select>
                <Button variant="outline" size="sm" className="min-h-11" onClick={runAnalysis} disabled={analyzing}>
                  {analyzing && <Loader2 aria-hidden className="size-4 animate-spin" />}
                  {analyzing ? "Reviewing…" : llmResult || batchResult ? "Run again" : "Run review"}
                </Button>
              </div>
            </header>
            <div className="min-w-0 py-3 [overflow-wrap:anywhere]">
              {llmError && (
                <div role="alert" className="flex items-start gap-2 p-3 rounded-md bg-destructive/10 text-destructive text-sm mb-4">
                  <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>{llmError}</span>
                </div>
              )}

              {analyzing && (
                <div role="status" className="flex items-center gap-2 text-sm text-muted-foreground py-4">
                  Waiting for the model’s review…
                </div>
              )}

              {/* Batch review result (from LLM Scan page) */}
              {batchResult && !llmResult && (
                <div className="space-y-3 mb-4 p-3 rounded-md border border-border bg-muted/30">
                  <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
                    <span className="font-semibold">{batchResult.isFalsePositive ? "Likely false positive" : "Needs human review"}</span>
                    {batchResult.adjustedSeverity && <SeverityBadge severity={batchResult.adjustedSeverity} />}
                    <span className="text-xs text-muted-foreground">
                      Legacy batch review{batchResult.mode && ` · ${batchResult.mode}`}
                      {batchResult.isFalsePositive && batchResult.confidence !== null && ` · ${Math.round(batchResult.confidence * 100)}% model estimate`}
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
                  No model review recorded.
                </p>
              )}

              {llmResult && (
                <AIEvidencePanel
                  review={llmResult}
                  original={configuration || [finding.filePath, finding.modulePath].some(isWranglerManifest) ? "" : finding.codeSnippet || ""}
                  language={finding.filePath.split(".").pop()}
                />
              )}
            </div>
          </section>
        </div>

        <div className="finding-reference">
          <section aria-labelledby="finding-history-heading">
            <header className="finding-section-heading"><h2 id="finding-history-heading">Finding history</h2></header>
            <FindingLifecyclePanel baselineState={finding.baselineState} identity={finding.identity} />
          </section>
          <section aria-labelledby="scan-details-heading">
            <header className="finding-section-heading"><h2 id="scan-details-heading">Scan details</h2></header>
            <dl className="finding-facts">
              <div><dt>Scanner confidence</dt><dd className="tabular-nums">{(finding.confidence * 100).toFixed(0)}%</dd></div>
              {finding.cweId && <div><dt>CWE</dt><dd>
                <a href={`https://cwe.mitre.org/data/definitions/${finding.cweId}.html`} target="_blank" rel="noopener noreferrer">
                  CWE-{finding.cweId}<ExternalLink aria-hidden className="ml-1 inline-block size-3" />
                </a>
              </dd></div>}
              {finding.owaspCategory && <div><dt>OWASP</dt><dd>{finding.owaspCategory}</dd></div>}
              <div><dt>Scan</dt><dd><Link href={`/scans/${finding.scanId}`}>{finding.scan.repository || finding.scanId.slice(0, 8)}</Link></dd></div>
              {finding.scan.commitSha && <div><dt>Commit</dt><dd><code title={finding.scan.commitSha}>{finding.scan.commitSha.slice(0, 7)}</code></dd></div>}
              <div><dt>Rule</dt><dd><Link className="font-mono" href={`/rules/${encodeURIComponent(finding.ruleId)}`}>{finding.ruleId}</Link></dd></div>
              {(finding.repositoryId || finding.modulePath) && <div>
                <dt>Evidence location</dt><dd><code>{[finding.repositoryId, finding.modulePath].filter(Boolean).join(":")}</code></dd>
              </div>}
              {finding.evidenceId && <div><dt>Evidence ID</dt><dd><code>{finding.evidenceId}</code></dd></div>}
              {finding.scan.workspaceSnapshot && <div><dt>Workspace snapshot</dt><dd><code>{finding.scan.workspaceSnapshot}</code></dd></div>}
              {evidenceProvenance.producer && <div>
                <dt>Evidence producer</dt><dd>
                  <code>{evidenceProvenance.producer}{evidenceProvenance.producer_version && `@${evidenceProvenance.producer_version}`}</code>
                  <p className="text-xs text-muted-foreground">{[evidenceProvenance.analysis_kind, evidenceProvenance.fidelity].filter(Boolean).join(" · ")}</p>
                </dd>
              </div>}
            </dl>
          </section>
        </div>
      </div>
    </div>
  );
}
