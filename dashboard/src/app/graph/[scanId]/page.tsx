"use client";

import { useEffect, useState, useRef, useCallback, useMemo, use } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ArrowLeft,
  Search,
  ZoomIn,
  ZoomOut,
  Maximize2,
  GitBranch,
  Loader2,
} from "lucide-react";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
});

interface GraphNode {
  id: string;
  qualifiedName: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  nodeType: string;
  hasFinding: boolean;
  findingSeverity: string | null;
  x?: number;
  y?: number;
}

interface GraphEdge {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  callSiteLine: number;
}

interface ForceNode extends GraphNode {
  x?: number;
  y?: number;
}

interface ForceLink {
  source: string;
  target: string;
  callSiteLine: number;
}

const NODE_COLORS: Record<string, string> = {
  entry_point: "#22c55e",
  sink: "#ef4444",
  module: "#6366f1",
  function: "#64748b",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

function getNodeColor(node: GraphNode): string {
  if (node.hasFinding && node.findingSeverity) {
    return (
      SEVERITY_COLORS[node.findingSeverity] ||
      NODE_COLORS[node.nodeType] ||
      "#64748b"
    );
  }
  return NODE_COLORS[node.nodeType] || "#64748b";
}

function getNodeRadius(node: GraphNode, baseScale: number = 1): number {
  const base = baseScale;
  if (node.nodeType === "entry_point") return 5 * base;
  if (node.nodeType === "sink") return 5 * base;
  if (node.hasFinding) return 4.5 * base;
  if (node.nodeType === "module") return 3.5 * base;
  return 3 * base;
}

function getShortName(qualifiedName: string): string {
  const moduleMatch = qualifiedName.match(/^<module:(.+)>$/);
  if (moduleMatch) {
    const parts = moduleMatch[1].split("/");
    return parts[parts.length - 1];
  }
  if (qualifiedName === "<anonymous>") return "(anon)";
  const parts = qualifiedName.split(".");
  if (parts.length <= 2) return qualifiedName;
  return parts.slice(-2).join(".");
}

export default function CallGraphPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = use(params);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState("");
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [graphMode, setGraphMode] = useState<"summary" | "full">("summary");
  const [totalNodes, setTotalNodes] = useState(0);
  const [totalEdges, setTotalEdges] = useState(0);

  // Fetch data
  useEffect(() => {
    fetch(
      `/api/graph/${encodeURIComponent(scanId)}?mode=${graphMode}&maxNodes=3000`
    )
      .then((r) => r.json())
      .then((data) => {
        if (data.nodes && data.nodes.length > 0) {
          setNodes(data.nodes);
          setEdges(data.edges || []);
          setTotalNodes(data.totalNodes || data.nodes.length);
          setTotalEdges(data.totalEdges || data.edges?.length || 0);
        }
      })
      .finally(() => setLoading(false));
  }, [scanId, graphMode]);

  // Track container size
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const measure = () => {
      const rect = container.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        setDimensions({ width: rect.width, height: rect.height });
      }
    };

    measure();
    const observer = new ResizeObserver(() => measure());
    observer.observe(container);
    window.addEventListener("resize", measure);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, [loading]);

  // Dynamic node scale based on graph size
  const nodeScale = useMemo(() => {
    const n = nodes.length;
    if (n < 200) return 1.2;
    if (n < 500) return 1.0;
    if (n < 1500) return 0.8;
    return 0.6;
  }, [nodes.length]);

  // Build filtered graph data
  const graphData = useMemo(() => {
    const searchLower = search.toLowerCase();

    const matchedIds = new Set<string>();
    for (const n of nodes) {
      if (filterType && n.nodeType !== filterType) continue;
      if (
        searchLower &&
        !n.qualifiedName.toLowerCase().includes(searchLower) &&
        !n.filePath.toLowerCase().includes(searchLower)
      )
        continue;
      matchedIds.add(n.id);
    }

    const visibleIds = new Set(matchedIds);
    if (searchLower || filterType) {
      for (const e of edges) {
        if (matchedIds.has(e.sourceNodeId)) visibleIds.add(e.targetNodeId);
        if (matchedIds.has(e.targetNodeId)) visibleIds.add(e.sourceNodeId);
      }
    }

    const filteredNodes: ForceNode[] = nodes.filter((n) =>
      visibleIds.has(n.id)
    );

    const filteredLinks: ForceLink[] = edges
      .filter(
        (e) => visibleIds.has(e.sourceNodeId) && visibleIds.has(e.targetNodeId)
      )
      .map((e) => ({
        source: e.sourceNodeId,
        target: e.targetNodeId,
        callSiteLine: e.callSiteLine,
      }));

    return { nodes: filteredNodes, links: filteredLinks };
  }, [nodes, edges, search, filterType]);

  // Optimized physics based on graph size
  const physicsConfig = useMemo(() => {
    const n = graphData.nodes.length;
    if (n < 200) {
      return {
        d3AlphaDecay: 0.03,
        d3VelocityDecay: 0.3,
        warmupTicks: 80,
        cooldownTime: 3000,
        cooldownTicks: 200,
        chargeStrength: -120,
        linkDistance: 60,
      };
    }
    if (n < 1000) {
      return {
        d3AlphaDecay: 0.05,
        d3VelocityDecay: 0.4,
        warmupTicks: 50,
        cooldownTime: 2000,
        cooldownTicks: 100,
        chargeStrength: -80,
        linkDistance: 40,
      };
    }
    // Large graph: fast settle
    return {
      d3AlphaDecay: 0.08,
      d3VelocityDecay: 0.5,
      warmupTicks: 30,
      cooldownTime: 1000,
      cooldownTicks: 50,
      chargeStrength: -40,
      linkDistance: 25,
    };
  }, [graphData.nodes.length]);

  // Custom node rendering - optimized
  const paintNode = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as ForceNode;
      const r = getNodeRadius(n, nodeScale);
      const color = getNodeColor(n);
      const isSelected = selectedNode?.id === n.id;
      const x = n.x ?? 0;
      const y = n.y ?? 0;

      // Draw node
      if (n.nodeType === "module") {
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.85;
        ctx.fillRect(x - r, y - r, r * 2, r * 2);
        ctx.globalAlpha = 1;
        if (isSelected) {
          ctx.strokeStyle = "#ffffff";
          ctx.lineWidth = 2 / globalScale;
          ctx.strokeRect(x - r - 1, y - r - 1, r * 2 + 2, r * 2 + 2);
        }
      } else {
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.globalAlpha = n.hasFinding ? 1 : 0.85;
        ctx.fill();
        ctx.globalAlpha = 1;

        // Glow ring for finding nodes
        if (n.hasFinding) {
          ctx.beginPath();
          ctx.arc(x, y, r + 2, 0, 2 * Math.PI);
          ctx.strokeStyle = color;
          ctx.globalAlpha = 0.3;
          ctx.lineWidth = 2 / globalScale;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }

        if (isSelected) {
          ctx.beginPath();
          ctx.arc(x, y, r + 1.5, 0, 2 * Math.PI);
          ctx.strokeStyle = "#ffffff";
          ctx.lineWidth = 2 / globalScale;
          ctx.stroke();
        }
      }

      // Labels: scale dynamically with zoom level
      const labelThreshold = graphData.nodes.length > 500 ? 1.2 : 0.8;
      if (globalScale > labelThreshold) {
        const label = getShortName(n.qualifiedName);

        // Font size grows with zoom: base 3 in graph-space, so it
        // appears larger as the user zooms in and smaller when zoomed out.
        // Clamp the *screen* size between 8px and 22px for readability.
        const graphSpaceSize = 3;                       // constant in graph coords
        const screenSize = graphSpaceSize * globalScale; // grows with zoom
        const clampedScreen = Math.min(22, Math.max(8, screenSize));
        const fontSize = clampedScreen / globalScale;    // back to graph coords

        ctx.font = `${fontSize}px "SF Mono", "Fira Code", monospace`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";

        // Fade labels in: fully opaque above 2x threshold, transparent near threshold
        const fadeAlpha = Math.min(1, (globalScale - labelThreshold) / labelThreshold);

        // Text shadow for readability
        const isDark =
          document.documentElement.classList.contains("dark");
        ctx.globalAlpha = fadeAlpha * 0.6;
        ctx.fillStyle = isDark
          ? "rgba(0, 0, 0, 1)"
          : "rgba(255, 255, 255, 1)";
        ctx.fillText(label, x + 0.5, y + r + 3.5);
        ctx.globalAlpha = fadeAlpha * 0.9;
        ctx.fillStyle = isDark
          ? "rgba(226, 232, 240, 1)"
          : "rgba(30, 41, 59, 1)";
        ctx.fillText(label, x, y + r + 3);
        ctx.globalAlpha = 1;
      }
    },
    [selectedNode, nodeScale, graphData.nodes.length]
  );

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodeClick = useCallback((node: any) => {
    setSelectedNode(node as GraphNode);
  }, []);

  const zoomIn = () => graphRef.current?.zoom(1.5, 300);
  const zoomOut = () => graphRef.current?.zoom(0.67, 300);
  const resetView = () => graphRef.current?.zoomToFit(400, 40);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 gap-3">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <span className="text-muted-foreground">
          Loading call graph...
        </span>
      </div>
    );
  }

  if (nodes.length === 0) {
    return (
      <div className="space-y-4">
        <Link
          href={`/scans/${scanId}`}
          className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1"
        >
          <ArrowLeft className="h-4 w-4" /> Back to scan
        </Link>
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <GitBranch className="h-8 w-8 mx-auto mb-3 opacity-50" />
            <p className="mb-2">No call graph data available for this scan.</p>
            <p className="text-xs">
              Ensure the SARIF report includes call graph data when uploading.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const entryPoints = nodes.filter((n) => n.nodeType === "entry_point");
  const sinks = nodes.filter((n) => n.nodeType === "sink");
  const withFindings = nodes.filter((n) => n.hasFinding);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link
            href={`/scans/${scanId}`}
            className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1"
          >
            <ArrowLeft className="h-4 w-4" /> Back
          </Link>
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <GitBranch className="h-4 w-4" />
            Call Graph
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative w-56">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search nodes..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 h-7 text-xs"
            />
          </div>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="h-7 rounded-md border border-input bg-background px-2 text-xs"
          >
            <option value="">All types</option>
            <option value="entry_point">Entry points</option>
            <option value="sink">Sinks</option>
            <option value="function">Functions</option>
            <option value="module">Modules</option>
          </select>
          <div className="h-7 rounded-md border border-input bg-background flex text-xs overflow-hidden">
            <button
              onClick={() => {
                setLoading(true);
                setGraphMode("summary");
              }}
              className={`px-2.5 transition-colors ${
                graphMode === "summary"
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted"
              }`}
            >
              Summary
            </button>
            <button
              onClick={() => {
                setLoading(true);
                setGraphMode("full");
              }}
              className={`px-2.5 transition-colors border-l border-input ${
                graphMode === "full"
                  ? "bg-primary text-primary-foreground"
                  : "hover:bg-muted"
              }`}
            >
              Full
            </button>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={zoomIn}
            className="h-7 w-7 p-0"
          >
            <ZoomIn className="h-3 w-3" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={zoomOut}
            className="h-7 w-7 p-0"
          >
            <ZoomOut className="h-3 w-3" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={resetView}
            className="h-7 w-7 p-0"
          >
            <Maximize2 className="h-3 w-3" />
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-[1fr_260px] gap-3 h-[calc(100vh-10rem)]">
        {/* Graph */}
        <div
          ref={containerRef}
          className="relative rounded-lg border border-border overflow-hidden bg-muted/50 h-full min-h-0"
        >
          <ForceGraph2D
            ref={graphRef}
            width={dimensions.width}
            height={dimensions.height}
            graphData={graphData}
            nodeCanvasObject={paintNode}
            nodePointerAreaPaint={(node, color, ctx) => {
              const r = getNodeRadius(node as GraphNode, nodeScale) + 3;
              ctx.fillStyle = color;
              ctx.beginPath();
              ctx.arc(
                (node as ForceNode).x ?? 0,
                (node as ForceNode).y ?? 0,
                r,
                0,
                2 * Math.PI
              );
              ctx.fill();
            }}
            onNodeClick={handleNodeClick}
            linkColor={() =>
              document.documentElement.classList.contains("dark")
                ? "rgba(148, 163, 184, 0.15)"
                : "rgba(100, 116, 139, 0.2)"
            }
            linkWidth={0.5}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={1}
            linkDirectionalArrowColor={() =>
              document.documentElement.classList.contains("dark")
                ? "rgba(148, 163, 184, 0.3)"
                : "rgba(100, 116, 139, 0.35)"
            }
            backgroundColor="transparent"
            d3AlphaDecay={physicsConfig.d3AlphaDecay}
            d3VelocityDecay={physicsConfig.d3VelocityDecay}
            warmupTicks={physicsConfig.warmupTicks}
            cooldownTime={physicsConfig.cooldownTime}
            cooldownTicks={physicsConfig.cooldownTicks}
            enableNodeDrag={true}
            enableZoomInteraction={true}
            enablePanInteraction={true}
            onEngineStop={() => graphRef.current?.zoomToFit(400, 30)}
          />

          {/* Legend */}
          <div className="absolute bottom-2.5 left-2.5 bg-background/80 backdrop-blur-sm rounded-md px-2.5 py-2 text-[10px] space-y-1 pointer-events-none border border-border/50">
            <div className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: NODE_COLORS.entry_point }}
              />
              <span>Entry Point</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: NODE_COLORS.sink }}
              />
              <span>Sink</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: NODE_COLORS.function }}
              />
              <span>Function</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5"
                style={{
                  backgroundColor: NODE_COLORS.module,
                  borderRadius: 1,
                }}
              />
              <span>Module</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-full ring-2 ring-orange-400/40"
                style={{ backgroundColor: SEVERITY_COLORS.high }}
              />
              <span>Has Finding</span>
            </div>
          </div>

          {/* HUD */}
          <div className="absolute bottom-2.5 right-2.5 bg-background/80 backdrop-blur-sm rounded-md px-2 py-1 text-[10px] font-mono text-muted-foreground pointer-events-none border border-border/50">
            {graphData.nodes.length.toLocaleString()} /{" "}
            {totalNodes.toLocaleString()} nodes &middot;{" "}
            {graphData.links.length.toLocaleString()} /{" "}
            {totalEdges.toLocaleString()} edges
            {graphMode === "summary" && (
              <span className="ml-1 text-primary">(summary)</span>
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-2.5 overflow-y-auto">
          <Card>
            <CardHeader className="py-2.5 px-3">
              <CardTitle className="text-[11px] font-medium">
                Graph Statistics
              </CardTitle>
            </CardHeader>
            <CardContent className="px-3 pb-2.5 space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Total Nodes</span>
                <span className="font-mono text-[11px]">
                  {totalNodes.toLocaleString()}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Total Edges</span>
                <span className="font-mono text-[11px]">
                  {totalEdges.toLocaleString()}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Visible</span>
                <span className="font-mono text-[11px]">
                  {graphData.nodes.length.toLocaleString()} nodes
                </span>
              </div>
              <div className="border-t border-border/50 my-1" />
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Entry Points</span>
                <span className="font-mono text-[11px] text-green-500">
                  {entryPoints.length}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Sinks</span>
                <span className="font-mono text-[11px] text-red-500">
                  {sinks.length}
                </span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">With Findings</span>
                <span className="font-mono text-[11px] text-orange-500">
                  {withFindings.length}
                </span>
              </div>
            </CardContent>
          </Card>

          {selectedNode && (
            <Card className="border-primary/30">
              <CardHeader className="py-2.5 px-3">
                <CardTitle className="text-[11px] font-medium">
                  Selected Node
                </CardTitle>
              </CardHeader>
              <CardContent className="px-3 pb-2.5 space-y-1.5">
                <div>
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
                    Name
                  </span>
                  <p className="text-[11px] font-mono break-all leading-tight">
                    {selectedNode.qualifiedName}
                  </p>
                </div>
                <div>
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
                    File
                  </span>
                  <p className="text-[11px] font-mono break-all leading-tight text-muted-foreground">
                    {selectedNode.filePath.split("/").slice(-3).join("/")}:
                    {selectedNode.lineStart}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
                    Type
                  </span>
                  <span
                    className="text-[11px] capitalize px-1.5 py-0.5 rounded text-white"
                    style={{
                      backgroundColor:
                        NODE_COLORS[selectedNode.nodeType] || "#64748b",
                    }}
                  >
                    {selectedNode.nodeType.replace("_", " ")}
                  </span>
                </div>
                {selectedNode.hasFinding && selectedNode.findingSeverity && (
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
                      Finding
                    </span>
                    <SeverityBadge severity={selectedNode.findingSeverity} />
                  </div>
                )}
                <div className="flex gap-3 text-[11px] font-mono pt-0.5">
                  <span className="text-muted-foreground">
                    {
                      edges.filter(
                        (e) => e.sourceNodeId === selectedNode.id
                      ).length
                    }{" "}
                    out
                  </span>
                  <span className="text-muted-foreground">
                    {
                      edges.filter(
                        (e) => e.targetNodeId === selectedNode.id
                      ).length
                    }{" "}
                    in
                  </span>
                </div>
              </CardContent>
            </Card>
          )}

          {entryPoints.length > 0 && (
            <Card>
              <CardHeader className="py-2.5 px-3">
                <CardTitle className="text-[11px] font-medium">
                  Entry Points ({entryPoints.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="px-3 pb-2.5">
                <div className="space-y-0.5 max-h-36 overflow-y-auto">
                  {entryPoints.slice(0, 30).map((n) => (
                    <button
                      key={n.id}
                      onClick={() => setSelectedNode(n)}
                      className={`block w-full text-left text-[11px] font-mono truncate py-0.5 px-1 rounded transition-colors ${
                        selectedNode?.id === n.id
                          ? "bg-primary/10 text-foreground"
                          : "hover:bg-muted text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {getShortName(n.qualifiedName)}
                    </button>
                  ))}
                  {entryPoints.length > 30 && (
                    <p className="text-[10px] text-muted-foreground pt-1">
                      +{entryPoints.length - 30} more...
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {sinks.length > 0 && (
            <Card>
              <CardHeader className="py-2.5 px-3">
                <CardTitle className="text-[11px] font-medium">
                  Sinks ({sinks.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="px-3 pb-2.5">
                <div className="space-y-0.5 max-h-36 overflow-y-auto">
                  {sinks.slice(0, 30).map((n) => (
                    <button
                      key={n.id}
                      onClick={() => setSelectedNode(n)}
                      className={`block w-full text-left text-[11px] font-mono truncate py-0.5 px-1 rounded transition-colors ${
                        selectedNode?.id === n.id
                          ? "bg-primary/10 text-foreground"
                          : "hover:bg-muted text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      {getShortName(n.qualifiedName)}
                    </button>
                  ))}
                  {sinks.length > 30 && (
                    <p className="text-[10px] text-muted-foreground pt-1">
                      +{sinks.length - 30} more...
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
