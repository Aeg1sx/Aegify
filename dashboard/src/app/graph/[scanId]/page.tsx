"use client";

import { useEffect, useState, useRef, useCallback, useMemo, use } from "react";
import dynamic from "next/dynamic";
import type { NodeObject } from "react-force-graph-2d";
import Link from "next/link";
import { SeverityBadge } from "@/components/severity-badge";
import { graphSymbolName } from "@/lib/graph-path";
import { StructureExplorer } from "@/components/structure-explorer";
import {
  ArrowLeft,
  ZoomIn,
  ZoomOut,
  Maximize2,
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
  entry_point: "#458969",
  sink: "#b66645",
  module: "#6582a0",
  function: "#72817e",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#b94259",
  high: "#bc6235",
  medium: "#a47f22",
  low: "#4a7fa2",
};

function getNodeRadius(node: GraphNode, baseScale: number = 1): number {
  const base = baseScale;
  if (node.nodeType === "entry_point") return 5 * base;
  if (node.nodeType === "sink") return 5 * base;
  if (node.hasFinding) return 4.5 * base;
  if (node.nodeType === "module") return 3.5 * base;
  return 3 * base;
}

function getShortName(qualifiedName: string): string {
  const label = graphSymbolName(qualifiedName);
  if (label !== qualifiedName) return label;
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
  return <GraphWorkspace key={scanId} scanId={scanId} />;
}

function GraphWorkspace({ scanId }: { scanId: string }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [scan, setScan] = useState<{ repository: string; branch: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState("");
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [graphMode, setGraphMode] = useState<"summary" | "full">("summary");
  const [totalNodes, setTotalNodes] = useState(0);
  const [totalEdges, setTotalEdges] = useState(0);
  const [view, setView] = useState<"structure" | "network">("structure");
  const [error, setError] = useState("");

  // Fetch data
  useEffect(() => {
    const controller = new AbortController();
    fetch(
      `/api/graph/${encodeURIComponent(scanId)}?mode=${graphMode}&maxNodes=3000`,
      { signal: controller.signal },
    )
      .then((r) => { if (!r.ok) throw new Error("Unable to load the graph"); return r.json(); })
      .then((data) => {
        if (!Array.isArray(data.nodes) || !Array.isArray(data.edges)) throw new Error("Graph data is unavailable.");
        if (!controller.signal.aborted) {
          setScan({ repository: data.repository ?? "", branch: data.branch ?? "" });
          setNodes(data.nodes);
          setEdges(data.edges || []);
          setTotalNodes(data.totalNodes || data.nodes.length);
          setTotalEdges(data.totalEdges || data.edges?.length || 0);
          setError("");
          setSelectedNode((current) => data.nodes.find((node: GraphNode) => node.id === current?.id)
            ?? data.nodes.find((node: GraphNode) => node.hasFinding) ?? data.nodes[0] ?? null);
        }
      })
      .catch((e) => { if (!controller.signal.aborted) setError(e.message); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
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
  }, [loading, view, graphMode]);

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

  const paintNode = useCallback(
    (graphNode: NodeObject, ctx: CanvasRenderingContext2D, scale: number) => {
      const node = graphNode as ForceNode;
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      const radius = getNodeRadius(node, nodeScale);
      const dark = document.documentElement.classList.contains("dark");
      function outline(padding: number) {
        const r = radius + padding / scale;
        ctx.beginPath();
        if (node.nodeType === "module") ctx.rect(x - r, y - r, r * 2, r * 2);
        else ctx.arc(x, y, r, 0, 2 * Math.PI);
      }

      ctx.save();
      outline(0);
      ctx.fillStyle = NODE_COLORS[node.nodeType] ?? NODE_COLORS.function;
      ctx.fill();
      if (node.hasFinding) {
        outline(2.5);
        ctx.strokeStyle = SEVERITY_COLORS[node.findingSeverity ?? ""] ?? (dark ? "#c7d7ce" : "#485c52");
        ctx.lineWidth = 1.7 / scale;
        ctx.stroke();
      }
      if (node.id === selectedNode?.id) {
        outline(node.hasFinding ? 6 : 3.5);
        ctx.strokeStyle = dark ? "#ffffff" : "#172c25";
        ctx.lineWidth = 1.5 / scale;
        ctx.setLineDash([3 / scale, 2 / scale]);
        ctx.stroke();
      }
      const count = graphData.nodes.length;
      if (count <= 80 || scale > (count > 500 ? 1.2 : 0.8)) {
        const screenSize = Math.min(20, Math.max(count <= 80 ? 12 : 10, 3 * scale));
        ctx.font = (screenSize / scale) + 'px ui-monospace, monospace';
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        ctx.fillStyle = dark ? "#e1e9e4" : "#253b31";
        ctx.fillText(getShortName(node.qualifiedName), x, y + radius + 7 / scale);
      }
      ctx.restore();
    }, [selectedNode?.id, nodeScale, graphData.nodes.length]
  );

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodeClick = useCallback((node: any) => {
    setSelectedNode(node as GraphNode);
  }, []);

  const autoFitRef = useRef(true);
  useEffect(() => { autoFitRef.current = true; }, [graphData, view]);
  function zoom(factor: number) {
    autoFitRef.current = false;
    const graph = graphRef.current;
    if (graph) graph.zoom(graph.zoom() * factor, 180);
  }
  const choose = (id: string) => setSelectedNode(nodes.find((node) => node.id === id) ?? null);
  const selected = selectedNode ?? nodes.find((node) => node.hasFinding) ?? nodes[0];
  const entries = nodes.filter((node) => node.nodeType === "entry_point");
  const sinks = nodes.filter((node) => node.nodeType === "sink");
  return <div className="graph-workspace">
    <Link className="inline-flex min-h-11 items-center gap-2 text-sm text-primary" href={"/scans/" + scanId}>
      <ArrowLeft aria-hidden className="size-4" /> Back to scan
    </Link>
    <header className="graph-heading">
      <div><h1 className="workbench-title">Call graph</h1>
        {scan?.repository && <p className="mt-2 break-all text-sm text-muted-foreground"><strong className="font-medium text-foreground">{scan.repository}</strong>{scan.branch && " · " + scan.branch}</p>}
      </div>
      {scan && <dl className="graph-totals">
        <div><dt>Symbols</dt><dd>{totalNodes.toLocaleString()}</dd></div>
        <div><dt>Recorded calls</dt><dd>{totalEdges.toLocaleString()}</dd></div>
      </dl>}
    </header>
    {scan && <div className="graph-view-bar">
      <div role="group" aria-label="Graph view" className="graph-view-buttons">
        {(["structure", "network"] as const).map((name) => <button type="button" key={name} aria-pressed={view === name}
          onClick={() => setView(name)}>{name === "structure" ? "Structure & source" : "Network"}</button>)}
      </div>
      <label className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground"><span className="hidden sm:inline">Show</span>
        <select aria-label="Graph scope" className="workbench-select min-h-11" value={graphMode} onChange={(event) => {
          setLoading(true); setGraphMode(event.target.value === "full" ? "full" : "summary");
        }}><option value="summary">Summary</option><option value="full">Full graph</option></select>
      </label>
    </div>}
    {error ? <p role="alert" className="py-5">{error}</p> : loading && !scan ?
      <p role="status" className="flex items-center gap-2 py-5 text-sm text-muted-foreground"><Loader2 aria-hidden className="size-4 animate-spin" />Loading call graph…</p> :
      <div aria-busy={loading}>
        {loading && <p role="status" className="py-2 text-sm text-muted-foreground">Updating graph…</p>}
        {!nodes.length ? <section className="border-t border-border py-5"><h2 className="font-semibold">
          {totalNodes ? "No symbols in this summary" : "No call graph recorded"}</h2><p className="mt-2 text-sm text-muted-foreground">
          {totalNodes ? "Choose Full graph to browse the scan’s other symbols." : "A scan report containing call graph data will show its symbols and calls here."}</p></section> :
        view === "structure" ? <StructureExplorer scanId={scanId} nodes={nodes} edges={edges} selectedId={selected?.id} onSelect={choose} /> :
        <section aria-label="Network" className="min-w-0">
          <div className="graph-network-tools">
            <input aria-label="Search network symbols" placeholder="Find a symbol or file" className="workbench-select min-h-11" value={search} onChange={(event) => setSearch(event.target.value)} />
            <select aria-label="Filter network node types" className="workbench-select min-h-11" value={filterType} onChange={(event) => setFilterType(event.target.value)}>
              <option value="">All types</option><option value="entry_point">Entry points</option><option value="sink">Sinks</option>
              <option value="function">Functions</option><option value="method">Methods</option><option value="module">Modules</option>
            </select>
            <div role="group" aria-label="Network zoom" className="graph-zoom">
              <button type="button" aria-label="Zoom out" title="Zoom out" onClick={() => zoom(1 / 1.5)}><ZoomOut aria-hidden /></button>
              <button type="button" aria-label="Zoom in" title="Zoom in" onClick={() => zoom(1.5)}><ZoomIn aria-hidden /></button>
              <button type="button" aria-label="Fit graph" title="Fit graph" onClick={() => { autoFitRef.current = false; graphRef.current?.zoomToFit(200, 40); }}><Maximize2 aria-hidden /></button>
            </div>
          </div>
          <div className="graph-network-layout">
            <div className="min-w-0">
              <div ref={containerRef} className="graph-canvas" aria-label="Network diagram">
                {graphData.nodes.length ? <ForceGraph2D
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
                      ? "rgba(172, 191, 183, 0.54)"
                      : "rgba(68, 91, 81, 0.49)"
                  }
                  linkWidth={1}
                  linkDirectionalArrowLength={3}
                  linkDirectionalArrowRelPos={1}
                  linkDirectionalArrowColor={() =>
                    document.documentElement.classList.contains("dark")
                      ? "rgba(172, 191, 183, 0.75)"
                      : "rgba(68, 91, 81, 0.77)"
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
                  onEngineStop={() => {
                    if (autoFitRef.current) { graphRef.current?.zoomToFit(200, 40); autoFitRef.current = false; }
                  }}
                /> : <p className="p-5 text-sm text-muted-foreground">No symbols match these filters.</p>}
              </div>
              <p className="mt-2 text-xs text-muted-foreground" role="status">{graphData.nodes.length.toLocaleString()} of {totalNodes.toLocaleString()} symbols · {graphData.links.length.toLocaleString()} of {totalEdges.toLocaleString()} calls</p>
              <ul aria-label="Network legend" className="graph-legend">
                {Object.entries(NODE_COLORS).map(([type, color]) => <li key={type}><i aria-hidden style={{ backgroundColor: color, borderRadius: type === "module" ? "1px" : "50%" }} />{type.replace("_", " ")}</li>)}
                <li><i aria-hidden className="rounded-full border-2 border-current" />Finding in file</li>
                <li><i aria-hidden className="rounded-full border border-dashed border-current" />Selected</li>
              </ul>
            </div>
            <aside className="graph-network-index" aria-label="Network symbols">
              {selected && <section><h2>Selected symbol</h2><h3 className="mt-2 font-mono font-semibold [overflow-wrap:anywhere]" title={selected.qualifiedName}>{graphSymbolName(selected.qualifiedName)}</h3>
                <p className="my-2 font-mono text-xs text-muted-foreground [overflow-wrap:anywhere]">{selected.filePath}{selected.lineStart > 0 && ":" + selected.lineStart}</p>
                {selected.hasFinding && selected.findingSeverity && <div className="flex items-center gap-2 text-xs text-muted-foreground">File finding <SeverityBadge severity={selected.findingSeverity} /></div>}
                <button type="button" className="block min-h-11 text-sm text-primary underline underline-offset-4" onClick={() => { choose(selected.id); setView("structure"); }}>Open in source structure</button>
              </section>}
              {[{ list: entries, label: "Entry points" }, { list: sinks, label: "Sinks" }].map(({ list, label }) => {
                return list.length > 0 && <section key={label}><h2>{label} <span className="text-xs font-normal text-muted-foreground">{list.length}</span></h2>
                  <ul className="max-h-52 overflow-auto">{list.slice(0, 30).map((node) => <li key={node.id}><button type="button" className="graph-call-row font-mono" aria-pressed={selected?.id === node.id}
                    onClick={() => choose(node.id)}>{getShortName(node.qualifiedName)}</button></li>)}</ul>
                  {list.length > 30 && <p className="text-xs text-muted-foreground">First 30 shown</p>}
                </section>;
              })}
            </aside>
          </div>
        </section>}
      </div>}
  </div>;
}
