"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ChevronRight, FileCode2, ArrowRight, CircleDot } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { snippetStart } from "@/lib/code-evidence";
import { entryPath } from "@/lib/graph-path";
import type { FindingEvidenceView } from "@/components/finding/evidence-workbench";

interface Node { id: string; qualifiedName: string; filePath: string; lineStart: number; lineEnd: number; nodeType: string; hasFinding: boolean }
interface Edge { sourceNodeId: string; targetNodeId: string; callSiteLine: number }
export function StructureExplorer({ nodes, edges, scanId }: { nodes: Node[]; edges: Edge[]; scanId: string }) {
  const [selectedId, setSelectedId] = useState("");
  const [filter, setFilter] = useState("");
  const byId = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const selected = byId.get(selectedId) || nodes.find((node) => node.hasFinding) || nodes[0];
  const groups = useMemo(() => {
    const files = new Map<string, Node[]>();
    for (const node of nodes) {
      if (filter && !(node.filePath + node.qualifiedName).toLowerCase().includes(filter.toLowerCase())) continue;
      const group = files.get(node.filePath) || [];
      group.push(node); files.set(node.filePath, group);
    }
    return [...files.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [nodes, filter]);
  const path = useMemo(() => selected ? entryPath(nodes, edges, selected.id) : [], [nodes, edges, selected]);
  if (!selected) return <p>No recorded nodes.</p>;
  const incoming = edges.filter((edge) => edge.targetNodeId === selected.id);
  const outgoing = edges.filter((edge) => edge.sourceNodeId === selected.id);
  const nodeButton = (node: Node, suffix?: string) => <button type="button" onClick={() => setSelectedId(node.id)} className={`w-full rounded-md border p-3 text-left transition-colors hover:border-primary/50 ${node.id === selected.id ? "border-primary/50 bg-primary/5" : "border-border bg-card"}`}><span className="block break-all font-mono text-xs">{node.qualifiedName}</span><span className="mt-1 block text-[11px] text-muted-foreground">{suffix || node.nodeType.replaceAll("_", " ")}{node.hasFinding && " · finding"}</span></button>;
  return <div className="grid items-start gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
    <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-xs font-semibold">Source structure</h2><span className="font-mono text-xs text-muted-foreground">{groups.length} files</span></div><div className="p-3"><input aria-label="Filter source structure" placeholder="Find file or symbol…" className="workbench-select w-full" value={filter} onChange={(e) => setFilter(e.target.value)} /></div>
      <div className="max-h-[70vh] overflow-auto px-2 pb-3">{groups.map(([file, members]) => <details key={file} open={filter ? true : undefined} className="group text-xs"><summary className="flex cursor-pointer items-center gap-2 rounded px-2 py-2.5 hover:bg-accent"><FileCode2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" /><span className="min-w-0 flex-1 truncate" title={file}>{file || "Unknown file"}</span><span className="font-mono text-[10px] text-muted-foreground">{members.length}</span></summary><div className="ml-4 border-l border-border pl-2">{members.map((node) => <button key={node.id} type="button" title={node.qualifiedName} onClick={() => setSelectedId(node.id)} className={`flex w-full items-center gap-2 rounded px-2 py-2 text-left ${node.id === selected.id ? "bg-primary/10 text-primary" : "hover:bg-accent"}`}><CircleDot className={`h-3 w-3 shrink-0 ${node.hasFinding ? "text-destructive" : "text-muted-foreground"}`} /><span className="truncate font-mono">{node.qualifiedName}</span></button>)}</div></details>)}{!groups.length && <p className="p-3 text-muted-foreground">No matching symbols.</p>}</div>
    </section>
    <div className="min-w-0 space-y-4">
      <section className="workbench-panel"><div className="workbench-heading"><div className="min-w-0"><p className="eyebrow mb-2">Recorded connections</p><h2 className="break-all font-mono text-sm font-semibold">{selected.qualifiedName}</h2><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{selected.filePath}:{selected.lineStart}–{selected.lineEnd}</p></div></div>
        <div className="bg-[radial-gradient(var(--border)_1px,transparent_1px)] [background-size:16px_16px] p-5">
          <div className="grid items-start gap-3 md:grid-cols-[1fr_20px_1fr_20px_1fr]">
            <div className="space-y-2"><p className="eyebrow mb-3">Callers · {incoming.length}</p>{incoming.slice(0, 6).map((edge, i) => <div key={i}>{byId.has(edge.sourceNodeId) && nodeButton(byId.get(edge.sourceNodeId)!, `call at L${edge.callSiteLine}`)}</div>)}{!incoming.length && <p className="text-xs text-muted-foreground">None recorded</p>}</div>
            <ArrowRight className="mt-10 hidden h-4 w-4 text-muted-foreground md:block" />
            <div className="space-y-3"><p className="eyebrow">Selected symbol</p>{nodeButton(selected)}</div>
            <ArrowRight className="mt-10 hidden h-4 w-4 text-muted-foreground md:block" />
            <div className="space-y-2"><p className="eyebrow mb-3">Callees · {outgoing.length}</p>{outgoing.slice(0, 6).map((edge, i) => <div key={i}>{byId.has(edge.targetNodeId) && nodeButton(byId.get(edge.targetNodeId)!, `call at L${edge.callSiteLine}`)}</div>)}{!outgoing.length && <p className="text-xs text-muted-foreground">None recorded</p>}</div>
          </div>
          {(incoming.length > 6 || outgoing.length > 6) && <p className="mt-4 text-xs text-muted-foreground">Showing the first 6 connections per direction. Use the network view for all loaded edges.</p>}
        </div>
        <div className="border-t border-border p-5"><p className="eyebrow mb-3">One recorded entry path</p>{path.length > 0 ? <ol className="flex flex-wrap items-center gap-2">{path.slice(0, 30).map((id, index) => <li key={id} className="flex items-center gap-2"><button type="button" onClick={() => setSelectedId(id)} className="max-w-56 truncate rounded border bg-muted/40 px-2 py-1.5 font-mono text-xs" title={byId.get(id)?.qualifiedName}>{byId.get(id)?.qualifiedName}</button>{index < path.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}</li>)}</ol> : <p className="text-xs text-muted-foreground">No entry path found in the loaded subgraph. This does not establish unreachability.</p>}{path.length > 30 && <p className="mt-2 text-xs text-muted-foreground">Path display limited to 30 of {path.length} symbols.</p>}<p className="mt-3 text-[11px] leading-5 text-muted-foreground">Call relationships only. Data flow, authentication, service boundaries, and runtime behavior require separate evidence.</p></div>
      </section>
      <GraphSource key={selected.id} node={selected} scanId={scanId} />
    </div>
  </div>;
}

function GraphSource({ node, scanId }: { node: Node; scanId: string }) {
  const [finding, setFinding] = useState<FindingEvidenceView | null>(null);
  const [status, setStatus] = useState("Loading recorded source…");
  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams({ scanId, search: node.filePath, limit: "100" });
    fetch(`/api/findings?${query}`, { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error("Source evidence could not be loaded.");
      const data = await response.json();
      const match = (data.findings || []).find((item: FindingEvidenceView) => item.filePath === node.filePath && item.lineStart <= node.lineEnd && item.lineEnd >= node.lineStart && item.codeSnippet);
      if (!controller.signal.aborted) { setFinding(match || null); setStatus(data.total > 100 ? "No matching snippet in the first 100 findings. Open the scan to inspect the complete results." : "No finding snippet overlaps this symbol. Source code has not been fetched or invented."); }
    }).catch((e) => { if (!controller.signal.aborted) setStatus(e.message); });
    return () => controller.abort();
  }, [node, scanId]);
  if (!finding) return <div className="workbench-panel p-5 text-sm text-muted-foreground">{status}</div>;
  return <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-xs font-semibold">Related finding · {finding.ruleName}</h2><Link className="text-xs text-primary" href={`/findings/${finding.id}`}>Inspect evidence →</Link></div><div className="p-4"><CodeHighlight code={finding.codeSnippet} filePath={finding.filePath} lineStart={snippetStart(finding)} highlightStart={finding.lineStart} highlightEnd={finding.lineEnd} /></div></section>;
}
