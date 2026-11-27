"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { ChevronRight, X } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { lineRange, snippetStart } from "@/lib/code-evidence";
import { entryPath, graphSymbolName } from "@/lib/graph-path";
import { ConfigurationEvidence } from "@/components/finding/configuration-evidence";
import { isWranglerManifest } from "@/lib/configuration-evidence";

interface SourceNode {
  id: string; qualifiedName: string; filePath: string; lineStart: number; lineEnd: number;
  nodeType: string; hasFinding: boolean;
}
interface Edge { sourceNodeId: string; targetNodeId: string; callSiteLine: number }

export function StructureExplorer({ nodes, edges, selectedId, onSelect, scanId }: {
  nodes: SourceNode[]; edges: Edge[]; selectedId?: string; onSelect: (id: string) => void; scanId: string;
}) {
  const [filter, setFilter] = useState("");
  const [filesOpen, setFilesOpen] = useState(false);
  const filterInput = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const byId = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const selected = (selectedId && byId.get(selectedId)) || nodes.find((node) => node.hasFinding) || nodes[0];
  const groups = useMemo(() => {
    const files = new Map<string, SourceNode[]>();
    const term = filter.trim().toLowerCase();
    for (const node of nodes) {
      if (term && !node.filePath.toLowerCase().includes(term) && !node.qualifiedName.toLowerCase().includes(term)) continue;
      const members = files.get(node.filePath) || [];
      members.push(node);
      files.set(node.filePath, members);
    }
    for (const members of files.values()) members.sort((a, b) => a.lineStart - b.lineStart || a.qualifiedName.localeCompare(b.qualifiedName));
    return [...files.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [nodes, filter]);
  const path = useMemo(() => selected ? entryPath(nodes, edges, selected.id) : [], [nodes, edges, selected]);
  if (!selected) return null;

  function choose(id: string) {
    onSelect(id);
    setFilesOpen(false);
    heading.current?.focus();
  }
  const directions = [
    { title: "Called by", edges: edges.filter((edge) => edge.targetNodeId === selected.id), other: (edge: Edge) => edge.sourceNodeId },
    { title: "Calls", edges: edges.filter((edge) => edge.sourceNodeId === selected.id), other: (edge: Edge) => edge.targetNodeId },
  ];
  return <div className="graph-reader">
    <section aria-label="Source files" className="graph-files">
      <div className="hidden items-baseline justify-between gap-2 lg:flex">
        <h2 className="font-semibold">Source files</h2><span className="text-xs text-muted-foreground">{groups.length} {groups.length === 1 ? "file" : "files"}</span>
      </div>
      <button type="button" className="graph-file-toggle" aria-expanded={filesOpen} aria-controls="graph-file-index" onClick={() => setFilesOpen(!filesOpen)}>
        Browse source files <span className="ml-auto text-xs text-muted-foreground">{groups.length}</span>
        <ChevronRight aria-hidden className={filesOpen ? "size-4 rotate-90" : "size-4"} />
      </button>
      <div id="graph-file-index" className={filesOpen ? "block" : "hidden lg:block"}>
        <div className="relative my-3">
          <input ref={filterInput} aria-label="Filter source structure" placeholder="Find a file or symbol" className="workbench-select min-h-11 w-full pr-11" value={filter} onChange={(e) => setFilter(e.target.value)} />
          {filter && <button type="button" aria-label="Clear file filter" className="absolute inset-y-0 right-0 grid w-11 place-items-center text-muted-foreground hover:text-foreground" onClick={() => { setFilter(""); filterInput.current?.focus(); }}>
            <X aria-hidden className="size-4" />
          </button>}
        </div>
        <div className="max-h-[52vh] overflow-auto lg:max-h-[66vh]">
          {groups.map(([file, members]) => <details key={file} open={Boolean(filter) || file === selected.filePath} className="graph-file-group">
            <summary><ChevronRight aria-hidden className="graph-chevron size-3.5 shrink-0" /><span className="min-w-0 flex-1 font-mono [overflow-wrap:anywhere]">{file || "Unknown file"}</span></summary>
            <ul>{members.map((node) => <li key={node.id}>
              <button type="button" title={node.qualifiedName} onClick={() => choose(node.id)} aria-current={node.id === selected.id ? "true" : undefined}>
                <span className="min-w-0 [overflow-wrap:anywhere]">{graphSymbolName(node.qualifiedName)}</span>
                {node.lineStart > 0 && <span className="font-mono text-muted-foreground tabular-nums">L{node.lineStart}</span>}
              </button>
            </li>)}</ul>
          </details>)}
          {!groups.length && <p className="py-3 text-sm text-muted-foreground">No matching files or symbols.</p>}
        </div>
      </div>
    </section>
    <article className="min-w-0" aria-labelledby="graph-symbol-name">
      <header className="border-t-2 border-foreground pt-4">
        <p className="text-sm text-muted-foreground">{selected.nodeType.replaceAll("_", " ")}{selected.hasFinding && " · Finding in file"}</p>
        <h2 id="graph-symbol-name" title={selected.qualifiedName} ref={heading} tabIndex={-1} className="my-1 font-mono text-xl font-semibold tracking-tight [overflow-wrap:anywhere] sm:text-2xl">{graphSymbolName(selected.qualifiedName)}</h2>
        <p className="font-mono text-sm text-muted-foreground [overflow-wrap:anywhere]">{selected.filePath}{selected.lineStart > 0 && ":" + lineRange(selected.lineStart, selected.lineEnd)}</p>
      </header>
      <div className="my-5 grid gap-x-6 gap-y-3 sm:grid-cols-2">
        {directions.map((group) => <section key={group.title} aria-label={group.title} className="min-w-0 border-t border-border">
          <h3 className="flex items-baseline justify-between pt-3 font-semibold">{group.title}<span className="font-mono text-xs font-normal text-muted-foreground">{group.edges.length}</span></h3>
          {group.edges.length ? <ul className="divide-y divide-border">{group.edges.slice(0, 6).map((edge, i) => {
            const other = byId.get(group.other(edge));
            return other && <li key={i}><button type="button" className="graph-call-row" onClick={() => choose(other.id)}>
              <span className="font-mono [overflow-wrap:anywhere]" title={other.qualifiedName}>{graphSymbolName(other.qualifiedName)}</span>
              {edge.callSiteLine > 0 && <span className="whitespace-nowrap text-xs text-muted-foreground">Call at L{edge.callSiteLine}</span>}
            </button></li>;
          })}</ul> : <p className="py-3 text-sm text-muted-foreground">None recorded</p>}
          {group.edges.length > 6 && <p className="py-1 text-xs text-muted-foreground">First 6 shown. Open Network to see all loaded calls.</p>}
        </section>)}
      </div>
      <section aria-label="Recorded entry path" className="border-t border-border pt-3">
        <h3 className="font-semibold">Recorded entry path</h3>
        {path.length ? <ol className="graph-path">{path.slice(0, 30).map((id, index) => <li key={id}>
          {index > 0 && <ChevronRight aria-hidden className="size-3.5 shrink-0 text-muted-foreground" />}
          {id === selected.id ? <code title={selected.qualifiedName} aria-current="step">{graphSymbolName(selected.qualifiedName)}</code> :
            <button type="button" onClick={() => choose(id)} title={byId.get(id)?.qualifiedName}>{graphSymbolName(byId.get(id)?.qualifiedName || "")}</button>}
        </li>)}</ol> : <p className="mt-2 text-sm text-muted-foreground">No entry path appears in the loaded graph.</p>}
        {path.length > 30 && <p className="text-xs text-muted-foreground">Showing 30 of {path.length} symbols.</p>}
      </section>
      <GraphSource key={selected.id} node={selected} scanId={scanId} />
    </article>
  </div>;
}

function GraphSource({ node, scanId }: { node: SourceNode; scanId: string }) {
  const [finding, setFinding] = useState<{
    id: string; ruleName: string; filePath: string; lineStart: number; lineEnd: number; codeSnippet: string; provenance: string;
  } | null>(null);
  const [status, setStatus] = useState("Loading recorded source…");
  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams({ sourceNode: node.id });
    fetch(`/api/graph/${encodeURIComponent(scanId)}?${query}`, { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error("Source evidence could not be loaded.");
      const data = await response.json();
      if (!controller.signal.aborted) {
        setFinding(data.finding);
        setStatus("No recorded finding excerpt overlaps this symbol.");
      }
    }).catch((e) => { if (!controller.signal.aborted) setStatus(e.message); });
    return () => controller.abort();
  }, [node.id, scanId]);
  if (!finding) return <p role="status" className="mt-5 border-t border-border pt-4 text-sm text-muted-foreground">{status}</p>;
  return <section className="mt-5 min-w-0 border-t border-border pt-4" aria-label="Related finding">
    <h3 className="font-semibold">Related finding</h3>
    <Link className="inline-flex min-h-11 items-center text-sm text-primary underline underline-offset-4" href={`/findings/${finding.id}`}>{finding.ruleName}</Link>
    {isWranglerManifest(finding.filePath) ? <ConfigurationEvidence finding={finding} /> :
      <CodeHighlight code={finding.codeSnippet} filePath={finding.filePath} lineStart={snippetStart(finding)} highlightStart={finding.lineStart} highlightEnd={finding.lineEnd} />}
  </section>;
}
