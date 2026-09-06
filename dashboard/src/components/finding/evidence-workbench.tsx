"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowUpRight, Download, GitBranch, X } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { Markdown } from "@/components/markdown";
import { SeverityBadge } from "@/components/severity-badge";
import { EVIDENCE_LABELS, parseEvidenceSteps, snippetStart } from "@/lib/code-evidence";

export interface FindingEvidenceView {
  id: string; scanId: string; ruleId: string; ruleName: string; severity: string;
  evidenceState: string; status: string; filePath: string; lineStart: number; lineEnd: number;
  codeSnippet: string; message: string; provenance?: string; taintFlow?: string | null;
  remediation?: string | null; owner?: string; baselineState?: string; disposition?: string;
}

export function EvidenceWorkbench({ finding, onClose }: { finding: FindingEvidenceView; onClose?: () => void }) {
  const [tab, setTab] = useState<"source" | "flow" | "remediation">("source");
  const [selectedLine, setSelectedLine] = useState<number>();
  const flow = parseEvidenceSteps(finding.taintFlow);
  const start = snippetStart(finding);
  const end = start === null ? null : start + finding.codeSnippet.split("\n").length - 1;
  return <section className="workbench-panel h-fit" aria-label="Finding evidence inspector">
    <div className="workbench-heading">
      <span className="eyebrow">Evidence inspector</span>
      <div className="flex gap-3">
        <Link className="text-xs text-muted-foreground hover:text-foreground" href={`/findings/${finding.id}/report`} aria-label="Open vulnerability report"><Download className="h-4 w-4" /></Link>
        <Link className="text-xs text-muted-foreground hover:text-foreground" href={`/findings/${finding.id}`} aria-label="Open full finding"><ArrowUpRight className="h-4 w-4" /></Link>
        {onClose && <button type="button" aria-label="Close inspector" onClick={onClose}><X className="h-4 w-4" /></button>}
      </div>
    </div>
    <div className="space-y-3 p-5">
      <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="text-xs text-muted-foreground">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified evidence"}</span></div>
      <h2 className="text-lg font-semibold tracking-tight">{finding.ruleName}</h2>
      <p className="text-sm leading-6 text-muted-foreground">{finding.message}</p>
      <div className="flex flex-wrap gap-2 text-xs"><Link className="font-mono text-primary" href={`/rules/${encodeURIComponent(finding.ruleId)}`}>{finding.ruleId}</Link><span className="text-muted-foreground">· {finding.owner || "Unassigned"}</span></div>
    </div>
    <div className="flex border-y border-border px-4" role="tablist" aria-label="Evidence views">
      {(["source", "flow", "remediation"] as const).map((name) => <button type="button" key={name} role="tab" aria-selected={tab === name} onClick={() => setTab(name)} className={`border-b-2 px-3 py-3 text-xs font-medium capitalize ${tab === name ? "border-primary text-primary" : "border-transparent text-muted-foreground"}`}>{name}{name === "flow" && ` · ${flow.steps.length}`}</button>)}
    </div>
    <div className="space-y-4 p-4" role="tabpanel" aria-label={tab}>
      {tab === "source" && <>
        <p className="text-xs text-muted-foreground">Reported location <span className="font-mono text-foreground">L{finding.lineStart}–{finding.lineEnd}</span></p>
        <CodeHighlight code={finding.codeSnippet} filePath={finding.filePath} lineStart={start} highlightStart={finding.lineStart} highlightEnd={finding.lineEnd} selectedLine={selectedLine} onLineSelect={setSelectedLine} />
      </>}
      {tab === "flow" && <>
        <div className="flex items-center gap-2 text-xs text-muted-foreground"><GitBranch className="h-4 w-4" />Recorded static flow · runtime behavior is separate</div>
        {flow.warning && <p role="alert" className="text-sm text-amber-600">{flow.warning}</p>}
        {!flow.steps.length && <p className="py-4 text-sm text-muted-foreground">No structured flow evidence in this artifact.</p>}
        <ol className="space-y-0">{flow.steps.map((step, index) => {
          const available = start !== null && end !== null && step.file === finding.filePath && step.line >= start && step.line <= end;
          return <li key={index} className="relative ml-3 border-l border-border pb-5 pl-6 last:border-transparent">
            <span className="absolute -left-3 grid h-6 w-6 place-items-center rounded-full border bg-card font-mono text-[11px]">{index + 1}</span>
            <p className="text-sm">{step.message}</p><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{step.file}:{step.line}</p>
            {available ? <button type="button" onClick={() => { setSelectedLine(step.line); setTab("source"); }} className="mt-2 text-xs text-primary">Show source line →</button> : <span className="mt-2 block text-[11px] text-muted-foreground">Source context not included</span>}
          </li>;
        })}</ol>
        <Link href={`/graph/${finding.scanId}`} className="text-xs text-primary">Explore scan call graph →</Link>
      </>}
      {tab === "remediation" && <>
        <p className="text-xs text-muted-foreground">Recorded guidance · changes are not applied automatically</p>
        {finding.remediation ? <Markdown content={finding.remediation} /> : <p className="py-4 text-sm text-muted-foreground">No remediation was supplied. Review the rule and source before proposing a patch.</p>}
      </>}
    </div>
  </section>;
}
