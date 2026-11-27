"use client";

import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import Link from "next/link";
import { ArrowUpRight, ChevronRight, FileCode2, FileText, GitBranch, X } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { ConfigurationEvidence } from "@/components/finding/configuration-evidence";
import { Markdown } from "@/components/markdown";
import { SeverityBadge } from "@/components/severity-badge";
import { codePreview, describeFlowMessage, EVIDENCE_LABELS, isConfigurationEvidence, parseEvidenceSteps, snippetStart } from "@/lib/code-evidence";

export interface FindingEvidenceView {
  id: string; scanId: string; ruleId: string; ruleName: string; severity: string;
  evidenceState: string; status: string; filePath: string; lineStart: number; lineEnd: number;
  codeSnippet: string; message: string; provenance?: string; taintFlow?: string | null;
  remediation?: string | null; owner?: string; baselineState?: string; disposition?: string;
}

type View = "source" | "flow" | "remediation";

export function EvidenceWorkbench({ finding, onClose, detailQuery = "" }: { finding: FindingEvidenceView; onClose?: () => void; detailQuery?: string }) {
  const [tab, setTab] = useState<View>("source");
  const configuration = isConfigurationEvidence(finding.provenance);
  const flow = parseEvidenceSteps(finding.taintFlow);
  const views: View[] = !configuration && (flow.steps.length || flow.warning) ? ["source", "flow", "remediation"] : ["source", "remediation"];
  const [selectedLine, setSelectedLine] = useState<number>();
  const tabsId = useId();
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);
  const reader = useRef<HTMLElement>(null);
  useEffect(() => {
    if (onClose || window.location.hash !== "#finding-evidence") return;
    // The evidence mounts after the finding request, after native fragment navigation.
    reader.current?.focus({ preventScroll: true });
    reader.current?.scrollIntoView({ block: "start" });
  }, [finding.id, onClose]);
  const start = snippetStart(finding);
  const end = start === null || !finding.codeSnippet ? null : start + codePreview(finding.codeSnippet).lines.length - 1;
  function changeTab(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const destination = { ArrowRight: (index + 1) % views.length, ArrowLeft: (index + views.length - 1) % views.length, Home: 0, End: views.length - 1 }[event.key];
    if (destination === undefined) return;
    event.preventDefault();
    setTab(views[destination]);
    buttons.current[destination]?.focus();
  }
  const tabs = <div className="evidence-tabs" role="tablist" aria-label="Evidence views">
    {views.map((name, index) => <button type="button" key={name} ref={el => { buttons.current[index] = el; }} id={tabsId + name} role="tab" aria-controls={tabsId + "-panel"} aria-selected={tab === name} tabIndex={tab === name ? 0 : -1} onKeyDown={event => changeTab(event, index)} onClick={() => setTab(name)}>
      {configuration && name === "source" ? "Settings" : name}{name === "flow" && ` · ${flow.steps.length}`}
    </button>)}
  </div>;
  return <section ref={reader} id={onClose ? "finding-inspector" : "finding-evidence"} tabIndex={-1} className="evidence-reader workbench-panel h-fit scroll-mt-3" aria-label="Finding evidence inspector" onKeyDown={event => {
    if (event.key === "Escape" && onClose) { event.stopPropagation(); onClose(); }
  }}>
    <div className={onClose ? "workbench-heading" : "evidence-toolbar"}>
      <h2 className={onClose ? "text-sm font-semibold" : "text-lg font-semibold tracking-tight"}>Finding evidence</h2>
      {!onClose && tabs}
      {onClose && <div className="-my-2 flex items-center text-muted-foreground">
        <Link className="grid size-11 place-items-center rounded-md hover:bg-accent" href={`/findings/${finding.id}/report`} aria-label="Open finding report" title="Open report"><FileText aria-hidden className="size-4" /></Link>
        <Link className="grid size-11 place-items-center rounded-md hover:bg-accent" href={`/findings/${finding.id}${detailQuery}`} aria-label="Open full finding" title="Open full finding"><ArrowUpRight aria-hidden className="size-4" /></Link>
        <button className="hidden size-11 place-items-center rounded-md hover:bg-accent md:grid" type="button" aria-label="Close inspector" title="Close inspector" onClick={onClose}><X aria-hidden className="size-4" /></button>
      </div>}
    </div>
    {onClose && <div className="space-y-3 p-5">
      <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="text-xs text-muted-foreground">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified evidence"}</span></div>
      <h2 className="text-lg font-semibold tracking-tight">{finding.ruleName}</h2>
      <p className="text-sm leading-6 text-muted-foreground">{finding.message}</p>
      <div className="flex flex-wrap gap-2 text-xs"><Link className="font-mono text-primary" href={`/rules/${encodeURIComponent(finding.ruleId)}`}>{finding.ruleId}</Link><span className="text-muted-foreground">· {finding.owner || "Unassigned"}</span></div>
    </div>}
    {onClose && <div className="border-y px-4">{tabs}</div>}
    <div id={tabsId + "-panel"} className={onClose ? "space-y-4 p-4" : "space-y-4 py-4"} role="tabpanel" tabIndex={0} aria-labelledby={tabsId + tab}>
      {tab === "source" && (configuration ? <ConfigurationEvidence finding={finding} /> :
        <CodeHighlight code={finding.codeSnippet} filePath={finding.filePath} lineStart={start} highlightStart={finding.lineStart} highlightEnd={finding.lineEnd} selectedLine={selectedLine} onLineSelect={setSelectedLine} />)}
      {tab === "flow" && <>
        <div className="flex items-center gap-2 text-sm font-medium"><GitBranch aria-hidden className="size-4 text-muted-foreground" />Recorded static flow</div>
        {flow.warning && <p role="alert" className="text-sm text-amber-600">{flow.warning}</p>}
        {!flow.steps.length && <p className="py-4 text-sm text-muted-foreground">No structured flow evidence in this artifact.</p>}
        <ol className="evidence-flow" aria-label="Recorded flow steps">{flow.steps.map((step, index) => {
          const available = start !== null && end !== null && step.file === finding.filePath && step.line >= start && step.line <= end;
          const { label, value } = describeFlowMessage(step.message);
          const fileStart = index === 0 || flow.steps[index - 1].file !== step.file;
          const separator = Math.max(step.file.lastIndexOf("/"), step.file.lastIndexOf("\\"));
          const description = <span className="flow-description">
            {label && <strong>{label}</strong>}
            {value && (label ? <code>{value}</code> : <span>{value}</span>)}
          </span>;
          return <li key={index}>
            {fileStart && <p className="flow-file"><FileCode2 aria-hidden className="size-4 shrink-0" />
              <span className="font-medium">{step.file.slice(separator + 1) || "Unknown file"}</span>
              {separator >= 0 && <span className="flow-directory">{step.file.slice(0, separator + 1)}</span>}
            </p>}
            {available ? <div className="flow-row"><button type="button" className="flow-line" aria-label={"Show source line " + step.line + " in " + step.file}
              onClick={() => { setSelectedLine(step.line); setTab("source"); buttons.current[0]?.focus(); }}>
              L{step.line}<ArrowUpRight aria-hidden />
            </button>{description}</div> : step.snippet ? <details className="flow-disclosure">
              <summary className="flow-row"><span className="flow-line">L{step.line}<ChevronRight aria-hidden /></span>
                <span className="sr-only">Recorded excerpt in {step.file}. </span>{description}</summary>
              <pre className="flow-excerpt"><code>{step.snippet}</code></pre>
            </details> : <div className="flow-row">
              <span className="flow-line" title="Source excerpt unavailable">L{step.line}<span className="sr-only"> in {step.file}. Source excerpt unavailable.</span></span>{description}
            </div>}
          </li>;
        })}</ol>
        <Link href={`/graph/${finding.scanId}`} className="inline-flex min-h-11 items-center gap-1 text-sm text-primary underline underline-offset-4">Open scan call graph <ArrowUpRight aria-hidden className="size-3.5" /></Link>
      </>}
      {tab === "remediation" && <>
        {finding.remediation ? <Markdown content={finding.remediation} /> : <div className="space-y-1 text-sm">
          <p className="text-muted-foreground">This finding has no recorded remediation.</p>
          <Link href={`/rules/${encodeURIComponent(finding.ruleId)}`} className="inline-flex min-h-11 items-center gap-1.5 font-medium text-primary hover:underline">View rule {finding.ruleId}<ArrowUpRight aria-hidden className="size-3.5" /></Link>
        </div>}
      </>}
    </div>
  </section>;
}
