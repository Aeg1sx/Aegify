"use client";
import { use, useEffect, useState } from "react";
import Link from "next/link";
import { Download, Printer } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { Markdown } from "@/components/markdown";
import { SeverityBadge } from "@/components/severity-badge";
import { EVIDENCE_LABELS, parseEvidenceSteps, snippetStart } from "@/lib/code-evidence";
import type { ReportFinding } from "@/lib/finding-report";

export default function FindingReport({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [finding, setFinding] = useState<ReportFinding | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/findings/${encodeURIComponent(id)}`, { signal: controller.signal }).then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Report unavailable");
      if (!controller.signal.aborted) setFinding(data);
    }).catch((e) => { if (!controller.signal.aborted) setError(String(e.message)); });
    return () => controller.abort();
  }, [id]);
  if (error) return <p role="alert">{error}</p>;
  if (!finding) return <p role="status">Preparing report…</p>;
  const flow = parseEvidenceSteps(finding.taintFlow);
  return <article className="mx-auto max-w-5xl space-y-7 pb-12">
    <nav className="no-print flex flex-wrap items-center justify-between gap-4 text-sm"><Link href={`/findings/${id}`}>← Finding</Link><div className="flex gap-4"><a className="flex items-center gap-2" href={`/api/findings/${encodeURIComponent(id)}/report`}><Download className="h-4 w-4" />Markdown</a><button type="button" className="flex items-center gap-2" onClick={() => window.print()}><Printer className="h-4 w-4" />Print / PDF</button></div></nav>
    <header className="border-b border-border pb-6"><p className="eyebrow mb-4">Aegify / Vulnerability report</p><h1 className="text-3xl font-semibold tracking-tight">{finding.ruleName}</h1><div className="mt-4 flex flex-wrap items-center gap-3"><SeverityBadge severity={finding.severity} /><span className="text-sm">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified"}</span><span className="font-mono text-xs text-muted-foreground">{finding.ruleId}</span></div></header>
    <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-sm md:grid-cols-4">{Object.entries({ Repository: finding.scan.repository, Branch: finding.scan.branch, Commit: finding.scan.commitSha || "Not supplied", Owner: finding.owner || "Unassigned", Status: finding.status, Gate: finding.disposition }).map(([label, value]) => <div key={label}><dt className="eyebrow mb-1">{label}</dt><dd className="break-all">{value}</dd></div>)}</dl>
    <section><h2 className="mb-3 text-lg font-semibold">Summary</h2><p className="text-sm leading-7">{finding.message}</p></section>
    <section className="space-y-3"><h2 className="text-lg font-semibold">Source evidence</h2><p className="text-sm text-muted-foreground">Reported location: {finding.filePath}:{finding.lineStart}–{finding.lineEnd}</p><CodeHighlight code={finding.codeSnippet} filePath={finding.filePath} lineStart={snippetStart(finding)} highlightStart={finding.lineStart} highlightEnd={finding.lineEnd} /></section>
    <section className="space-y-3"><h2 className="text-lg font-semibold">Recorded flow</h2><p className="text-xs text-muted-foreground">Static connections are not evidence of runtime exploitability.</p>{flow.warning && <p role="alert" className="text-sm text-amber-600">{flow.warning}</p>}<ol className="divide-y divide-border">{flow.steps.map((step, index) => <li key={index} className="flex gap-4 py-3 text-sm"><span className="font-mono text-muted-foreground">{String(index + 1).padStart(2, "0")}</span><div><p>{step.message}</p><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{step.file}:{step.line}</p></div></li>)}</ol>{!flow.steps.length && <p className="text-sm text-muted-foreground">No structured flow supplied.</p>}</section>
    <section><h2 className="mb-3 text-lg font-semibold">Remediation guidance</h2>{finding.remediation ? <Markdown content={finding.remediation} /> : <p className="text-sm text-muted-foreground">No remediation supplied.</p>}</section>
    <footer className="border-t border-border pt-4 text-xs leading-6 text-muted-foreground">This report preserves the scanner classification. AI suggestions, static paths, runtime observations, and impact evidence are separate claims. Guidance is not an applied or verified patch.<br /><span className="font-mono">Finding {finding.id}</span></footer>
  </article>;
}
