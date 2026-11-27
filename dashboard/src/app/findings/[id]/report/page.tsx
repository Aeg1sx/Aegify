"use client";

import { use, useEffect, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { ArrowLeft, ArrowUpRight, Download, Printer } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { ConfigurationEvidence } from "@/components/finding/configuration-evidence";
import { Markdown } from "@/components/markdown";
import { SeverityBadge } from "@/components/severity-badge";
import { describeFlowMessage, EVIDENCE_LABELS, isConfigurationEvidence, lineRange, snippetStart } from "@/lib/code-evidence";
import { coverageSummary, reportFlow, reportScope, reportStatus, type ReportFinding } from "@/lib/finding-report";

function Field({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  return <div className={wide ? "col-span-2 min-w-0" : "min-w-0"}>
    <dt className="text-xs text-muted-foreground">{label}</dt>
    <dd className="mt-0.5 text-sm [overflow-wrap:anywhere]">{children}</dd>
  </div>;
}

function ReportTime({ value }: { value: string }) {
  return <time dateTime={value}>{value.slice(0, 19).replace("T", " ")} UTC</time>;
}

function Decision({ finding }: { finding: ReportFinding }) {
  const decision = finding.decision;
  return <section aria-labelledby="decision-heading" className="report-decision min-w-0 border-t-2 border-primary pt-3">
    <h2 id="decision-heading" className="text-base font-semibold">Triage decision</h2>
    {decision ? <>
      <p className="mt-1 text-xs text-muted-foreground">{reportScope(decision)}</p>
      <dl className="mt-4 grid grid-cols-2 gap-x-3 gap-y-3">
        <Field label="Current status"><strong className="text-lg font-semibold tracking-tight">{reportStatus(decision.status)}</strong></Field>
        <Field label="Current owner">{decision.owner || "Unassigned"}</Field>
        {decision.actor && <Field label="Recorded by">{decision.actor}</Field>}
        {decision.recordedAt && <Field label="Decision recorded"><ReportTime value={decision.recordedAt} /></Field>}
        {decision.expiresAt && <Field label="Expires"><ReportTime value={decision.expiresAt} /></Field>}
      </dl>
      {decision.reason ? <div className="mt-4 border-t border-input/70 pt-3">
        <h3 className="text-xs font-medium text-muted-foreground">Rationale</h3>
        <p className="mt-1 whitespace-pre-wrap text-sm leading-6 [overflow-wrap:anywhere]">{decision.reason}</p>
      </div> : <p className="mt-4 text-xs text-muted-foreground">No rationale recorded.</p>}
      {decision.needsReview && <p className="mt-3 text-sm">Historical assignments need review.</p>}
    </> : <p className="mt-2 text-sm">The current triage decision is unavailable.</p>}
  </section>;
}

export default function FindingReport({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <ReportRecord key={id} id={id} />;
}

function ReportRecord({ id }: { id: string }) {
  const [snapshot, setSnapshot] = useState<{ finding: ReportFinding; etag: string } | null>(null);
  const [error, setError] = useState("");
  const [downloadError, setDownloadError] = useState("");
  const [busy, setBusy] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const activeDownload = useRef<AbortController | null>(null);
  const url = "/api/findings/" + encodeURIComponent(id) + "/report";
  useEffect(() => {
    const controller = new AbortController();
    fetch(url + "?format=json", { signal: controller.signal, cache: "no-store" })
      .then(async (response) => {
        const content = await response.json();
        if (!response.ok) throw new Error(content.error || "Report unavailable.");
        const etag = response.headers.get("X-Aegify-Markdown-ETag");
        if (!etag) throw new Error("Report version unavailable.");
        if (!controller.signal.aborted) setSnapshot({ finding: content, etag });
      }).catch((cause) => { if (!controller.signal.aborted) setError(cause.message || "Report unavailable."); });
    return () => { controller.abort(); activeDownload.current?.abort(); };
  }, [url, attempt]);

  function reload() {
    activeDownload.current?.abort();
    setSnapshot(null);
    setError("");
    setDownloadError("");
    setBusy(false);
    setAttempt((value) => value + 1);
  }

  async function download() {
    if (!snapshot || activeDownload.current) return;
    const controller = new AbortController();
    activeDownload.current = controller;
    setBusy(true);
    setDownloadError("");
    try {
      const response = await fetch(url, { headers: { "If-Match": snapshot.etag }, signal: controller.signal, cache: "no-store" });
      if (!response.ok) throw new Error((await response.json()).error || "Download unavailable.");
      const blob = await response.blob();
      if (controller.signal.aborted) return;
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = "aegify-finding-report.md";
      link.click();
      setTimeout(() => URL.revokeObjectURL(href), 1000);
    } catch (cause) {
      if (!controller.signal.aborted) setDownloadError(cause instanceof Error ? cause.message : "Download unavailable.");
    } finally {
      activeDownload.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  if (error) return <div role="alert" className="space-y-3">
    <h1 className="workbench-title">Report unavailable</h1><p className="text-sm">{error}</p>
    <button className="min-h-11 text-sm font-semibold text-primary" onClick={reload}>Retry</button>
  </div>;
  if (!snapshot) return <p role="status" className="text-sm text-muted-foreground">Loading finding report…</p>;
  const { finding } = snapshot;
  const configuration = isConfigurationEvidence(finding.provenance);
  const flow = reportFlow(finding);
  return <article className="finding-report mx-auto max-w-[68rem] space-y-6 pb-4">
    <nav aria-label="Report actions" className="no-print flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-sm text-primary">
      <Link className="inline-flex min-h-11 items-center gap-2 hover:underline" href={"/findings/" + encodeURIComponent(id)}>
        <ArrowLeft aria-hidden className="size-4" />Back to finding
      </Link>
      <div className="flex flex-wrap gap-x-4">
        <button type="button" aria-label={busy ? "Downloading Markdown" : "Download Markdown"} className="inline-flex min-h-11 items-center gap-2 hover:underline disabled:opacity-60" onClick={download} disabled={busy}>
          <Download aria-hidden className="size-4" />{busy ? "Downloading…" : <span><span className="hidden sm:inline">Download </span>Markdown</span>}
        </button>
        <button type="button" aria-label="Print or save PDF" className="inline-flex min-h-11 items-center gap-2 hover:underline" onClick={() => window.print()}>
          <Printer aria-hidden className="size-4" /><span>Print<span className="hidden sm:inline"> / PDF</span></span>
        </button>
      </div>
    </nav>
    {downloadError && <div role="alert" className="no-print flex flex-wrap items-center gap-x-3 border-l-2 border-destructive pl-3 text-sm">
      {downloadError}<button onClick={reload} className="min-h-11 font-semibold text-primary">Reload report</button>
    </div>}
    <header className="border-t-2 border-foreground pt-4">
      <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <span>Finding report</span><span className="font-mono [overflow-wrap:anywhere]">{finding.ruleId}</span>
        <SeverityBadge severity={finding.severity} />
      </div>
      <h1 className="max-w-4xl text-balance text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">{finding.ruleName}</h1>
      <a className="report-location mt-1 inline-block max-w-full break-all font-mono text-xs leading-6 text-primary underline decoration-primary/40 underline-offset-4 hover:decoration-primary" href="#evidence-heading">{finding.filePath}:{lineRange(finding.lineStart, finding.lineEnd)}</a>
      <p className="mt-2 max-w-3xl text-sm leading-6 [overflow-wrap:anywhere]">{finding.message}</p>
    </header>
    <section className="report-coverage" aria-labelledby="coverage-heading">
      <h2 id="coverage-heading">Scan coverage</h2>
      <p><strong>{reportStatus(finding.scan.status || "")}</strong><span>{coverageSummary(finding.scan.coverage)}</span></p>
      {finding.scanId && <Link href={`/scans/${encodeURIComponent(finding.scanId)}`} className="no-print">
        View scan <ArrowUpRight aria-hidden className="size-3.5" /></Link>}
    </section>
    <div className="report-records grid items-start gap-x-8 gap-y-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
      <Decision finding={finding} />
      <section aria-labelledby="observation-heading" className="min-w-0 border-t border-input pt-3">
        <h2 id="observation-heading" className="text-base font-semibold">{finding.decision?.scope === "identity" && finding.isCurrent === false ? "Earlier scan observation" : "Scan observation"}</h2>
        <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3">
          <Field label="Repository">{finding.scan.repository || "Unavailable"}</Field>
          <Field label="Branch">{finding.scan.branch || "Unavailable"}</Field>
          <Field label="Stored status">{reportStatus(finding.status)}</Field>
          <Field label="Stored owner">{finding.owner || "Unassigned"}</Field>
          <Field label="Evidence">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified"}</Field>
          <Field label="CI disposition">{reportStatus(finding.disposition)}</Field>
          {finding.source && <Field label="Producer">{finding.source === "sast" ? "SAST" : finding.source}</Field>}
          {finding.scan.createdAt && <Field label="Scan recorded"><ReportTime value={finding.scan.createdAt} /></Field>}
          {finding.repositoryId && finding.repositoryId !== finding.scan.repository && <Field label="Repository ID">{finding.repositoryId}</Field>}
          {finding.scan.commitSha && <Field label="Commit" wide><code>{finding.scan.commitSha}</code></Field>}
        </dl>
      </section>
    </div>
    <section className="space-y-3 border-t border-input pt-4" aria-labelledby="evidence-heading">
      <h2 id="evidence-heading" className="text-xl font-semibold tracking-tight">{configuration ? "Configuration settings" : "Source evidence"}</h2>
      {configuration ? <ConfigurationEvidence finding={finding} /> : <>
        {finding.codeSnippet ? <CodeHighlight code={finding.codeSnippet} filePath={finding.filePath} lineStart={snippetStart(finding)}
          highlightStart={finding.lineStart} highlightEnd={finding.lineEnd} /> : <>
            <p className="break-all font-mono text-xs text-muted-foreground">{finding.filePath} · line {lineRange(finding.lineStart, finding.lineEnd)}</p>
            <p className="text-sm">No source snippet supplied.</p>
          </>}
      </>}
      {!configuration && !flow.steps.length && !flow.warning && <p className="text-xs text-muted-foreground">No flow recorded for this observation.</p>}
    </section>
    {!configuration && (flow.steps.length > 0 || flow.warning) && <section className="space-y-3 border-t border-input pt-4" aria-labelledby="report-flow-heading">
      <h2 id="report-flow-heading" className="text-xl font-semibold tracking-tight">Recorded flow</h2>
      {flow.warning && <p role="alert" className="text-sm">{flow.warning}</p>}
      {flow.steps.length > 0 && <ol aria-label="Flow source locations" className="report-trace">{flow.steps.map((step, index) => {
        const { label, value } = describeFlowMessage(step.message);
        return <li key={index}>
          {(index === 0 || step.file !== flow.steps[index - 1].file) && <p className="report-trace-file">{step.file || "Unknown file"}</p>}
          <div className="report-trace-row">
            <span className="report-trace-line"><span className="sr-only">{step.file}, line </span><span aria-hidden>L</span>{step.line}</span>
            <div className="min-w-0">
              <p>{label && <strong>{label}</strong>}{label && value && " "}{label ? <code>{value}</code> : value}</p>
              {step.snippet && <pre><code>{step.snippet}</code></pre>}
            </div>
          </div>
        </li>;
      })}</ol>}
    </section>}
    <section className="min-w-0 space-y-3 border-t border-input pt-4 [overflow-wrap:anywhere]">
      <h2 className="text-xl font-semibold tracking-tight">Remediation guidance</h2>
      {finding.remediation ? <Markdown content={finding.remediation} /> : <p className="text-sm">No remediation supplied.</p>}
    </section>
    <footer className="space-y-1 border-t pt-3 text-xs leading-5 text-muted-foreground [overflow-wrap:anywhere]">
      <p>Finding <code>{finding.id}</code></p>
      {finding.scanId && <p>Scan <code>{finding.scanId}</code></p>}
      {finding.evidenceId && <p>Evidence <code>{finding.evidenceId}</code></p>}
    </footer>
  </article>;
}
