"use client";

import { useEffect, useId, useState } from "react";
import Link from "next/link";
import type { SavedReview } from "@/lib/ai-review-history";
import { normalizeAIReviewEvidence } from "@/lib/ai-review-evidence";
import { AIToolEvidence } from "./finding/ai-tool-evidence";
import { ArrowDownToLine, ArrowUpRight, RefreshCw } from "lucide-react";
import { CodeHighlight } from "./code-highlight";
import { ConfigurationEvidence } from "./finding/configuration-evidence";
import { isConfigurationEvidence, snippetStart, sourceLine } from "@/lib/code-evidence";
import { isWranglerManifest } from "@/lib/configuration-evidence";
import { Button } from "./ui/button";
import { SeverityBadge } from "./severity-badge";
import type { AiReviewJob } from "./ai-review-job-card";

interface Summary {
  id: string; findingId: string; ruleId: string; ruleName: string; severity: string;
  filePath: string; lineStart: number; verdict: string; metadataTruncated: boolean;
}
interface HistoryPage {
  historyVersion: number; saved: number; totalFindings: number; published: number;
  preservedHumanDecisions: number; missingReviewHistory: number;
  reviews: Summary[]; nextCursor: string | null;
}
interface HistoryDetail {
  record: SavedReview; payloadDigest: string;
  current: {
    findingId: string; status: string; aiReviewStatus: string; state: string;
    triage: { scope: string; status: string };
  } | null;
}
const verdicts: Record<string, string> = {
  likely_true_positive: "Likely true positive", likely_false_positive: "Likely false positive", needs_review: "Needs review",
};
async function readJson<T>(response: Response): Promise<T> {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Saved reviews are unavailable.");
  return data as T;
}

function SavedSource({ record }: { record: SavedReview }) {
  const data = record.finding.data;
  const filePath = typeof data.filePath === "string" ? data.filePath : "";
  const codeSnippet = typeof data.codeSnippet === "string" ? data.codeSnippet : "";
  const start = sourceLine(data.lineStart), end = sourceLine(data.lineEnd);
  const configuration = isConfigurationEvidence(data.provenance) ||
    [filePath, data.modulePath].some((path) => typeof path === "string" && isWranglerManifest(path));
  if (configuration) {
    if (!start) return <p className="text-sm text-muted-foreground">This review has no located configuration evidence.</p>;
    return <ConfigurationEvidence finding={{ filePath, lineStart: start, lineEnd: end ?? start, codeSnippet }} />;
  }
  if (!codeSnippet) return <p className="text-sm text-muted-foreground">This review was saved without a source excerpt.</p>;
  const offset = start ? snippetStart({ provenance: typeof data.provenance === "string" ? data.provenance : undefined, codeSnippet, lineStart: start, lineEnd: end ?? start }) : null;
  return <CodeHighlight code={codeSnippet} filePath={filePath} lineStart={offset} highlightStart={start ?? undefined} highlightEnd={end ?? undefined} />;
}

function SavedResult({ detail, root }: { detail: HistoryDetail; root: string }) {
  const { record, current } = detail;
  const { result, finding } = record;
  const title = String(finding.data.ruleName || finding.data.ruleId || "Untitled finding");
  return <article className="min-w-0 space-y-5 [overflow-wrap:anywhere]">
    <header>
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <SeverityBadge severity={String(finding.data.severity || "unknown")} />
        {finding.data.ruleId && <span className="font-mono">{finding.data.ruleId}</span>}
      </div>
      <h3 className="mt-2 text-xl font-semibold leading-tight tracking-tight sm:text-2xl">{title}</h3>
      <div className="mt-4 flex flex-wrap gap-x-8 gap-y-3 border-y py-3 text-sm" aria-label="Review decisions">
        <div><p className="text-xs text-muted-foreground">Model verdict</p><p className="mt-1 font-semibold">{verdicts[result.verdict]}</p>
          {result.verdict !== "needs_review" && <p className="mt-1 text-xs text-muted-foreground">{Math.round(result.confidence * 100)}% model estimate</p>}</div>
        {current && <div><p className="text-xs text-muted-foreground">{current.triage.scope === "identity" ? "Tracked finding status" : "Scan finding status"}</p>
          <p className="mt-1 font-medium capitalize">{current.triage.status.replaceAll("_", " ")}</p></div>}
      </div>
    </header>
    <section aria-label="Evidence supplied to this review">
      <h4 className="mb-2 text-sm font-semibold">Reviewed source</h4>
      <SavedSource record={record} />
      {finding.omittedFields.length > 0 && <details className="mt-1 text-xs text-muted-foreground"><summary className="w-fit cursor-pointer py-2">Input limits ({finding.omittedFields.length} fields)</summary><p className="pb-2">{finding.omittedFields.join(", ")}</p></details>}
    </section>
    <section><h4 className="text-sm font-semibold">Analysis</h4><p className="mt-1.5 whitespace-pre-wrap text-sm leading-6">{result.reasoning}</p></section>
    {result.evidenceGaps.length > 0 && <section className="border-l-2 border-input pl-3"><h4 className="text-sm font-semibold">Evidence gaps</h4>
      <ul className="mt-1 space-y-1 text-sm leading-6">{result.evidenceGaps.map((value, index) => <li className="whitespace-pre-wrap" key={index}>{value}</li>)}</ul></section>}
    {result.remediation && <section><h4 className="text-sm font-semibold">Suggested fix</h4><p className="mt-1.5 whitespace-pre-wrap text-sm leading-6">{result.remediation}</p></section>}
    {result.adjustedSeverity && <p className="text-sm">Suggested severity · <strong>{result.adjustedSeverity}</strong></p>}
    {([["Supporting evidence", result.evidenceFor], ["Contrary evidence", result.evidenceAgainst]] as const).filter(([, values]) => values.length > 0).map(([label, values]) =>
      <details key={label} className="text-sm"><summary className="cursor-pointer font-medium">{label} ({values.length})</summary><ul className="mt-2 list-disc space-y-1 pl-5 leading-6">{values.map((value, index) => <li className="whitespace-pre-wrap" key={index}>{value}</li>)}</ul></details>)}
    {record.sourceEvidence && <section className="space-y-3">
      <p className="text-xs leading-5 text-muted-foreground">{record.sourceEvidence.catalog.files} files in the review snapshot · commit <span className="break-all font-mono">{record.sourceEvidence.catalog.commit}</span>. {record.sourceEvidence.catalog.truncated ? `The review omitted ${record.sourceEvidence.catalog.omittedFiles} additional files. The original fetch may also be incomplete.` : "Coverage is limited to the stored provider snapshot."}</p>
      {!!record.sourceEvidence.catalog.unverifiedSigningKeyFiles && <p className="text-xs leading-5 text-muted-foreground">
        The review excluded {record.sourceEvidence.catalog.unverifiedSigningKeyFiles} {record.sourceEvidence.catalog.unverifiedSigningKeyFiles === 1 ? "Python file" : "Python files"} because it could not verify signing-key redaction.
      </p>}
      <AIToolEvidence evidence={normalizeAIReviewEvidence({ ...record.sourceEvidence })} />
    </section>}
    <section className="space-y-1 border-t pt-4 text-sm">
      <h4 className="font-semibold">Finding record</h4>
      <p className="text-sm leading-6">{record.publication === "human_decision_preserved" ? "An existing human decision was preserved when this review was saved." : "Published as a suggestion when this batch completed."}</p>
      {current ? <>
        {current.state === "superseded" && <p className="text-muted-foreground">The finding currently displays a different suggestion.</p>}
        {current.state === "source_changed" && <p className="text-muted-foreground">The source evidence has changed since this review.</p>}
        <dl className="mt-2 flex flex-wrap gap-x-2 text-xs"><dt className="text-muted-foreground">Suggestion on this observation</dt><dd className="capitalize">{current.aiReviewStatus}</dd></dl>
        <Link href={`/findings/${encodeURIComponent(current.findingId)}`} className="inline-flex min-h-11 items-center gap-1 font-medium text-primary underline underline-offset-4">Open finding <ArrowUpRight aria-hidden className="size-3.5" /></Link>
      </> : <p className="text-muted-foreground">The original scan finding has been removed.</p>}
    </section>
    <footer className="border-t text-xs">
      <details><summary className="w-fit cursor-pointer py-3.5 font-medium">Review provenance</summary>
        <p className="mb-3 leading-5">{record.provider} · {record.model} · {new Date(record.createdAt).toLocaleString()}</p>
        <dl className="space-y-2 break-all pb-3">{Object.entries({ "Saved record": detail.payloadDigest, "Input snapshot": record.inputDigest, "Finding evidence": finding.evidenceDigest, "Source scan": record.scanDigest, Prompt: record.promptDigest, "Provider response": record.responseDigest, Call: record.callId }).map(([key, value]) => <div key={key}><dt className="text-muted-foreground">{key}</dt><dd className="font-mono">{value}</dd></div>)}</dl>
      </details>
      <a className="inline-flex min-h-11 items-center gap-2 text-primary underline underline-offset-4" href={`${root}/${encodeURIComponent(record.id)}`} download={`aegify-review-${record.id}.json`}><ArrowDownToLine aria-hidden className="size-3.5" />Download saved evidence</a>
    </footer>
  </article>;
}

export function AiReviewHistory({ job }: { job: AiReviewJob }) {
  const [page, setPage] = useState<HistoryPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [previous, setPrevious] = useState<Array<string | null>>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<HistoryDetail | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const chooser = useId();
  const [revision, setRevision] = useState(0);
  const root = `/api/llm-jobs/${encodeURIComponent(job.id)}/reviews`;

  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams({ limit: "20", ...(cursor ? { cursor } : {}) });
    fetch(`${root}?${query}`, { signal: controller.signal, cache: "no-store" }).then(readJson<HistoryPage>).then((data) => {
      if (controller.signal.aborted) return;
      setPage(data); setPageError(null);
      setSelected((current) => data.reviews.some((row) => row.id === current) ? current : data.reviews[0]?.id ?? null);
    }).catch((failure) => {
      if (controller.signal.aborted) return;
      setPageError(failure instanceof Error ? failure.message : "Saved reviews are unavailable."); setPage(null); setSelected(null); setDetail(null);
    });
    return () => controller.abort();
  }, [root, cursor, revision, job.currentBatch, job.status]);

  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    fetch(`${root}/${encodeURIComponent(selected)}`, { signal: controller.signal, cache: "no-store" }).then(readJson<HistoryDetail>).then((data) => {
      if (!controller.signal.aborted) { setDetail(data); setDetailError(null); }
    }).catch((failure) => {
      if (!controller.signal.aborted) { setDetail(null); setDetailError(failure instanceof Error ? failure.message : "Saved evidence is unavailable."); }
    });
    return () => controller.abort();
  }, [root, selected, revision, job.currentBatch, job.status]);

  const currentDetail = detail?.record.id === selected ? detail : null;
  const changePage = (next: string | null) => { setCursor(next); setPage(null); setSelected(null); setDetail(null); setDetailError(null); setPageError(null); };
  const selectResult = (id: string) => {
    if (id === selected) return;
    setSelected(id); setDetail(null); setDetailError(null);
  };
  const first = previous.length * 20 + 1;
  return <section aria-label="Saved AI review history" className="workbench-panel @container scroll-mt-4">
    <header className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 border-b px-4 py-2.5 sm:px-5">
      <h2 className="text-lg font-semibold tracking-tight">Review results</h2>
      <Button variant="ghost" size="sm" className="min-h-11" aria-label="Refresh results" onClick={() => { setDetail(null); setRevision((value) => value + 1); }}><RefreshCw aria-hidden className="size-3.5" />Refresh</Button>
      {page && <p className="col-span-2 pb-1 text-xs leading-5 text-muted-foreground" aria-live="polite">{page.saved} of {page.totalFindings} findings have a saved review{page.preservedHumanDecisions > 0 && ` · ${page.published} published · ${page.preservedHumanDecisions} human decisions preserved`}</p>}
    </header>
    {pageError && <p role="alert" className="p-5 text-sm text-destructive">{pageError}</p>}
    {!page && !pageError && <p role="status" className="p-5 text-sm text-muted-foreground">Loading saved results…</p>}
    {page && <>
      {(page.historyVersion === 0 || page.missingReviewHistory > 0) && <p className="border-b px-5 py-3 text-sm text-muted-foreground">This run predates complete retained history. {page.missingReviewHistory} earlier reviewed findings have no saved record.</p>}
      {!page.reviews.length ? <p className="p-5 text-sm text-muted-foreground">No saved results yet. The run status and call receipts show which reviews completed.</p> :
        <div className="grid min-w-0 @min-[44rem]:grid-cols-[minmax(14rem,30%)_minmax(0,1fr)]">
          <div className="min-w-0 border-b bg-muted/25 @min-[44rem]:border-r @min-[44rem]:border-b-0" aria-label="Saved review list">
            <div className="hidden @min-[44rem]:block">
              <p className="border-b px-4 py-2.5 text-xs font-medium text-muted-foreground">Findings in this run</p>
              {page.reviews.map((row) => <button key={row.id} type="button" aria-pressed={selected === row.id} onClick={() => selectResult(row.id)} className="group block w-full border-b border-l-2 border-l-transparent px-4 py-3.5 text-left hover:bg-accent/50 aria-pressed:border-l-primary aria-pressed:bg-accent/60 focus-visible:-outline-offset-2">
                <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1"><SeverityBadge severity={row.severity} /><span className="text-xs text-muted-foreground">{verdicts[row.verdict] || "Unknown verdict"}</span></span>
                <span className="mt-2 block text-sm font-semibold leading-snug [overflow-wrap:anywhere]">{row.ruleName || row.ruleId}</span>
                <span className="mt-1 block break-all font-mono text-[11px] leading-4 text-muted-foreground">{row.filePath}:{row.lineStart}</span>
                {row.metadataTruncated && <span className="mt-1 block text-xs text-muted-foreground">Summary shortened</span>}
              </button>)}
            </div>
            <div className="px-4 py-3 @min-[44rem]:hidden">
              <label htmlFor={chooser} className="mb-1.5 block text-xs font-medium text-muted-foreground">Finding in this run</label>
              <select id={chooser} value={selected ?? ""} onChange={(event) => selectResult(event.target.value)} className="h-11 w-full min-w-0 max-w-full rounded-md border border-input bg-card px-2 text-sm">
                {page.reviews.map((row, index) => <option key={row.id} value={row.id}>{first + index}. {row.ruleName || row.ruleId} · {row.filePath}:{row.lineStart}</option>)}
              </select>
            </div>
            {(previous.length > 0 || page.nextCursor) && <div className="flex flex-wrap items-center gap-1 px-3 py-2 text-xs">
              <Button size="sm" variant="ghost" className="min-h-11" disabled={!previous.length} onClick={() => { const next = previous[previous.length - 1]; setPrevious((values) => values.slice(0, -1)); changePage(next); }}>Previous results</Button>
              <Button size="sm" variant="ghost" className="min-h-11" disabled={!page.nextCursor} onClick={() => { setPrevious((values) => [...values, cursor]); changePage(page.nextCursor); }}>Next results</Button>
              <span className="text-muted-foreground">{first}–{first + page.reviews.length - 1} of {page.saved}</span>
            </div>}
          </div>
          <section aria-label="Saved review detail" aria-busy={!currentDetail && !detailError} className="min-w-0 p-4 @min-[44rem]:p-6">
            {detailError ? <p role="alert" className="text-sm text-destructive">{detailError}</p> : currentDetail
              ? <SavedResult key={currentDetail.record.id} detail={currentDetail} root={root} />
              : <p role="status" className="text-sm text-muted-foreground">Loading saved evidence…</p>}
          </section>
        </div>}
    </>}
  </section>;
}
