"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { SavedReview } from "@/lib/ai-review-history";
import { normalizeAIReviewEvidence } from "@/lib/ai-review-evidence";
import { AIToolEvidence } from "./finding/ai-tool-evidence";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { SeverityBadge } from "./severity-badge";
import type { AiReviewJob } from "./ai-review-job-card";

interface Summary {
  id: string; findingId: string; ruleId: string; ruleName: string; severity: string;
  filePath: string; lineStart: number; verdict: string; confidence: number;
  publication: string; metadataTruncated: boolean;
}
interface HistoryPage {
  historyVersion: number; saved: number; totalFindings: number; published: number;
  preservedHumanDecisions: number; missingReviewHistory: number;
  reviews: Summary[]; nextCursor: string | null;
}
interface HistoryDetail {
  record: SavedReview; payloadDigest: string;
  current: { findingId: string; status: string; aiReviewStatus: string; state: string } | null;
}
const verdicts: Record<string, string> = {
  likely_true_positive: "Likely true positive", likely_false_positive: "Likely false positive", needs_review: "Needs review",
};
async function readJson<T>(response: Response): Promise<T> {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Saved reviews are unavailable.");
  return data as T;
}

export function AiReviewHistory({ job }: { job: AiReviewJob }) {
  const [page, setPage] = useState<HistoryPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [previous, setPrevious] = useState<Array<string | null>>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<HistoryDetail | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const error = pageError || detailError;
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
  const record = currentDetail?.record;
  const changePage = (next: string | null) => { setCursor(next); setPage(null); setSelected(null); setDetail(null); setDetailError(null); setPageError(null); };

  return <Card aria-label="Saved AI review history">
    <CardHeader><CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
      <span>Saved review results</span>
      <Button variant="outline" size="sm" onClick={() => { setDetail(null); setRevision((value) => value + 1); }}>Refresh results</Button>
    </CardTitle></CardHeader>
    <CardContent className="space-y-4">
      <p className="text-xs text-muted-foreground">Each result belongs to this run. Model suggestions and confidence estimates do not change human triage decisions.</p>
      {error && <p role="alert" className="break-words text-sm text-destructive">{error}</p>}
      {!page && !error && <p role="status" className="text-sm">Loading saved results…</p>}
      {page && <>
        <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm" aria-live="polite">
          <p><strong>{page.saved}</strong> saved results / {page.totalFindings} input findings</p>
          <p>{page.published} published suggestions</p>
          <p>{page.preservedHumanDecisions} human decisions preserved</p>
        </div>
        {(page.historyVersion === 0 || page.missingReviewHistory > 0) && <p className="rounded-md border p-3 text-sm text-muted-foreground">This run predates complete retained history. {page.missingReviewHistory} earlier reviewed findings have no saved record. Current finding contents cannot reconstruct them.</p>}
        {!page.reviews.length && <p className="text-sm text-muted-foreground">No saved result is available for this run yet. Inspect its status and call receipts for omitted or failed reviews.</p>}
        {page.reviews.length > 0 && <div className="grid min-w-0 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)]">
          <div className="min-w-0 space-y-2" aria-label="Saved review list">
            {page.reviews.map((row) => <button key={row.id} type="button" aria-pressed={selected === row.id} onClick={() => { if (selected === row.id) return; setSelected(row.id); setDetail(null); setDetailError(null); setPageError(null); }} className={`block w-full min-w-0 rounded-md border p-3 text-left ${selected === row.id ? "border-primary bg-primary/5" : "border-border hover:bg-accent/30"}`}>
              <div className="mb-2 flex flex-wrap items-center gap-2"><SeverityBadge severity={row.severity} /><Badge variant="outline">{verdicts[row.verdict] || "Unrecognized verdict"}</Badge></div>
              <p className="break-words text-sm font-medium">{row.ruleName}</p>
              <p className="mt-1 break-all text-xs text-muted-foreground">{row.filePath}:{row.lineStart}</p>
              <p className="mt-2 text-xs">{Math.round(row.confidence * 100)}% model estimate</p>
              {row.publication === "human_decision_preserved" && <p className="mt-1 text-xs text-muted-foreground">Saved without replacing the human decision</p>}
              {row.metadataTruncated && <p className="mt-1 text-xs text-muted-foreground">Summary shortened; inspect saved evidence.</p>}
            </button>)}
          </div>
          <section aria-label="Saved review detail" className="min-w-0 rounded-md border p-4 text-sm">
            {!record && !error && <p role="status">Loading saved evidence…</p>}
            {record && currentDetail && <div className="space-y-4">
              <div><p className="font-medium">{verdicts[record.result.verdict]}</p><p className="mt-1 text-xs text-muted-foreground">{record.provider} · {record.model} · {new Date(record.createdAt).toLocaleString()}</p></div>
              <div className="rounded-md bg-muted/50 p-3 text-xs">
                <p>{record.publication === "human_decision_preserved" ? "This result was saved without replacing an accepted or rejected human decision." : "This result was published as a suggestion when the run completed this batch."}</p>
                {currentDetail.current ? <>
                  <p className="mt-2">Current finding at load: {currentDetail.current.status} · AI review decision: {currentDetail.current.aiReviewStatus}</p>
                  {currentDetail.current.state === "superseded" && <p className="mt-2">The finding currently displays a different suggestion. This saved result is unchanged.</p>}
                  {currentDetail.current.state === "source_changed" && <p className="mt-2">Source evidence has changed since this review. Inspect the current finding before applying this advice.</p>}
                  <Link className="mt-2 inline-block underline" href={`/findings/${encodeURIComponent(currentDetail.current.findingId)}`}>Open current finding</Link>
                </> : <p className="mt-2">The finding is no longer present in this scan. Its saved review remains available until the scan is removed.</p>}
              </div>
              <div><h3 className="font-medium">Analysis</h3><p className="mt-2 whitespace-pre-wrap break-words">{record.result.reasoning}</p></div>
              <div><h3 className="font-medium">Remediation</h3><p className="mt-2 whitespace-pre-wrap break-words">{record.result.remediation || "No remediation was returned."}</p></div>
              {record.result.adjustedSeverity && <p>Suggested severity: {record.result.adjustedSeverity}. The finding severity has not been changed.</p>}
              {([['Supporting evidence', record.result.evidenceFor], ['Contrary evidence', record.result.evidenceAgainst], ['Evidence gaps', record.result.evidenceGaps]] as const).map(([label, values]) => <details key={label} open={label === "Evidence gaps" && values.length > 0}><summary className="cursor-pointer font-medium">{label} ({values.length})</summary><ul className="mt-2 list-disc space-y-2 pl-5">{values.map((value, index) => <li key={index} className="whitespace-pre-wrap break-words">{value}</li>)}</ul></details>)}
              <details><summary className="cursor-pointer font-medium">Evidence supplied to this review</summary>
                <p className="mt-2 break-all text-xs">{String(record.finding.data.filePath)}:{String(record.finding.data.lineStart)}</p>
                <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">{String(record.finding.data.codeSnippet || "No code excerpt was supplied.")}</pre>
                {record.finding.omittedFields.length > 0 && <p className="mt-2 text-xs">Input fields shortened before review: {record.finding.omittedFields.join(", ")}</p>}
              </details>
              <details><summary className="cursor-pointer font-medium">Evidence identities</summary><dl className="mt-2 space-y-2 break-all font-mono text-xs">{Object.entries({ "Saved record": currentDetail.payloadDigest, "Input snapshot": record.inputDigest, "Finding evidence": record.finding.evidenceDigest, "Source scan": record.scanDigest, Prompt: record.promptDigest, "Provider response": record.responseDigest, Call: record.callId }).map(([key, value]) => <div key={key}><dt className="font-medium">{key}</dt><dd>{value}</dd></div>)}</dl></details>
              {record.sourceEvidence && <div className="space-y-3">
                <p className="text-xs text-muted-foreground">Admitted source: {record.sourceEvidence.catalog.files} files · commit <span className="break-all font-mono">{record.sourceEvidence.catalog.commit}</span>. {record.sourceEvidence.catalog.truncated ? `Coverage is incomplete (${record.sourceEvidence.catalog.omittedFiles} additional files omitted from review; the original fetch may also be incomplete).` : "All files in the stored provider snapshot were admitted; this does not establish whole-repository coverage."}</p>
                <AIToolEvidence evidence={normalizeAIReviewEvidence({ ...record.sourceEvidence })} />
              </div>}
              <a className="inline-block text-xs underline" href={`${root}/${encodeURIComponent(record.id)}`} download={`aegify-review-${record.id}.json`}>Download saved evidence</a>
            </div>}
          </section>
        </div>}
        {(previous.length > 0 || page.nextCursor) && <div className="flex gap-2">
          <Button size="sm" variant="outline" disabled={!previous.length} onClick={() => { const next = previous[previous.length - 1]; setPrevious((values) => values.slice(0, -1)); changePage(next); }}>Previous results</Button>
          <Button size="sm" variant="outline" disabled={!page.nextCursor} onClick={() => { setPrevious((values) => [...values, cursor]); changePage(page.nextCursor); }}>Next results</Button>
        </div>}
      </>}
    </CardContent>
  </Card>;
}
