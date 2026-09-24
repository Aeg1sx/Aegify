"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowDown, ArrowLeft, Download, FlaskConical, Loader2, Play, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { FixtureSuiteEditor } from "./fixture-suite-editor";
import { ruleFixtureExamples } from "@/lib/rule-fixture-examples";
import type { FixtureDetail, FixtureFinding, FixtureInput, FixtureJobView, FixtureReport } from "@/lib/rule-fixture-contract";

interface JobList { project: { name: string; archived: boolean }; jobs: FixtureJobView[]; canManage: boolean; workerAvailable: boolean }
const active = (job: FixtureJobView) => ["queued", "running"].includes(job.status);
const percent = (value: number | null | undefined) => value == null ? "—" : `${(value * 100).toFixed(1)}%`;
function label(job: FixtureJobView) { return job.status === "completed" ? job.outcome : job.status; }
function statusClass(status: string) { return status === "passed" ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" : ["failed", "error"].includes(status) ? "bg-red-500/10 text-red-700 dark:text-red-300" : "bg-amber-500/10 text-amber-700 dark:text-amber-300"; }
function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a"); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function responseData<T>(response: Response): Promise<T> {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data as T;
}
function Flow({ finding }: { finding: FixtureFinding }) {
  const flow = finding.taint_flow;
  if (!flow) return null;
  const nodes = [
    { kind: "Source", name: flow.source.variable, detail: flow.source.source_type, file: flow.source.file_path, line: flow.source.line },
    ...flow.path.slice(0, 20).map((step) => ({ kind: "Propagation", name: step.variable, detail: step.propagation_type, file: step.file_path, line: step.line })),
    { kind: "Sink", name: flow.sink.function, detail: flow.sink.sink_type, file: flow.sink.file_path, line: flow.sink.line },
  ];
  return <div className="mt-3 rounded-md border border-border p-3" aria-label="Static data flow">
    <p className="mb-3 text-xs text-muted-foreground">Static data flow · {flow.sanitized ? `sanitizer: ${flow.sanitizer || "recognized"}` : "no recognized sanitizer"}</p>
    <ol className="space-y-1">{nodes.map((node, index) => <li key={index}>
      {index > 0 && <ArrowDown aria-hidden="true" className="mx-3 h-4 w-4 text-muted-foreground" />}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded border border-border bg-muted/20 px-3 py-2 text-xs"><span className="w-20 text-primary">{node.kind}</span><code className="break-all">{node.name}</code><span className="text-muted-foreground">{node.detail}</span><code className="ml-auto break-all text-muted-foreground">{node.file}:{node.line}</code></div>
    </li>)}</ol>
    {flow.path.length > 20 && <p className="mt-2 text-xs text-muted-foreground">Showing 20 propagation steps. Download the report for the complete path.</p>}
  </div>;
}
function Report({ report }: { report: FixtureReport }) {
  return <div className="space-y-4">
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">{[["Fixture precision", percent(report.metrics?.precision)], ["Fixture recall", percent(report.metrics?.recall)], ["Matched · TP", report.metrics?.true_positives ?? "—"], ["Unexpected · FP", report.metrics?.false_positives ?? "—"], ["Missed · FN", report.metrics?.false_negatives ?? "—"]].map(([title, value]) => <div key={title} className="rounded-lg border border-border bg-background p-3"><p className="text-xs text-muted-foreground">{title}</p><p className="mt-2 text-2xl font-semibold tabular-nums">{value}</p></div>)}</div>
    <p className="text-xs text-muted-foreground">{report.positive_cases} positive / {report.negative_cases} negative cases. These scores apply to the supplied examples. Assertions check locations; taint paths and evidence states are shown for inspection. Source code is parsed without being run.</p>
    {report.status === "incomplete" && <p className="rounded-md bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">Analysis is incomplete. Precision and recall are unavailable until every case is analyzed and the required controls are present.</p>}
    {report.issues.length > 0 && <div role="status" className="rounded-md border border-border p-3 text-sm"><h3 className="mb-1 font-medium">Evaluation issues</h3><ul className="list-inside list-disc">{report.issues.map((issue, index) => <li key={index}>{issue.replaceAll("_", " ")}</li>)}</ul></div>}
    {report.diagnostics.length > 0 && <div className="rounded-md border border-border p-3 text-sm"><h3 className="mb-2 font-medium">Rule diagnostics</h3>{report.diagnostics.map((item, index) => <p key={index}>{typeof item.line === "number" ? `Line ${item.line}: ` : ""}{String(item.message || item.code || "Invalid rule")}</p>)}</div>}
    {report.cases.map((item) => <details key={item.id} open={item.status !== "passed"} className="rounded-lg border border-border bg-background">
      <summary className="cursor-pointer px-4 py-3 text-sm"><span className={"mr-3 rounded px-2 py-1 text-xs " + statusClass(item.status)}>{item.status}</span><span className="font-medium">{item.id}</span><span className="ml-3 text-xs text-muted-foreground">{item.files_scanned} files · {item.actual.length} findings · {item.duration_seconds.toFixed(2)}s</span></summary>
      <div className="space-y-3 border-t border-border p-4">
        {!!item.issues.length && <p className="text-sm text-amber-700 dark:text-amber-300">{item.issues.map((issue) => issue.replaceAll("_", " ")).join(" · ")}</p>}
        {[["Missed expected locations", item.unmatched_expected], ["Unexpected detected locations", item.unmatched_actual]].map(([title, locations]) => (locations as string[]).length > 0 && <div key={title as string} className="text-xs"><h4 className="mb-1 font-semibold">{title as string}</h4><ul className="space-y-1 font-mono">{(locations as string[]).slice(0, 100).map((location, index) => <li key={index} className="break-all">{location}</li>)}</ul>{(locations as string[]).length > 100 && <p>Showing 100 locations; download the full report for all locations.</p>}</div>)}
        {!item.actual.length && <p className="text-sm text-muted-foreground">{item.status === "incomplete" ? "No findings were reported; analysis gaps prevent a negative result." : "No findings in this case."}</p>}
        {item.actual.slice(0, 100).map((finding, index) => <article key={index} className="rounded-md border border-border p-3"><div className="flex flex-wrap gap-2 text-xs"><code className="break-all font-medium">{finding.file_path}:{finding.line_start}</code><span className="ml-auto text-muted-foreground">{finding.evidence_state} · {finding.disposition} · {finding.severity}</span></div><p className="mt-2 text-sm">{finding.message}</p><Flow finding={finding} /></article>)}
        {item.actual.length > 100 && <p className="text-xs text-muted-foreground">Showing 100 findings; download the report for all {item.actual.length} findings.</p>}
        {item.parse_diagnostics.length > 0 && <details><summary className="cursor-pointer text-xs">Parser diagnostics</summary><pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(item.parse_diagnostics, null, 2).slice(0, 16_000)}</pre><p className="text-xs text-muted-foreground">Preview limited to 16,000 characters. Full diagnostics are included in the report.</p></details>}
        <p className="break-all font-mono text-[10px] text-muted-foreground">Source: {item.source_digest}</p>
      </div>
    </details>)}
    <details className="rounded-md border border-border p-3"><summary className="cursor-pointer text-xs">Reproducibility manifest</summary><pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(report.manifest, null, 2)}</pre><p className="mt-2 break-all font-mono text-[10px]">Stable evaluation digest: {report.result_digest || "Unavailable for invalid input"}</p></details>
  </div>;
}
export function RuleFixtureWorkbench({ projectId }: { projectId: string }) {
  const endpoint = `/api/projects/${encodeURIComponent(projectId)}/rule-fixtures`;
  const [list, setList] = useState<JobList | null>(null);
  const [input, setInput] = useState<FixtureInput>(ruleFixtureExamples.call);
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<FixtureDetail | null>(null);
  const [savedInput, setSavedInput] = useState<{ id: string; input: FixtureInput } | null>(null);
  const [listError, setListError] = useState("");
  const [detailError, setDetailError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    const load = async () => {
      if (pending) return;
      pending = true;
      try {
        const data = await responseData<JobList>(await fetch(endpoint, { signal: controller.signal, cache: "no-store" }));
        if (!controller.signal.aborted) { setList(data); setListError(""); setSelected((current) => current || data.jobs[0]?.id || ""); }
      } catch (error) { if (!controller.signal.aborted) { setListError(error instanceof Error ? error.message : "Could not load evaluations."); setList(null); } }
      finally { pending = false; }
    };
    void load(); const pulse = setInterval(load, 5000);
    return () => { controller.abort(); clearInterval(pulse); };
  }, [endpoint, revision]);
  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    let pending = false;
    let terminal = false;
    const load = async () => {
      if (pending || terminal) return;
      pending = true;
      try {
        const data = await responseData<FixtureDetail>(await fetch(`${endpoint}/${encodeURIComponent(selected)}`, { signal: controller.signal, cache: "no-store" }));
        if (!controller.signal.aborted) { setDetail(data); setDetailError(""); terminal = !active(data.job); }
      } catch (error) { if (!controller.signal.aborted) { setDetailError(error instanceof Error ? error.message : "Could not load the report."); setDetail(null); } }
      finally { pending = false; }
    };
    void load(); const pulse = setInterval(load, 4000);
    return () => { controller.abort(); clearInterval(pulse); };
  }, [endpoint, selected, revision]);
  const run = async () => {
    setBusy(true); setActionError("");
    try {
      const job = await responseData<FixtureJobView>(await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input), signal: AbortSignal.timeout(15_000) }));
      setSavedInput({ id: job.id, input }); setSelected(job.id); refresh();
    } catch (error) { setActionError(error instanceof Error ? error.message : "Could not queue evaluation."); }
    finally { setBusy(false); }
  };
  const action = async (name: "cancel" | "rerun" | "load") => {
    if (!selected) return;
    setBusy(true); setActionError("");
    try {
      const path = `${endpoint}/${encodeURIComponent(selected)}`;
      if (name === "load") {
        const data = await responseData<FixtureDetail>(await fetch(path + "?input=1", { cache: "no-store", signal: AbortSignal.timeout(15_000) }));
        if (data.input) { setInput(data.input); setSavedInput({ id: selected, input: data.input }); }
      } else {
        const data = await responseData<FixtureJobView>(await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: name }), signal: AbortSignal.timeout(15_000) }));
        if (name === "rerun") { setSelected(data.id); setSavedInput(null); }
      }
      refresh();
    } catch (error) { setActionError(error instanceof Error ? error.message : "Could not update the evaluation."); }
    finally { setBusy(false); }
  };
  const visible = list && detail?.job.id === selected ? detail : null;
  const canEdit = Boolean(list?.canManage && !list.project.archived);
  const jobs = list?.jobs.map((job) => visible?.job.id === job.id && !active(visible.job) ? visible.job : job) ?? [];
  const running = jobs.some(active);
  const changed = savedInput?.id === selected && (savedInput.input.ruleYaml !== input.ruleYaml || savedInput.input.suiteJson !== input.suiteJson);
  return <div className="space-y-6">
    <Link href={`/projects/${encodeURIComponent(projectId)}`} className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="h-4 w-4" /> {list?.project.name || "Project"}</Link>
    <header className="flex flex-wrap items-start justify-between gap-4"><div><p className="eyebrow mb-2">Project rule authoring</p><h1 className="flex items-center gap-2 text-2xl font-bold"><FlaskConical className="h-6 w-6 text-primary" /> Rule lab</h1><p className="mt-2 max-w-3xl text-sm text-muted-foreground">Define a rule, add positive and negative examples, and inspect the scanner’s actual findings and data flow.</p></div><Button variant="outline" size="sm" onClick={refresh}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></header>
    {listError && <p role="alert" className="text-sm text-red-600">{listError}</p>}
    {list && <>
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted/20 p-4 text-xs"><span>{list.workerAvailable ? "Evaluation worker connected" : "Waiting for an evaluation worker. Jobs remain queued until the worker is available."}</span><span className="text-muted-foreground">{list.project.archived ? "Archived project · history only" : list.canManage ? "Maintainer access" : "Viewer access · a maintainer can run evaluations"} · input and reports retained for 7 days</span></div>
      <div className="flex flex-wrap items-center gap-2"><span className="mr-2 text-sm font-medium">Start from an example</span><Button variant="outline" size="sm" onClick={() => { setInput(ruleFixtureExamples.call); setActionError(""); }} disabled={!canEdit || busy}>Call selector</Button><Button variant="outline" size="sm" onClick={() => { setInput(ruleFixtureExamples.taint); setActionError(""); }} disabled={!canEdit || busy}>Taint &amp; cross-file helper</Button><a href="https://github.com/Aeg1sx/Aegify/blob/main/docs/analysis/rule-authoring.mdx" target="_blank" rel="noreferrer" className="ml-auto text-xs text-primary underline">Rule authoring guide</a></div>
      <div className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
        <section className="workbench-panel min-w-0"><div className="workbench-heading"><h2 className="font-semibold">1. Rule YAML</h2><span className="text-xs text-muted-foreground">One rule · max 128 KiB</span></div><textarea aria-label="Rule YAML" className="min-h-[460px] w-full resize-y bg-[#11151c] p-4 font-mono text-[13px] leading-6 text-slate-200 outline-none focus-visible:ring-2 focus-visible:ring-primary" value={input.ruleYaml} onChange={(event) => setInput({ ...input, ruleYaml: event.target.value })} disabled={!canEdit || busy} spellCheck={false} wrap="off" /><p className="p-4 text-xs text-muted-foreground">The worker validates supported fields and Python pattern syntax before evaluating cases. See the guide for taint selectors and framework support.</p></section>
        <FixtureSuiteEditor value={input.suiteJson} onChange={(suiteJson) => setInput({ ...input, suiteJson })} disabled={!canEdit || busy} />
      </div>
      <div className="flex flex-wrap items-center gap-3"><Button onClick={run} disabled={!canEdit || busy || running}>{busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}Run evaluation</Button><Button variant="outline" size="sm" onClick={() => download("rule.yml", input.ruleYaml, "text/yaml")}>Export rule</Button><Button variant="outline" size="sm" onClick={() => download("fixtures.json", input.suiteJson, "application/json")}>Export fixtures</Button><p className="text-xs text-muted-foreground">One active evaluation per project · 30 second budget · no model calls</p></div>
      <p className="text-xs text-muted-foreground">Run the same exported inputs in CI: <code className="break-all">aegify test-rule rule.yml --fixtures fixtures.json --timeout-seconds 30 --json</code>. The lab does not publish a global rule.</p>
    </>}
    {actionError && <p role="alert" className="rounded-md bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-300">{actionError}</p>}
    <section className="space-y-4" aria-label="Evaluation history"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-lg font-semibold">3. Evaluation results</h2><label className="flex min-w-0 max-w-full flex-col gap-1 text-xs sm:flex-row sm:items-center sm:gap-2">Recent runs <select aria-label="Evaluation history" value={selected} onChange={(event) => setSelected(event.target.value)} className="min-w-0 max-w-full rounded border border-input bg-background p-2">{!jobs.length && <option value="">No evaluations yet</option>}{jobs.map((job) => <option key={job.id} value={job.id}>{label(job)} · {new Date(job.createdAt).toLocaleString()} · {job.id.slice(-6)}</option>)}</select></label></div>
      {detailError && <p role="alert" className="text-sm text-red-600">{detailError}</p>}
      {selected && !visible && !detailError && <p className="text-sm text-muted-foreground">Loading saved evaluation…</p>}
      {!selected && <div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">Run an example to see exact matches, missed findings and false positives here.</div>}
      {visible && <>
        <div className="flex flex-wrap items-center gap-3"><span role="status" className={"rounded-md px-3 py-1.5 text-sm font-medium " + statusClass(label(visible.job))}>{label(visible.job)}</span><span className="text-xs text-muted-foreground">Attempt {visible.job.attempts}/{visible.job.maxAttempts}</span>
          {visible.canManage && <div className="ml-auto flex flex-wrap gap-2">{active(visible.job) && <Button variant="outline" size="sm" onClick={() => action("cancel")} disabled={busy}>Cancel evaluation</Button>}<Button variant="outline" size="sm" onClick={() => action("load")} disabled={busy || visible.expired || !canEdit}>Load saved input</Button><Button variant="outline" size="sm" onClick={() => action("rerun")} disabled={busy || visible.expired || !canEdit || running}>Rerun saved input</Button></div>}
          {visible.report && <Button variant="outline" size="sm" onClick={() => download("rule-fixture-report.json", JSON.stringify(visible.report, null, 2), "application/json")}><Download className="mr-2 h-4 w-4" />Report JSON</Button>}
        </div>
        {changed && <p className="text-sm text-amber-700 dark:text-amber-300">The draft has changed since this run. Run it again to evaluate your edits.</p>}
        {savedInput?.id !== selected && <p className="text-xs text-muted-foreground">This report belongs to the saved input. Load that input to compare it with your draft.</p>}
        {visible.expired && <p className="rounded-md border border-border p-3 text-sm">Input and report retention has expired. Job status and digests remain available.</p>}
        {visible.job.status === "failed" && <p role="alert" className="text-sm">Evaluation could not finish: {visible.job.errorCode.replaceAll("_", " ")}. No passing result is available.</p>}
        {visible.report && <Report report={visible.report} />}
        <details className="rounded-md border border-border p-3"><summary className="cursor-pointer text-xs">Job log and retained evidence</summary><ol className="mt-3 space-y-2 text-xs">{visible.events.map((event) => <li key={event.id}><time className="mr-3 text-muted-foreground">{new Date(event.createdAt).toLocaleTimeString()}</time>{event.message}</li>)}</ol><div className="mt-4 space-y-1 break-all font-mono text-[10px] text-muted-foreground"><p>Input digest: {visible.job.inputDigest}</p><p>Report bytes digest: {visible.job.resultDigest || "Pending"}</p><p>Retained until: {new Date(visible.job.expiresAt).toLocaleString()}</p><p>History shows the latest 25 jobs.</p></div></details>
      </>}
    </section>
  </div>;
}
