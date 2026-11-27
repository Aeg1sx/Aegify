"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Search, SlidersHorizontal, Save, ListChecks, Loader2, ArrowLeft, ArrowUpRight, X } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { EvidenceWorkbench, type FindingEvidenceView } from "@/components/finding/evidence-workbench";
import { EVIDENCE_LABELS } from "@/lib/code-evidence";
import { findingFilters, filterQuery, invalidFindingScope, QUEUE_LABELS, type FindingFilters } from "@/lib/finding-view";

interface Finding extends FindingEvidenceView { scan: { projectId: string | null }; repositoryId: string; aiVerdict: string; createdAt: string; confidence: number }
interface ReviewScan { id: string; repository: string; branch: string; commitSha: string; createdAt: string; status: string }
interface SavedView { name: string; query: string }
const presets = [
  { name: "All findings", values: {} },
  { name: "Critical / open", values: { severity: "critical", status: "open" } },
  { name: "Regressions", values: { baselineState: "regressed" } },
  { name: "Static candidates", values: { evidenceState: "candidate" } },
];

export default function FindingsPage() {
  const [filters, setFilters] = useState(findingFilters());
  const [invalidScope, setInvalidScope] = useState(false);
  const [loadedQuery, setLoadedQuery] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const [reviewScan, setReviewScan] = useState<ReviewScan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [fetching, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [advanced, setAdvanced] = useState(false);
  const [compact, setCompact] = useState(true);
  const [showOwner, setShowOwner] = useState(true);
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const returnToRow = useRef<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchMessage, setBatchMessage] = useState("");
  const [saved, setSaved] = useState<SavedView[]>([]);
  const [saveName, setSaveName] = useState("");
  const [viewMessage, setViewMessage] = useState("");
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>([]);
  const [rules, setRules] = useState<Array<{ id: string; name: string }>>([]);
  const [languages, setLanguages] = useState<string[]>([]);
  const rowButtons = useRef<Map<string, HTMLButtonElement>>(new Map());

  useEffect(() => {
    const restore = () => {
      const params = new URLSearchParams(window.location.search);
      setInvalidScope(invalidFindingScope(params));
      setFilters(findingFilters(params));
    };
    const frame = requestAnimationFrame(() => {
      restore();
      try {
        const parsed: unknown = JSON.parse(localStorage.getItem("aegify.findingViews.v1") || "[]");
        if (Array.isArray(parsed)) setSaved(parsed.filter((v): v is SavedView => typeof v?.name === "string" && typeof v?.query === "string" && !invalidFindingScope(new URLSearchParams(v.query))).slice(0, 12));
        setCompact(localStorage.getItem("aegify.tableDensity") !== "comfortable");
        setShowOwner(localStorage.getItem("aegify.findingOwner") !== "hidden");
      } catch { /* Storage may be unavailable. The workbench remains usable. */ }
      setReady(true);
    });
    window.addEventListener("popstate", restore);
    return () => { cancelAnimationFrame(frame); window.removeEventListener("popstate", restore); };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    async function options(path: string) {
      const response = await fetch(path, { signal: controller.signal });
      if (!response.ok) throw new Error("Filter options unavailable");
      return response.json();
    }
    Promise.allSettled([options("/api/projects"), options("/api/findings/rules"), options("/api/findings/languages")]).then(([p, r, l]) => {
      if (controller.signal.aborted) return;
      if (p.status === "fulfilled") setProjects(p.value.projects || []);
      if (r.status === "fulfilled") setRules(r.value.rules || []);
      if (l.status === "fulfilled") setLanguages(l.value.languages || []);
    });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (!ready || invalidScope) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      setLoading(true); setError("");
      const query = filterQuery(filters);
      window.history.replaceState(null, "", "/findings?" + query);
      try {
        const response = await fetch("/api/findings?" + query + "&limit=50", { signal: controller.signal });
        const data = await response.json();
        if (!response.ok || !Array.isArray(data.findings)) throw new Error(data.error || "Unable to load findings.");
        if (!controller.signal.aborted) {
          const lastPage = Math.max(1, Math.ceil(data.total / 50));
          if (Number(filters.page) > lastPage) {
            setFilters((previous) => ({ ...previous, page: String(lastPage) }));
            return;
          }
          setReviewScan(data.scan ?? null); setLoadedQuery(query); setFindings(data.findings); setTotal(data.total); setSelected(new Set());
          setInspectedId((id) => data.findings.some((f: Finding) => f.id === id) ? id : null);
        }
      } catch (e) {
        if (!controller.signal.aborted) { setError(e instanceof Error ? e.message : "Unable to load findings."); setReviewScan(null); setFindings([]); setSelected(new Set()); setInspectedId(null); setTotal(0); }
      } finally { if (!controller.signal.aborted) setLoading(false); }
    }, 220);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [filters, ready, retry, invalidScope]);

  const change = (key: keyof FindingFilters, value: string) => setFilters((f) => ({ ...f, [key]: value, page: key === "page" ? value : "1" }));
  const closeInspector = useCallback(() => {
    returnToRow.current = inspectedId;
    setInspectedId(null);
  }, [inspectedId]);
  const query = filterQuery(filters);
  const loading = fetching || loadedQuery !== query;
  const inspected = !loading && findings.find((finding) => finding.id === inspectedId);
  useEffect(() => {
    if (!inspectedId && returnToRow.current) {
      rowButtons.current.get(returnToRow.current)?.focus();
      returnToRow.current = null;
    }
    if (inspectedId && window.matchMedia("(max-width: 1279px)").matches) {
      const inspector = document.getElementById("finding-inspector");
      inspector?.focus({ preventScroll: true });
      inspector?.scrollIntoView({ block: "start" });
    }
  }, [inspectedId]);
  const page = Number(filters.page);
  const detailQuery = query === filterQuery(findingFilters()) ? "" : "?" + query;
  const pages = Math.max(1, Math.ceil(total / 50));
  const scoped = Boolean(filters.scanId || filters.repositoryId);
  const defaults = { ...findingFilters(), scanId: filters.scanId, repositoryId: filters.repositoryId,
    projectId: scoped ? filters.projectId : "" };
  const scan = loadedQuery === query && reviewScan?.id === filters.scanId ? reviewScan : null;
  const views = [
    ...presets.map((preset) => ({ name: preset.name, filters: { ...defaults, ...preset.values } })),
    ...saved.map((view) => ({ name: view.name, filters: findingFilters(new URLSearchParams(view.query)) })),
  ];
  const currentQuery = filterQuery({ ...filters, page: "1" });
  const viewIndex = views.findIndex((view) => filterQuery({ ...view.filters, page: "1" }) === currentQuery);
  const filterCount = Object.entries(filters).filter(([key, value]) => value && !["page", "sort", "search", "queue", "scanId", "repositoryId"].includes(key)).length;
  const toggle = (id: string) => setSelected((previous) => {
    const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next;
  });
  const batchAnalyze = async () => {
    const ids = [...selected];
    setBatchRunning(true);
    let succeeded = 0; let failed = 0;
    try {
      for (let index = 0; index < ids.length; index += 20) {
        const chunk = ids.slice(index, index + 20);
        setBatchMessage("Reviewing " + (index + 1) + "–" + Math.min(index + 20, ids.length) + " / " + ids.length);
        try {
          const response = await fetch("/api/findings/analyze-batch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids: chunk }) });
          const data = await response.json();
          if (!response.ok) throw new Error("Review failed");
          succeeded += data.summary?.success || 0; failed += data.summary?.failed || 0;
        } catch { failed += chunk.length; }
      }
      setBatchMessage(succeeded + " reviews succeeded · " + failed + " failed. AI suggestions do not change triage status.");
      setRetry((n) => n + 1);
    } finally { setBatchRunning(false); }
  };

  function selectFilter(key: keyof FindingFilters, label: string, values: Array<[string, string]>) {
    return <select aria-label={label} className="workbench-select w-full" value={filters[key]} onChange={(e) => change(key, e.target.value)}>
      <option value="">{label}</option>{values.map(([value, name]) => <option key={value} value={value}>{name}</option>)}
    </select>;
  }

  if (invalidScope) return <section className="workbench-panel space-y-3 p-5">
    <h1 className="workbench-title">Findings</h1>
    <p role="alert">Invalid scan or repository filter.</p>
    <button type="button" className="min-h-11 text-sm text-primary underline" onClick={() => {
      setFilters(findingFilters()); setInvalidScope(false);
    }}>Open all findings</button>
  </section>;

  return <div className="finding-workspace space-y-5" data-detail-open={Boolean(inspected)}>
    <header className="flex flex-wrap items-center justify-between gap-3">
      <h1 className="workbench-title">Findings</h1>
      {inspected && <button type="button" onClick={closeInspector} className="inline-flex min-h-11 items-center gap-2 text-sm font-medium text-primary md:hidden"><ArrowLeft aria-hidden className="size-4" />Back to list</button>}
      <select aria-label="Finding view" className="workbench-select min-h-11 max-w-[65%] text-sm sm:hidden" value={viewIndex} onChange={(event) => setFilters(views[Number(event.target.value)].filters)}>
        {viewIndex < 0 && <option value={-1} disabled>{QUEUE_LABELS[filters.queue as keyof typeof QUEUE_LABELS] || "Custom view"}</option>}
        {views.map((view, index) => <option key={index} value={index}>{view.name}</option>)}
      </select>
      {filters.queue && <button type="button" className="hidden min-h-10 items-center gap-2 rounded-md border border-border bg-card px-3 text-sm font-medium sm:inline-flex" onClick={() => change("queue", "")} aria-label="Clear review queue filter">{QUEUE_LABELS[filters.queue as keyof typeof QUEUE_LABELS]}<X aria-hidden className="size-3.5" /></button>}
    </header>
    {scoped && <section aria-label="Review scope" className="flex min-w-0 flex-wrap items-center gap-x-5 gap-y-2 rounded-lg border bg-card px-4 py-2">
      {filters.projectId && <div className="min-w-0">
        <span className="block text-xs text-muted-foreground">Project</span>
        <span className="break-all text-sm font-medium">{projects.find((p) => p.id === filters.projectId)?.name || filters.projectId}</span>
      </div>}
      {filters.scanId && <div className="min-w-0">
        <span className="block text-xs text-muted-foreground">Scan</span>
        {scan ? <>
          <Link href={"/scans/" + encodeURIComponent(scan.id)} className="break-all text-sm font-semibold text-primary underline underline-offset-4">{scan.repository || "Scan record"}</Link>
          <p className="break-words text-xs text-muted-foreground">
            {[scan.branch, scan.commitSha.slice(0, 8), new Date(scan.createdAt).toLocaleString()].filter(Boolean).join(" · ")}
          </p>
        </> : <span className="break-all font-mono text-sm">{filters.scanId}</span>}
      </div>}
      {filters.repositoryId && <div className="min-w-0">
        <span className="block text-xs text-muted-foreground">Repository</span>
        <span className="break-all font-mono text-sm font-semibold">{filters.repositoryId}</span>
      </div>}
      {scan && scan.status !== "completed" && <span className="rounded-md border border-[var(--severity-medium)]/50 px-2 py-1 text-xs font-medium">
        {scan.status === "partial" ? "Partial scan coverage" : "Scan status · " + scan.status}
      </span>}
      <button type="button" className="ml-auto min-h-11 text-sm text-primary hover:underline"
        onClick={() => filters.repositoryId ? change("repositoryId", "") : setFilters(findingFilters())}>
        {filters.repositoryId ? "Show all repositories" : "Leave scan view"}
      </button>
    </section>}
    <div aria-label="Finding views" role="group" className="hidden flex-wrap items-center gap-x-5 border-b sm:flex">
      {views.map((view, index) => <button key={index} type="button" aria-pressed={viewIndex === index} className="hidden min-h-11 border-b-2 border-transparent text-sm text-muted-foreground hover:text-foreground aria-pressed:border-primary aria-pressed:font-semibold aria-pressed:text-foreground sm:inline-flex sm:items-center" onClick={() => setFilters(view.filters)}>{view.name}</button>)}
    </div>
    <div className="finding-tools space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-0 basis-full sm:flex-1"><Search aria-hidden className="absolute left-3 top-3.5 size-4 text-muted-foreground" /><input type="search" aria-label="Search findings" placeholder="Search rule, file, or message…" className="h-11 w-full rounded-md border border-input bg-card pl-9 pr-3 text-base sm:text-sm" value={filters.search} onChange={(e) => change("search", e.target.value)} /></div>
        <Button variant="outline" className="h-11" aria-expanded={advanced} aria-controls="finding-filters" onClick={() => setAdvanced(!advanced)}><SlidersHorizontal aria-hidden />Filters{filterCount > 0 && <span className="font-mono">{filterCount}</span>}</Button>
        <select aria-label="Sort findings" className="workbench-select ml-auto h-11 text-sm" value={filters.sort} onChange={(e) => change("sort", e.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="file">Source location</option><option value="rule">Rule name</option></select>
      </div>
      <div id="finding-filters" hidden={!advanced} className="workbench-panel space-y-4 p-4">
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        {selectFilter("severity", "All severities", ["critical", "high", "medium", "low"].map((v) => [v, v]))}
        {selectFilter("status", "All statuses", ["open", "triaged", "confirmed", "in_progress", "false_positive", "accepted_risk", "fixed"].map((v) => [v, v.replaceAll("_", " ")]))}
        {selectFilter("evidenceState", "All evidence", Object.entries(EVIDENCE_LABELS))}
        {selectFilter("projectId", "All projects", projects.map((p) => [p.id, p.name]))}
        {selectFilter("ruleId", "All rules", rules.map((r) => [r.id, r.id]))}
        {selectFilter("language", "All languages", languages.map((l) => [l, l]))}
        {selectFilter("source", "All sources", [["sast", "SAST"], ["llm", "AI review"]])}
        {selectFilter("disposition", "All gates", [["blocking", "Blocking"], ["advisory", "Advisory"]])}
        </div>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t pt-3 text-sm">
          {!filters.scanId && <label className="inline-flex min-h-10 items-center gap-2"><input type="checkbox" checked={filters.history === "true"} onChange={(e) => change("history", e.target.checked ? "true" : "")} />Include history</label>}
          <label className="inline-flex min-h-10 items-center gap-2"><input type="checkbox" checked={showOwner} onChange={(e) => { setShowOwner(e.target.checked); try { localStorage.setItem("aegify.findingOwner", e.target.checked ? "visible" : "hidden"); } catch {} }} />Show owners</label>
          <select className="workbench-select" aria-label="Table density" value={compact ? "compact" : "comfortable"} onChange={(e) => { setCompact(e.target.value === "compact"); try { localStorage.setItem("aegify.tableDensity", e.target.value); } catch {} }}><option value="compact">Compact rows</option><option value="comfortable">Comfortable rows</option></select>
          <button type="button" className="min-h-10 text-sm text-primary hover:underline" onClick={() => setFilters(defaults)}>Reset filters</button>
        </div>
        <div className="flex flex-wrap items-center gap-2">
        <input aria-label="Saved view name" placeholder="Name this view" maxLength={40} value={saveName} onChange={(e) => setSaveName(e.target.value)} className="workbench-select w-44" />
        <Button variant="outline" size="sm" disabled={!saveName.trim() || saved.length >= 12} onClick={() => {
          const next = [...saved, { name: saveName.trim(), query: filterQuery({ ...filters, page: "1" }) }]; setSaved(next); setSaveName("");
          try { localStorage.setItem("aegify.findingViews.v1", JSON.stringify(next)); setViewMessage("View saved."); } catch { setViewMessage("View saved for this session. Browser storage is unavailable."); }
        }}><Save className="mr-1 h-3.5 w-3.5" />Save view</Button>
        {saved.map((view, index) => <button key={index} type="button" aria-label={"Delete saved view " + view.name} className="inline-flex min-h-10 items-center gap-1.5 px-2 text-xs text-muted-foreground hover:text-foreground" onClick={() => { const next = saved.filter((_, i) => i !== index); setSaved(next); try { localStorage.setItem("aegify.findingViews.v1", JSON.stringify(next)); } catch {} }}>{view.name}<X aria-hidden className="size-3.5" /></button>)}
        {viewMessage && <span role="status" className="text-sm text-muted-foreground">{viewMessage}</span>}
        </div>
      </div>
    </div>
    {batchMessage && <p role="status" className="text-sm text-muted-foreground">{batchMessage}</p>}
    {error && <div role="alert" className="flex items-center justify-between rounded-md border border-destructive/30 p-4 text-sm text-destructive">{error}<Button variant="outline" size="sm" onClick={() => setRetry((n) => n + 1)}>Retry</Button></div>}
    {!error && <div className={"grid items-start gap-4 " + (inspected ? "2xl:grid-cols-[minmax(0,1fr)_480px] xl:grid-cols-[minmax(0,1fr)_420px]" : "")}>
      <section aria-label="Finding results" className="finding-results workbench-panel">
        <div className="workbench-heading">
          <h2 className="text-sm font-semibold">{filters.scanId ? "Occurrences in this scan" : filters.history === "true" ? "All recorded occurrences" : "Current occurrences"} <span className="ml-2 font-mono font-normal tabular-nums text-muted-foreground">{loading ? "…" : total.toLocaleString()}</span></h2>
          {!loading && selected.size > 0 && <Button size="sm" className="min-h-10" disabled={batchRunning || loading} onClick={batchAnalyze}>{batchRunning ? <Loader2 aria-hidden className="animate-spin" /> : <ListChecks aria-hidden />}Review selected ({selected.size})</Button>}
        </div>
        <div className="finding-scroll" aria-busy={loading}>
          <table className={"data-table finding-table " + (compact ? "compact" : "")}>
            <caption className="sr-only">Security findings. Use up and down arrows on a finding title to inspect adjacent rows.</caption>
            <thead><tr>
              <th scope="col" className="finding-check"><label><input aria-label="Select all visible findings" type="checkbox" disabled={loading || !findings.length} checked={findings.length > 0 && selected.size === findings.length} ref={(input) => { if (input) input.indeterminate = selected.size > 0 && selected.size < findings.length; }} onChange={() => setSelected(selected.size === findings.length ? new Set() : new Set(findings.map((f) => f.id)))} /></label></th>
              <th scope="col" className="finding-column">Severity</th><th scope="col">Finding / source</th><th scope="col" className="finding-column">Evidence</th><th scope="col" className="finding-column">Status</th>{showOwner && <th scope="col" className="finding-column">Owner</th>}<th scope="col" className="finding-details"><span className="sr-only">Details</span></th>
            </tr></thead>
            <tbody>{loading ? <tr><td colSpan={showOwner ? 7 : 6} className="h-40 text-center text-muted-foreground"><Loader2 aria-hidden className="mx-auto mb-2 size-5 animate-spin" />Loading findings…</td></tr> : findings.length === 0 ? <tr><td colSpan={showOwner ? 7 : 6} className="h-40 text-center text-muted-foreground">{filterCount || filters.search || filters.queue ? <>No findings match this view. <button type="button" className="min-h-11 text-primary hover:underline" onClick={() => setFilters(defaults)}>Clear filters</button></> : scoped ? "No findings recorded in this scope." : "No findings recorded."}</td></tr> : findings.map((finding, index) => <tr key={finding.id} data-inspected={inspectedId === finding.id}>
              <td className="finding-check"><label><input aria-label={"Select " + finding.ruleName + " at " + [finding.repositoryId, finding.modulePath || finding.filePath].filter(Boolean).join(" · ")} type="checkbox" checked={selected.has(finding.id)} onChange={() => toggle(finding.id)} /></label></td>
              <td className="finding-column"><SeverityBadge severity={finding.severity} /></td>
              <td className="finding-summary">
                <button type="button" aria-expanded={inspectedId === finding.id} aria-controls={inspectedId === finding.id ? "finding-inspector" : undefined} ref={(el) => { if (el) rowButtons.current.set(finding.id, el); else rowButtons.current.delete(finding.id); }} className="max-w-full break-words text-left text-sm font-semibold leading-snug hover:text-primary hover:underline" onClick={() => setInspectedId((current) => current === finding.id ? null : finding.id)} onKeyDown={(event) => {
                if (event.key === "Escape") { closeInspector(); return; }
                if (!["ArrowDown", "ArrowUp"].includes(event.key)) return;
                event.preventDefault(); const next = findings[index + (event.key === "ArrowDown" ? 1 : -1)];
                if (next) { setInspectedId(next.id); rowButtons.current.get(next.id)?.focus(); }
              }}>{finding.ruleName}</button><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{finding.repositoryId && (filters.repositoryId ? <span className="font-semibold">{finding.repositoryId} · </span> : <>
                  <button type="button" aria-label={`View findings for ${finding.repositoryId} in this scan`} className="font-semibold text-primary underline underline-offset-4"
                    onClick={() => setFilters({ ...defaults, projectId: finding.scan.projectId ?? filters.projectId, scanId: finding.scanId, repositoryId: finding.repositoryId, page: "1" })}>{finding.repositoryId}</button> · </>)}{finding.modulePath || finding.filePath}:{finding.lineStart}</p>
                <div className="finding-narrow mt-2 flex-wrap items-center gap-x-2 gap-y-1"><SeverityBadge severity={finding.severity} /><StatusBadge status={finding.status} /></div>
                <div className="finding-narrow mt-2 flex-wrap gap-x-2 gap-y-1 text-xs text-muted-foreground"><span>{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified"}</span>{showOwner && <span>· {finding.owner || "Unassigned"}</span>}{finding.aiVerdict && <span>· AI suggestion available</span>}</div>
                {finding.baselineState === "regressed" && <span className="text-xs text-destructive">Reopened</span>}
              </td>
              <td className="finding-column"><span className="text-xs">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified"}</span>{finding.aiVerdict && <p className="mt-1 text-xs text-muted-foreground">AI suggestion available</p>}</td>
              <td className="finding-column"><StatusBadge status={finding.status} /></td>{showOwner && <td className="finding-column break-words text-xs text-muted-foreground">{finding.owner || "Unassigned"}</td>}
              <td className="finding-details"><Link href={"/findings/" + finding.id + detailQuery} aria-label={"Full details for " + finding.ruleName} className="grid size-11 place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-primary"><ArrowUpRight aria-hidden className="size-4" /></Link></td>
            </tr>)}</tbody>
          </table>
        </div>
        {pages > 1 && <nav aria-label="Finding pages" className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-xs text-muted-foreground">
          <span>{(page - 1) * 50 + 1}–{Math.min(page * 50, total)} of {total}</span>
          <div className="flex items-center gap-3"><Button variant="ghost" size="sm" className="min-h-11" disabled={loading || page <= 1} onClick={() => change("page", String(page - 1))}>Previous</Button><span>{page} / {pages}</span><Button variant="ghost" size="sm" className="min-h-11" disabled={loading || page >= pages} onClick={() => change("page", String(page + 1))}>Next</Button></div>
        </nav>}
      </section>
      {inspected && <EvidenceWorkbench key={inspected.id} finding={inspected} detailQuery={detailQuery} onClose={closeInspector} />}
    </div>}
  </div>;
}
