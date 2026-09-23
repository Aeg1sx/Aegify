"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Search, SlidersHorizontal, Save, Bot, Loader2, ArrowUpRight } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { EvidenceWorkbench, type FindingEvidenceView } from "@/components/finding/evidence-workbench";
import { EVIDENCE_LABELS } from "@/lib/code-evidence";
import { findingFilters, filterQuery, type FindingFilters } from "@/lib/finding-view";

interface Finding extends FindingEvidenceView { aiVerdict: string; createdAt: string; confidence: number }
interface SavedView { name: string; query: string }
const presets = [
  { name: "All findings", values: {} },
  { name: "Critical / open", values: { severity: "critical", status: "open" } },
  { name: "Regressions", values: { baselineState: "regressed" } },
  { name: "Static candidates", values: { evidenceState: "candidate" } },
];

export default function FindingsPage() {
  const [filters, setFilters] = useState(findingFilters());
  const [ready, setReady] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [advanced, setAdvanced] = useState(false);
  const [compact, setCompact] = useState(true);
  const [showOwner, setShowOwner] = useState(true);
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchMessage, setBatchMessage] = useState("");
  const [saved, setSaved] = useState<SavedView[]>([]);
  const [saveName, setSaveName] = useState("");
  const [projects, setProjects] = useState<Array<{ id: string; name: string }>>([]);
  const [rules, setRules] = useState<Array<{ id: string; name: string }>>([]);
  const [languages, setLanguages] = useState<string[]>([]);
  const rowButtons = useRef<Map<string, HTMLButtonElement>>(new Map());

  useEffect(() => {
    const restore = () => setFilters(findingFilters(new URLSearchParams(window.location.search)));
    const frame = requestAnimationFrame(() => {
      restore();
      try {
        const parsed: unknown = JSON.parse(localStorage.getItem("aegify.findingViews.v1") || "[]");
        if (Array.isArray(parsed)) setSaved(parsed.filter((v): v is SavedView => typeof v?.name === "string" && typeof v?.query === "string").slice(0, 12));
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
    if (!ready) return;
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
          setFindings(data.findings); setTotal(data.total); setSelected(new Set());
          setInspectedId((id) => data.findings.some((f: Finding) => f.id === id) ? id : null);
        }
      } catch (e) {
        if (!controller.signal.aborted) { setError(e instanceof Error ? e.message : "Unable to load findings."); setFindings([]); }
      } finally { if (!controller.signal.aborted) setLoading(false); }
    }, 220);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [filters, ready, retry]);

  const change = (key: keyof FindingFilters, value: string) => setFilters((f) => ({ ...f, [key]: value, page: key === "page" ? value : "1" }));
  const closeInspector = useCallback(() => {
    if (inspectedId) rowButtons.current.get(inspectedId)?.focus();
    setInspectedId(null);
  }, [inspectedId]);
  const inspected = findings.find((finding) => finding.id === inspectedId);
  useEffect(() => {
    if (inspectedId && window.matchMedia("(max-width: 1279px)").matches) {
      document.querySelector('[aria-label="Finding evidence inspector"]')?.scrollIntoView({ block: "start" });
    }
  }, [inspectedId]);
  const page = Number(filters.page);
  const pages = Math.max(1, Math.ceil(total / 50));
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
    return <select aria-label={label} className="workbench-select" value={filters[key]} onChange={(e) => change(key, e.target.value)}>
      <option value="">{label}</option>{values.map(([value, name]) => <option key={value} value={value}>{name}</option>)}
    </select>;
  }

  return <div className="space-y-5">
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="eyebrow mb-2">Triage workspace</p><h1 className="text-3xl font-semibold tracking-tight">Findings <span className="ml-2 font-mono text-lg font-normal text-muted-foreground">{loading ? "…" : total.toLocaleString()}</span></h1><p className="mt-2 text-sm text-muted-foreground">Inspect the source. Follow the evidence. Decide what to fix.</p></div>
      <div className="flex items-center gap-2">
        <select className="workbench-select" aria-label="Table density" value={compact ? "compact" : "comfortable"} onChange={(e) => { setCompact(e.target.value === "compact"); try { localStorage.setItem("aegify.tableDensity", e.target.value); } catch {} }}><option value="compact">Compact rows</option><option value="comfortable">Comfortable rows</option></select>
        <label className="flex items-center gap-2 text-xs text-muted-foreground"><input type="checkbox" checked={showOwner} onChange={(e) => { setShowOwner(e.target.checked); try { localStorage.setItem("aegify.findingOwner", e.target.checked ? "visible" : "hidden"); } catch {} }} />Owner column</label>
      </div>
    </header>
    <div className="flex flex-wrap gap-1 border-b border-border pb-3">
      {presets.map((preset) => <button key={preset.name} type="button" className="rounded-md px-3 py-1.5 text-xs font-medium hover:bg-accent" onClick={() => setFilters({ ...findingFilters(), ...preset.values })}>{preset.name}</button>)}
      {saved.map((view, index) => <span key={view.name + index} className="inline-flex items-center rounded-md border bg-card">
        <button type="button" className="px-3 py-1.5 text-xs" onClick={() => setFilters(findingFilters(new URLSearchParams(view.query)))}>{view.name}</button>
        <button type="button" aria-label={"Delete saved view " + view.name} className="px-2 text-muted-foreground" onClick={() => { const next = saved.filter((_, i) => i !== index); setSaved(next); try { localStorage.setItem("aegify.findingViews.v1", JSON.stringify(next)); } catch {} }}>×</button>
      </span>)}
    </div>
    <div className="workbench-panel">
      <div className="flex flex-wrap items-center gap-2 p-3">
        <div className="relative min-w-52 flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><input aria-label="Search findings" placeholder="Search rule, file, or message…" className="h-9 w-full rounded-md border bg-background pl-9 pr-3 text-sm" value={filters.search} onChange={(e) => change("search", e.target.value)} /></div>
        {selectFilter("severity", "All severities", ["critical", "high", "medium", "low"].map((v) => [v, v]))}
        {selectFilter("status", "All statuses", ["open", "triaged", "confirmed", "in_progress", "false_positive", "accepted_risk", "fixed"].map((v) => [v, v.replaceAll("_", " ")]))}
        {selectFilter("evidenceState", "All evidence", Object.entries(EVIDENCE_LABELS))}
        <Button variant="outline" size="sm" aria-expanded={advanced} onClick={() => setAdvanced(!advanced)}><SlidersHorizontal className="mr-1 h-3.5 w-3.5" />Filters</Button>
        <select aria-label="Sort findings" className="workbench-select" value={filters.sort} onChange={(e) => change("sort", e.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="file">Source location</option><option value="rule">Rule name</option></select>
      </div>
      {advanced && <div className="flex flex-wrap items-center gap-2 border-t border-border bg-muted/30 p-3">
        {selectFilter("projectId", "All projects", projects.map((p) => [p.id, p.name]))}
        {selectFilter("ruleId", "All rules", rules.map((r) => [r.id, r.id]))}
        {selectFilter("language", "All languages", languages.map((l) => [l, l]))}
        {selectFilter("source", "All sources", [["sast", "SAST"], ["llm", "AI review"]])}
        {selectFilter("disposition", "All gates", [["blocking", "Blocking"], ["advisory", "Advisory"]])}
        <label className="flex items-center gap-2 px-2 text-xs"><input type="checkbox" checked={filters.history === "true"} onChange={(e) => change("history", e.target.checked ? "true" : "")} />Include history</label>
        <input aria-label="Saved view name" placeholder="Name this view" maxLength={40} value={saveName} onChange={(e) => setSaveName(e.target.value)} className="workbench-select w-36" />
        <Button variant="outline" size="sm" disabled={!saveName.trim() || saved.length >= 12} onClick={() => {
          const next = [...saved, { name: saveName.trim(), query: filterQuery({ ...filters, page: "1" }) }]; setSaved(next); setSaveName("");
          try { localStorage.setItem("aegify.findingViews.v1", JSON.stringify(next)); } catch { setError("Browser storage is unavailable. This view will only last for this session."); }
        }}><Save className="mr-1 h-3.5 w-3.5" />Save view</Button>
        <button type="button" className="px-2 text-xs text-primary" onClick={() => setFilters(findingFilters())}>Reset filters</button>
      </div>}
    </div>
    {batchMessage && <p role="status" className="text-sm text-muted-foreground">{batchMessage}</p>}
    {error && <div role="alert" className="flex items-center justify-between rounded-md border border-destructive/30 p-4 text-sm text-destructive">{error}<Button variant="outline" size="sm" onClick={() => setRetry((n) => n + 1)}>Retry</Button></div>}
    <div className={"grid items-start gap-4 " + (inspected ? "2xl:grid-cols-[minmax(0,1fr)_480px] xl:grid-cols-[minmax(0,1fr)_420px]" : "")}>
      <section className="workbench-panel">
        <div className="workbench-heading">
          <p className="text-xs text-muted-foreground">{filters.history === "true" ? "All recorded occurrences" : "Current occurrences"} · {selected.size ? selected.size + " selected" : "Select a finding to inspect"}</p>
          {selected.size > 0 && <Button size="sm" disabled={batchRunning || loading} onClick={batchAnalyze}>{batchRunning ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Bot className="mr-1 h-3.5 w-3.5" />}Review selected</Button>}
        </div>
        <div className="max-h-[68vh] overflow-auto" aria-busy={loading}>
          <table className={"data-table " + (compact ? "compact" : "")}>
            <caption className="sr-only">Security findings. Use up and down arrows on a finding title to inspect adjacent rows.</caption>
            <thead><tr>
              <th className="w-10"><input aria-label="Select all visible findings" type="checkbox" disabled={loading || !findings.length} checked={findings.length > 0 && selected.size === findings.length} onChange={() => setSelected(selected.size === findings.length ? new Set() : new Set(findings.map((f) => f.id)))} /></th>
              <th>Severity</th><th className="min-w-64">Finding / source</th><th className="min-w-32">Evidence</th><th>Status</th>{showOwner && <th>Owner</th>}<th><span className="sr-only">Details</span></th>
            </tr></thead>
            <tbody>{loading ? <tr><td colSpan={showOwner ? 7 : 6} className="h-40 text-center text-muted-foreground"><Loader2 className="mx-auto mb-2 h-5 w-5 animate-spin" />Loading findings…</td></tr> : findings.length === 0 ? <tr><td colSpan={showOwner ? 7 : 6} className="h-40 text-center text-muted-foreground">No findings match this view. <button type="button" className="text-primary" onClick={() => setFilters(findingFilters())}>Clear filters</button></td></tr> : findings.map((finding, index) => <tr key={finding.id} className={inspectedId === finding.id ? "!bg-primary/5" : ""} aria-selected={inspectedId === finding.id}>
              <td><input aria-label={"Select " + finding.ruleName + " at " + finding.filePath} type="checkbox" checked={selected.has(finding.id)} onChange={() => toggle(finding.id)} /></td>
              <td><SeverityBadge severity={finding.severity} /></td>
              <td><button type="button" ref={(el) => { if (el) rowButtons.current.set(finding.id, el); else rowButtons.current.delete(finding.id); }} className="block max-w-lg text-left font-medium hover:text-primary" onClick={() => setInspectedId(finding.id)} onKeyDown={(event) => {
                if (event.key === "Escape") { closeInspector(); return; }
                if (!["ArrowDown", "ArrowUp"].includes(event.key)) return;
                event.preventDefault(); const next = findings[index + (event.key === "ArrowDown" ? 1 : -1)];
                if (next) { setInspectedId(next.id); rowButtons.current.get(next.id)?.focus(); }
              }}>{finding.ruleName}</button><p title={finding.filePath} className="mt-1 max-w-sm truncate font-mono text-[11px] text-muted-foreground">{finding.filePath}:{finding.lineStart}</p>{finding.baselineState === "regressed" && <span className="text-[11px] text-destructive">↳ Regressed</span>}</td>
              <td><span className="text-xs">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified"}</span>{finding.aiVerdict && <p className="mt-1 text-[10px] text-muted-foreground">AI suggestion available</p>}</td>
              <td><StatusBadge status={finding.status} /></td>{showOwner && <td className="text-xs text-muted-foreground">{finding.owner || "Unassigned"}</td>}
              <td><Link href={"/findings/" + finding.id} aria-label={"Full details for " + finding.ruleName}><ArrowUpRight className="h-4 w-4 text-muted-foreground" /></Link></td>
            </tr>)}</tbody>
          </table>
        </div>
        <footer className="flex items-center justify-between gap-2 border-t border-border px-4 py-3 text-xs text-muted-foreground">
          <span>{total ? ((page - 1) * 50 + 1) + "–" + Math.min(page * 50, total) : 0} of {total} · 50 per page</span>
          <div className="flex items-center gap-3"><Button variant="ghost" size="sm" disabled={loading || page <= 1} onClick={() => change("page", String(page - 1))}>Previous</Button><span>{page} / {pages}</span><Button variant="ghost" size="sm" disabled={loading || page >= pages} onClick={() => change("page", String(page + 1))}>Next</Button></div>
        </footer>
      </section>
      {inspected && <EvidenceWorkbench key={inspected.id} finding={inspected} onClose={closeInspector} />}
    </div>
  </div>;
}
