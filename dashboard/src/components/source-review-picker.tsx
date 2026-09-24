"use client";

import { useEffect, useState } from "react";
import { Button } from "./ui/button";

interface Choice { id: string; ruleName: string; severity: string; filePath: string; lineStart: number }

export function SourceReviewPicker({ scanId, selected, onChange, disabled }: { scanId: string; selected: string[]; onChange: (ids: string[]) => void; disabled: boolean }) {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<{ page: number; findings: Choice[]; total: number } | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams({ scanId, page: String(page), limit: "20", ...(query ? { search: query } : {}) });
    fetch(`/api/findings?${params}`, { signal: controller.signal, cache: "no-store" }).then(async (response) => {
      const value = await response.json();
      if (!response.ok) throw new Error(value.error || "Could not load findings.");
      if (!controller.signal.aborted) { setData({ page, findings: value.findings, total: value.total }); setError(""); }
    }).catch((failure) => {
      if (!controller.signal.aborted) { setData(null); setError(failure instanceof Error ? failure.message : "Could not load findings."); }
    });
    return () => controller.abort();
  }, [scanId, page, query, reload]);
  const ready = data?.page === page;
  return <section className="space-y-3 rounded-md border p-3" aria-label="Select findings for source review">
    <div><h3 className="text-sm font-medium">Choose findings to investigate · {selected.length}/25</h3>
      <p className="mt-1 text-xs text-muted-foreground">The agent can list, read and search retained source from this scan. It reviews five findings per batch. Select up to 25 across pages.</p></div>
    <div className="flex gap-2">
      <input aria-label="Search findings for source review" className="min-w-0 flex-1 rounded border px-2 py-1 text-xs" value={search} onChange={(event) => setSearch(event.target.value)} disabled={disabled} />
      <Button type="button" size="sm" variant="outline" disabled={disabled} onClick={() => { setData(null); setPage(1); setQuery(search); setReload((value) => value + 1); }}>Search</Button>
      <Button type="button" size="sm" variant="outline" disabled={disabled || !selected.length} onClick={() => onChange([])}>Clear selection</Button>
    </div>
    {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    {!ready && !error && <p role="status" className="text-xs">Loading findings…</p>}
    {ready && <>
      <div className="max-h-80 space-y-2 overflow-auto">{data.findings.map((finding) => <label key={finding.id} className="flex items-start gap-2 rounded border p-2 text-xs">
        <input type="checkbox" className="mt-1" checked={selected.includes(finding.id)} disabled={disabled || (!selected.includes(finding.id) && selected.length >= 25)}
          onChange={(event) => onChange(event.target.checked ? [...selected, finding.id] : selected.filter((id) => id !== finding.id))} />
        <span className="min-w-0"><span className="block font-medium">{finding.ruleName} · {finding.severity}</span><span className="block break-all font-mono text-muted-foreground">{finding.filePath}:{finding.lineStart}</span></span>
      </label>)}{!data.findings.length && <p className="text-xs text-muted-foreground">No matching findings.</p>}</div>
      <div className="flex items-center justify-between gap-2 text-xs">
        <Button type="button" size="sm" variant="outline" disabled={disabled || page <= 1} onClick={() => setPage(page - 1)}>Previous findings</Button>
        <span>Page {page} · {data.total} matches</span>
        <Button type="button" size="sm" variant="outline" disabled={disabled || page * 20 >= data.total} onClick={() => setPage(page + 1)}>Next findings</Button>
      </div>
    </>}
  </section>;
}
