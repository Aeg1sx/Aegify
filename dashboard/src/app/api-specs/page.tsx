"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, FileJson2, FileUp, GitCompareArrows, Link2, Loader2, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CodeHighlight } from "@/components/code-highlight";
import type { ApiContract, ContractEndpoint, ContractOperation } from "@/lib/openapi-contract";

interface Scan { id: string; repository: string; branch: string; createdAt: string }
interface Snapshot { id: string; repositoryId: string; title: string; sourceName: string; sourceUrl: string; contentHash: string; apiVersion: string; specVersion: string; operationCount: number; createdAt: string }
interface Operation extends ContractOperation { matches: ContractEndpoint[]; association: string; reviewNotes: string[] }
interface Comparison { operations: Operation[]; matched: number; specOnly: number; ambiguous: number; codeOnly: ContractEndpoint[] }
interface Inspection { contract: ApiContract; comparison: Comparison; sourceName: string }
const field = "h-10 w-full min-w-0 rounded-md border bg-background px-3 text-sm";
const AUTH_LABELS = { required: "Required by spec", optional: "Optional by spec", none: "No requirement", undeclared: "Not declared", unknown: "Unknown" };

export default function ApiSpecificationsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanId, setScanId] = useState("");
  const [repositories, setRepositories] = useState<string[]>([]);
  const [repositoryId, setRepositoryId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [totalSnapshots, setTotalSnapshots] = useState(0);
  const [snapshotId, setSnapshotId] = useState("");
  const [mode, setMode] = useState<"file" | "url">("file");
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [preview, setPreview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState("");
  const [visible, setVisible] = useState(100);
  const [revision, setRevision] = useState(0);
  const invalidate = () => { setPreview(false); setInspection(null); setSnapshotId(""); setError(""); setNotice(""); setSelected(""); };
  const changeSource = (nextMode: "file" | "url") => {
    if (nextMode === mode) return;
    invalidate();
    // The keyed file input is unmounted on a source change; clear its backing file too.
    setFile(null);
    setMode(nextMode);
  };

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/scans?limit=100", { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error("Unable to load scans.");
      const data = await response.json(); setScans(data.scans || []);
      const requested = new URLSearchParams(window.location.search).get("scanId");
      if (requested && data.scans.some((scan: Scan) => scan.id === requested)) setScanId(requested);
    }).catch((reason) => { if (!controller.signal.aborted) setError(reason.message); });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (!scanId) return;
    const controller = new AbortController();
    void fetch("/api/endpoints/import-openapi?scanId=" + encodeURIComponent(scanId), { signal: controller.signal, cache: "no-store" }).then(async (response) => {
      if (!response.ok) throw new Error("Unable to load specification snapshots.");
      const data = await response.json(); setRepositories(data.repositoryIds); setSnapshots(data.specifications); setTotalSnapshots(data.total);
    }).catch((reason) => { if (!controller.signal.aborted) setError(reason.message); });
    return () => controller.abort();
  }, [scanId, revision]);
  useEffect(() => {
    if (!snapshotId || !scanId) return;
    const controller = new AbortController();
    const frame = requestAnimationFrame(() => {
      setLoading(true); setError(""); setInspection(null); setPreview(false); setSelected("");
      void fetch("/api/endpoints/import-openapi?" + new URLSearchParams({ scanId, id: snapshotId }), { signal: controller.signal, cache: "no-store" }).then(async (response) => {
        const data = await response.json(); if (!response.ok) throw new Error(data.error || "Unable to load snapshot.");
        if (!controller.signal.aborted) setInspection({ contract: data.spec.contract, comparison: data.comparison, sourceName: data.spec.sourceName });
      }).catch((reason) => { if (!controller.signal.aborted) setError(reason.message); }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    });
    return () => { cancelAnimationFrame(frame); controller.abort(); };
  }, [snapshotId, scanId]);

  const importSpec = async (save: boolean) => {
    if (repositoryId === null) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const params = new URLSearchParams({ scanId, repositoryId });
      if (save) params.set("expectedHash", inspection?.contract.digest || ""); else params.set("preview", "true");
      let body: BodyInit; const headers: Record<string, string> = {};
      if (mode === "file") { if (!file) throw new Error("Choose a specification file."); const form = new FormData(); form.set("file", file); body = form; }
      else { headers["Content-Type"] = "application/json"; body = JSON.stringify({ url, authorized }); }
      const response = await fetch("/api/endpoints/import-openapi?" + params, { method: "POST", body, headers });
      const data = await response.json(); if (!response.ok) { setPreview(false); throw new Error(data.error || "Import failed."); }
      if (save) {
        setPreview(false); setNotice(data.duplicate ? "This exact snapshot is already attached. No endpoints changed." : "Snapshot attached. " + data.imported + " documentation-only endpoints added; source findings and auth signals were not changed.");
        setRevision((value) => value + 1); setSnapshotId(data.id);
      } else { setInspection(data); setSnapshotId(""); setPreview(true); setSelected(""); setVisible(100); }
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Import failed."); }
    finally { setBusy(false); }
  };
  const comparison = inspection?.comparison;
  const operations = (comparison?.operations || []).filter((operation) => (filter === "all" || operation.association === filter) && (operation.method + " " + operation.path + " " + operation.operationId + " " + operation.tags.join(" ")).toLowerCase().includes(query.toLowerCase()));
  const operation = operations.find((item) => item.pointer === selected) || operations[0];
  const activeSnapshot = snapshots.find((item) => item.id === snapshotId);
  const download = () => {
    if (!inspection) return;
    const blob = new Blob([JSON.stringify({ kind: "normalized_contract_review", evidenceBoundary: "Documentation and exact-route associations only; not runtime proof or a full schema validator.", scanId, repositoryId: activeSnapshot?.repositoryId ?? repositoryId, ...inspection }, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = href; link.download = "api-contract-" + inspection.contract.digest.slice(0, 12) + ".json"; link.click(); URL.revokeObjectURL(href);
  };
  return <div className="space-y-6">
    <header className="flex flex-wrap items-start justify-between gap-4"><div><p className="eyebrow">Application context</p><h1 className="mt-2 text-3xl font-semibold tracking-tight">API specifications</h1><p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">Connect the documented API to the code you scanned. Inspect requirements, preserve provenance, and identify gaps without treating documentation as proof.</p></div><Link href="/endpoints" className="inline-flex items-center gap-2 text-xs text-primary">Endpoint inventory<ArrowRight className="h-3 w-3" /></Link></header>
    {error && <p role="alert" className="rounded-md border border-destructive/30 p-3 text-sm text-destructive">{error}</p>}
    {notice && <p role="status" className="rounded-md border border-emerald-500/30 p-3 text-sm">{notice}</p>}
    <div className="grid items-start gap-5 xl:grid-cols-[300px_minmax(0,1fr)]">
      <aside className="min-w-0 space-y-5">
        <section className="workbench-panel p-5"><h2 className="text-sm font-semibold">Attach a contract</h2><p className="mt-2 text-xs leading-6 text-muted-foreground">Swagger 2.0 · OpenAPI 3.0 / 3.1 / 3.2<br />JSON or YAML · up to 2 MiB</p>
          <fieldset disabled={busy || loading} className="mt-5 min-w-0 space-y-4">
            <div><label htmlFor="spec-scan" className="mb-2 block text-xs font-medium">Scan snapshot</label><select id="spec-scan" className={field} value={scanId} onChange={(event) => { invalidate(); setScanId(event.target.value); setRepositoryId(null); setRepositories([]); setSnapshots([]); }}><option value="">Select a scan…</option>{scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.repository || scan.id.slice(0, 8)} · {scan.branch || "snapshot"} · {new Date(scan.createdAt).toLocaleDateString("en-US")}</option>)}</select></div>
            <div><label htmlFor="spec-repository" className="mb-2 block text-xs font-medium">Repository scope</label><select id="spec-repository" className={field} value={repositoryId === null ? "__choose__" : repositoryId} disabled={!scanId} onChange={(event) => { invalidate(); setRepositoryId(event.target.value === "__choose__" ? null : event.target.value); }}><option value="__choose__">Select a repository…</option>{repositories.map((id) => <option key={id} value={id}>{id || "Scan default repository"}</option>)}</select></div>
            <div className="grid grid-cols-2 gap-1 rounded-md bg-muted p-1" aria-label="Specification source">{(["file", "url"] as const).map((value) => <button type="button" key={value} aria-pressed={mode === value} onClick={() => changeSource(value)} className={"inline-flex items-center justify-center gap-2 rounded px-3 py-2 text-xs " + (mode === value ? "bg-background shadow-sm" : "text-muted-foreground")}>{value === "file" ? <FileUp className="h-3.5 w-3.5" /> : <Link2 className="h-3.5 w-3.5" />}{value === "file" ? "Upload file" : "HTTPS URL"}</button>)}</div>
            {/* Distinct keys prevent React from reusing an uncontrolled file input as a controlled URL input. */}
            {mode === "file" ? (
              <div key="file">
                <label htmlFor="spec-file" className="mb-2 block text-xs font-medium">Specification file</label>
                <input id="spec-file" type="file" accept=".json,.yaml,.yml" className="w-full min-w-0 text-xs file:mr-3 file:rounded file:border file:bg-muted file:px-3 file:py-2" onChange={(event) => { invalidate(); setFile(event.target.files?.[0] || null); }} />
              </div>
            ) : (
              <div key="url" className="space-y-3">
                <label htmlFor="spec-url" className="block text-xs font-medium">Raw specification URL</label>
                <input id="spec-url" type="url" className={field} value={url} placeholder="https://api.example.com/openapi.json" onChange={(event) => { invalidate(); setUrl(event.target.value); }} />
                <label className="flex items-start gap-2 text-xs leading-5">
                  <input type="checkbox" className="mt-1" checked={authorized} onChange={(event) => { invalidate(); setAuthorized(event.target.checked); }} />
                  I am authorized to retrieve this specification.
                </label>
                <p className="text-[11px] leading-5 text-muted-foreground">Public HTTPS only. Preview and import each fetch the document once. No redirects, credentials, private IPs, or external reference fetching. Upload private specs as files.</p>
              </div>
            )}
            <Button className="w-full" variant="outline" disabled={!scanId || repositoryId === null || (mode === "file" ? !file : !url || !authorized)} onClick={() => importSpec(false)}>{busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}Preview contract</Button>
            {preview && <Button className="w-full" disabled={!inspection?.contract.operations.length} onClick={() => importSpec(true)}>Attach this snapshot<ArrowRight className="ml-2 h-4 w-4" /></Button>}
          </fieldset>
        </section>
        <section className="workbench-panel overflow-hidden"><div className="border-b p-4"><h2 className="text-sm font-semibold">Snapshot history</h2><p className="mt-1 text-[11px] text-muted-foreground">Showing {snapshots.length} of {totalSnapshots} · selected scan</p></div><div className="max-h-[420px] overflow-auto">{snapshots.length ? snapshots.map((snapshot) => <button key={snapshot.id} disabled={busy || loading} onClick={() => { setSnapshotId(snapshot.id); setPreview(false); setQuery(""); setFilter("all"); }} className={"block w-full border-b px-4 py-3 text-left last:border-0 " + (snapshotId === snapshot.id ? "bg-primary/5" : "hover:bg-muted/40")}><p className="truncate text-xs font-medium">{snapshot.title}</p><p className="mt-1 truncate text-[11px] text-muted-foreground">{snapshot.repositoryId || "Default repository"} · {snapshot.operationCount} operations</p><p className="mt-2 font-mono text-[10px] text-muted-foreground">{snapshot.contentHash.slice(0, 12)} · {new Date(snapshot.createdAt).toLocaleDateString("en-US")}</p></button>) : <p className="p-5 text-xs leading-6 text-muted-foreground">{scanId ? "No imported snapshots in this scan." : "Select a scan to view its specification history."}</p>}</div></section>
      </aside>
      <main className="min-w-0 space-y-5">
        {loading && <p role="status" className="flex items-center gap-2 p-6 text-sm"><Loader2 className="h-4 w-4 animate-spin" />Loading snapshot…</p>}
        {!inspection && !loading && <section className="workbench-panel px-8 py-16"><GitCompareArrows className="h-9 w-9 text-primary" /><h2 className="mt-5 text-xl font-semibold">From API contract to code context</h2><p className="mt-3 max-w-lg text-sm leading-7 text-muted-foreground">Choose a scan and repository, then preview a spec or open a saved snapshot. Route matching never crosses scan or repository boundaries.</p><div className="mt-10 grid gap-5 sm:grid-cols-3">{[["01", "Read the contract", "Parameters, schemas, security alternatives, and response types."], ["02", "Compare with source", "Exact method/path matches, documentation-only routes, and source-only routes."], ["03", "Review the evidence", "Inspect linked source findings and missing enforcement signals. No live API calls."]].map(([number, title, detail]) => <div key={number} className="border-t pt-4"><p className="font-mono text-xs text-primary">{number}</p><h3 className="mt-3 text-sm font-medium">{title}</h3><p className="mt-2 text-xs leading-6 text-muted-foreground">{detail}</p></div>)}</div></section>}
        {inspection && comparison && <>
          <section className="workbench-panel p-5"><div className="flex flex-wrap justify-between gap-3"><div className="min-w-0"><p className="eyebrow">{preview ? "Unsaved preview" : "Saved documentation snapshot"}</p><h2 className="mt-2 break-words text-xl font-semibold">{inspection.contract.title}</h2><p className="mt-2 break-all text-xs text-muted-foreground">{inspection.sourceName} · spec {inspection.contract.version} · API {inspection.contract.apiVersion || "unspecified"}</p></div><Button size="sm" variant="outline" onClick={download}><FileJson2 className="mr-2 h-3.5 w-3.5" />Export review</Button></div><p className="mt-4 break-all font-mono text-[10px] text-muted-foreground">SHA-256 {inspection.contract.digest}</p>{activeSnapshot?.sourceUrl && <Button className="mt-4" size="sm" variant="outline" onClick={() => { invalidate(); setFile(null); setMode("url"); setUrl(activeSnapshot.sourceUrl); setRepositoryId(activeSnapshot.repositoryId); setAuthorized(false); }}>Prepare URL refresh</Button>}<div className="mt-5 grid grid-cols-2 gap-3 border-t pt-4 sm:grid-cols-4">{[["Exact route matches", comparison.matched], ["Spec only", comparison.specOnly], ["Ambiguous", comparison.ambiguous], ["Code only vs this spec", comparison.codeOnly.length]].map(([label, count]) => <div key={String(label)}><p className="text-2xl font-semibold tabular-nums">{count}</p><p className="mt-1 text-[11px] text-muted-foreground">{label}</p></div>)}</div></section>
          <div className="flex items-start gap-2 rounded-md border border-amber-500/25 p-3 text-xs leading-6 text-muted-foreground"><ShieldCheck className="mt-1 h-4 w-4 shrink-0" /><p>Declared authentication is not verified enforcement. Spec-only does not mean deployed, and code-only does not prove an undocumented vulnerability. Source associations are exact-route matches, not proven execution paths.</p></div>
          {!!inspection.contract.warnings.length && <details className="workbench-panel p-4" open><summary className="cursor-pointer text-xs font-medium">Extraction gaps · {inspection.contract.warnings.length}</summary><ul className="mt-3 list-disc space-y-2 pl-5 text-xs text-muted-foreground">{inspection.contract.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></details>}
          <section className="workbench-panel overflow-hidden"><div className="flex flex-wrap gap-3 border-b p-4"><input aria-label="Search specification operations" className={field + " flex-1 basis-48"} value={query} placeholder="Search route, operation ID, tag…" onChange={(event) => { setQuery(event.target.value); setVisible(100); }} /><select aria-label="Filter contract associations" className={field + " sm:w-44"} value={filter} onChange={(event) => { setFilter(event.target.value); setVisible(100); }}><option value="all">All operations</option><option value="exact_route">Exact route match</option><option value="spec_only">Spec only</option><option value="ambiguous">Ambiguous</option></select></div><div className="max-h-[380px] overflow-auto"><table className="data-table w-full min-w-[580px]"><thead><tr><th>Operation</th><th>Association</th><th>Authentication</th></tr></thead><tbody>{operations.slice(0, visible).map((item) => <tr key={item.pointer} className={operation?.pointer === item.pointer ? "bg-primary/5" : ""}><td><button className="block w-full text-left" onClick={() => setSelected(item.pointer)}><span className="mr-3 font-mono text-[10px] font-semibold text-primary">{item.method}</span><span className="break-all font-mono text-xs">{item.path}</span><span className="mt-1 block text-[11px] text-muted-foreground">{item.operationId || item.summary || "No operation ID"}</span></button></td><td className="text-xs">{item.association.replaceAll("_", " ")}</td><td className="text-xs">{AUTH_LABELS[item.security.state]}</td></tr>)}</tbody></table>{!operations.length && <p className="p-5 text-xs text-muted-foreground">No operations match this filter.</p>}</div>{operations.length > visible && <Button variant="ghost" className="w-full" onClick={() => setVisible((count) => count + 100)}>Show 100 more ({operations.length - visible} remaining)</Button>}</section>
          {operation && <section className="workbench-panel min-w-0 overflow-hidden"><div className="border-b p-5"><p className="eyebrow">Contract inspector</p><h3 className="mt-2 break-all font-mono text-sm">{operation.method} {operation.path}</h3><p className="mt-2 break-all text-[11px] text-muted-foreground">{operation.pointer}</p>{operation.reviewNotes.map((note) => <p key={note} className="mt-3 text-xs leading-6 text-amber-700 dark:text-amber-300">{note}</p>)}<div className="mt-4 space-y-2">{operation.matches.map((match) => <Link key={match.id} href={"/endpoints/" + match.id} className="flex items-start justify-between gap-2 rounded border p-3 text-xs hover:bg-muted/40"><span className="min-w-0 break-all">{match.filePath}:{match.lineStart}–{match.lineEnd}<span className="mt-1 block text-muted-foreground">Inspect source findings and recorded evidence</span></span><ArrowRight className="h-4 w-4 shrink-0 text-primary" /></Link>)}</div></div><CodeHighlight code={JSON.stringify({ security: operation.security, securitySchemes: inspection.contract.securitySchemes, parameters: operation.parameters, requestBody: operation.requestBody, responses: operation.responses, servers: operation.servers, deprecated: operation.deprecated }, null, 2)} language="json" filePath="normalized-contract.json" /></section>}
          {!!comparison.codeOnly.length && <details className="workbench-panel p-4"><summary className="cursor-pointer text-sm font-medium">Source routes absent from this specification · {comparison.codeOnly.length}</summary><p className="mt-2 text-xs leading-6 text-muted-foreground">This comparison covers only the selected document, not every specification for this service.</p><div className="mt-4 max-h-64 space-y-2 overflow-auto">{comparison.codeOnly.map((endpoint) => <Link key={endpoint.id} href={"/endpoints/" + endpoint.id} className="block break-all font-mono text-xs text-primary">{endpoint.method} {endpoint.path}</Link>)}</div></details>}
        </>}
      </main>
    </div>
  </div>;
}
