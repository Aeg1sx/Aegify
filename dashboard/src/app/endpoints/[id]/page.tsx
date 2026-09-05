"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Activity, ArrowLeft, ArrowRight, Check, Copy, Download, FileCode2, GitBranch, Layers, Loader2, MonitorSmartphone, Route, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CodeHighlight } from "@/components/code-highlight";
import { SeverityBadge } from "@/components/severity-badge";
import { EvidenceWorkbench, type FindingEvidenceView } from "@/components/finding/evidence-workbench";
import { handlerRange, parseEndpointContract, parseEndpointEvidence, type EvidenceKind } from "@/lib/endpoint-evidence";

interface EndpointDetail {
  id: string; scanId: string; path: string; method: string; handlerFunction: string;
  filePath: string; lineStart: number; lineEnd: number; framework: string; authRequired: boolean;
  parameters: string; middleware: string; repositoryId: string;
  calledByFrontend: boolean; frontendCallCount: number; frontendEvidence: string;
  exposedViaGateway: boolean; gatewayEvidence: string;
  runtimeObserved: boolean; runtimeObservationCount: number; runtimeEvidence: string;
  scan: { id: string; repository: string; branch: string; commitSha: string; createdAt: string };
}
interface DetailResponse {
  apiContractContext?: { boundary: string; snapshotLimit: number; references: Array<{ specificationId: string; title: string; contentHash: string; pointer: string; reviewNote: string; security: { state: string } }> };
  endpoint: EndpointDetail; relatedFindings: FindingEvidenceView[]; relatedFindingCount: number;
  association: "handler_range_overlap" | "unavailable_handler_range";
  siblings: Array<Pick<EndpointDetail, "id" | "method" | "path" | "handlerFunction" | "lineStart" | "lineEnd" | "authRequired">>;
  siblingCount: number;
}
type Tab = "overview" | "evidence" | "findings" | "contract";
const KINDS: EvidenceKind[] = ["frontend", "gateway", "runtime"];
const LABELS = { frontend: "Frontend", gateway: "Gateway", runtime: "Runtime" };
const ICONS = { frontend: MonitorSmartphone, gateway: Route, runtime: Activity };

export default function EndpointDetailPage() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<DetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const [tab, setTab] = useState<Tab>("overview");
  const [evidenceKind, setEvidenceKind] = useState<"all" | EvidenceKind>("all");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [selectedEvidence, setSelectedEvidence] = useState("");
  const [selectedFinding, setSelectedFinding] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    const frame = requestAnimationFrame(() => {
      setLoading(true); setError(""); setNotice(""); setQuery(""); setSelectedEvidence(""); setSelectedFinding("");
      void (async () => {
        try {
          const response = await fetch("/api/endpoints/" + encodeURIComponent(params.id), { signal: controller.signal, cache: "no-store" });
          const result = await response.json();
          if (!response.ok || !result.endpoint) throw new Error(result.error || "Unable to load endpoint.");
          if (!controller.signal.aborted) setData(result);
        } catch (reason) {
          if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Unable to load endpoint.");
        } finally { if (!controller.signal.aborted) setLoading(false); }
      })();
    });
    return () => { cancelAnimationFrame(frame); controller.abort(); };
  }, [params.id, retry]);

  const endpoint = data?.endpoint;
  const parsed = useMemo(() => ({
    frontend: parseEndpointEvidence(endpoint?.frontendEvidence || "[]", "frontend"),
    gateway: parseEndpointEvidence(endpoint?.gatewayEvidence || "[]", "gateway"),
    runtime: parseEndpointEvidence(endpoint?.runtimeEvidence || "[]", "runtime"),
  }), [endpoint]);
  const contract = useMemo(() => parseEndpointContract(endpoint?.parameters || "[]", endpoint?.middleware || "[]"), [endpoint]);
  const allEvidence = KINDS.flatMap((kind) => parsed[kind].items);
  const filteredEvidence = allEvidence.filter((item) => (evidenceKind === "all" || item.kind === evidenceKind) && JSON.stringify(item.details).toLowerCase().includes(query.toLowerCase()));
  const evidence = filteredEvidence.find((item) => item.key === selectedEvidence) || filteredEvidence[0];
  const findings = (data?.relatedFindings || []).filter((item) => (!severity || item.severity === severity) && (item.ruleName + " " + item.ruleId + " " + item.message).toLowerCase().includes(query.toLowerCase()));
  const finding = findings.find((item) => item.id === selectedFinding) || findings[0];
  const warnings = KINDS.flatMap((kind) => parsed[kind].warnings).concat(contract.warnings);

  if (loading) return <p role="status" className="flex items-center gap-2 p-6 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading endpoint evidence…</p>;
  if (error || !data || !endpoint) return <div className="workbench-panel space-y-4 p-6"><p role="alert">{error || "Endpoint data is unavailable."}</p><div className="flex gap-4"><Button variant="outline" onClick={() => setRetry((value) => value + 1)}>Retry</Button><Link href="/endpoints" className="self-center text-sm text-primary">Back to endpoints</Link></div></div>;
  const range = handlerRange(endpoint.lineStart, endpoint.lineEnd);
  const sourceLocation = endpoint.filePath + (range ? ":" + range.start + "–" + range.end : " · handler range unavailable");
  const copy = async (value: string, label: string) => {
    try { await navigator.clipboard.writeText(value); setNotice(label + " copied."); }
    catch { setNotice("Clipboard access failed. Select and copy the displayed text instead."); }
  };
  const exportMetadata = () => {
    const exported = {
      schemaVersion: "aegify.endpoint-metadata.v1", exportedAt: new Date().toISOString(),
      endpoint: { id: endpoint.id, method: endpoint.method, path: endpoint.path.split(/[?#]/)[0], handler: endpoint.handlerFunction, filePath: endpoint.filePath, range, framework: endpoint.framework, repositoryId: endpoint.repositoryId, authentication: endpoint.authRequired ? "static_auth_signal_found" : "not_established" },
      scan: endpoint.scan,
      evidence: allEvidence.map((item) => ({ kind: item.kind, ...item.details })),
      contract, warnings, previewLimits: { evidencePerKind: 200, relatedFindings: 100 },
      findingAssociation: data.association, relatedFindingCount: data.relatedFindingCount,
      relatedFindings: data.relatedFindings.map((item) => ({ id: item.id, ruleId: item.ruleId, severity: item.severity, evidenceState: item.evidenceState, filePath: item.filePath, lineStart: item.lineStart, lineEnd: item.lineEnd })),
      caveat: "Imported link metadata and source-range associations do not prove public exposure, authorization failure, or exploitability. Request headers and bodies are not included.",
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = "endpoint-" + endpoint.id + ".json"; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice("Endpoint metadata exported locally. No requests were sent to the endpoint.");
  };
  const openTab = (next: Tab) => { setTab(next); setQuery(""); setNotice(""); };
  return <div className="space-y-6 pb-8">
    <header className="space-y-4">
      <Link href="/endpoints" className="inline-flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" />Attack surface / Endpoints</Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0"><p className="eyebrow mb-2">Endpoint workbench</p><div className="flex items-start gap-3"><span className="rounded-md border border-primary/20 bg-primary/10 px-2.5 py-1.5 font-mono text-sm font-semibold text-primary">{endpoint.method}</span><h1 className="break-all font-mono text-2xl font-semibold tracking-tight">{endpoint.path}</h1></div><p className="mt-3 break-all text-xs text-muted-foreground">{endpoint.framework || "Framework not recorded"} · {endpoint.scan.repository || "Repository not recorded"} · {endpoint.scan.branch || "Branch not recorded"}</p></div>
        <div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" onClick={() => copy(endpoint.method + " " + endpoint.path, "Route")}><Copy className="mr-2 h-3.5 w-3.5" />Copy route</Button><Button variant="outline" size="sm" onClick={exportMetadata}><Download className="mr-2 h-3.5 w-3.5" />Export metadata</Button><Link href={"/graph/" + endpoint.scanId} className="inline-flex h-8 items-center gap-2 rounded-md border px-3 text-xs"><GitBranch className="h-3.5 w-3.5" />Scan graph</Link></div>
      </div>
      {notice && <p role="status" className="flex items-center gap-2 text-xs text-muted-foreground"><Check className="h-3.5 w-3.5" />{notice}</p>}
    </header>

    <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 xl:grid-cols-4">
      <div className="bg-card p-4"><p className="eyebrow">Authentication</p><p className="mt-2 flex items-center gap-2 text-sm font-medium"><ShieldCheck className="h-4 w-4 text-muted-foreground" />{endpoint.authRequired ? "Auth signal found" : "Not established"}</p><p className="mt-1 text-[11px] text-muted-foreground">Static detection · enforcement not verified</p></div>
      <div className="bg-card p-4"><p className="eyebrow">Linked evidence</p><p className="mt-2 font-mono text-xl">{allEvidence.length}</p><p className="mt-1 text-[11px] text-muted-foreground">Readable records in this preview</p></div>
      <div className="bg-card p-4"><p className="eyebrow">Handler findings</p><p className="mt-2 font-mono text-xl">{range ? data.relatedFindingCount : "—"}</p><p className="mt-1 text-[11px] text-muted-foreground">{range ? "Overlapping source locations" : "Handler bounds are required"}</p></div>
      <div className="bg-card p-4"><p className="eyebrow">Runtime evidence</p><p className="mt-2 text-sm font-medium">{parsed.runtime.items.length ? "Records available" : endpoint.runtimeObserved ? "Flag only · records missing" : "No records"}</p><p className="mt-1 text-[11px] text-muted-foreground">Observation does not prove a vulnerability</p></div>
    </div>

    <div className="flex flex-wrap border-b border-border" role="tablist" aria-label="Endpoint views">{(["overview", "evidence", "findings", "contract"] as const).map((name) => <button type="button" key={name} role="tab" aria-selected={tab === name} onClick={() => openTab(name)} className={"border-b-2 px-4 py-3 text-sm capitalize " + (tab === name ? "border-primary font-medium text-primary" : "border-transparent text-muted-foreground")}>{name}{name === "evidence" ? " · " + allEvidence.length : name === "findings" && range ? " · " + data.relatedFindingCount : ""}</button>)}</div>
    {warnings.length > 0 && <details className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-800 dark:text-amber-200"><summary className="cursor-pointer font-medium">{warnings.length} artifact quality notices</summary><ul className="mt-3 list-disc space-y-2 pl-5">{warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul></details>}

    <div role="tabpanel" aria-label={"Endpoint " + tab}>
      {tab === "overview" && <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 space-y-5">
          <section className="workbench-panel">
            <div className="workbench-heading"><div><h2 className="flex items-center gap-2 text-sm font-semibold"><Layers className="h-4 w-4" />Recorded surface map</h2><p className="mt-1 text-xs text-muted-foreground">Artifact links → route → source association</p></div></div>
            <div className="grid items-center gap-4 p-5 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
              <div className="space-y-2">{KINDS.map((kind) => { const Icon = ICONS[kind]; return <button type="button" key={kind} className="flex w-full items-center gap-3 rounded-md border bg-background p-3 text-left hover:border-primary/40" onClick={() => { setEvidenceKind(kind); openTab("evidence"); }}><Icon className="h-4 w-4 shrink-0 text-muted-foreground" /><span className="min-w-0 flex-1 text-xs font-medium">{LABELS[kind]}<span className="mt-1 block text-[11px] font-normal text-muted-foreground">{parsed[kind].items.length ? parsed[kind].items.length + " readable links" : "No readable links"}</span></span><span className="font-mono text-xs text-muted-foreground">{parsed[kind].items.length}</span></button>; })}</div>
              <ArrowRight className="hidden h-4 w-4 text-muted-foreground md:block" aria-hidden="true" />
              <div className="min-w-0 rounded-lg border border-primary/20 bg-primary/5 p-4"><p className="eyebrow">Route & handler</p><p className="mt-3 break-all font-mono text-sm font-medium">{endpoint.method} {endpoint.path}</p><div className="my-4 border-t border-primary/15" /><p className="flex items-start gap-2 break-all font-mono text-xs"><FileCode2 className="h-4 w-4 shrink-0 text-primary" />{endpoint.handlerFunction || "Handler not recorded"}</p><p className="mt-2 break-all font-mono text-[11px] leading-5 text-muted-foreground">{sourceLocation}</p><button type="button" onClick={() => openTab("findings")} className="mt-4 text-xs text-primary">{range ? data.relatedFindingCount + " handler-overlapping findings" : "Finding association unavailable"} →</button></div>
            </div>
            <p className="border-t border-border px-5 py-3 text-[11px] leading-5 text-muted-foreground">This is a map of imported associations, not an execution trace. A gateway match does not establish public exposure; runtime traffic does not establish an authorization failure.</p>
          </section>
          <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-sm font-semibold">Source & scan provenance</h2><button type="button" onClick={() => copy(sourceLocation, "Source location")} aria-label="Copy source location" className="text-muted-foreground"><Copy className="h-4 w-4" /></button></div><dl className="grid gap-4 p-5 text-xs sm:grid-cols-2">{[["Source file", endpoint.filePath || "Not included"], ["Handler range", range ? "L" + range.start + "–" + range.end : "Not available"], ["Repository ID", endpoint.repositoryId || "Not recorded"], ["Commit", endpoint.scan.commitSha || "Not recorded"], ["Scanned at", new Date(endpoint.scan.createdAt).toLocaleString()], ["Scan ID", endpoint.scanId]].map(([label, value]) => <div key={label}><dt className="text-muted-foreground">{label}</dt><dd className="mt-1.5 break-all font-mono leading-5">{value}</dd></div>)}</dl><div className="border-t border-border px-5 py-3"><Link href={"/scans/" + endpoint.scanId} className="text-xs text-primary">Open scan details →</Link></div></section>
        </div>
        <aside className="min-w-0 space-y-5">
          <section className="workbench-panel p-5"><p className="eyebrow">Review checklist</p><ul className="mt-4 space-y-4 text-xs leading-5"><li><span className="font-medium">Authentication / authorization</span><p className="mt-1 text-muted-foreground">{endpoint.authRequired ? "An authentication-related signal was detected. Review middleware and object-level access controls." : "No authentication signal was recorded. This is unknown, not a conclusion that authentication is absent."}</p></li><li><span className="font-medium">Source completeness</span><p className="mt-1 text-muted-foreground">{range ? "Findings are linked only when their location overlaps this handler in the same scan, repository, and file." : "A complete handler range was not recorded. Whole-file findings are intentionally not assigned to this endpoint."}</p></li><li><span className="font-medium">Traffic & exposure</span><p className="mt-1 text-muted-foreground">Check evidence provenance and match confidence before treating a linked route as reachable.</p></li></ul></section>
          <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-sm font-semibold">More in this source file</h2><span className="font-mono text-xs text-muted-foreground">{data.siblingCount}</span></div>{data.siblings.length ? <div className="divide-y divide-border">{data.siblings.map((item) => <Link key={item.id} href={"/endpoints/" + item.id} className="block space-y-1 px-5 py-3 hover:bg-accent/50"><p className="break-all font-mono text-xs"><span className="mr-2 text-primary">{item.method}</span>{item.path}</p><p className="break-all text-[11px] text-muted-foreground">{item.handlerFunction || "Unknown handler"} · {item.lineStart > 0 ? "L" + item.lineStart : "Location unknown"}</p></Link>)}</div> : <p className="p-5 text-xs text-muted-foreground">No other endpoints recorded in this source file.</p>}{data.siblingCount > data.siblings.length && <p className="border-t p-3 text-xs text-muted-foreground">Showing the first {data.siblings.length} endpoints.</p>}</section>
        </aside>
      </div>}

      {tab === "evidence" && <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3"><div className="flex flex-wrap gap-1" aria-label="Evidence type filters">{(["all", ...KINDS] as const).map((kind) => <button type="button" key={kind} aria-pressed={evidenceKind === kind} onClick={() => setEvidenceKind(kind)} className={"rounded-md px-3 py-2 text-xs " + (evidenceKind === kind ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent")}>{kind === "all" ? "All evidence" : LABELS[kind]} <span className="ml-1 font-mono">{kind === "all" ? allEvidence.length : parsed[kind].items.length}</span></button>)}</div><label className="flex items-center gap-2 rounded-md border bg-background px-3 py-2"><Search className="h-3.5 w-3.5 text-muted-foreground" /><input aria-label="Search endpoint evidence" placeholder="Search paths, traces, IDs…" className="w-48 min-w-0 bg-transparent text-xs outline-none" value={query} onChange={(event) => setQuery(event.target.value)} /></label></div>
        <div className="grid items-start gap-5 2xl:grid-cols-[minmax(0,1fr)_420px]">
          <section className="workbench-panel min-w-0 overflow-hidden"><div className="overflow-x-auto"><table className="data-table w-full text-left text-xs"><thead><tr><th>Source</th><th>Recorded link</th><th>Match</th><th>Link confidence</th></tr></thead><tbody>{filteredEvidence.map((item) => <tr key={item.key} className={evidence?.key === item.key ? "bg-primary/5" : ""}><td><span className="text-muted-foreground">{LABELS[item.kind]}</span></td><td><button type="button" aria-label={"Inspect " + item.kind + " evidence " + (item.id || item.key)} aria-pressed={evidence?.key === item.key} className="max-w-md text-left" onClick={() => setSelectedEvidence(item.key)}><p className="break-all font-mono text-xs font-medium">{item.method !== "—" && <span className="mr-2 text-primary">{item.method}</span>}{item.label}</p><p className="mt-1 break-all text-[11px] text-muted-foreground">{item.location}</p></button></td><td className="text-muted-foreground">{item.matchKind || "Not recorded"}</td><td className="font-mono">{item.confidence !== undefined ? Math.round(item.confidence * 100) + "%" : "—"}</td></tr>)}</tbody></table></div>{!filteredEvidence.length && <p className="p-8 text-center text-sm text-muted-foreground">{query ? "No evidence matches your search." : "No readable evidence of this type was included in this artifact."}</p>}</section>
          {evidence && <section className="workbench-panel min-w-0"><div className="workbench-heading"><div><p className="eyebrow">{LABELS[evidence.kind]} evidence</p><p className="mt-2 break-all font-mono text-xs">{evidence.id || "Evidence ID not included"}</p></div></div><div className="space-y-4 p-4"><p className="text-xs leading-6 text-muted-foreground">Link confidence measures the recorded association, not exploit confidence. Only allowlisted metadata is shown; request headers and bodies are excluded.</p><CodeHighlight code={JSON.stringify(evidence.details, null, 2)} language="json" /><p className="text-[11px] leading-5 text-muted-foreground">{evidence.kind === "runtime" ? "HTTP status, duration, and passed flags describe the imported observation. They are not a vulnerability verdict." : "Static caller or route metadata does not prove the route is reachable in a deployed environment."}</p></div></section>}
        </div>
      </div>}

      {tab === "findings" && <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3"><p className="max-w-xl text-xs leading-6 text-muted-foreground">{range ? "Findings whose recorded source range overlaps this handler. This is a location association, not a confirmed attack chain." : "Finding association is unavailable because the handler source range is incomplete."}</p><div className="flex flex-wrap gap-2"><input aria-label="Search handler findings" placeholder="Search rule or finding…" className="h-9 rounded-md border bg-background px-3 text-xs" value={query} onChange={(event) => setQuery(event.target.value)} /><select aria-label="Filter handler finding severity" className="workbench-select" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{value}</option>)}</select></div></div>
        <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <section className="workbench-panel min-w-0 overflow-hidden"><div className="overflow-x-auto"><table className="data-table w-full text-left text-xs"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th></tr></thead><tbody>{findings.map((item) => <tr key={item.id} className={finding?.id === item.id ? "bg-primary/5" : ""}><td><SeverityBadge severity={item.severity} /></td><td><button type="button" onClick={() => setSelectedFinding(item.id)} className="text-left" aria-pressed={finding?.id === item.id}><p className="font-medium">{item.ruleName}</p><p className="mt-1 font-mono text-[11px] text-muted-foreground">{item.ruleId}</p></button></td><td className="whitespace-nowrap font-mono text-muted-foreground">L{item.lineStart}–{item.lineEnd}</td></tr>)}</tbody></table></div>{!findings.length && <p className="p-8 text-sm text-muted-foreground">{query || severity ? "No findings match these filters." : range ? "No findings overlap this handler in the scan artifact. This does not establish that the endpoint is secure." : "No whole-file findings are assigned without valid handler bounds."}</p>}{data.relatedFindingCount > data.relatedFindings.length && <p className="border-t border-border p-4 text-xs text-muted-foreground">Showing the first {data.relatedFindings.length} of {data.relatedFindingCount} findings by source location. Filters apply to this preview.</p>}</section>
          {finding && <EvidenceWorkbench key={finding.id} finding={finding} />}
        </div>
      </div>}

      {tab === "contract" && <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <section className="workbench-panel min-w-0 p-5 lg:col-span-2"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-sm font-semibold">OpenAPI / Swagger context</h2><Link href={"/api-specs?scanId=" + endpoint.scanId} className="text-xs text-primary">Manage specifications →</Link></div><p className="mt-3 text-xs leading-6 text-muted-foreground">{data.apiContractContext?.boundary || "Imported contracts are documentation, not proof of implementation."} Showing matches in up to {data.apiContractContext?.snapshotLimit || 10} recent snapshots.</p><div className="mt-4 grid gap-3 sm:grid-cols-2">{data.apiContractContext?.references.map((reference) => <div key={reference.specificationId + reference.pointer} className="rounded-md border p-4"><p className="text-sm font-medium">{reference.title}</p><p className="mt-2 break-all font-mono text-[10px] text-muted-foreground">{reference.contentHash.slice(0, 12)} · {reference.pointer}</p><p className="mt-3 text-xs">Declared authentication: {reference.security.state}</p><p className="mt-2 text-xs leading-6 text-muted-foreground">{reference.reviewNote}</p></div>)}</div>{!data.apiContractContext?.references.length && <p className="mt-3 text-xs text-muted-foreground">No exact-route specification references found in this scan and repository.</p>}</section>
        <section className="workbench-panel min-w-0 overflow-hidden"><div className="workbench-heading"><h2 className="text-sm font-semibold">Detected parameters</h2><span className="font-mono text-xs text-muted-foreground">{contract.parameters.length}</span></div><div className="overflow-x-auto"><table className="data-table w-full text-left text-xs"><thead><tr><th>Name</th><th>Location</th><th>Type</th></tr></thead><tbody>{contract.parameters.map((item, index) => <tr key={index}><td className="break-all font-mono">{item.name}</td><td className="text-muted-foreground">{item.location}</td><td className="font-mono text-muted-foreground">{item.type}</td></tr>)}</tbody></table></div>{!contract.parameters.length && <p className="p-5 text-xs text-muted-foreground">No parameter metadata was recorded. This is not a complete API schema.</p>}</section>
        <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-sm font-semibold">Detected middleware</h2><span className="font-mono text-xs text-muted-foreground">{contract.middleware.length}</span></div><div className="p-5">{contract.middleware.length ? <ol className="space-y-3">{contract.middleware.map((item, index) => <li key={index} className="flex gap-3 rounded-md border p-3 text-xs"><span className="font-mono text-muted-foreground">{String(index + 1).padStart(2, "0")}</span><span className="break-all font-mono">{item}</span></li>)}</ol> : <p className="text-xs text-muted-foreground">No middleware metadata was recorded.</p>}<p className="mt-4 text-[11px] leading-5 text-muted-foreground">Order is preserved from the scan artifact. Runtime order and enforcement are not verified here.</p></div></section>
      </div>}
    </div>
  </div>;
}
