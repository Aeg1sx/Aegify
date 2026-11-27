"use client";

import { Suspense, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowRight,
  ChevronDown,
  ChevronRight,
  FileCode,
  Search,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface Endpoint {
  id: string;
  path: string;
  method: string;
  handlerFunction: string;
  filePath: string;
  lineStart: number;
  framework: string;
  authRequired: boolean;
  repositoryId: string;
  calledByFrontend: boolean;
  frontendCallCount: number;
  exposedViaGateway: boolean;
  runtimeObserved: boolean;
  runtimeObservationCount: number;
  scan: { id: string; projectId: string | null; repository: string };
}

interface Inventory {
  endpoints: Endpoint[];
  frameworks: string[];
  totalUnfiltered: number;
}

type View = "routes" | "files";
type EvidenceFilter = "" | "frontend" | "gateway" | "runtime" | "unlinked";

const columns = "@3xl/inventory:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)_minmax(11rem,0.85fr)]";
const selectStyle = "workbench-select min-h-11 w-full text-sm";

function evidenceMatches(ep: Endpoint, filter: EvidenceFilter) {
  switch (filter) {
    case "frontend":
      return ep.calledByFrontend;
    case "gateway":
      return ep.exposedViaGateway;
    case "runtime":
      return ep.runtimeObserved;
    case "unlinked":
      return !ep.calledByFrontend && !ep.exposedViaGateway && !ep.runtimeObserved;
    default:
      return true;
  }
}

function repository(ep: Endpoint) {
  return ep.repositoryId || ep.scan.repository;
}

function Routes({ records }: { records: Endpoint[] }) {
  return (
    <ul className="divide-y" aria-label="Endpoint records">
      {records.map((ep) => {
        const evidence = [];
        if (ep.calledByFrontend)
          evidence.push(ep.frontendCallCount > 0 ? "Frontend (" + ep.frontendCallCount + ")" : "Frontend");
        if (ep.exposedViaGateway) evidence.push("Gateway");
        if (ep.runtimeObserved)
          evidence.push(
            ep.runtimeObservationCount > 0 ? "Runtime (" + ep.runtimeObservationCount + ")" : "Runtime",
          );
        return (
          <li key={ep.id}>
            <Link
              href={"/endpoints/" + ep.id}
              className={
                "group grid min-w-0 items-start gap-x-5 gap-y-2 px-4 py-3.5 hover:bg-accent/50 focus-visible:outline-offset-[-3px] sm:px-5 " +
                columns
              }
            >
              <div className="min-w-0">
                <div className="flex items-baseline gap-2.5">
                  <span className="shrink-0 rounded-sm border px-1.5 py-0.5 font-mono text-[11px] font-medium">
                    {ep.method}
                  </span>
                  <span className="min-w-0 break-all font-mono text-sm font-semibold text-foreground group-hover:text-primary">
                    {ep.path}
                  </span>
                </div>
                <p className="mt-1.5 break-all text-xs text-muted-foreground">
                  {[repository(ep), ep.framework].filter(Boolean).join(" · ") ||
                    "Scan " + ep.scan.id.slice(-8)}
                </p>
              </div>
              <div className="min-w-0">
                {ep.handlerFunction && <p className="break-all font-mono text-xs">{ep.handlerFunction}</p>}
                <p className="mt-0.5 break-all font-mono text-xs text-muted-foreground">
                  {ep.filePath || "Source unavailable"}
                  {ep.filePath && ep.lineStart > 0 ? ":" + ep.lineStart : ""}
                </p>
              </div>
              <div className="space-y-1 text-xs text-muted-foreground">
                <p className="flex items-center gap-1.5">
                  {ep.authRequired && <ShieldCheck aria-hidden className="size-3.5 shrink-0 text-primary" />}
                  {ep.authRequired ? "Auth signal recorded" : "No auth signal recorded"}
                </p>
                {evidence.length > 0 && <p>{evidence.join(" · ")}</p>}
              </div>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

export default function EndpointsPage() {
  return (
    <Suspense
      fallback={
        <p className="p-5 text-sm text-muted-foreground" role="status">
          Loading endpoints…
        </p>
      }
    >
      <InventoryView />
    </Suspense>
  );
}

const inventoryChanged = "aegify:endpoint-inventory-changed";

function subscribeInventory(notify: () => void) {
  window.addEventListener("popstate", notify);
  window.addEventListener(inventoryChanged, notify);
  return () => {
    window.removeEventListener("popstate", notify);
    window.removeEventListener(inventoryChanged, notify);
  };
}

function currentSearch() {
  return window.location.search;
}

function InventoryView() {
  const routeSearch = useSearchParams();
  // The native history mutation is synchronous; Next's route snapshot can trail
  // a keystroke. Read every control and the filtered list from the same URL.
  const queryString = useSyncExternalStore(subscribeInventory, currentSearch, () => routeSearch.toString());
  const search = new URLSearchParams(queryString);
  const framework = search.get("framework") || "";
  const method = search.get("method") || "";
  const authValue = search.get("auth");
  const auth = authValue === "true" || authValue === "false" ? authValue : "";
  const exposureValue = search.get("evidence");
  const exposure =
    exposureValue === "frontend" ||
    exposureValue === "gateway" ||
    exposureValue === "runtime" ||
    exposureValue === "unlinked"
      ? exposureValue
      : "";
  const allRecords = search.get("all") === "1";
  const query = search.get("q") || "";
  const view: View = search.get("view") === "files" ? "files" : "routes";
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [attempt, setAttempt] = useState(0);
  const [response, setResponse] = useState<{ key: string; data: Inventory | null } | null>(null);

  const params = new URLSearchParams();
  if (framework) params.set("framework", framework);
  if (method) params.set("method", method);
  if (auth) params.set("authOnly", auth);
  if (!allRecords) params.set("quality", "api");
  const key = params.toString();
  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const result = await fetch("/api/endpoints?" + key, { signal: controller.signal });
        if (!result.ok) throw new Error();
        const data: Inventory = await result.json();
        if (!controller.signal.aborted) setResponse({ key, data });
      } catch {
        if (!controller.signal.aborted) setResponse({ key, data: null });
      }
    }
    void load();
    return () => controller.abort();
  }, [key, attempt]);

  const current = response?.key === key ? response.data : undefined;
  const records = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (current?.endpoints || []).filter(
      (ep) =>
        evidenceMatches(ep, exposure) &&
        (!needle ||
          [ep.path, ep.handlerFunction, ep.filePath, ep.framework, ep.method, repository(ep)].some((value) =>
            value.toLowerCase().includes(needle),
          )),
    );
  }, [current, query, exposure]);

  const files = useMemo(() => {
    const groups = new Map<string, Endpoint[]>();
    for (const ep of records) {
      const source = ep.filePath || ep.handlerFunction || ep.id;
      const group = JSON.stringify([
        ep.scan.projectId,
        repository(ep) || ep.scan.projectId || ep.scan.id,
        source,
      ]);
      const entries = groups.get(group);
      if (entries) entries.push(ep);
      else groups.set(group, [ep]);
    }
    return [...groups].sort(
      ([, left], [, right]) =>
        right.length - left.length || left[0].filePath.localeCompare(right[0].filePath),
    );
  }, [records]);

  const applied = [framework, method, auth, exposure, allRecords].filter(Boolean).length;
  const filtering = Boolean(applied || query.trim());
  const frameworks = [...new Set([...(response?.data?.frameworks || []), framework].filter(Boolean))].sort();
  const linked = records.filter((ep) => !evidenceMatches(ep, "unlinked")).length;
  const authSignals = records.filter((ep) => ep.authRequired).length;

  function update(changes: Record<string, string>) {
    const url = new URL(window.location.href);
    for (const [name, value] of Object.entries(changes)) {
      if (value) url.searchParams.set(name, value);
      else url.searchParams.delete(name);
    }
    window.history.replaceState(null, "", url);
    window.dispatchEvent(new Event(inventoryChanged));
  }

  function reset() {
    update({ framework: "", method: "", auth: "", evidence: "", all: "", q: "" });
  }

  function toggleFile(id: string) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="@container/inventory min-w-0 space-y-5">
      <header className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1">
        <h1 className="workbench-title">Endpoints</h1>
        <Link
          href="/api-specs"
          className="inline-flex min-h-11 items-center gap-2 text-sm font-medium text-primary hover:underline"
        >
          API specifications <ArrowRight aria-hidden className="size-4" />
        </Link>
        {current && (
          <p className="col-span-full flex flex-wrap gap-x-2 gap-y-1 text-sm text-muted-foreground">
            <span>
              {records.length.toLocaleString()} {allRecords ? "route record" : "route"}
              {records.length === 1 ? "" : "s"}
            </span>
            <span aria-hidden>·</span>
            <span>{authSignals.toLocaleString()} with auth signals</span>
            <span aria-hidden>·</span>
            <span>{linked.toLocaleString()} with linked evidence</span>
          </p>
        )}
      </header>

      <section aria-label="Endpoint inventory" className="workbench-panel">
        <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3 sm:px-5">
          <label className="relative min-w-0 basis-full @lg/inventory:flex-1">
            <span className="sr-only">Search endpoints</span>
            <Search
              aria-hidden
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            />
            <input
              type="search"
              value={query}
              onChange={(event) => update({ q: event.target.value })}
              placeholder="Search path, handler, or repository…"
              className="h-11 w-full rounded-md border border-input bg-background pl-9 pr-3 text-sm"
            />
          </label>
          <Button
            type="button"
            variant="outline"
            className="h-11"
            aria-expanded={filtersOpen}
            aria-controls="endpoint-filters"
            onClick={() => setFiltersOpen(!filtersOpen)}
          >
            <SlidersHorizontal aria-hidden />
            Filters{applied ? " (" + applied + ")" : ""}
          </Button>
          <div
            role="group"
            aria-label="Group endpoints"
            className="inline-flex min-w-0 rounded-md border bg-background p-0.5"
          >
            {(["routes", "files"] as const).map((option) => (
              <button
                key={option}
                type="button"
                aria-pressed={view === option}
                onClick={() => update({ view: option === "files" ? option : "" })}
                className="min-h-10 rounded-sm px-2.5 text-sm text-muted-foreground hover:text-foreground aria-pressed:bg-accent aria-pressed:font-medium aria-pressed:text-foreground"
              >
                {option === "routes" ? "Routes" : "By file"}
              </button>
            ))}
          </div>
        </div>
        <div id="endpoint-filters" hidden={!filtersOpen} className="border-b bg-muted/30 px-4 py-3 sm:px-5">
          <div className="grid grid-cols-1 gap-3 @sm/inventory:grid-cols-2 @3xl/inventory:grid-cols-4">
            <label className="grid gap-1.5 text-xs text-muted-foreground">
              Framework
              <select
                className={selectStyle}
                value={framework}
                onChange={(e) => update({ framework: e.target.value })}
              >
                <option value="">All frameworks</option>
                {frameworks.map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </label>
            <label className="grid gap-1.5 text-xs text-muted-foreground">
              HTTP method
              <select
                className={selectStyle}
                value={method}
                onChange={(e) => update({ method: e.target.value })}
              >
                <option value="">All methods</option>
                {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"].map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </label>
            <label className="grid gap-1.5 text-xs text-muted-foreground">
              Authentication
              <select className={selectStyle} value={auth} onChange={(e) => update({ auth: e.target.value })}>
                <option value="">All auth states</option>
                <option value="true">Auth signal recorded</option>
                <option value="false">No auth signal recorded</option>
              </select>
            </label>
            <label className="grid gap-1.5 text-xs text-muted-foreground">
              Linked evidence
              <select
                className={selectStyle}
                value={exposure}
                onChange={(e) => update({ evidence: e.target.value })}
              >
                <option value="">All evidence</option>
                <option value="frontend">Frontend calls</option>
                <option value="gateway">Gateway routes</option>
                <option value="runtime">Runtime observations</option>
                <option value="unlinked">No linked evidence</option>
              </select>
            </label>
          </div>
          <label className="mt-2 inline-flex min-h-11 items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={allRecords}
              onChange={(e) => update({ all: e.target.checked ? "1" : "" })}
            />
            Include all scan records{current ? " (" + current.totalUnfiltered.toLocaleString() + ")" : ""}
          </label>
        </div>
        {applied > 0 && (
          <button
            type="button"
            onClick={reset}
            className="mx-4 min-h-11 text-sm text-primary hover:underline sm:mx-5"
          >
            Clear filters
          </button>
        )}
        {current === undefined ? (
          <p className="p-5 text-sm text-muted-foreground" role="status">
            Loading endpoints…
          </p>
        ) : current === null ? (
          <div className="p-5" role="alert">
            <p className="text-sm">Couldn’t load endpoint records.</p>
            <button
              className="min-h-11 text-sm font-medium text-primary hover:underline"
              onClick={() => {
                setResponse(null);
                setAttempt((n) => n + 1);
              }}
            >
              Retry
            </button>
          </div>
        ) : !records.length ? (
          <div className="space-y-1 p-5">
            <h2 className="font-medium">
              {filtering ? "No endpoints match these filters" : "No API routes recorded"}
            </h2>
            {query.trim() && applied === 0 && (
              <button type="button" onClick={reset} className="min-h-11 text-sm text-primary hover:underline">
                Clear search
              </button>
            )}
            {!filtering && (
              <p className="text-sm text-muted-foreground">
                {current.totalUnfiltered
                  ? "Open Filters and include all scan records to see assets and internal routes."
                  : "Routes recorded by repository scans appear here."}
              </p>
            )}
          </div>
        ) : view === "routes" ? (
          <>
            <div
              aria-hidden
              className={
                "hidden gap-5 border-b bg-muted/50 px-5 py-2 text-xs font-medium text-muted-foreground @3xl/inventory:grid " +
                columns
              }
            >
              <span>Method and path</span>
              <span>Source</span>
              <span>Recorded evidence</span>
            </div>
            <Routes records={records} />
          </>
        ) : (
          <>
            <div className="flex flex-wrap items-center justify-between gap-x-4 border-b px-4 sm:px-5">
              <span className="text-sm font-medium">
                {files.length} {files.length === 1 ? "source group" : "source groups"}
              </span>
              <div className="flex gap-4 text-xs font-medium text-primary">
                <button
                  type="button"
                  className="min-h-11 hover:underline"
                  onClick={() => setExpanded(new Set(files.map(([id]) => id)))}
                >
                  Expand all
                </button>
                <button
                  type="button"
                  className="min-h-11 hover:underline"
                  onClick={() => setExpanded(new Set())}
                >
                  Collapse all
                </button>
              </div>
            </div>
            <ul className="divide-y" aria-label="Source groups">
              {files.map(([id, entries]) => {
                const first = entries[0];
                const open = expanded.has(id);
                const Icon = open ? ChevronDown : ChevronRight;
                return (
                  <li key={id}>
                    <button
                      type="button"
                      className="flex w-full min-w-0 items-center gap-2 px-4 py-3 text-left hover:bg-accent/50 sm:px-5"
                      aria-expanded={open}
                      onClick={() => toggleFile(id)}
                    >
                      <Icon aria-hidden className="size-4 shrink-0" />
                      <FileCode aria-hidden className="size-4 shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1">
                        <span className="block break-all font-mono text-sm">
                          {first.filePath || first.handlerFunction || "Source unavailable"}
                        </span>
                        <span className="block break-all text-xs text-muted-foreground">
                          {repository(first) || "Scan " + first.scan.id.slice(-8)}
                        </span>
                      </span>
                      <span className="text-xs tabular-nums text-muted-foreground">
                        {entries.length} {entries.length === 1 ? "route" : "routes"}
                      </span>
                    </button>
                    {open && (
                      <div className="border-t bg-muted/20">
                        <Routes records={entries} />
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </section>
    </div>
  );
}
