"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { ArrowRight, Plus, RefreshCw, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";

interface Rule {
  id: string;
  name: string;
  severity: string;
  cweId: number | null;
  owaspCategory: string | null;
  languages: string;
  enabled: boolean;
  findingCount: number;
}

const PAGE_SIZE = 50;
const severities = ["critical", "high", "medium", "low"];
const columns = "@3xl/catalog:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_5.5rem_6.5rem]";

function RuleRow({ rule, catalogQuery }: { rule: Rule; catalogQuery: string }) {
  const languages = rule.languages.split(",").map((language) => language.trim()).filter(Boolean);
  return (
    <li className={"grid min-w-0 gap-x-5 px-4 py-2.5 hover:bg-accent/35 sm:px-5 @3xl/catalog:items-center " + columns}>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 text-xs text-muted-foreground">
          <span className="break-all font-mono">{rule.id}</span>
          {rule.cweId !== null && <span>CWE-{rule.cweId}</span>}
        </div>
        <Link
          href={"/rules/" + encodeURIComponent(rule.id) + catalogQuery}
          prefetch={false}
          className="inline-flex min-h-11 max-w-full items-center [overflow-wrap:anywhere] py-1 font-medium leading-snug text-foreground underline-offset-4 hover:text-primary hover:underline"
        >
          {rule.name}
        </Link>
      </div>
      <div className="min-w-0 text-sm">
        <span className="sr-only">Languages </span>
        {languages.length ? languages.join(", ") : "Unspecified"}
        <span className="ml-2 text-xs text-muted-foreground @3xl/catalog:ml-0 @3xl/catalog:mt-1 @3xl/catalog:block">
          {rule.enabled ? "Enabled" : "Disabled"}
        </span>
      </div>
      <div className="col-start-1 row-start-3 self-center @3xl/catalog:col-auto @3xl/catalog:row-auto">
        <SeverityBadge severity={rule.severity} />
      </div>
      <Link
        href={"/findings?ruleId=" + encodeURIComponent(rule.id)}
        prefetch={false}
        aria-label={rule.findingCount + " findings for " + rule.id}
        className="col-start-1 row-start-3 inline-flex min-h-11 items-center justify-self-end gap-1.5 text-sm font-medium tabular-nums text-primary underline-offset-4 hover:underline @3xl/catalog:col-auto @3xl/catalog:row-auto"
      >
        {rule.findingCount.toLocaleString()} <span className="@3xl/catalog:sr-only">findings</span>
        <ArrowRight aria-hidden className="size-3.5" />
      </Link>
    </li>
  );
}

function RuleCatalog() {
  const search = useSearchParams();
  const query = search.get("q") || "";
  const severity = search.get("severity") || "";
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [failure, setFailure] = useState<"access" | "load" | null>(null);
  const countRef = useRef<HTMLParagraphElement>(null);
  const [attempt, setAttempt] = useState(0);
  const [syncing, setSyncing] = useState(false);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const result = await fetch("/api/rules?view=catalog", { signal: controller.signal });
        if (result.status === 403) {
          if (!controller.signal.aborted) setFailure("access");
          return;
        }
        if (!result.ok) throw new Error();
        const data = await result.json();
        if (!Array.isArray(data.rules)) throw new Error();
        if (!controller.signal.aborted) { setRules(data.rules); setFailure(null); }
      } catch {
        if (!controller.signal.aborted) setFailure("load");
      }
    }
    void load();
    return () => controller.abort();
  }, [attempt]);

  async function sync() {
    setSyncing(true);
    setNotice("");
    try {
      const result = await fetch("/api/rules/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ direction: "yaml-to-db" }),
      });
      if (!result.ok) throw new Error();
      const data = await result.json();
      if (typeof data.synced !== "number") throw new Error();
      const errors = data.errors?.length || 0;
      setNotice("Synced " + data.synced + " rules." + (errors ? " " + errors + " sync errors." : ""));
      setAttempt((n) => n + 1);
    } catch {
      setNotice("Rule sync failed. Try syncing again.");
    } finally {
      setSyncing(false);
    }
  }

  function update(changes: Record<string, string>) {
    const url = new URL(window.location.href);
    if (!("page" in changes)) url.searchParams.delete("page");
    for (const [key, value] of Object.entries(changes)) {
      if (value) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    }
    window.history.replaceState(null, "", url);
    if ("page" in changes) {
      countRef.current?.focus({ preventScroll: true });
      countRef.current?.scrollIntoView({ block: "start" });
    }
  }

  const needle = query.trim().toLowerCase();
  const filtered = (rules || []).filter((rule) =>
    (!severity || rule.severity === severity) &&
    (!needle || [rule.id, rule.name, rule.owaspCategory, rule.languages, rule.cweId && "CWE-" + rule.cweId]
      .some((value) => String(value || "").toLowerCase().includes(needle))),
  );
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const requestedPage = Number(search.get("page"));
  const page = Number.isSafeInteger(requestedPage) ? Math.min(totalPages, Math.max(1, requestedPage)) : 1;
  const start = (page - 1) * PAGE_SIZE;
  const hasFilters = Boolean(query || severity);
  const catalog = new URLSearchParams();
  if (query) catalog.set("q", query);
  if (severity) catalog.set("severity", severity);
  if (page > 1) catalog.set("page", String(page));
  const catalogQuery = catalog.size ? "?" + catalog.toString() : "";

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <h1 className="workbench-title">Detection rules</h1>
        {failure !== "access" && <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" onClick={sync} disabled={syncing} className="min-h-11">
            <RefreshCw aria-hidden className={syncing ? "animate-spin" : ""} />
            {syncing ? "Syncing…" : "Sync rules"}
          </Button>
          <Button asChild className="min-h-11"><Link href="/rules/new"><Plus aria-hidden />New rule</Link></Button>
        </div>}
      </header>

      {notice && <p role="status" className="border-l-2 border-primary pl-3 text-sm">{notice}</p>}

      <section aria-label="Rule catalog" className="@container/catalog workbench-panel">
        <div className="grid gap-3 border-b p-4 sm:grid-cols-[minmax(0,1fr)_11rem] sm:px-5">
          <label className="grid gap-1.5 text-xs font-medium" htmlFor="rule-query">
            Search rules
            <span className="relative">
              <Search aria-hidden className="pointer-events-none absolute left-3 top-3.5 size-4 text-muted-foreground" />
              <input id="rule-query" type="search" placeholder="Name, rule ID, language, or CWE"
                className="h-11 w-full rounded-md border border-input bg-background pl-9 pr-3 text-base font-normal sm:text-sm"
                value={query} onChange={(e) => update({ q: e.target.value })} />
            </span>
          </label>
          <label className="grid gap-1.5 text-xs font-medium" htmlFor="rule-severity">
            Severity
            <select id="rule-severity" className="workbench-select min-h-11 w-full text-sm font-normal"
              value={severity} onChange={(e) => update({ severity: e.target.value })}>
              <option value="">All severities</option>
              {severities.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}
            </select>
          </label>
        </div>

        {failure === "access" ? (
          <p role="alert" className="p-5 text-sm">Workspace administrator access is required to view these rules.</p>
        ) : failure ? (
          <div className="p-5"><p role="alert">Couldn’t load the rule catalog.</p>
            <Button type="button" variant="outline" className="mt-3 min-h-11" onClick={() => { setFailure(null); setAttempt((n) => n + 1); }}>Retry</Button>
          </div>
        ) : !rules ? <p role="status" className="p-5 text-sm text-muted-foreground">Loading rules…</p> : (
          <>
            <div className="flex min-h-12 items-center justify-between gap-3 border-b px-4 text-sm sm:px-5">
              <p ref={countRef} tabIndex={-1} role="status" className="font-medium tabular-nums">
                {hasFilters ? filtered.length.toLocaleString() + " of " + rules.length.toLocaleString() + " rules" : rules.length.toLocaleString() + (rules.length === 1 ? " rule" : " rules")}
              </p>
              {hasFilters && <Button variant="link" type="button" className="min-h-11 px-0" onClick={() => update({ q: "", severity: "" })}>Clear filters</Button>}
            </div>
            {filtered.length === 0 ? (
              <p className="p-5 text-sm text-muted-foreground">{hasFilters ? "No rules match these filters." : "Sync the catalog or create your first rule."}</p>
            ) : (
              <>
                <div aria-hidden className={"hidden gap-x-5 border-b bg-muted/60 px-5 py-2 text-xs font-medium text-muted-foreground @3xl/catalog:grid " + columns}>
                  <span>Rule</span><span>Languages / state</span><span>Severity</span><span className="text-right">Findings</span>
                </div>
                <ul aria-label="Detection rules" className="divide-y">{filtered.slice(start, start + PAGE_SIZE).map((rule) => <RuleRow key={rule.id} rule={rule} catalogQuery={catalogQuery} />)}</ul>
              </>
            )}
            {totalPages > 1 && (
              <nav aria-label="Rule pages" className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 sm:px-5">
                <span className="text-xs text-muted-foreground">Page {page} of {totalPages}</span>
                <div className="flex gap-2">
                  <Button variant="outline" className="min-h-11" disabled={page === 1} onClick={() => update({ page: String(page - 1) })}>Previous</Button>
                  <Button variant="outline" className="min-h-11" disabled={page === totalPages} onClick={() => update({ page: String(page + 1) })}>Next</Button>
                </div>
              </nav>
            )}
          </>
        )}
      </section>
    </div>
  );
}

export default function RulesPage() {
  return <Suspense fallback={<p role="status">Loading rules…</p>}><RuleCatalog /></Suspense>;
}
