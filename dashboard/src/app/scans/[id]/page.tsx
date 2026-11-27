"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, ArrowUpRight, CircleAlert, GitBranch, GitCommitHorizontal, Search } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { SeverityChart } from "@/components/severity-chart";
import { ScanJobPanel } from "@/components/scan-job-panel";
import { GatewayInventoryPanel } from "@/components/gateway-inventory-panel";
import type { GatewayReview } from "@/lib/gateway-inventory";
import { EVIDENCE_LABELS } from "@/lib/code-evidence";

interface Finding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  evidenceState: string;
  status: string;
  filePath: string;
  lineStart: number;
  message: string;
  cweId: number | null;
}

interface ScanDetail {
  gatewayInventory?: GatewayReview | null;
  id: string;
  repository: string;
  branch: string;
  commitSha: string;
  status: string;
  filesScanned: number;
  duration: number;
  createdAt: string;
  findings: Finding[];
  severities: Record<string, number>;
  statuses: Record<string, number>;
  topRules: Array<{ ruleId: string; ruleName: string; count: number }>;
  hasCallGraph?: boolean;
  callGraphNodeCount?: number;
  progressMessage?: string;
  hasSourceJob: boolean;
}

const date = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const levelOrder = ["critical", "high", "medium", "low"];
const levelRanks = new Map(levelOrder.map((level, index) => [level, index]));
const incompleteStates: Record<string, string> = {
  partial: "Partial analysis",
  failed: "Analysis failed",
  cancelled: "Analysis cancelled",
};

function BackLink() {
  return (
    <Link
      href="/scans"
      className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground hover:text-primary"
    >
      <ArrowLeft aria-hidden className="size-4" />
      Scans
    </Link>
  );
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  return <ScanRecord key={id} id={id} />;
}

function ScanRecord({ id }: { id: string }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<"missing" | "unavailable" | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [ruleId, setRuleId] = useState("");
  const refresh = useCallback(() => setAttempt((previous) => previous + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const response = await fetch("/api/scans/" + encodeURIComponent(id), {
          cache: "no-store",
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        if (response.status === 404 || response.status === 403) {
          setScan(null);
          setError("missing");
          return;
        }
        if (!response.ok) throw new Error();
        const record: ScanDetail = await response.json();
        if (!controller.signal.aborted) {
          setScan(record);
          setError(null);
        }
      } catch {
        if (!controller.signal.aborted) setError("unavailable");
      }
    }
    void load();
    return () => controller.abort();
  }, [id, attempt]);

  if (!scan)
    return (
      <div className="space-y-5">
        <BackLink />
        <h1 className="workbench-title">Scan record</h1>
        {error ? (
          <div role="alert" className="workbench-panel max-w-2xl p-5">
            <p>
              {error === "missing"
                ? "This scan could not be found or is outside your workspace."
                : "The scan record could not be loaded."}
            </p>
            {error === "unavailable" && (
              <button className="min-h-11 font-medium text-primary" onClick={refresh}>
                Retry
              </button>
            )}
          </div>
        ) : (
          <p role="status" className="text-sm text-muted-foreground">
            Loading scan record…
          </p>
        )}
      </div>
    );

  const query = search.trim().toLowerCase();
  const levels = [...new Set([...levelOrder, ...Object.keys(scan.severities)])];
  const filtered = scan.findings
    .filter(
      (item) =>
        (!severity || item.severity === severity) &&
        (!ruleId || item.ruleId === ruleId) &&
        (!query ||
          [item.message, item.filePath, item.ruleId, item.ruleName].some((value) =>
            value.toLowerCase().includes(query),
          )),
    )
    .sort(
      (a, b) =>
        (levelRanks.get(a.severity) ?? levelRanks.size) - (levelRanks.get(b.severity) ?? levelRanks.size),
    );
  const filtering = Boolean(query || ruleId || severity);
  const active = scan.status === "pending" || scan.status === "running";
  const awaitingFindings = active && !scan.findings.length;
  const clearFilters = () => {
    setSearch("");
    setSeverity("");
    setRuleId("");
  };

  return (
    <div className="min-w-0 space-y-6 pb-6">
      <header className="space-y-2">
        <BackLink />
        <div className="flex flex-wrap items-center justify-between gap-x-5 gap-y-2">
          <h1 className="workbench-title min-w-0 break-words [overflow-wrap:anywhere]">
            {scan.repository || "Scan record"}
          </h1>
          {scan.hasCallGraph && (
            <Link
              href={"/graph/" + scan.id}
              className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-3 text-sm font-medium hover:bg-accent"
            >
              <GitBranch aria-hidden className="size-4" />
              Call graph
              {Boolean(scan.callGraphNodeCount) && (
                <span className="text-xs text-muted-foreground">{scan.callGraphNodeCount} nodes</span>
              )}
              <ArrowUpRight aria-hidden className="size-3.5" />
            </Link>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm text-muted-foreground">
          {!(active && scan.hasSourceJob) && (
            <span className="inline-flex items-center gap-2 font-medium capitalize text-foreground">
              <span
                aria-hidden
                className={
                  "size-2 rounded-full " +
                  (scan.status === "completed" ? "bg-primary" : "bg-[var(--severity-medium)]")
                }
              />
              {scan.status}
            </span>
          )}
          {scan.branch && (
            <span className="inline-flex min-w-0 items-center gap-1.5 font-mono text-xs">
              <GitBranch aria-hidden className="size-3.5 shrink-0" />
              <span className="break-all">{scan.branch}</span>
            </span>
          )}
          {scan.commitSha && (
            <span
              aria-label={"Commit " + scan.commitSha}
              className="inline-flex items-center gap-1.5 font-mono text-xs"
            >
              <GitCommitHorizontal aria-hidden className="size-4" />
              {scan.commitSha.slice(0, 8)}
            </span>
          )}
          {active && (
            <span>
              Recorded <time dateTime={scan.createdAt}>{date.format(new Date(scan.createdAt))}</time>
            </span>
          )}
        </div>
      </header>

      {!active && (
        <dl className="grid grid-cols-2 gap-y-3 border-y py-3 text-sm sm:flex sm:gap-x-10">
          <div>
            <dt className="text-xs text-muted-foreground">Files scanned</dt>
            <dd className="mt-1 font-mono tabular-nums">{scan.filesScanned.toLocaleString()}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Duration</dt>
            <dd className="mt-1 font-mono tabular-nums">{scan.duration.toFixed(1)} s</dd>
          </div>
          <div className="col-span-2">
            <dt className="text-xs text-muted-foreground">Recorded</dt>
            <dd className="mt-1">
              <time dateTime={scan.createdAt}>{date.format(new Date(scan.createdAt))}</time>
            </dd>
          </div>
        </dl>
      )}

      {error && (
        <p role="alert" className="text-sm">
          The latest update could not be loaded.{" "}
          <button onClick={refresh} className="min-h-11 font-semibold text-primary">
            Retry
          </button>
        </p>
      )}
      {scan.status !== "completed" && !(active && scan.hasSourceJob) && (
        <div
          role="status"
          className="flex items-start gap-3 rounded-md border border-[var(--severity-medium)]/40 bg-card p-4 text-sm"
        >
          <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-[var(--severity-medium)]" />
          <div className="min-w-0">
            <h2 className="font-semibold">{incompleteStates[scan.status] || "Analysis in progress"}</h2>
            {scan.progressMessage && <p className="mt-1 whitespace-pre-line [overflow-wrap:anywhere]">{scan.progressMessage}</p>}
            {scan.status === "partial" && <p className="mt-1 text-muted-foreground">
              Earlier findings stay open when a partial scan does not observe them.
            </p>}
            {!scan.progressMessage && scan.status !== "partial" && <p className="mt-1 text-muted-foreground">
              {active ? "Findings will appear as results become available." : "This record shows the findings saved before analysis stopped."}
            </p>}
          </div>
        </div>
      )}
      {scan.hasSourceJob && <ScanJobPanel scanId={id} onFinished={refresh} />}
      {scan.gatewayInventory && <GatewayInventoryPanel key={id} review={scan.gatewayInventory} />}

      {awaitingFindings ? (
        <section aria-labelledby="scan-findings" className="border-t pt-4">
          <h2 id="scan-findings" className="text-base font-semibold">
            Findings
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Findings will appear here when the scan publishes its results.
          </p>
        </section>
      ) : (
        <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_17rem] xl:grid-cols-[minmax(0,1fr)_19rem]">
          <section aria-labelledby="scan-findings" className="workbench-panel">
            <div className="workbench-heading">
              <h2 id="scan-findings" className="text-lg font-semibold">
                Findings
              </h2>
              <span role="status" className="text-sm tabular-nums text-muted-foreground">
                {filtering ? filtered.length.toLocaleString() + " of " : ""}
                {scan.findings.length.toLocaleString()} {scan.findings.length === 1 ? "record" : "records"}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2 border-b p-3 sm:px-4">
              <label className="relative min-w-0 basis-full sm:flex-1">
                <span className="sr-only">Search scan findings</span>
                <Search
                  aria-hidden
                  className="pointer-events-none absolute top-3.5 left-3 size-4 text-muted-foreground"
                />
                <input
                  type="search"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search rule, file, or message…"
                  className="h-11 w-full rounded-md border border-input bg-background pr-3 pl-9 text-base sm:text-sm"
                />
              </label>
              <label className="min-w-0 flex-1 sm:flex-none">
                <span className="sr-only">Filter scan by severity</span>
                <select
                  value={severity}
                  onChange={(event) => setSeverity(event.target.value)}
                  className="h-11 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="">All severities</option>
                  {levels.map((level) => (
                    <option key={level} value={level}>
                      {level.charAt(0).toUpperCase() + level.slice(1)}
                    </option>
                  ))}
                </select>
              </label>
              {filtering && (
                <button
                  type="button"
                  className="min-h-11 px-2 text-sm font-medium text-primary hover:underline"
                  onClick={clearFilters}
                >
                  Clear filters
                </button>
              )}
              {ruleId && (
                <span className="w-full font-mono text-xs text-muted-foreground">Rule {ruleId}</span>
              )}
            </div>
            {filtered.length ? (
              <ul aria-label="Findings in this scan" className="divide-y">
                {filtered.map((item) => (
                  <li key={item.id}>
                    <Link
                      href={"/findings/" + item.id}
                      className="group grid gap-1 px-4 py-3.5 hover:bg-accent/60 focus-visible:outline-offset-[-3px] sm:px-5"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <h3 className="break-words text-sm font-semibold group-hover:text-primary">
                          {item.ruleName}
                        </h3>
                        <ArrowUpRight
                          aria-hidden
                          className="mt-0.5 size-3.5 shrink-0 text-muted-foreground"
                        />
                      </div>
                      <span className="break-all font-mono text-xs text-muted-foreground">
                        {item.filePath}:{item.lineStart}
                      </span>
                      <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
                        <SeverityBadge severity={item.severity} />
                        <StatusBadge status={item.status} />
                        <span className="font-mono text-xs text-muted-foreground">{item.ruleId}</span>
                        {item.cweId && (
                          <span className="text-xs text-muted-foreground">CWE-{item.cweId}</span>
                        )}
                        <span className="text-xs text-muted-foreground sm:ml-auto">
                          {EVIDENCE_LABELS[item.evidenceState] || "Unclassified evidence"}
                        </span>
                      </div>
                      {item.message && (
                        <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">{item.message}</p>
                      )}
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="px-5 py-8 text-sm text-muted-foreground">
                {filtering
                  ? "No findings match these filters."
                  : scan.status === "completed"
                    ? "This scan recorded no findings."
                    : "No findings have been recorded yet."}
              </p>
            )}
          </section>

          <aside aria-label="Scan breakdown" className="workbench-panel divide-y">
            <section>
              <h2 className="workbench-heading text-base font-semibold">Severity</h2>
              <SeverityChart severities={scan.severities} selectedLevel={severity} onSelect={setSeverity} />
            </section>
            {Boolean(Object.keys(scan.statuses).length) && (
              <section className="p-5">
                <h2 className="mb-3 font-semibold">Triage status</h2>
                <dl className="space-y-2">
                  {Object.entries(scan.statuses).map(([state, count]) => (
                    <div key={state} className="flex items-center justify-between gap-2">
                      <dt>
                        <StatusBadge status={state} />
                      </dt>
                      <dd className="font-mono text-sm">{count.toLocaleString()}</dd>
                    </div>
                  ))}
                </dl>
              </section>
            )}
            {scan.topRules.length > 0 && (
              <section className="p-5">
                <h2 className="mb-2 font-semibold">Most frequent rules</h2>
                <ul className="divide-y">
                  {scan.topRules.slice(0, 5).map((rule) => (
                    <li key={rule.ruleId + "/" + rule.ruleName}>
                      <button
                        type="button"
                        aria-pressed={ruleId === rule.ruleId}
                        onClick={() => setRuleId(ruleId === rule.ruleId ? "" : rule.ruleId)}
                        className="flex min-h-11 w-full items-center justify-between gap-3 py-2 text-left text-sm hover:text-primary aria-pressed:font-semibold aria-pressed:text-primary"
                      >
                        <span>{rule.ruleName}</span>
                        <span className="font-mono tabular-nums">{rule.count.toLocaleString()}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}
