"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  Check,
  CircleAlert,
  CircleX,
  Clock3,
  GitBranch,
  LoaderCircle,
  RefreshCw,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";

const REFRESH_OPTIONS = [
  ["Off", 0],
  ["15s", 15_000],
  ["30s", 30_000],
  ["1m", 60_000],
  ["5m", 300_000],
  ["15m", 900_000],
  ["30m", 1_800_000],
] as const;
const PAGE_SIZE = 50;

interface Scan {
  id: string;
  repository: string;
  branch: string;
  commitSha: string;
  status: string;
  scanType: string;
  filesScanned: number;
  duration: number;
  createdAt: string;
  findingsCount: number;
  severities: Record<string, number>;
  progressPercent: number;
  progressMessage: string;
  progressEta: number | null;
}
interface ScanList {
  page: number;
  scans: Scan[];
  total: number;
}

const date = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });
const time = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const severityOrder = ["critical", "high", "medium", "low"];
const scanStates = new Map<string, [LucideIcon, string]>([
  ["completed", [Check, "text-primary"]],
  ["partial", [CircleAlert, "text-[var(--severity-medium)]"]],
  ["failed", [CircleX, "text-destructive"]],
  ["running", [LoaderCircle, "text-primary"]],
]);

function ScanIdentity({ scan }: { scan: Scan }) {
  return (
    <div className="min-w-0">
      <Link
        href={"/scans/" + scan.id}
        className="inline-flex min-h-11 max-w-full items-center break-all text-sm font-semibold leading-snug hover:text-primary hover:underline focus-visible:outline-offset-2 @3xl/history:min-h-8"
      >
        {scan.repository || "Scan " + scan.id.slice(-8)}
      </Link>
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-muted-foreground">
        {scan.branch && (
          <span className="inline-flex min-w-0 items-center gap-1 font-mono">
            <GitBranch aria-hidden className="size-3 shrink-0" />
            <span className="break-all">{scan.branch}</span>
          </span>
        )}
        {scan.commitSha ? (
          <span className="font-mono">{scan.commitSha.slice(0, 8)}</span>
        ) : (
          scan.repository && <span className="font-mono">#{scan.id.slice(-8)}</span>
        )}
      </div>
    </div>
  );
}

function RecordedAt({ scan }: { scan: Scan }) {
  const value = new Date(scan.createdAt);
  return (
    <time
      dateTime={scan.createdAt}
      className="inline-flex flex-wrap gap-x-2 gap-y-0.5 text-xs tabular-nums text-muted-foreground @3xl/history:flex-col"
    >
      <span>{date.format(value)}</span>
      <span>{time.format(value)}</span>
    </time>
  );
}

function ResultCounts({ scan }: { scan: Scan }) {
  const inProgress = scan.status === "pending" || scan.status === "running" || scan.status === "queued";
  if (!scan.findingsCount && (inProgress || scan.status === "failed" || scan.status === "cancelled")) {
    return (
      <span className="text-xs text-muted-foreground">
        {inProgress ? "Awaiting results" : "No results recorded"}
      </span>
    );
  }
  const levels = [...new Set([...severityOrder, ...Object.keys(scan.severities).sort()])].filter(
    (level) => scan.severities[level] > 0,
  );
  return (
    <div className="min-w-0">
      <span className="font-mono text-sm font-medium tabular-nums">
        {scan.findingsCount.toLocaleString()}
      </span>
      <span className="ml-1 text-xs text-muted-foreground @3xl/history:sr-only">
        {scan.findingsCount === 1 ? "finding" : "findings"}
      </span>
      {inProgress && <span className="ml-1 text-xs text-muted-foreground">so far</span>}
      {levels.length > 0 && (
        <ul aria-label="Severity counts" className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          {levels.map((level) => (
            <li key={level} className="inline-flex items-center gap-1.5 whitespace-nowrap">
              <span
                aria-hidden
                className="size-1.5 rounded-full"
                style={{
                  backgroundColor: severityOrder.includes(level)
                    ? "var(--severity-" + level + ")"
                    : "var(--muted-foreground)",
                }}
              />
              <span className="text-muted-foreground">
                <span className="capitalize">{level}</span> {scan.severities[level]}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ScanState({ scan }: { scan: Scan }) {
  const name = scan.status;
  const [Icon, color] = scanStates.get(name) ?? [Clock3, "text-muted-foreground"];
  return (
    <div className="min-w-0">
      <span className="inline-flex items-center gap-1.5 text-sm font-medium capitalize">
        <Icon aria-hidden className={"size-3.5 shrink-0 " + color} />
        {name || "Unknown"}
      </span>
      {name === "partial" && <span className="block text-xs text-muted-foreground">Incomplete coverage</span>}
      {name === "running" ? (
        <RunningScan scan={scan} />
      ) : (
        (name === "completed" || name === "partial" || scan.filesScanned > 0 || scan.duration > 0) && (
          <span className="mt-0.5 block text-xs text-muted-foreground">
            {scan.filesScanned.toLocaleString()} {scan.filesScanned === 1 ? "file" : "files"} ·{" "}
            {scan.duration.toFixed(1)} s
          </span>
        )
      )}
    </div>
  );
}

function RunningScan({ scan }: { scan: Scan }) {
  const scale = scan.scanType === "repo-ai-candidate" ? 1 : 100;
  const percent = Math.round(Math.max(0, Math.min(100, scan.progressPercent * scale)));
  return (
    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
      {scan.progressMessage && <span className="basis-full break-words">{scan.progressMessage}</span>}
      <progress
        aria-label="Scan progress"
        value={percent}
        max={100}
        className="h-1.5 w-20 appearance-none overflow-hidden rounded-sm border-0 bg-muted accent-primary [&::-moz-progress-bar]:bg-primary [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-primary"
      />
      <span className="font-mono text-xs">{percent}%</span>
      {scan.progressEta != null && scan.progressEta > 0 && (
        <span className="text-xs text-muted-foreground">
          ETA {Math.floor(scan.progressEta / 60)}m {Math.floor(scan.progressEta % 60)}s
        </span>
      )}
    </div>
  );
}

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const [result, setResult] = useState<ScanList | null>(null);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [intervalMs, setIntervalMs] = useState(0);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      try {
        const saved = Number(localStorage.getItem("scans_refresh_interval"));
        if (REFRESH_OPTIONS.some(([, value]) => value === saved)) setIntervalMs(saved);
      } catch {
        /* Refresh remains manual when storage is unavailable. */
      }
    });
    return () => cancelAnimationFrame(frame);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let fetching = false;
    async function load() {
      if (fetching) return;
      fetching = true;
      try {
        const query = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
        const response = await fetch("/api/scans?" + query, { signal: controller.signal });
        if (!response.ok) throw new Error();
        const data: ScanList = await response.json();
        if (controller.signal.aborted) return;
        const lastPage = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
        if (page > lastPage) setPage(lastPage);
        else setResult(data);
        setError(false);
      } catch {
        if (!controller.signal.aborted) {
          setError(true);
          setResult(null);
        }
      } finally {
        fetching = false;
      }
    }
    void load();
    const timer = intervalMs ? setInterval(load, intervalMs) : undefined;
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [page, attempt, intervalMs]);

  const current = result?.page === page ? result : null;
  const pages = current ? Math.ceil(current.total / PAGE_SIZE) : 0;
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="workbench-title">Scan history</h1>
          {current && (
            <p className="mt-1.5 text-sm text-muted-foreground">
              {current.total.toLocaleString()} recorded {current.total === 1 ? "run" : "runs"}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="inline-flex items-center gap-2 text-sm text-muted-foreground">
            Auto-refresh
            <select
              className="workbench-select min-h-11 text-sm text-foreground"
              value={intervalMs}
              onChange={(event) => {
                const next = Number(event.target.value);
                setIntervalMs(next);
                try {
                  localStorage.setItem("scans_refresh_interval", String(next));
                } catch {
                  /* Session preference still applies. */
                }
              }}
            >
              {REFRESH_OPTIONS.map(([label, value]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <Button
            type="button"
            variant="outline"
            className="h-11"
            onClick={() => setAttempt((value) => value + 1)}
          >
            <RefreshCw aria-hidden />
            Refresh
          </Button>
        </div>
      </header>
      {error ? (
        <p role="alert" className="workbench-panel p-5 text-sm">
          Couldn’t load scan history. Use Refresh to try again.
        </p>
      ) : !current ? (
        <p role="status" className="text-sm text-muted-foreground">
          Loading scan history…
        </p>
      ) : current.total === 0 ? (
        <section className="workbench-panel p-5">
          <h2 className="font-semibold">No scans yet</h2>
          <Link
            href="/upload"
            className="mt-2 inline-flex min-h-11 items-center gap-2 text-sm text-primary hover:underline"
          >
            Import a SARIF file <ArrowRight aria-hidden className="size-4" />
          </Link>
        </section>
      ) : (
        <section aria-label="Scan history" className="@container/history min-w-0 border-y">
          <table className="hidden w-full table-fixed border-collapse text-left @3xl/history:table">
            <caption className="sr-only">Scan history, newest first</caption>
            <colgroup>
              <col className="w-[34%]" />
              <col className="w-[21%]" />
              <col className="w-[29%]" />
              <col className="w-[16%]" />
            </colgroup>
            <thead className="border-b bg-muted/60 text-xs text-muted-foreground">
              <tr>
                {["Repository / run", "Status", "Findings", "Recorded"].map((label) => (
                  <th scope="col" key={label} className="px-3 py-2.5 font-medium">
                    {label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y">
              {current.scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-accent/50 focus-within:bg-accent/50">
                  <th scope="row" className="px-3 py-3 font-normal">
                    <ScanIdentity scan={scan} />
                  </th>
                  <td className="px-3 py-3">
                    <ScanState scan={scan} />
                  </td>
                  <td className="px-3 py-3">
                    <ResultCounts scan={scan} />
                  </td>
                  <td className="px-3 py-3">
                    <RecordedAt scan={scan} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <ul aria-label="Recorded runs" className="divide-y @3xl/history:hidden">
            {current.scans.map((scan) => (
              <li key={scan.id} className="min-w-0 space-y-2.5 py-4">
                <ScanIdentity scan={scan} />
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <ScanState scan={scan} />
                  <RecordedAt scan={scan} />
                </div>
                <ResultCounts scan={scan} />
              </li>
            ))}
          </ul>
          {pages > 1 && (
            <nav
              aria-label="Scan history pages"
              className="flex items-center justify-between gap-2 border-t px-5 py-3 text-sm"
            >
              <Button variant="outline" disabled={page === 1} onClick={() => setPage(page - 1)}>
                Previous
              </Button>
              <span>
                {page} / {pages}
              </span>
              <Button variant="outline" disabled={page >= pages} onClick={() => setPage(page + 1)}>
                Next
              </Button>
            </nav>
          )}
        </section>
      )}
    </div>
  );
}
