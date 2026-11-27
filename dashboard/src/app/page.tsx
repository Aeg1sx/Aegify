"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { ArrowUpRight, CheckCheck, ChevronDown, CircleAlert, FileCode2, FileUp, GitBranch, Inbox } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { SeverityChart } from "@/components/severity-chart";
import { EVIDENCE_LABELS } from "@/lib/code-evidence";
import { ACTIVE_STATUSES } from "@/lib/finding-view";

interface Stats {
  totalScans: number;
  totalFindings: number;
  severities: Record<string, number>;
  statuses: Record<string, number>;
  evidence: Record<string, number>;
  regressions: number;
  overdue: number;
  priorityQueue: Array<{ id: string; ruleId: string; scan: { repository: string; branch: string }; ruleName: string; severity: string; filePath: string; lineStart: number; evidenceState: string; owner: string }>;
  recentScans: Array<{ id: string; repository: string; project: { name: string } | null; branch: string; status: string; filesScanned: number; createdAt: string; findingsCount: number }>;
  topRules: Array<{ ruleId: string; ruleName: string; severity: string; count: number }>;
}

const timestamp = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

function scanLabel(scan: Stats["recentScans"][number]) {
  return scan.repository || scan.project?.name || "Scan " + scan.id.slice(-8);
}

function ScanActivityRow({ scan }: { scan: Stats["recentScans"][number] }) {
  const hasResults = ["completed", "partial"].includes(scan.status) || scan.filesScanned > 0 || scan.findingsCount > 0;
  const missing = <><span aria-hidden>—</span><span className="sr-only">No result recorded</span></>;
  const recorded = <time dateTime={scan.createdAt}>{timestamp.format(new Date(scan.createdAt))}</time>;
  return <tr>
    <td><Link href={"/scans/" + scan.id} className="wrap-anywhere font-medium hover:text-primary">{scanLabel(scan)}</Link>
      {scan.branch && <p className="mt-1 flex items-center gap-1 font-mono text-xs text-muted-foreground"><GitBranch aria-hidden className="size-3 shrink-0" /><span className="truncate">{scan.branch}</span></p>}
      <p className="overview-scan-meta mt-1 text-xs text-muted-foreground">{hasResults && <>{scan.filesScanned.toLocaleString()} files · </>}{recorded}</p>
    </td>
    <td><span className="inline-flex items-center gap-1.5 capitalize">{["partial", "failed"].includes(scan.status) && <CircleAlert aria-hidden className="size-3.5 text-destructive" />}{scan.status}</span></td>
    <td className="overview-wide-column text-right font-mono">{hasResults ? scan.filesScanned.toLocaleString() : missing}</td>
    <td className="text-right font-mono">{hasResults ? scan.findingsCount.toLocaleString() : missing}</td>
    <td className="overview-wide-column whitespace-nowrap text-muted-foreground">{recorded}</td>
  </tr>;
}

function Section({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return <section className="min-w-0">
    <header className="flex min-h-14 flex-wrap items-center justify-between gap-x-3 gap-y-1 pb-2">
      <h2 className="text-xl font-semibold tracking-tight">{title}</h2>{action}
    </header>
    {children}
  </section>;
}

function ViewLink({ href, children }: { href: string; children: ReactNode }) {
  return <Link href={href} className="inline-flex min-h-11 items-center text-sm font-medium text-primary underline decoration-primary/35 underline-offset-4 hover:decoration-current">{children}</Link>;
}

function ImportLink() {
  return <Link href="/upload" className="inline-flex min-h-11 items-center justify-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:bg-primary/90">
    <FileUp aria-hidden className="size-4" />Import scan
  </Link>;
}

function PriorityQueue({ findings }: { findings: Stats["priorityQueue"] }) {
  const [expandedId, setExpandedId] = useState<string | null>(findings[0]?.id ?? null);
  if (!findings.length) return <p className="flex items-center gap-3 border-y py-6 text-sm"><CheckCheck aria-hidden className="size-5 shrink-0 text-primary" />No unresolved critical or high findings.</p>;

  return <ul className="priority-records" aria-label="Priority findings">{findings.map((finding) => {
    const expanded = finding.id === expandedId;
    const panelId = "priority-context-" + finding.id;
    const file = finding.filePath || "Location unavailable";
    const line = finding.filePath && finding.lineStart > 0 ? finding.lineStart : null;
    const location = line ? file + ":" + line : file;
    const recordLabel = [finding.ruleName, finding.scan.repository, location].filter(Boolean).join(", ");
    return <li key={finding.id}>
      <article className="priority-record" data-expanded={expanded}>
        <div className="priority-record-heading">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <SeverityBadge severity={finding.severity} />
            <code className="text-xs text-muted-foreground">{finding.ruleId}</code>
          </div>
          <h3><Link href={"/findings/" + finding.id} aria-label={recordLabel}>{finding.ruleName}</Link></h3>
          <button type="button" aria-label={`${expanded ? "Hide" : "Show"} context for ${recordLabel}`} aria-expanded={expanded} aria-controls={panelId}
            onClick={() => setExpandedId(expanded ? null : finding.id)}>
            Context <ChevronDown aria-hidden className="size-3.5" />
          </button>
        </div>
        {!expanded && <p className="mt-1 flex flex-wrap items-baseline gap-x-2 text-xs leading-5 text-muted-foreground">
          {finding.scan.repository && <span className="wrap-anywhere">{finding.scan.repository}</span>}
          <code className="wrap-anywhere">{location}</code>
        </p>}
        <div id={panelId} hidden={!expanded} className="priority-context">
          <Link href={"/findings/" + finding.id + "#finding-evidence"} className="priority-location" aria-label={"Inspect evidence for " + recordLabel}>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
              <span className="inline-flex min-w-0 items-center gap-2"><FileCode2 aria-hidden className="size-4 shrink-0" /><span className="wrap-anywhere">{finding.scan.repository || "Source location"}</span></span>
              {finding.scan.branch && <span className="inline-flex min-w-0 items-center gap-1.5 font-mono"><GitBranch aria-hidden className="size-3 shrink-0" /><span className="wrap-anywhere">{finding.scan.branch}</span></span>}
            </div>
            <p className="priority-path"><code>{file}</code>{line && <span aria-label={"Line " + line}>L{line}</span>}</p>
            <ArrowUpRight aria-hidden className="priority-open-icon size-4" />
          </Link>
          <dl className="priority-facts">
            <div><dt>Evidence</dt><dd>{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified"}</dd></div>
            <div><dt>Owner</dt><dd>{finding.owner || "Unassigned"}</dd></div>
          </dl>
        </div>
      </article>
    </li>;
  })}</ul>;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const response = await fetch("/api/stats", { signal: controller.signal });
        if (!response.ok) throw new Error();
        const data: Stats = await response.json();
        if (!controller.signal.aborted) setStats(data);
      } catch {
        if (!controller.signal.aborted) setError(true);
      }
    }
    void load();
    return () => controller.abort();
  }, [attempt]);

  if (error) return <section role="alert" className="workbench-panel space-y-3 p-6">
    <h1 className="text-xl font-semibold">Security overview unavailable</h1>
    <button className="min-h-11 text-sm font-semibold text-primary" onClick={() => { setError(false); setAttempt(attempt + 1); }}>Retry</button>
  </section>;
  if (!stats) return <div role="status" className="space-y-6"><h1 className="text-3xl font-semibold tracking-tight">Security overview</h1><p className="text-sm text-muted-foreground">Loading scan records…</p></div>;
  if (stats.totalScans === 0) return <div className="space-y-7">
    <h1 className="text-3xl font-semibold tracking-tight">Security overview</h1>
    <section className="workbench-panel max-w-3xl p-6 sm:p-9">
      <Inbox aria-hidden className="mb-5 size-7 text-primary" />
      <h2 className="text-xl font-semibold">Add your first scan</h2>
      <p className="mb-6 mt-2 max-w-lg text-sm leading-relaxed text-muted-foreground">Import a SARIF file to review findings, or open a project to scan a connected repository.</p>
      <div className="flex flex-wrap items-center gap-5"><ImportLink /><ViewLink href="/projects">Open projects</ViewLink></div>
    </section>
  </div>;

  const latest = stats.recentScans[0];
  const incomplete = stats.recentScans.filter((scan) => scan.status === "partial" || scan.status === "failed");
  const unresolved = ACTIVE_STATUSES.reduce((sum, status) => sum + (stats.statuses[status] || 0), 0);
  const metrics = [
    { label: "Unresolved", count: unresolved, href: "/findings?queue=active" },
    { label: "Reopened", count: stats.regressions, href: "/findings?queue=regressed" },
    { label: "Past due", count: stats.overdue, href: "/findings?queue=overdue" },
    { label: "Recorded scans", count: stats.totalScans, href: "/scans" },
  ];
  return <div className="overview space-y-5 pb-4 sm:space-y-7">
    <header className="workspace-masthead flex flex-wrap items-center justify-between gap-x-5 gap-y-3">
      <div className="min-w-0">
        <h1 className="workbench-title">Security overview</h1>
        {latest && <p className="mt-2.5 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm text-muted-foreground">
          Latest scan <Link className="min-w-0 break-all font-medium text-foreground underline decoration-input underline-offset-4 hover:text-primary" href={"/scans/" + latest.id}>{scanLabel(latest)}</Link>
          <time dateTime={latest.createdAt}>{timestamp.format(new Date(latest.createdAt))}</time>
        </p>}
      </div><ImportLink />
    </header>

    <div className="grid items-start gap-x-9 gap-y-6 xl:grid-cols-[minmax(0,1.85fr)_minmax(15rem,1fr)]">
      <Section title="High-risk review queue" action={<ViewLink href="/findings?queue=priority">View queue</ViewLink>}>
        <PriorityQueue findings={stats.priorityQueue} />
      </Section>

      <Section title="Workspace totals">
        <dl className="overview-totals">
          {metrics.map(({ label, count, href }) => <div key={label}>
            <dt>{label}</dt>
            <dd><Link aria-label={label + ", " + count.toLocaleString()} href={href}>{count.toLocaleString()}</Link></dd>
          </div>)}
        </dl>
        {incomplete.length > 0 && <section aria-label="Incomplete scan coverage" className="mt-5 border-l-2 border-[var(--severity-medium)] pl-3">
          <h3 className="text-sm font-semibold">Incomplete coverage</h3>
          <p className="my-1 text-xs leading-5 text-muted-foreground">{incomplete.length} of the last {stats.recentScans.length} scans {incomplete.length === 1 ? "was" : "were"} partial or failed.</p>
          <ul>{incomplete.slice(0, 2).map((scan) => <li key={scan.id}>
            <Link href={"/scans/" + scan.id} className="flex min-h-11 items-center justify-between gap-2 text-sm hover:text-primary">
              <span className="min-w-0 truncate">{scanLabel(scan)} <span className="font-mono text-xs text-muted-foreground">#{scan.id.slice(-6)}</span></span>
              <span className="inline-flex shrink-0 items-center gap-1 text-xs capitalize">{scan.status}<ArrowUpRight aria-hidden className="size-3.5" /></span>
            </Link>
          </li>)}</ul>
        </section>}
      </Section>
    </div>

    <div className="grid items-start gap-x-9 gap-y-6 xl:grid-cols-[minmax(0,1.85fr)_minmax(15rem,1fr)]">
      <Section title="Scan activity" action={<ViewLink href="/scans">Scan history</ViewLink>}>
        <div className="overflow-x-auto"><table className="data-table overview-scans table-fixed"><caption className="sr-only">Recent scan snapshots</caption>
          <thead><tr><th className="w-[45%]">Repository</th><th>Status</th><th className="overview-wide-column text-right">Files</th><th className="text-right">Findings</th><th className="overview-wide-column">Recorded</th></tr></thead>
          <tbody>{stats.recentScans.slice(0, 6).map((scan) => <ScanActivityRow key={scan.id} scan={scan} />)}</tbody>
        </table></div>
      </Section>

      <Section title="Severity distribution"><SeverityChart severities={stats.severities} /></Section>
    </div>

    <div className="grid gap-9 lg:grid-cols-2">
      <Section title="Evidence coverage">{Object.entries(EVIDENCE_LABELS).map(([key, label]) =>
        <Link key={key} href={"/findings?evidenceState=" + key} className="flex min-h-11 items-center justify-between gap-4 border-b py-2 text-sm last:border-0 hover:bg-accent">
          {label}<span className="font-mono tabular-nums">{(stats.evidence[key] || 0).toLocaleString()}</span>
        </Link>)}</Section>
      <Section title="Most frequent rules">{stats.topRules.length ? stats.topRules.slice(0, 5).map((rule) =>
        <Link key={[rule.ruleId, rule.ruleName, rule.severity].join("/")} href={"/findings?ruleId=" + encodeURIComponent(rule.ruleId)} className="flex min-h-11 items-center justify-between gap-3 border-b py-2 text-sm last:border-0 hover:bg-accent">
          <span className="min-w-0 break-words">{rule.ruleName} <span className="font-mono text-xs text-muted-foreground">{rule.ruleId}</span></span>
          <span className="font-mono tabular-nums">{rule.count.toLocaleString()}</span>
        </Link>) : <p className="p-5 text-sm text-muted-foreground">No rule occurrences recorded.</p>}</Section>
    </div>
  </div>;
}
