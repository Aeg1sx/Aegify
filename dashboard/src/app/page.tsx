"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, ArrowRight, Loader2, ScanSearch } from "lucide-react";
import { SeverityBadge } from "@/components/severity-badge";
import { SeverityChart } from "@/components/severity-chart";
import { EVIDENCE_LABELS } from "@/lib/code-evidence";

interface Stats {
  totalScans: number; totalFindings: number; severities: Record<string, number>;
  statuses: Record<string, number>; evidence: Record<string, number>; regressions: number; overdue: number;
  priorityQueue: Array<{ id: string; ruleName: string; severity: string; filePath: string; lineStart: number; evidenceState: string; owner: string; baselineState: string }>;
  recentScans: Array<{ id: string; repository: string; branch: string; status: string; filesScanned: number; duration: number; createdAt: string; findingsCount: number }>;
  topRules: Array<{ ruleId: string; ruleName: string; severity: string; count: number }>;
}
export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/stats", { signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error("Unable to load security overview");
      const data = await response.json();
      if (!controller.signal.aborted) { setStats(data); setError(""); }
    }).catch((e) => { if (!controller.signal.aborted) setError(e.message); });
    return () => controller.abort();
  }, [attempt]);
  if (error) return <div role="alert" className="workbench-panel p-6">{error}<button type="button" className="ml-4 text-primary" onClick={() => setAttempt((n) => n + 1)}>Retry</button></div>;
  if (!stats) return <div role="status" className="flex items-center gap-3 p-8 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading security overview…</div>;
  const unresolved = ["open", "triaged", "confirmed", "in_progress"].reduce((n, status) => n + (stats.statuses[status] || 0), 0);
  const maxEvidence = Math.max(1, ...Object.values(stats.evidence));
  return <div className="space-y-6">
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div><p className="eyebrow mb-2">Security operations</p><h1 className="text-3xl font-semibold tracking-tight">Overview</h1><p className="mt-2 text-sm text-muted-foreground">Current exposure, evidence coverage, and work that needs attention.</p></div>
      <Link href="/upload" className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2.5 text-xs font-medium text-primary-foreground"><ScanSearch className="h-4 w-4" />Import scan</Link>
    </header>
    <div className="grid grid-cols-2 divide-x divide-border border-y border-border bg-card py-5 lg:grid-cols-4">
      {[["Unresolved", unresolved, "Current active findings"], ["Regressions", stats.regressions, "Reopened in a later scan"], ["Past due", stats.overdue, "Unresolved · assigned deadline"], ["Scans recorded", stats.totalScans, "Across all repositories"]].map(([label, count, hint]) => <div key={label} className="px-5 py-2"><p className="eyebrow">{label}</p><p className="my-2 font-mono text-3xl tabular-nums tracking-tight">{Number(count).toLocaleString()}</p><p className="text-xs text-muted-foreground">{hint}</p></div>)}
    </div>
    {stats.totalScans === 0 && <div className="workbench-panel p-6"><h2 className="font-semibold">Build your first security baseline</h2><p className="mt-2 text-sm text-muted-foreground">Import a scan artifact to populate this workspace. No sample findings or synthetic trends are shown.</p></div>}
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
      <section className="workbench-panel">
        <div className="workbench-heading"><div><h2 className="text-sm font-semibold">High-risk work queue</h2><p className="mt-1 text-xs text-muted-foreground">Unresolved critical & high · critical first, then newest</p></div><Link href="/findings" className="flex items-center gap-1 text-xs text-primary">All findings <ArrowUpRight className="h-3.5 w-3.5" /></Link></div>
        <div className="overflow-x-auto"><table className="data-table"><thead><tr><th>Severity</th><th>Finding / source</th><th>Evidence</th><th>Owner</th></tr></thead><tbody>
          {stats.priorityQueue.map((finding) => <tr key={finding.id}><td><SeverityBadge severity={finding.severity} /></td><td><Link href={"/findings/" + finding.id} className="font-medium hover:text-primary">{finding.ruleName}</Link><p className="mt-1 max-w-sm truncate font-mono text-[11px] text-muted-foreground">{finding.filePath}:{finding.lineStart}</p></td><td className="whitespace-nowrap text-xs">{EVIDENCE_LABELS[finding.evidenceState] || "Unclassified"}</td><td className="text-xs text-muted-foreground">{finding.owner || "Unassigned"}</td></tr>)}
          {!stats.priorityQueue.length && <tr><td colSpan={4} className="h-36 text-center text-muted-foreground">No unresolved critical or high findings in the current records.</td></tr>}
        </tbody></table></div>
      </section>
      <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-sm font-semibold">Severity distribution</h2></div><div className="p-5"><SeverityChart severities={stats.severities} /></div></section>
    </div>
    <div className="grid gap-5 lg:grid-cols-2">
      <section className="workbench-panel">
        <div className="workbench-heading"><div><h2 className="text-sm font-semibold">Evidence coverage</h2><p className="mt-1 text-xs text-muted-foreground">Recorded classification · not a confidence score</p></div></div>
        <div className="space-y-5 p-5">{Object.entries(EVIDENCE_LABELS).map(([key, label]) => <Link key={key} href={"/findings?evidenceState=" + key} className="block"><div className="mb-2 flex items-center justify-between text-xs"><span>{label}</span><span className="font-mono tabular-nums">{stats.evidence[key] || 0}</span></div><div className="h-1.5 rounded-sm bg-muted"><div className="h-full rounded-sm bg-primary/65" style={{ width: ((stats.evidence[key] || 0) / maxEvidence * 100) + "%" }} /></div></Link>)}</div>
      </section>
      <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-sm font-semibold">Most frequent rules</h2><Link href="/rules" aria-label="View rules"><ArrowUpRight className="h-4 w-4 text-muted-foreground" /></Link></div><div className="divide-y divide-border">{stats.topRules.slice(0, 5).map((rule, index) => <Link key={rule.ruleId + rule.severity} href={"/findings?ruleId=" + encodeURIComponent(rule.ruleId)} className="flex items-center gap-3 px-5 py-4 hover:bg-accent/40"><span className="font-mono text-xs text-muted-foreground">{String(index + 1).padStart(2, "0")}</span><div className="min-w-0 flex-1"><p className="truncate text-sm">{rule.ruleName}</p><p className="mt-1 font-mono text-[10px] text-muted-foreground">{rule.ruleId}</p></div><span className="font-mono text-sm">{rule.count}</span></Link>)}{!stats.topRules.length && <p className="p-5 text-sm text-muted-foreground">No rule occurrences yet.</p>}</div></section>
    </div>
    <section className="workbench-panel"><div className="workbench-heading"><div><h2 className="text-sm font-semibold">Scan activity</h2><p className="mt-1 text-xs text-muted-foreground">Individual scan snapshots · findings are not a deduplicated trend</p></div><Link href="/scans" className="flex items-center gap-1 text-xs text-primary">Scan history <ArrowRight className="h-3.5 w-3.5" /></Link></div><div className="overflow-x-auto"><table className="data-table"><thead><tr><th>Repository</th><th>Branch</th><th>Status</th><th>Files</th><th>Findings</th><th>Recorded</th></tr></thead><tbody>{stats.recentScans.slice(0, 6).map((scan) => <tr key={scan.id}><td><Link className="font-medium hover:text-primary" href={"/scans/" + scan.id}>{scan.repository || "Unnamed scan"}</Link></td><td className="font-mono text-xs text-muted-foreground">{scan.branch || "—"}</td><td className="text-xs">{scan.status}</td><td className="font-mono text-xs">{scan.filesScanned.toLocaleString()}</td><td className="font-mono text-xs">{scan.findingsCount}</td><td className="whitespace-nowrap text-xs text-muted-foreground">{new Date(scan.createdAt).toLocaleString()}</td></tr>)}</tbody></table></div></section>
  </div>;
}
