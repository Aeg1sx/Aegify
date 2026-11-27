"use client";
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

import { ArrowUpRight, Play, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { SECURITY_AGENTS } from "@/lib/agent-catalog";

interface Scan {
  id: string;
  repository: string;
  branch: string;
  commitSha: string;
  findingsCount: number;
  status: string;
}

interface AgentRunListItem {
  id: string;
  mode: string;
  provider: string;
  status: string;
  currentRole: string;
  createdAt: string;
  artifactDigest: string;
  scan: { repository: string; branch: string; commitSha: string };
  _count: { approvals: number; evidence: number; stages: number };
}

export default function AgentsPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [runs, setRuns] = useState<AgentRunListItem[]>([]);
  const [scanId, setScanId] = useState("");
  const [mode, setMode] = useState<"lite" | "deep">("deep");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch("/api/scans?limit=100").then((response) => { if (!response.ok) throw new Error("Scan data unavailable"); return response.json(); }),
      fetch("/api/agent-runs?limit=50").then((response) => { if (!response.ok) throw new Error("Agent data unavailable"); return response.json(); }),
    ]).then(([scanData, runData]) => {
      const available = (scanData.scans || []).filter((scan: Scan) => scan.status === "completed");
      setScans(available);
      setScanId((current) => current || available[0]?.id || "");
      setRuns(runData.runs || []);
      setError("");
    }).catch(() => setError("Unable to load agent operations.")).finally(() => setLoading(false));
  }, [refresh]);

  const selectedScan = useMemo(
    () => scans.find((scan) => scan.id === scanId),
    [scans, scanId],
  );

  const startRun = async () => {
    if (!scanId) return;
    setStarting(true);
    setError("");
    try {
      const response = await fetch("/api/agent-runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanId, mode, cves: [] }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Unable to start this run.");
      router.push(`/agents/${data.id}`);
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : "Unable to start this run.");
    } finally {
      setStarting(false);
    }
  };


  const waiting = runs.filter((run) => ["awaiting_approval", "awaiting_evidence"].includes(run.status));
  return <div className="space-y-6 pb-8">
    <header className="flex flex-wrap items-center justify-between gap-4"><h1 className="workbench-title">AI agents</h1><Button variant="outline" onClick={() => { setLoading(true); setRefresh((n) => n + 1); }} disabled={loading}><RefreshCw aria-hidden className={"size-4 " + (loading ? "animate-spin" : "")} />Refresh</Button></header>
    {error && <p role="alert" className="rounded-md border border-destructive/30 p-4 text-sm text-destructive">{error}</p>}
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
      <div className="space-y-5">
        <dl className="grid grid-cols-3 divide-x border-y py-4" aria-label="Recent analysis activity">
          {[["Recent runs", runs.length], ["Needs attention", waiting.length], ["Evidence records", runs.reduce((sum, run) => sum + run._count.evidence, 0)]].map(([label, count]) => <div key={label} className="px-3 sm:px-5"><dt className="text-sm text-muted-foreground">{label}</dt><dd className="mt-2 font-mono text-2xl tabular-nums">{loading ? "…" : count}</dd></div>)}
        </dl>
        <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-base font-semibold">Run history</h2><span className="text-xs text-muted-foreground">Latest 50 runs</span></div>
          <div className="overflow-auto"><table className="data-table"><thead><tr><th>Repository / snapshot</th><th>Status</th><th>Stage</th><th>Evidence</th><th>Started</th></tr></thead><tbody>
            {runs.map((run) => <tr key={run.id}><td><Link className="inline-flex items-center gap-2 font-medium hover:text-primary" href={"/agents/" + run.id}>{run.scan.repository || "Unnamed scan"}<ArrowUpRight className="h-3.5 w-3.5" /></Link><p className="mt-1 font-mono text-[11px] text-muted-foreground">{run.scan.branch || "default"} · {run.scan.commitSha?.slice(0, 8) || "snapshot"} · {run.mode}</p></td><td><RunStatus status={run.status} /></td><td className="text-xs">{SECURITY_AGENTS.find((agent) => agent.role === run.currentRole)?.name || "—"}</td><td className="font-mono text-xs">{run._count.evidence}</td><td className="whitespace-nowrap text-xs text-muted-foreground">{new Date(run.createdAt).toLocaleString("en-US")}</td></tr>)}
            {!runs.length && <tr><td colSpan={5} className="h-44 text-center text-sm text-muted-foreground">{loading ? "Loading operations…" : "No runs yet. Select a completed scan to start an analysis."}</td></tr>}
          </tbody></table></div>
        </section>
        {waiting.length > 0 && <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-sm font-semibold">Needs attention</h2></div><div className="divide-y divide-border">{waiting.map((run) => <Link key={run.id} href={"/agents/" + run.id} className="flex items-center justify-between gap-3 px-5 py-4 hover:bg-accent/40"><span className="text-sm">{run.scan.repository || run.id}</span><RunStatus status={run.status} /></Link>)}</div></section>}
      </div>
      <aside className="space-y-5">
        <section className="workbench-panel"><div className="workbench-heading"><h2 className="text-sm font-semibold">New analysis</h2><Play className="h-4 w-4 text-muted-foreground" /></div><div className="space-y-4 p-5">
          <label className="block text-xs text-muted-foreground">Completed scan<select aria-label="Scan to analyze" value={scanId} onChange={(e) => setScanId(e.target.value)} className="workbench-select mt-2 w-full">{!scans.length && <option value="">No completed scans</option>}{scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.repository || "Unnamed"} · {scan.commitSha?.slice(0, 8) || scan.id.slice(0, 8)}</option>)}</select></label>
          <div className="grid grid-cols-2 gap-2">{(["lite", "deep"] as const).map((value) => <button type="button" key={value} aria-pressed={mode === value} onClick={() => setMode(value)} className={"rounded-md border px-3 py-3 text-left " + (mode === value ? "border-primary/50 bg-primary/5" : "border-border")}><span className="block text-xs font-semibold uppercase">{value}</span><span className="mt-1 block text-[11px] text-muted-foreground">{value === "lite" ? "Quick triage" : "Detailed evidence review"}</span></button>)}</div>
          {selectedScan && <p className="break-all font-mono text-[11px] text-muted-foreground">{selectedScan.branch || "default"} · {selectedScan.findingsCount} findings</p>}
          <Button className="w-full" onClick={startRun} disabled={!scanId || starting || loading}><Play className="mr-2 h-3.5 w-3.5" />{starting ? "Preparing run…" : "Start analysis"}</Button>
          <p className="text-[11px] leading-5 text-muted-foreground">Analyze a recorded scan artifact. Dynamic evidence collection requires a separate scope approval.</p>
        </div></section>
      </aside>
    </div>
    <details className="workbench-panel"><summary className="cursor-pointer px-5 py-4 text-sm font-semibold">Agent roles and tools · 6 roles</summary><div className="overflow-auto"><table className="data-table"><thead><tr><th>Agent</th><th>Role</th><th>Responsibility</th><th>Tools</th></tr></thead><tbody>{SECURITY_AGENTS.map((agent) => <tr key={agent.role}><td className="whitespace-nowrap font-medium">{agent.name}<span className="mt-1 block font-mono text-[10px] text-muted-foreground">{agent.code}</span></td><td className="font-mono text-xs">{agent.role}</td><td className="min-w-64 text-xs text-muted-foreground">{agent.mission}</td><td className="font-mono text-[11px] text-muted-foreground">{agent.tools.join(" · ")}</td></tr>)}</tbody></table></div></details>
  </div>;
}

function RunStatus({ status }: { status: string }) {
  const style = status === "completed" ? "text-emerald-700 dark:text-emerald-400" : ["awaiting_approval", "awaiting_evidence"].includes(status) ? "text-amber-700 dark:text-amber-300" : ["failed", "partial"].includes(status) ? "text-destructive" : "text-muted-foreground";
  return <span className={"inline-flex items-center gap-1.5 whitespace-nowrap text-xs " + style}><span className="h-1.5 w-1.5 rounded-full bg-current" />{status.replaceAll("_", " ")}</span>;
}
