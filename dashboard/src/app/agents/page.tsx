"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Activity,
  ArrowRight,
  Braces,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Network,
  Play,
  Radar,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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

const AGENT_COLORS = [
  "from-cyan-400/20 to-blue-500/5 border-cyan-400/25 text-cyan-300",
  "from-violet-400/20 to-fuchsia-500/5 border-violet-400/25 text-violet-300",
  "from-orange-400/20 to-rose-500/5 border-orange-400/25 text-orange-300",
  "from-blue-400/20 to-indigo-500/5 border-blue-400/25 text-blue-300",
  "from-emerald-400/20 to-teal-500/5 border-emerald-400/25 text-emerald-300",
  "from-amber-300/20 to-lime-500/5 border-amber-300/25 text-amber-200",
];

export default function AgentsPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [runs, setRuns] = useState<AgentRunListItem[]>([]);
  const [scanId, setScanId] = useState("");
  const [mode, setMode] = useState<"lite" | "deep">("deep");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      fetch("/api/scans?limit=100").then((response) => response.json()),
      fetch("/api/agent-runs?limit=50").then((response) => response.json()),
    ]).then(([scanData, runData]) => {
      const available = (scanData.scans || []).filter((scan: Scan) => scan.status === "completed");
      setScans(available);
      setScanId((current) => current || available[0]?.id || "");
      setRuns(runData.runs || []);
    }).catch(() => setError("에이전트 운영 데이터를 불러오지 못했습니다."));
  }, []);

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
      if (!response.ok) throw new Error(data.error || "실행을 시작하지 못했습니다.");
      router.push(`/agents/${data.id}`);
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : "실행을 시작하지 못했습니다.");
    } finally {
      setStarting(false);
    }
  };

  return (
    <div className="space-y-8 pb-12">
      <section className="relative overflow-hidden rounded-3xl border border-white/10 bg-[#07111f] text-white shadow-2xl shadow-blue-950/30">
        <div className="absolute inset-0 opacity-70 [background-image:radial-gradient(circle_at_18%_18%,rgba(34,211,238,.18),transparent_32%),radial-gradient(circle_at_82%_4%,rgba(139,92,246,.23),transparent_30%),linear-gradient(120deg,transparent_35%,rgba(59,130,246,.08)_50%,transparent_65%)]" />
        <div className="relative grid gap-8 px-8 py-10 lg:grid-cols-[1.3fr_.7fr] lg:px-10">
          <div className="space-y-5">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/10 px-3 py-1 text-xs font-medium text-cyan-100">
              <Sparkles className="h-3.5 w-3.5" />
              Aegify Autonomous Security Team
            </div>
            <div>
              <h1 className="max-w-3xl text-3xl font-semibold tracking-tight md:text-4xl">
                코드에서 실제 공격 표면까지,
                <span className="block bg-gradient-to-r from-cyan-300 via-blue-300 to-violet-300 bg-clip-text text-transparent">
                  증거로 연결되는 보안 AI 에이전트
                </span>
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-300">
                위협 모델링, 정적 분석, 승인형 동적 검증, CVE 적용성, 통합 보고와
                평가 기반 개선 루프를 하나의 감사 가능한 워크플로로 실행합니다.
              </p>
            </div>
            <div className="flex flex-wrap gap-2 text-xs text-slate-300">
              {["Evidence-bound", "Owned fixture only", "SHA-256 provenance", "Human approval", "MCP-ready"].map((label) => (
                <span key={label} className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                  {label}
                </span>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-white/[.055] p-5 backdrop-blur-xl">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">새 분석 실행</p>
                <p className="text-xs text-slate-400">완료된 스캔을 에이전트 팀에 전달</p>
              </div>
              <Play className="h-5 w-5 text-cyan-300" />
            </div>
            <div className="space-y-3">
              <select
                aria-label="분석할 스캔"
                value={scanId}
                onChange={(event) => setScanId(event.target.value)}
                className="h-11 w-full rounded-xl border border-white/10 bg-black/20 px-3 text-sm text-white outline-none focus:border-cyan-300/50"
              >
                {scans.length === 0 && <option value="">완료된 스캔 없음</option>}
                {scans.map((scan) => (
                  <option key={scan.id} value={scan.id} className="bg-slate-950">
                    {scan.repository || "unnamed"} · {scan.findingsCount} findings
                  </option>
                ))}
              </select>
              <div className="grid grid-cols-2 gap-2 rounded-xl bg-black/20 p-1">
                {(["lite", "deep"] as const).map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setMode(value)}
                    className={`rounded-lg px-3 py-2 text-xs font-medium transition ${mode === value ? "bg-white/10 text-white shadow" : "text-slate-400 hover:text-white"}`}
                  >
                    {value === "lite" ? "Lite · 빠른 분류" : "Deep · 전체 리치어빌리티"}
                  </button>
                ))}
              </div>
              <Button
                onClick={startRun}
                disabled={!scanId || starting}
                className="h-11 w-full rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 font-semibold text-slate-950 hover:from-cyan-300 hover:to-blue-400"
              >
                {starting ? <Activity className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />}
                {starting ? "분석 준비 중" : "에이전트 팀 실행"}
              </Button>
              {selectedScan && (
                <p className="truncate text-[11px] text-slate-500">
                  {selectedScan.branch} · {selectedScan.commitSha?.slice(0, 12) || "snapshot"}
                </p>
              )}
            </div>
          </div>
        </div>
      </section>

      {error && <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-600 dark:text-red-300">{error}</div>}

      <section className="space-y-4">
        <div className="flex items-end justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[.18em] text-primary">Architecture</p>
            <h2 className="mt-1 text-xl font-semibold">에이전트 협업 흐름</h2>
          </div>
          <div className="hidden items-center gap-2 text-xs text-muted-foreground md:flex">
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
            모델 서술과 판정 증거를 분리 저장
          </div>
        </div>
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          {SECURITY_AGENTS.map((agent, index) => (
            <div key={agent.code} className="relative">
              <div className={`h-full min-h-48 rounded-2xl border bg-gradient-to-br p-4 ${AGENT_COLORS[index]}`}>
                <div className="flex items-start justify-between">
                  <div className="grid h-9 w-9 place-items-center rounded-xl border border-current/15 bg-black/10">
                    {index === 0 ? <Radar className="h-4 w-4" /> : index === 1 ? <Braces className="h-4 w-4" /> : index === 2 ? <Activity className="h-4 w-4" /> : index === 3 ? <ShieldCheck className="h-4 w-4" /> : index === 4 ? <Network className="h-4 w-4" /> : <Sparkles className="h-4 w-4" />}
                  </div>
                  <span className="font-mono text-[10px] opacity-60">0{index + 1}</span>
                </div>
                <p className="mt-4 text-base font-semibold text-foreground">{agent.name}</p>
                <p className="text-[11px] font-medium uppercase tracking-widest opacity-70">{agent.romanizedName}</p>
                <p className="mt-3 text-xs leading-5 text-muted-foreground">{agent.mission}</p>
              </div>
              {index < SECURITY_AGENTS.length - 1 && (
                <ArrowRight className="absolute -right-3 top-1/2 z-10 hidden h-4 w-4 -translate-y-1/2 text-muted-foreground xl:block" />
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-[1fr_320px]">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[.18em] text-primary">Operations</p>
              <h2 className="mt-1 text-xl font-semibold">최근 실행</h2>
            </div>
            <span className="text-xs text-muted-foreground">{runs.length} runs</span>
          </div>
          {runs.length === 0 ? (
            <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">아직 에이전트 실행이 없습니다.</CardContent></Card>
          ) : runs.map((run) => (
            <button
              key={run.id}
              type="button"
              onClick={() => router.push(`/agents/${run.id}`)}
              className="group flex w-full items-center gap-4 rounded-2xl border bg-card p-4 text-left shadow-sm transition hover:-translate-y-0.5 hover:border-primary/30 hover:shadow-lg"
            >
              <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">
                <Workflow className="h-5 w-5" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="truncate font-medium">{run.scan.repository || "unnamed scan"}</p>
                  <RunStatus status={run.status} />
                  <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] uppercase">{run.mode}</span>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1"><Clock3 className="h-3 w-3" />{new Date(run.createdAt).toLocaleString()}</span>
                  <span>{run._count.stages}/6 agents</span>
                  <span>{run._count.approvals} approvals</span>
                  <span>{run._count.evidence} runtime evidence</span>
                </div>
              </div>
              <ChevronRight className="h-4 w-4 text-muted-foreground transition group-hover:translate-x-0.5 group-hover:text-primary" />
            </button>
          ))}
        </div>

        <div className="rounded-2xl border bg-card p-5 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
            실행 안전 경계
          </div>
          <div className="mt-4 space-y-4">
            {[
              ["정적 후보", "코드·그래프 증거만으로 런타임 성공을 주장하지 않음"],
              ["동적 승인", "owned loopback fixture와 비파괴 canary만 허용"],
              ["실제 증거", "이미지·정책·워크스페이스·출력 SHA-256 검증"],
              ["자가 개선", "최소 표본·정밀도 비회귀·사람 승인 전 자동 적용 금지"],
            ].map(([title, description]) => (
              <div key={title} className="flex gap-3">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                <div>
                  <p className="text-xs font-medium">{title}</p>
                  <p className="mt-0.5 text-[11px] leading-4 text-muted-foreground">{description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}

function RunStatus({ status }: { status: string }) {
  const style = status === "completed"
    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-300"
    : status === "awaiting_approval" || status === "awaiting_evidence"
      ? "bg-amber-500/10 text-amber-700 dark:text-amber-300"
      : status === "partial"
        ? "bg-orange-500/10 text-orange-700 dark:text-orange-300"
        : "bg-blue-500/10 text-blue-700 dark:text-blue-300";
  return <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${style}`}>{status.replaceAll("_", " ")}</span>;
}
