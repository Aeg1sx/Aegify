"use client";

import { use, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  Clock3,
  Code2,
  Database,
  FileJson,
  Fingerprint,
  GitBranch,
  KeyRound,
  Network,
  PlayCircle,
  Route,
  ShieldCheck,
  Sparkles,
  Upload,
  X,
} from "lucide-react";

import { CodeHighlight } from "@/components/code-highlight";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface Reachability {
  findingId: string;
  endpoint: string;
  method: string;
  entryPoint: string;
  sink: string;
  hops: Array<{ function: string; filePath: string; line: number; snippet: string }>;
  evidenceIds: string[];
  staticComplete: boolean;
  runtimeObserved: boolean;
  impactProven: boolean;
  unresolvedLinks: string[];
}

interface DynamicPlan {
  id: string;
  findingId: string;
  targetScope: string;
  targetOrigin: string;
  harness: string;
  requestTemplate: string;
  payloadTemplate: string;
  expectedSignal: string;
  negativeControl: string;
  cleanup: string[];
}

interface AgentStage {
  id: string;
  sequence: number;
  role: string;
  agentCode: string;
  agentName: string;
  status: string;
  summary: string;
  facts: Record<string, unknown>;
  evidenceIds: string[];
  reachability: Reachability[];
  dynamicPlans: DynamicPlan[];
  cveAssessments: Array<Record<string, unknown>>;
  improvementProposals: Array<Record<string, unknown>>;
  promptDigest: string;
  errorMessage: string;
}

interface Approval {
  id: string;
  resourceId: string;
  status: string;
  scopeDigest: string;
  decisionNote: string;
  requestedAt: string;
  expiresAt: string | null;
}

interface AgentRun {
  id: string;
  mode: string;
  provider: string;
  status: string;
  currentRole: string;
  workspaceSnapshot: string;
  artifactDigest: string;
  createdAt: string;
  completedAt: string | null;
  scan: { repository: string; branch: string; commitSha: string };
  stages: AgentStage[];
  approvals: Approval[];
  events: Array<{ id: string; type: string; actor: string; message: string; createdAt: string }>;
  evidence: Array<{ id: string; status: string; digest: string; producer: string; createdAt: string }>;
}

const ROLE_LABEL: Record<string, string> = {
  surface: "환경·위협 모델",
  static: "정적 진단",
  dynamic: "동적 진단",
  cve: "CVE 적용성",
  synthesis: "최종 결과",
  steward: "자가 개선",
};

const ROLE_ACCENT: Record<string, string> = {
  surface: "bg-cyan-500",
  static: "bg-violet-500",
  dynamic: "bg-orange-500",
  cve: "bg-blue-500",
  synthesis: "bg-emerald-500",
  steward: "bg-amber-500",
};

export default function AgentRunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [run, setRun] = useState<AgentRun | null>(null);
  const [activeRole, setActiveRole] = useState("surface");
  const [loading, setLoading] = useState(true);
  const [note, setNote] = useState("");
  const [evidenceJson, setEvidenceJson] = useState("");
  const [actionError, setActionError] = useState("");
  const [acting, setActing] = useState(false);

  const refresh = useCallback(async () => {
    const response = await fetch(`/api/agent-runs/${id}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "실행을 불러오지 못했습니다.");
    setRun(data);
  }, [id]);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      refresh().catch((error) => setActionError(error.message)).finally(() => setLoading(false));
    });
    return () => cancelAnimationFrame(frame);
  }, [refresh]);

  const activeStage = useMemo(
    () => run?.stages.find((stage) => stage.role === activeRole) || run?.stages[0],
    [run, activeRole],
  );

  const decide = async (approvalId: string, decision: "approved" | "rejected") => {
    setActing(true);
    setActionError("");
    try {
      const response = await fetch(`/api/agent-runs/${id}/approvals/${approvalId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, note }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "승인 상태를 변경하지 못했습니다.");
      setNote("");
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "승인 처리에 실패했습니다.");
    } finally {
      setActing(false);
    }
  };

  const importEvidence = async (approvalId: string) => {
    setActing(true);
    setActionError("");
    try {
      const parsed = JSON.parse(evidenceJson);
      const response = await fetch(`/api/agent-runs/${id}/evidence`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approvalId, evidence: parsed }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "증거를 가져오지 못했습니다.");
      setEvidenceJson("");
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "올바른 JSON 증거가 아닙니다.");
    } finally {
      setActing(false);
    }
  };

  if (loading) return <div className="grid h-[60vh] place-items-center text-sm text-muted-foreground">Loading agent evidence…</div>;
  if (!run) return <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-600">{actionError || "Agent run not found"}</div>;

  return (
    <div className="space-y-6 pb-16">
      <header className="relative overflow-hidden rounded-3xl border bg-[#07111f] px-7 py-7 text-white shadow-xl">
        <div className="absolute inset-0 opacity-70 [background-image:radial-gradient(circle_at_85%_20%,rgba(99,102,241,.25),transparent_30%),radial-gradient(circle_at_15%_80%,rgba(6,182,212,.15),transparent_30%)]" />
        <div className="relative">
          <Link href="/agents" className="mb-5 inline-flex items-center gap-1.5 text-xs text-slate-400 transition hover:text-white">
            <ArrowLeft className="h-3.5 w-3.5" /> Agent Operations
          </Link>
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-2xl font-semibold">{run.scan.repository || "Security agent run"}</h1>
                <StatusPill status={run.status} />
                <span className="rounded-md border border-white/10 bg-white/5 px-2 py-1 font-mono text-[10px] uppercase text-slate-300">{run.mode}</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-400">
                <span className="flex items-center gap-1.5"><GitBranch className="h-3.5 w-3.5" />{run.scan.branch || "default"} · {run.scan.commitSha?.slice(0, 12) || "snapshot"}</span>
                <span className="flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{new Date(run.createdAt).toLocaleString()}</span>
                <span className="flex items-center gap-1.5"><Fingerprint className="h-3.5 w-3.5" />{run.artifactDigest.slice(0, 24)}…</span>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <Metric label="Agents" value={`${run.stages.length}/6`} />
              <Metric label="Approvals" value={String(run.approvals.length)} />
              <Metric label="Evidence" value={String(run.evidence.length)} />
            </div>
          </div>
        </div>
      </header>

      {actionError && <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-600 dark:text-red-300">{actionError}</div>}

      <section className="rounded-2xl border bg-card p-3 shadow-sm">
        <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6">
          {run.stages.map((stage, index) => (
            <button
              key={stage.id}
              type="button"
              onClick={() => setActiveRole(stage.role)}
              className={`relative rounded-xl border p-3 text-left transition ${activeRole === stage.role ? "border-primary/40 bg-primary/5 shadow-sm" : "border-transparent hover:bg-muted/60"}`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] text-muted-foreground">0{index + 1}</span>
                <StageIcon status={stage.status} />
              </div>
              <p className="mt-3 text-sm font-semibold">{stage.agentName}</p>
              <p className="text-[10px] text-muted-foreground">{ROLE_LABEL[stage.role]}</p>
              {index < run.stages.length - 1 && <ChevronRight className="absolute -right-2.5 top-1/2 z-10 hidden h-4 w-4 -translate-y-1/2 text-muted-foreground xl:block" />}
            </button>
          ))}
        </div>
      </section>

      {activeStage && (
        <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
          <div className="space-y-5">
            <Card className="overflow-hidden">
              <div className={`h-1 ${ROLE_ACCENT[activeStage.role] || "bg-blue-500"}`} />
              <CardHeader className="pb-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[.18em] text-primary">{activeStage.agentCode}</p>
                    <CardTitle className="mt-1 text-xl">{activeStage.agentName} · {ROLE_LABEL[activeStage.role]}</CardTitle>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">{activeStage.summary}</p>
                  </div>
                  <StatusPill status={activeStage.status} />
                </div>
              </CardHeader>
              <CardContent>
                <StageContent
                  stage={activeStage}
                  approvals={run.approvals}
                  note={note}
                  setNote={setNote}
                  evidenceJson={evidenceJson}
                  setEvidenceJson={setEvidenceJson}
                  decide={decide}
                  importEvidence={importEvidence}
                  acting={acting}
                />
              </CardContent>
            </Card>
          </div>

          <aside className="space-y-4">
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Evidence contract</CardTitle></CardHeader>
              <CardContent className="space-y-3 text-xs">
                <InfoRow icon={<Fingerprint className="h-3.5 w-3.5" />} label="Prompt" value={`${activeStage.promptDigest.slice(0, 20)}…`} mono />
                <InfoRow icon={<Database className="h-3.5 w-3.5" />} label="Evidence" value={`${activeStage.evidenceIds.length} linked`} />
                <InfoRow icon={<ShieldCheck className="h-3.5 w-3.5" />} label="Authority" value="facts > model narrative" />
                <InfoRow icon={<KeyRound className="h-3.5 w-3.5" />} label="Execution" value="explicit approval" />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Audit timeline</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                {run.events.slice(-8).reverse().map((event) => (
                  <div key={event.id} className="relative border-l pl-3 text-xs">
                    <span className="absolute -left-1 top-1 h-2 w-2 rounded-full bg-primary" />
                    <p className="font-medium">{event.message}</p>
                    <p className="mt-1 text-[10px] text-muted-foreground">{event.actor} · {new Date(event.createdAt).toLocaleString()}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          </aside>
        </section>
      )}
    </div>
  );
}

function StageContent(props: {
  stage: AgentStage;
  approvals: Approval[];
  note: string;
  setNote: (value: string) => void;
  evidenceJson: string;
  setEvidenceJson: (value: string) => void;
  decide: (id: string, decision: "approved" | "rejected") => void;
  importEvidence: (id: string) => void;
  acting: boolean;
}) {
  const { stage } = props;
  if (stage.role === "static") return <ReachabilityPanel traces={stage.reachability} />;
  if (stage.role === "dynamic") return <DynamicPanel {...props} />;
  if (stage.role === "cve") return <CvePanel assessments={stage.cveAssessments} />;
  if (stage.role === "steward") return <ImprovementPanel proposals={stage.improvementProposals} />;
  if (stage.role === "synthesis") return <SynthesisPanel facts={stage.facts} />;
  return <SurfacePanel facts={stage.facts} />;
}

function SurfacePanel({ facts }: { facts: Record<string, unknown> }) {
  const scenarios = Array.isArray(facts.threatScenarios) ? facts.threatScenarios as Array<Record<string, unknown>> : [];
  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Fact label="Endpoints" value={facts.endpoints} />
        <Fact label="No auth evidence" value={facts.endpointsWithoutDetectedAuth} tone="warning" />
        <Fact label="Gateway exposed" value={facts.gatewayExposed} />
        <Fact label="Runtime observed" value={facts.runtimeObserved} tone="success" />
      </div>
      <div>
        <h3 className="mb-3 text-sm font-semibold">Threat surface</h3>
        <div className="grid gap-2 md:grid-cols-2">
          {scenarios.slice(0, 12).map((scenario, index) => (
            <div key={`${scenario.surface}-${index}`} className="flex items-center gap-3 rounded-xl border bg-muted/20 p-3">
              <div className="grid h-8 w-8 place-items-center rounded-lg bg-cyan-500/10 text-cyan-600"><Route className="h-4 w-4" /></div>
              <div className="min-w-0 flex-1">
                <p className="truncate font-mono text-xs font-medium">{String(scenario.surface)}</p>
                <p className="mt-0.5 text-[10px] text-muted-foreground">external → application · auth {String(scenario.auth)}</p>
              </div>
              {scenario.runtimeObserved === true && <span className="h-2 w-2 rounded-full bg-emerald-500" title="runtime observed" />}
            </div>
          ))}
          {scenarios.length === 0 && <Empty text="위협 시나리오를 만들 엔드포인트가 없습니다." />}
        </div>
      </div>
    </div>
  );
}

function ReachabilityPanel({ traces }: { traces: Reachability[] }) {
  return (
    <div className="space-y-6">
      {traces.map((trace) => (
        <div key={trace.findingId} className="overflow-hidden rounded-2xl border">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b bg-muted/25 px-4 py-3">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-violet-500" />
              <span className="font-mono text-xs">{trace.findingId}</span>
              <PathState trace={trace} />
            </div>
            <span className="font-mono text-xs text-muted-foreground">{trace.method} {trace.endpoint || "unresolved endpoint"}</span>
          </div>
          <div className="p-4">
            <div className="flex min-w-max items-center gap-2 overflow-x-auto pb-3">
              <FlowNode label={trace.entryPoint || "Unknown entry"} caption="entry point" tone="cyan" />
              {trace.hops.map((hop, index) => (
                <div key={`${hop.function}-${index}`} className="flex items-center gap-2">
                  <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <FlowNode label={hop.function} caption={`${hop.filePath}:${hop.line}`} tone="violet" />
                </div>
              ))}
              <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" />
              <FlowNode label={trace.sink} caption="security sink" tone="red" />
            </div>
            {trace.unresolvedLinks.length > 0 && (
              <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/5 p-3">
                <p className="flex items-center gap-2 text-xs font-medium text-amber-700 dark:text-amber-300"><AlertTriangle className="h-3.5 w-3.5" />Missing proof</p>
                <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
                  {trace.unresolvedLinks.map((gap) => <li key={gap}>• {gap}</li>)}
                </ul>
              </div>
            )}
            {trace.hops.some((hop) => hop.snippet) && (
              <div className="mt-4">
                <div className="mb-2 flex items-center gap-2 text-xs font-semibold"><Code2 className="h-3.5 w-3.5" />Vulnerable path snippet</div>
                {trace.hops.filter((hop) => hop.snippet).slice(-1).map((hop) => (
                  <div key={`${hop.filePath}:${hop.line}`}>
                    <p className="mb-2 font-mono text-[10px] text-muted-foreground">{hop.filePath}:{hop.line}</p>
                    <CodeHighlight
                      code={hop.snippet}
                      language={hop.filePath}
                      lineStart={hop.line}
                      highlightStart={hop.line}
                      highlightEnd={hop.line}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ))}
      {traces.length === 0 && <Empty text="이 스캔에는 리치어빌리티를 계산할 파인딩이 없습니다." />}
    </div>
  );
}

function DynamicPanel(props: Parameters<typeof StageContent>[0]) {
  const { stage, approvals, note, setNote, evidenceJson, setEvidenceJson, decide, importEvidence, acting } = props;
  return (
    <div className="space-y-4">
      {stage.dynamicPlans.map((plan) => {
        const approval = approvals.find((item) => item.resourceId === plan.id);
        return (
          <div key={plan.id} className="rounded-2xl border border-orange-500/20 bg-orange-500/[.035] p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="flex items-center gap-2 text-sm font-semibold"><PlayCircle className="h-4 w-4 text-orange-500" />{plan.requestTemplate}</p>
                <p className="mt-1 text-xs text-muted-foreground">{plan.targetScope} · {plan.targetOrigin} · {plan.harness}</p>
              </div>
              <StatusPill status={approval?.status || "pending"} />
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <Fact label="Safe payload" value={plan.payloadTemplate} mono />
              <Fact label="Expected signal" value={plan.expectedSignal} />
              <Fact label="Negative control" value={plan.negativeControl} />
              <Fact label="Scope digest" value={`${approval?.scopeDigest.slice(0, 28) || ""}…`} mono />
            </div>
            {approval?.status === "pending" && (
              <div className="mt-4 rounded-xl border bg-background p-3">
                <label className="text-xs font-medium">승인 범위와 fixture 소유권 근거</label>
                <textarea
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  placeholder="예: local fixture /run, 테스트 데이터만 사용, 종료 후 컨테이너 삭제"
                  className="mt-2 min-h-20 w-full rounded-lg border bg-background p-2 text-xs outline-none focus:border-primary"
                />
                <div className="mt-2 flex gap-2">
                  <Button size="sm" onClick={() => decide(approval.id, "approved")} disabled={acting || note.trim().length < 8}><Check className="mr-1 h-3.5 w-3.5" />Approve fixture run</Button>
                  <Button size="sm" variant="outline" onClick={() => decide(approval.id, "rejected")} disabled={acting}><X className="mr-1 h-3.5 w-3.5" />Reject</Button>
                </div>
              </div>
            )}
            {approval?.status === "approved" && (
              <div className="mt-4 rounded-xl border bg-background p-3">
                <label className="flex items-center gap-2 text-xs font-medium"><FileJson className="h-3.5 w-3.5" />Aegify harness evidence JSON</label>
                <p className="mt-1 text-[10px] text-muted-foreground">`verify-http`, `verify-browser`, `verify-proxy` 실행 결과에 아래 승인 범위 digest를 결합해야 합니다.</p>
                <textarea
                  value={evidenceJson}
                  onChange={(event) => setEvidenceJson(event.target.value)}
                  placeholder={`{"contract_version":1,"executed":true,"approval_scope_sha256":"${approval.scopeDigest}",...}`}
                  className="mt-2 min-h-32 w-full rounded-lg border bg-[#0d1117] p-3 font-mono text-xs text-slate-200 outline-none focus:border-primary"
                />
                <Button size="sm" className="mt-2" onClick={() => importEvidence(approval.id)} disabled={acting || !evidenceJson.trim()}><Upload className="mr-1 h-3.5 w-3.5" />Verify & import evidence</Button>
              </div>
            )}
          </div>
        );
      })}
      {stage.dynamicPlans.length === 0 && <Empty text="추가 실행이 필요한 미관측 정적 경로가 없습니다." />}
    </div>
  );
}

function CvePanel({ assessments }: { assessments: Array<Record<string, unknown>> }) {
  return assessments.length === 0 ? <Empty text="이 실행에 전달된 CVE가 없습니다. API 또는 CLI에서 CVE 후보를 추가할 수 있습니다." /> : (
    <div className="space-y-3">
      {assessments.map((item) => (
        <div key={String(item.cveId)} className="rounded-xl border p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="font-mono text-sm font-semibold">{String(item.cveId)}</p>
            <StatusPill status={String(item.applicability)} />
          </div>
          <p className="mt-2 text-sm text-muted-foreground">{String(item.rationale)}</p>
          {Array.isArray(item.missingEvidence) && item.missingEvidence.length > 0 && <p className="mt-2 text-xs text-amber-600">Missing: {item.missingEvidence.join(", ")}</p>}
        </div>
      ))}
    </div>
  );
}

function ImprovementPanel({ proposals }: { proposals: Array<Record<string, unknown>> }) {
  return proposals.length === 0 ? <Empty text="이번 실행에서 새 개선 제안이 생성되지 않았습니다." /> : (
    <div className="grid gap-3 md:grid-cols-2">
      {proposals.map((item) => (
        <div key={String(item.id)} className="rounded-2xl border bg-gradient-to-br from-amber-500/5 to-transparent p-4">
          <div className="flex items-center justify-between"><Sparkles className="h-4 w-4 text-amber-500" /><StatusPill status="proposed" /></div>
          <h3 className="mt-3 text-sm font-semibold">{String(item.title)}</h3>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{String(item.hypothesis)}</p>
          <div className="mt-3 rounded-lg bg-muted/40 p-2 text-[11px]">Target: {String(item.targetMetric)}</div>
          <p className="mt-2 text-[10px] text-muted-foreground">최소 {String(item.minimumSamples)} samples · auto apply: false</p>
        </div>
      ))}
    </div>
  );
}

function SynthesisPanel({ facts }: { facts: Record<string, unknown> }) {
  const findings = Array.isArray(facts.findings) ? facts.findings as Array<Record<string, unknown>> : [];
  return (
    <div className="space-y-3">
      {findings.map((finding) => (
        <div key={String(finding.findingId)} className="rounded-2xl border p-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-semibold">{String(finding.ruleId)}</span>
            <StatusPill status={String(finding.severity)} />
            <StatusPill status={String(finding.likelihood)} />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <Fact label="Attack surface" value={finding.attackSurface} mono />
            <Fact label="Code remediation" value={finding.remediation} />
          </div>
        </div>
      ))}
      {findings.length === 0 && <Empty text="통합할 파인딩이 없습니다." />}
    </div>
  );
}

function FlowNode({ label, caption, tone }: { label: string; caption: string; tone: string }) {
  const style = tone === "red" ? "border-red-500/25 bg-red-500/5" : tone === "cyan" ? "border-cyan-500/25 bg-cyan-500/5" : "border-violet-500/25 bg-violet-500/5";
  return <div className={`min-w-40 rounded-xl border p-3 ${style}`}><p className="truncate font-mono text-xs font-medium">{label}</p><p className="mt-1 truncate text-[10px] text-muted-foreground">{caption}</p></div>;
}

function PathState({ trace }: { trace: Reachability }) {
  const label = trace.impactProven ? "impact proven" : trace.runtimeObserved ? "runtime observed" : trace.staticComplete ? "static reachable" : "partial";
  return <StatusPill status={label} />;
}

function Fact({ label, value, tone, mono }: { label: string; value: unknown; tone?: string; mono?: boolean }) {
  const color = tone === "warning" ? "text-amber-600" : tone === "success" ? "text-emerald-600" : "text-foreground";
  return <div className="rounded-xl border bg-muted/20 p-3"><p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p><p className={`mt-1 text-sm font-semibold ${color} ${mono ? "font-mono text-xs" : ""}`}>{String(value ?? "—")}</p></div>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="min-w-20 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-center"><p className="text-lg font-semibold">{value}</p><p className="text-[9px] uppercase tracking-wider text-slate-400">{label}</p></div>;
}

function StageIcon({ status }: { status: string }) {
  if (status === "completed") return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  if (status === "waiting_approval") return <KeyRound className="h-4 w-4 text-amber-500" />;
  if (status === "partial") return <AlertTriangle className="h-4 w-4 text-orange-500" />;
  return <CircleDashed className="h-4 w-4 text-blue-500" />;
}

function StatusPill({ status }: { status: string }) {
  const normalized = status.replaceAll("_", " ");
  const style = /completed|passed|proven|observed|consumed/.test(status)
    ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
    : /waiting|pending|proposed|reachable|exposed/.test(status)
      ? "bg-amber-500/10 text-amber-700 dark:text-amber-300"
      : /critical|failed|rejected|error/.test(status)
        ? "bg-red-500/10 text-red-700 dark:text-red-300"
        : "bg-blue-500/10 text-blue-700 dark:text-blue-300";
  return <span className={`whitespace-nowrap rounded-full px-2 py-0.5 text-[10px] font-semibold ${style}`}>{normalized}</span>;
}

function InfoRow({ icon, label, value, mono }: { icon: React.ReactNode; label: string; value: string; mono?: boolean }) {
  return <div className="flex items-start gap-2"><span className="mt-0.5 text-muted-foreground">{icon}</span><div><p className="text-[10px] text-muted-foreground">{label}</p><p className={mono ? "font-mono text-[10px]" : "text-xs"}>{value}</p></div></div>;
}

function Empty({ text }: { text: string }) {
  return <div className="grid min-h-32 place-items-center rounded-xl border border-dashed text-center text-sm text-muted-foreground">{text}</div>;
}
