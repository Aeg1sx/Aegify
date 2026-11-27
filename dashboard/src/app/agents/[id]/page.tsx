"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowUpRight,
  Check,
  CheckCircle2,
  CircleDashed,
  Clock3,
  Code2,
  FileJson,
  GitBranch,
  KeyRound,
  Network,
  PlayCircle,
  Upload,
  X,
} from "lucide-react";

import { SECURITY_AGENTS } from "@/lib/agent-catalog";
import { CodeHighlight } from "@/components/code-highlight";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

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
  surface: "Environment & threats",
  static: "Static analysis",
  dynamic: "Dynamic validation",
  cve: "CVE applicability",
  synthesis: "Final assessment",
  steward: "Quality review",
};

export default function AgentRunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <AgentRunReview key={id} id={id} />;
}

function AgentRunReview({ id }: { id: string }) {
  const [run, setRun] = useState<AgentRun | null>(null);
  const [activeRole, setActiveRole] = useState("");
  const [destination, setDestination] = useState<{ id: string } | null>(null);

  const openRecord = (role: string, id: string) => {
    setActiveRole(role);
    setDestination({ id });
  };

  useEffect(() => {
    if (!destination) return;
    const frame = requestAnimationFrame(() => {
      const node = document.getElementById(destination.id);
      if (!node) return;
      const details = node.closest("details");
      if (details) details.open = true;
      node.focus({ preventScroll: true });
      node.scrollIntoView({ block: "center" });
    });
    return () => cancelAnimationFrame(frame);
  }, [destination]);

  const [loading, setLoading] = useState(true);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [evidenceDrafts, setEvidenceDrafts] = useState<Record<string, string>>({});
  const [actionError, setActionError] = useState("");
  const [acting, setActing] = useState(false);

  const refresh = useCallback(async () => {
    const response = await fetch(`/api/agent-runs/${id}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to load this run.");
    setRun(data);
  }, [id]);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      refresh().catch((error) => setActionError(error.message)).finally(() => setLoading(false));
    });
    return () => cancelAnimationFrame(frame);
  }, [refresh]);

  const preferredRole = activeRole || (run?.status === "completed" ? "synthesis" : "static");
  const activeStage = run?.stages.find((stage) => stage.role === preferredRole) || run?.stages[0];

  const decide = async (approvalId: string, decision: "approved" | "rejected") => {
    setActing(true);
    setActionError("");
    try {
      const response = await fetch(`/api/agent-runs/${id}/approvals/${approvalId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, note: notes[approvalId] || "" }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Unable to update approval status.");
      setNotes((previous) => ({ ...previous, [approvalId]: "" }));
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Approval update failed.");
    } finally {
      setActing(false);
    }
  };

  const importEvidence = async (approvalId: string) => {
    setActing(true);
    setActionError("");
    try {
      const parsed = JSON.parse(evidenceDrafts[approvalId] || "");
      const response = await fetch(`/api/agent-runs/${id}/evidence`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approvalId, evidence: parsed }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Unable to import evidence.");
      setEvidenceDrafts((previous) => ({ ...previous, [approvalId]: "" }));
      await refresh();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Evidence must be valid JSON.");
    } finally {
      setActing(false);
    }
  };

  if (loading) return <p role="status" className="py-12 text-sm text-muted-foreground">Loading analysis…</p>;
  if (!run) return (
    <div className="space-y-4">
      <Link href="/agents" className="text-sm text-primary">Back to AI agents</Link>
      <p role="alert" className="text-sm text-destructive">{actionError || "Analysis run not found."}</p>
    </div>
  );

  return (
    <div className="mx-auto max-w-[1440px] space-y-6 pb-12">
      <header className="space-y-3 border-b pb-5">
        <Link href="/agents" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-primary">
          <ArrowLeft aria-hidden className="size-4" /> AI agents
        </Link>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h1 className="workbench-title break-all">{run.scan.repository || "Analysis run"}</h1>
          <RunState status={run.status} />
        </div>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted-foreground">
          <span className="inline-flex items-center gap-1.5 font-mono text-xs">
            <GitBranch aria-hidden className="size-3.5" />{run.scan.branch || "default"}
            {run.scan.commitSha && <span>· {run.scan.commitSha.slice(0, 8)}</span>}
          </span>
          <time dateTime={run.createdAt} className="inline-flex items-center gap-1.5">
            <Clock3 aria-hidden className="size-3.5" />{new Date(run.createdAt).toLocaleString()}
          </time>
          <span>{run.mode === "deep" ? "Deep review" : run.mode === "lite" ? "Quick review" : run.mode}</span>
        </div>
      </header>

      {actionError && <p role="alert" className="border-l-2 border-destructive pl-3 text-sm text-destructive">{actionError}</p>}

      {activeStage ? (
        <Tabs orientation="vertical" value={activeStage.role} onValueChange={setActiveRole}
          className="grid items-start gap-5 lg:grid-cols-[13rem_minmax(0,1fr)]">
          <div>
            <h2 className="mb-3 hidden text-sm font-semibold lg:block">Review stages</h2>
            <TabsList variant="line" aria-label="Review stages" className="hidden h-auto w-full items-stretch gap-0 border-l p-0 lg:flex">
              {run.stages.map((stage) => (
                <TabsTrigger key={stage.id} value={stage.role}
                  className="min-h-12 justify-start gap-2.5 whitespace-normal rounded-none border-0 px-3 text-left text-sm text-muted-foreground after:hidden hover:bg-muted data-[state=active]:border-l-2 data-[state=active]:border-primary data-[state=active]:bg-accent data-[state=active]:text-foreground">
                  <StageIcon status={stage.status} />
                  {ROLE_LABEL[stage.role] || stage.role}
                  <span className="sr-only">, {stage.status.replaceAll("_", " ")}</span>
                </TabsTrigger>
              ))}
            </TabsList>
            <label className="flex items-center gap-3 text-sm font-medium lg:hidden">
              Stage
              <select className="workbench-select h-11 flex-1 bg-card px-3 text-sm" value={activeStage.role} onChange={(event) => setActiveRole(event.target.value)}>
                {run.stages.map((stage) => <option key={stage.id} value={stage.role}>{ROLE_LABEL[stage.role] || stage.role}</option>)}
              </select>
            </label>
          </div>
          {run.stages.map((stage) => (
            <TabsContent key={stage.id} value={stage.role} aria-label={ROLE_LABEL[stage.role] || stage.role}
              className="workbench-panel focus-visible:ring-2 focus-visible:ring-ring">
              <header className="space-y-3 border-b px-4 py-4 sm:px-6 sm:py-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2 id={stageHeadingId(stage)} tabIndex={-1} className="rounded-sm text-xl font-semibold tracking-tight focus-visible:outline-2 focus-visible:outline-ring">{ROLE_LABEL[stage.role] || stage.role}</h2>
                  <RunState status={stage.status} />
                </div>
                {stage.summary && <p className="max-w-prose text-sm leading-6 text-muted-foreground">{stage.summary}</p>}
                {stage.errorMessage && <p role="alert" className="text-sm text-destructive">{stage.errorMessage}</p>}
              </header>
              <div className="min-w-0 space-y-6 p-4 sm:p-6">
                {(stage.role === "static" || stage.role === "synthesis") &&
                  <ReviewHandoff value={stage.facts.reviewHandoff} stages={run.stages} openRecord={openRecord} />}
                <StageContent stage={stage} staticStage={run.stages.find((item) => item.role === "static")} openRecord={openRecord} approvals={run.approvals} notes={notes} evidenceDrafts={evidenceDrafts}
                  setNote={(id, value) => setNotes((previous) => ({ ...previous, [id]: value }))}
                  setEvidenceJson={(id, value) => setEvidenceDrafts((previous) => ({ ...previous, [id]: value }))}
                  decide={decide}
                  importEvidence={importEvidence} acting={acting} />
              </div>
              <details className="border-t text-sm">
                <summary className="cursor-pointer px-4 py-3 font-medium sm:px-6">Stage evidence · {stage.evidenceIds.length}</summary>
                <div className="space-y-3 px-4 pb-5 sm:px-6">
                  <dl className="grid gap-2 text-xs">
                    <InfoRow label="Agent" value={stage.agentName || SECURITY_AGENTS.find((agent) => agent.role === stage.role)?.name || stage.agentCode} />
                    {stage.promptDigest && <InfoRow label="Prompt digest" value={stage.promptDigest} mono />}
                  </dl>
                  {stage.evidenceIds.length > 0 && <ul aria-label="Evidence references" className="space-y-1 break-all font-mono text-xs">{stage.evidenceIds.map((ref) => <li key={ref} id={referenceId(stage, ref)} tabIndex={-1} className="w-fit max-w-full rounded-sm p-1 focus-visible:outline-2 focus-visible:outline-ring">{ref}</li>)}</ul>}
                </div>
              </details>
            </TabsContent>
          ))}
        </Tabs>
      ) : <p className="py-6 text-sm text-muted-foreground">This run has no recorded stages.</p>}

      <details className="workbench-panel">
        <summary className="cursor-pointer px-4 py-4 text-sm font-semibold sm:px-5">Run history · {run.events.length}</summary>
        <div className="space-y-4 border-t p-4 sm:p-5">
          <dl className="grid gap-x-6 gap-y-2 text-xs md:grid-cols-2">
            {run.artifactDigest && <InfoRow label="Artifact digest" value={run.artifactDigest} mono />}
            {run.provider && <InfoRow label="Provider" value={run.provider} />}
            <InfoRow label="Approvals" value={String(run.approvals.length)} />
            <InfoRow label="Evidence records" value={String(run.evidence.length)} />
          </dl>
          {run.events.length > 0 && <ol aria-label="Run events" className="divide-y border-t">
            {run.events.slice().reverse().map((event) => (
              <li key={event.id} className="flex flex-wrap items-baseline justify-between gap-x-5 gap-y-1 py-3 text-sm">
                <span className="break-words">{event.message}</span>
                <span className="text-xs text-muted-foreground">{event.actor} · <time dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleString()}</time></span>
              </li>
            ))}
          </ol>}
        </div>
      </details>
    </div>
  );
}

function StageContent(props: {
  stage: AgentStage;
  staticStage?: AgentStage;
  openRecord: (role: string, id: string) => void;
  approvals: Approval[];
  notes: Record<string, string>;
  setNote: (id: string, value: string) => void;
  evidenceDrafts: Record<string, string>;
  setEvidenceJson: (id: string, value: string) => void;
  decide: (id: string, decision: "approved" | "rejected") => void;
  importEvidence: (id: string) => void;
  acting: boolean;
}) {
  const { stage } = props;
  if (stage.role === "static") return <ReachabilityPanel traces={stage.reachability} />;
  if (stage.role === "dynamic") return <DynamicPanel {...props} />;
  if (stage.role === "cve") return <CvePanel assessments={stage.cveAssessments} />;
  if (stage.role === "steward") return <ImprovementPanel proposals={stage.improvementProposals} />;
  if (stage.role === "synthesis") return <SynthesisPanel facts={stage.facts} staticStage={props.staticStage} openRecord={props.openRecord} />;
  return <SurfacePanel facts={stage.facts} />;
}

const jumpClass = "inline-flex min-h-11 max-w-full items-center gap-1.5 rounded-sm text-left text-sm font-medium text-primary underline decoration-primary/35 underline-offset-4 hover:decoration-current focus-visible:outline-2 focus-visible:outline-ring";
const stageHeadingId = (stage: AgentStage) => `stage-heading-${stage.id}`;
const referenceId = (stage: AgentStage, ref: string) => `stage-reference-${encodeURIComponent(stage.id)}:${encodeURIComponent(ref)}`;
const traceId = (findingId: string) => `code-path-${encodeURIComponent(findingId)}`;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? [...new Set(value.filter((item): item is string => typeof item === "string" && !!item.trim()))] : [];
}

function GapList({ gaps, label }: { gaps: string[]; label: string }) {
  if (!gaps.length) return null;
  return <div className="mt-3 border-l-2 border-[var(--severity-medium)] pl-3">
    <p className="text-xs font-semibold">{label}</p>
    <ul className="mt-1 list-disc space-y-1 pl-4 text-sm leading-5 [overflow-wrap:anywhere]">
      {gaps.map((gap) => <li key={gap}>{gap}</li>)}
    </ul>
  </div>;
}

function ReviewHandoff({ value, stages, openRecord }: {
  value: unknown;
  stages: AgentStage[];
  openRecord: (role: string, id: string) => void;
}) {
  if (!record(value) || value.version !== 1 || !Array.isArray(value.inputs)) return null;
  const inputs = value.inputs.filter((input): input is Record<string, unknown> =>
    record(input) && (input.role === "surface" || input.role === "static") && typeof input.status === "string");
  const gaps = strings(value.gaps);
  if (!inputs.length && !gaps.length) return null;
  return <section aria-label="Review handoff" className="rounded-md border bg-muted/20 px-4 py-3">
    <h3 className="text-base font-semibold tracking-tight">Review handoff</h3>
    <ul aria-label="Source stages" className="mt-1 divide-y">
      {inputs.map((input, index) => {
        const role = String(input.role);
        const source = stages.find((item) => item.role === role);
        const refs = strings(input.evidenceIds);
        const omitted = typeof input.omittedEvidence === "number" && Number.isSafeInteger(input.omittedEvidence) && input.omittedEvidence > 0 ? input.omittedEvidence : 0;
        return <li key={role + index} className="py-1">
          <div className="flex flex-wrap items-center justify-between gap-x-3">
            {source
              ? <button type="button" className={jumpClass} onClick={() => openRecord(role, stageHeadingId(source))}>
                  {ROLE_LABEL[role]} <ArrowUpRight aria-hidden className="size-3.5" />
                </button>
              : <span className="py-2 text-sm font-medium">{ROLE_LABEL[role]}</span>}
            <RunState status={String(input.status)} />
          </div>
          {refs.length > 0 && <details className="text-xs">
            <summary className="w-fit max-w-full cursor-pointer rounded-sm py-3 font-medium focus-visible:outline-2 focus-visible:outline-ring">
              {refs.length} cited {refs.length === 1 ? "reference" : "references"}
            </summary>
            <ul className="pb-2 font-mono">
              {refs.map((ref) => <li key={ref}>
                {source?.evidenceIds.includes(ref)
                  ? <button type="button" className={`${jumpClass} break-all text-xs`} onClick={() => openRecord(role, referenceId(source, ref))}>{ref}<ArrowUpRight aria-hidden className="size-3 shrink-0" /></button>
                  : <span className="block break-all py-1">{ref}</span>}
              </li>)}
            </ul>
          </details>}
          {!refs.length && <p className="pb-2 text-xs text-muted-foreground">No cited references.</p>}
          {omitted > 0 && <p className="pb-2 text-xs text-muted-foreground">{omitted} additional {omitted === 1 ? "reference" : "references"} omitted from the handoff.</p>}
        </li>;
      })}
    </ul>
    <GapList gaps={gaps} label="Unresolved evidence" />
  </section>;
}

function SurfacePanel({ facts }: { facts: Record<string, unknown> }) {
  const scenarios = Array.isArray(facts.threatScenarios) ? facts.threatScenarios.filter(record) : [];
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-x-5 gap-y-4 border-b pb-5 lg:grid-cols-4">
        <Fact label="Endpoints" value={facts.endpoints} />
        <Fact label="Without auth evidence" value={facts.endpointsWithoutDetectedAuth} />
        <Fact label="Gateway exposed" value={facts.gatewayExposed} />
        <Fact label="Observed at runtime" value={facts.runtimeObserved} />
      </div>
      <div>
        <h3 className="text-sm font-semibold">Endpoint evidence</h3>
        {scenarios.length ? <ul className="mt-2 divide-y border-t">
          {scenarios.map((scenario, index) => (
            <li key={`${scenario.surface}-${index}`} className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 py-3">
              <div className="min-w-0">
                <p className="break-all font-mono text-xs">{String(scenario.surface ?? "Unknown endpoint")}</p>
                {typeof scenario.trustBoundary === "string" && <p className="mt-1 break-words text-xs text-muted-foreground">Trust boundary · {scenario.trustBoundary}</p>}
              </div>
              <span className="text-xs text-muted-foreground">{typeof scenario.auth === "string" && `Auth · ${scenario.auth.replaceAll("_", " ")}`}{scenario.runtimeObserved === true && (scenario.auth ? " · Observed at runtime" : "Observed at runtime")}</span>
            </li>
          ))}
        </ul> : <Empty text="No endpoint evidence was recorded." />}
      </div>
    </div>
  );
}

function ReachabilityPanel({ traces }: { traces: Reachability[] }) {
  return (
    <div className="space-y-6">
      {traces.map((trace) => (
        <div key={trace.findingId} id={traceId(trace.findingId)} tabIndex={-1} className="min-w-0 overflow-hidden rounded-md border focus-visible:outline-2 focus-visible:outline-ring">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b bg-muted/25 px-4 py-3">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <Network aria-hidden className="size-4 shrink-0 text-muted-foreground" />
              <span className="break-all font-mono text-xs">{trace.findingId}</span>
              <PathState trace={trace} />
            </div>
            <span className="break-all font-mono text-xs text-muted-foreground">{trace.method} {trace.endpoint || "unresolved endpoint"}</span>
          </div>
          <div className="p-4">
            <ol aria-label="Recorded code path" className="ml-1 border-l">
              <FlowStep label={trace.entryPoint || "Unknown entry"} caption="Entry point" />
              {trace.hops.map((hop, index) => (
                <FlowStep key={`${hop.function}-${index}`} label={hop.function} caption={`${hop.filePath}:${hop.line}`} />
              ))}
              <FlowStep label={trace.sink} caption="Sink" />
            </ol>
            {trace.unresolvedLinks.length > 0 && (
              <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/5 p-3">
                <p className="flex items-center gap-2 text-xs font-medium text-amber-700 dark:text-amber-300"><AlertTriangle className="h-3.5 w-3.5" />Unresolved links</p>
                <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-muted-foreground">
                  {trace.unresolvedLinks.map((gap) => <li key={gap}>{gap}</li>)}
                </ul>
              </div>
            )}
            {trace.hops.some((hop) => hop.snippet) && (
              <div className="mt-4">
                <div className="mb-2 flex items-center gap-2 text-xs font-semibold"><Code2 className="h-3.5 w-3.5" />Source excerpt</div>
                {trace.hops.filter((hop) => hop.snippet).slice(-1).map((hop) => (
                  <div key={`${hop.filePath}:${hop.line}`}>
                    <CodeHighlight
                      code={hop.snippet}
                      filePath={hop.filePath}
                      lineStart={hop.snippet.includes("\n") ? null : hop.line > 0 ? hop.line : null}
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
      {traces.length === 0 && <Empty text="No findings are available for reachability review." />}
    </div>
  );
}

function DynamicPanel(props: Parameters<typeof StageContent>[0]) {
  const { stage, approvals, notes, setNote, evidenceDrafts, setEvidenceJson, decide, importEvidence, acting } = props;
  return (
    <div className="space-y-4">
      {stage.dynamicPlans.map((plan) => {
        const approval = approvals.find((item) => item.resourceId === plan.id);
        const note = approval ? notes[approval.id] || "" : "";
        const evidenceJson = approval ? evidenceDrafts[approval.id] || "" : "";
        return (
          <div key={plan.id} className="rounded-md border p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="flex items-center gap-2 text-sm font-semibold"><PlayCircle className="size-4 text-muted-foreground" />{plan.requestTemplate}</p>
                <p className="mt-1 text-xs text-muted-foreground">{plan.targetScope} · {plan.targetOrigin} · {plan.harness}</p>
              </div>
              <RunState status={approval?.status || "pending"} />
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <Fact label="Safe payload" value={plan.payloadTemplate} mono />
              <Fact label="Expected signal" value={plan.expectedSignal} />
              <Fact label="Negative control" value={plan.negativeControl} />
              <Fact label="Scope digest" value={`${approval?.scopeDigest.slice(0, 28) || ""}…`} mono />
            </div>
            {approval?.status === "pending" && (
              <div className="mt-4 border-t pt-3">
                <label htmlFor={`note-${approval.id}`} className="text-sm font-medium">Approval scope and fixture ownership</label>
                <textarea
                  id={`note-${approval.id}`}
                  value={note}
                  onChange={(event) => setNote(approval.id, event.target.value)}
                  placeholder="Example: owned local fixture, test data only, remove the container after validation"
                  className="mt-2 min-h-20 w-full rounded-lg border bg-background p-2 text-xs outline-none focus:border-primary"
                />
                <div className="mt-2 flex gap-2">
                  <Button size="sm" onClick={() => decide(approval.id, "approved")} disabled={acting || note.trim().length < 8}><Check className="mr-1 h-3.5 w-3.5" />Approve fixture run</Button>
                  <Button size="sm" variant="outline" onClick={() => decide(approval.id, "rejected")} disabled={acting}><X className="mr-1 h-3.5 w-3.5" />Reject</Button>
                </div>
              </div>
            )}
            {approval?.status === "approved" && (
              <div className="mt-4 border-t pt-3">
                <label htmlFor={`evidence-${approval.id}`} className="flex items-center gap-2 text-sm font-medium"><FileJson className="h-3.5 w-3.5" />Aegify harness evidence JSON</label>
                <p className="mt-1 text-[10px] text-muted-foreground">Bind the approved scope digest below to the recorded harness output.</p>
                <textarea
                  id={`evidence-${approval.id}`}
                  value={evidenceJson}
                  onChange={(event) => setEvidenceJson(approval.id, event.target.value)}
                  placeholder={`{"contract_version":1,"executed":true,"approval_scope_sha256":"${approval.scopeDigest}",...}`}
                  className="mt-2 min-h-32 w-full rounded-lg border bg-[#0d1117] p-3 font-mono text-xs text-slate-200 outline-none focus:border-primary"
                />
                <Button size="sm" className="mt-2" onClick={() => importEvidence(approval.id)} disabled={acting || !evidenceJson.trim()}><Upload className="mr-1 h-3.5 w-3.5" />Verify &amp; import evidence</Button>
              </div>
            )}
          </div>
        );
      })}
      {stage.dynamicPlans.length === 0 && <Empty text="No unobserved static paths require an additional validation plan." />}
    </div>
  );
}

function CvePanel({ assessments }: { assessments: Array<Record<string, unknown>> }) {
  return assessments.length === 0 ? <Empty text="No CVE candidates were supplied. Candidates can be included through the API or CLI." /> : (
    <div className="space-y-3">
      {assessments.map((item) => (
        <div key={String(item.cveId)} className="border-b pb-4 last:border-0">
          <div className="flex items-center justify-between gap-3">
            <p className="font-mono text-sm font-semibold">{String(item.cveId)}</p>
            <RunState status={String(item.applicability)} />
          </div>
          <p className="mt-2 text-sm text-muted-foreground">{String(item.rationale)}</p>
          {Array.isArray(item.missingEvidence) && item.missingEvidence.length > 0 && <p className="mt-2 text-xs text-amber-600">Missing: {item.missingEvidence.join(", ")}</p>}
        </div>
      ))}
    </div>
  );
}

function ImprovementPanel({ proposals }: { proposals: Array<Record<string, unknown>> }) {
  return proposals.length === 0 ? <Empty text="No new improvement proposals were generated for this run." /> : (
    <div className="divide-y border-t">
      {proposals.map((item) => (
        <div key={String(item.id)} className="py-4">
          <h3 className="text-sm font-semibold">{String(item.title)}</h3>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{String(item.hypothesis)}</p>
          <div className="mt-3 text-xs">Target metric · {String(item.targetMetric)}</div>
          <p className="mt-2 text-xs text-muted-foreground">Minimum {String(item.minimumSamples)} samples · Requires review</p>
        </div>
      ))}
    </div>
  );
}

function SynthesisPanel({ facts, staticStage, openRecord }: {
  facts: Record<string, unknown>;
  staticStage?: AgentStage;
  openRecord: (role: string, id: string) => void;
}) {
  const findings = Array.isArray(facts.findings) ? facts.findings as Array<Record<string, unknown>> : [];
  return (
    <div className="space-y-3">
      {findings.map((finding) => (
        <div key={String(finding.findingId)} className="border-b pb-4 last:border-0 last:pb-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-semibold">{String(finding.ruleId)}</span>
            <RunState status={String(finding.severity)} />
            <RunState status={String(finding.likelihood)} />
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <Fact label="Attack surface" value={finding.attackSurface} mono />
            <Fact label="Code remediation" value={finding.remediation} />
          </div>
          <GapList gaps={strings(finding.preconditions)} label="Open preconditions" />
          {typeof finding.findingId === "string" && staticStage?.reachability.some((item) => item.findingId === finding.findingId) && (
            <button type="button" className={jumpClass} onClick={() => openRecord("static", traceId(String(finding.findingId)))}>
              Review code path <ArrowUpRight aria-hidden className="size-3.5" />
            </button>
          )}
        </div>
      ))}
      {findings.length === 0 && <Empty text="No findings are available to synthesize." />}
    </div>
  );
}

function FlowStep({ label, caption }: { label: string; caption: string }) {
  return <li className="relative pb-3 pl-4 last:pb-0">
    <span aria-hidden className="absolute -left-1 top-1.5 size-2 rounded-full border border-primary bg-card" />
    <p className="break-all font-mono text-sm">{label}</p>
    <p className="mt-0.5 break-all text-xs text-muted-foreground">{caption}</p>
  </li>;
}

function PathState({ trace }: { trace: Reachability }) {
  const label = trace.impactProven ? "verified impact" : trace.runtimeObserved ? "observed at runtime" : trace.staticComplete ? "statically reachable" : "partial path";
  return <RunState status={label} />;
}

function Fact({ label, value, mono }: { label: string; value: unknown; mono?: boolean }) {
  const display = typeof value === "boolean" ? (value ? "Yes" : "No") : String(value ?? "—");
  return <dl className="min-w-0">
    <dt className="text-xs text-muted-foreground">{label}</dt>
    <dd className={`mt-1 break-words text-sm ${mono ? "break-all font-mono" : "font-medium"}`}>{display}</dd>
  </dl>;
}

function StageIcon({ status }: { status: string }) {
  if (status === "completed") return <CheckCircle2 aria-hidden className="size-4 text-primary" />;
  if (status === "waiting_approval") return <KeyRound aria-hidden className="size-4 text-[var(--severity-medium)]" />;
  if (status === "partial") return <AlertTriangle aria-hidden className="size-4 text-[var(--severity-medium)]" />;
  if (status === "failed") return <AlertTriangle aria-hidden className="size-4 text-destructive" />;
  return <CircleDashed aria-hidden className="size-4 text-muted-foreground" />;
}

function RunState({ status }: { status: string }) {
  const words = status.replaceAll("_", " ");
  const label = words.charAt(0).toUpperCase() + words.slice(1);
  const color = /failed|rejected|critical|error/.test(status) ? "text-destructive"
    : /waiting|pending|partial/.test(status) ? "text-[var(--severity-medium)]"
    : /completed|passed|proven|observed/.test(status) ? "text-primary"
    : "text-muted-foreground";
  return <span className={`inline-flex items-center gap-1.5 whitespace-nowrap text-xs ${color}`}>
    <span aria-hidden className="size-1.5 rounded-full bg-current" />{label}
  </span>;
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="grid grid-cols-[6rem_minmax(0,1fr)] items-baseline gap-x-3">
    <dt className="text-muted-foreground">{label}</dt>
    <dd className={mono ? "break-all font-mono" : "break-words"}>{value}</dd>
  </div>;
}

function Empty({ text }: { text: string }) {
  return <p className="py-4 text-sm text-muted-foreground">{text}</p>;
}
