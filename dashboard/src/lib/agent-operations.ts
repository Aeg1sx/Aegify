import { Prisma } from "@prisma/client";

import {
  buildAgentBlueprint,
  CveInput,
  digest,
} from "@/lib/agent-contract";
import {
  validateHarnessEvidence,
} from "@/lib/agent-evidence";
import { prisma } from "@/lib/prisma";

export async function createSecurityAgentRun(
  scanId: string,
  mode: "lite" | "deep",
  cves: CveInput[],
) {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      findings: {
        select: {
          id: true,
          ruleId: true,
          severity: true,
          evidenceState: true,
          filePath: true,
          lineStart: true,
          message: true,
          remediation: true,
          evidenceId: true,
          callChain: true,
        },
      },
      endpoints: {
        select: {
          path: true,
          method: true,
          handlerFunction: true,
          filePath: true,
          framework: true,
          authRequired: true,
          calledByFrontend: true,
          exposedViaGateway: true,
          runtimeObserved: true,
        },
      },
    },
  });
  if (!scan) throw new Error("Scan not found");

  const blueprint = buildAgentBlueprint(scan, mode, cves);
  return prisma.$transaction(async (tx) => {
    const run = await tx.agentRun.create({
      data: {
        scanId,
        mode,
        provider: "deterministic",
        status: blueprint.status,
        currentRole: blueprint.status === "awaiting_approval" ? "dynamic" : "steward",
        workspaceSnapshot: scan.workspaceSnapshot,
        requestPayload: JSON.stringify({ mode, cves }),
        artifactDigest: blueprint.artifactDigest,
        completedAt: blueprint.status === "completed" ? new Date() : null,
      },
    });
    for (const stage of blueprint.stages) {
      await tx.agentStage.create({
        data: {
          runId: run.id,
          sequence: stage.sequence,
          role: stage.role,
          agentCode: stage.agentCode,
          agentName: stage.agentName,
          status: stage.status,
          summary: stage.summary,
          facts: JSON.stringify(stage.facts),
          evidenceIds: JSON.stringify(stage.evidenceIds),
          reachability: JSON.stringify(stage.reachability),
          dynamicPlans: JSON.stringify(stage.dynamicPlans),
          cveAssessments: JSON.stringify(stage.cveAssessments),
          improvementProposals: JSON.stringify(stage.improvementProposals),
          promptDigest: stage.promptDigest,
          completedAt: stage.status === "waiting_approval" ? null : new Date(),
        },
      });
      for (const plan of stage.dynamicPlans) {
        await tx.agentApproval.create({
          data: {
            runId: run.id,
            resourceId: plan.id,
            scopeDigest: digest(JSON.stringify(plan)),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1_000),
          },
        });
      }
    }
    await tx.agentEvent.create({
      data: {
        runId: run.id,
        type: "run_created",
        message: blueprint.status === "awaiting_approval"
          ? "Static analysis completed; dynamic plans require explicit approval."
          : "Agent workflow completed without a pending dynamic plan.",
        payload: JSON.stringify({ artifactDigest: blueprint.artifactDigest }),
      },
    });
    return tx.agentRun.findUniqueOrThrow({
      where: { id: run.id },
      include: runInclude,
    });
  });
}

export async function decideAgentApproval(
  runId: string,
  approvalId: string,
  decision: "approved" | "rejected",
  note: string,
  actor: string,
) {
  const now = new Date();
  return prisma.$transaction(async (tx) => {
    const current = await tx.agentApproval.findFirst({
      where: { id: approvalId, runId },
    });
    if (!current) throw new Error("Approval not found");
    if (current.status !== "pending") throw new Error("Approval was already decided");
    if (current.expiresAt && current.expiresAt <= now) {
      await tx.agentApproval.update({ where: { id: approvalId }, data: { status: "expired" } });
      throw new Error("Approval expired");
    }
    const updated = await tx.agentApproval.update({
      where: { id: approvalId },
      data: {
        status: decision,
        decidedBy: actor.slice(0, 200),
        decisionNote: note.slice(0, 2_000),
        decidedAt: now,
      },
    });
    await tx.agentEvent.create({
      data: {
        runId,
        type: `approval_${decision}`,
        actor: actor.slice(0, 200),
        message: decision === "approved"
          ? "Dynamic fixture execution was approved; signed harness evidence is still required."
          : "Dynamic validation plan was rejected.",
        payload: JSON.stringify({ approvalId, resourceId: current.resourceId }),
      },
    });
    if (decision === "approved") {
      await tx.agentRun.update({
        where: { id: runId },
        data: { status: "awaiting_evidence", currentRole: "dynamic" },
      });
    } else {
      await finalizeIfTerminal(tx, runId);
    }
    return updated;
  });
}

export async function ingestAgentEvidence(
  runId: string,
  approvalId: string,
  rawEvidence: unknown,
  actor: string,
) {
  const evidence = validateHarnessEvidence(rawEvidence);
  const canonical = canonicalJson(evidence);
  const evidenceDigest = digest(canonical);
  return prisma.$transaction(async (tx) => {
    const run = await tx.agentRun.findUnique({ where: { id: runId } });
    const approval = await tx.agentApproval.findFirst({
      where: { id: approvalId, runId },
    });
    if (!run || !approval) throw new Error("Run or approval not found");
    if (approval.status !== "approved") {
      throw new Error("Evidence requires an active approved plan");
    }
    if (evidence.approval_scope_sha256.replace(/^sha256:/, "")
      !== approval.scopeDigest.replace(/^sha256:/, "")) {
      throw new Error("Harness evidence does not match the approved plan scope");
    }
    if (run.workspaceSnapshot) {
      const expected = run.workspaceSnapshot.replace(/^sha256:/, "");
      const observed = evidence.workspace_sha256.replace(/^sha256:/, "");
      if (expected !== observed) throw new Error("Workspace evidence digest does not match the scan");
    }
    const record = await tx.agentEvidenceRecord.create({
      data: {
        runId,
        approvalId,
        kind: "dynamic_harness",
        producer: "aegify-verification-harness",
        status: evidence.status,
        digest: evidenceDigest,
        payload: canonical,
      },
    });
    await tx.agentApproval.update({
      where: { id: approvalId },
      data: { status: "consumed" },
    });
    await tx.agentEvent.create({
      data: {
        runId,
        type: "dynamic_evidence_imported",
        actor: actor.slice(0, 200),
        message: `Imported ${evidence.status} harness evidence for ${approval.resourceId}.`,
        payload: JSON.stringify({ approvalId, evidenceDigest }),
      },
    });
    await finalizeIfTerminal(tx, runId);
    return record;
  });
}

export async function getAgentRun(id: string) {
  return prisma.agentRun.findUnique({ where: { id }, include: runInclude });
}

export async function listAgentRuns(limit = 50) {
  return prisma.agentRun.findMany({
    orderBy: { createdAt: "desc" },
    take: Math.max(1, Math.min(limit, 100)),
    include: {
      scan: { select: { repository: true, branch: true, commitSha: true } },
      _count: { select: { approvals: true, evidence: true, stages: true } },
    },
  });
}

export function serializeAgentRun<T>(value: T): T {
  const copy = JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
  if (Array.isArray(copy.stages)) {
    copy.stages = copy.stages.map((raw) => {
      const stage = raw as Record<string, unknown>;
      for (const key of [
        "facts",
        "evidenceIds",
        "reachability",
        "dynamicPlans",
        "cveAssessments",
        "improvementProposals",
        "narrative",
      ]) {
        stage[key] = parseStoredJson(stage[key], key === "facts" || key === "narrative" ? {} : []);
      }
      return stage;
    });
  }
  if (Array.isArray(copy.events)) {
    copy.events = copy.events.map((raw) => {
      const event = raw as Record<string, unknown>;
      event.payload = parseStoredJson(event.payload, {});
      return event;
    });
  }
  return copy as T;
}

async function finalizeIfTerminal(tx: Prisma.TransactionClient, runId: string): Promise<void> {
  const approvals = await tx.agentApproval.findMany({ where: { runId } });
  if (approvals.some((item) => ["pending", "approved"].includes(item.status))) return;
  const evidence = await tx.agentEvidenceRecord.findMany({ where: { runId } });
  const hasFailed = evidence.some((item) => item.status !== "passed");
  const hasRejected = approvals.some((item) => ["rejected", "expired"].includes(item.status));
  const finalStatus = hasFailed || hasRejected ? "partial" : "completed";
  await tx.agentStage.updateMany({
    where: { runId, role: "dynamic" },
    data: {
      status: finalStatus,
      summary: hasFailed || hasRejected
        ? "Dynamic validation closed with rejected, expired, or non-passing evidence."
        : "Every approved dynamic plan has passing owned-fixture evidence.",
      completedAt: new Date(),
    },
  });
  await tx.agentRun.update({
    where: { id: runId },
    data: { status: finalStatus, currentRole: "steward", completedAt: new Date() },
  });
}

function parseStoredJson(value: unknown, fallback: unknown): unknown {
  if (typeof value !== "string") return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const runInclude = {
  scan: { select: { repository: true, branch: true, commitSha: true } },
  stages: { orderBy: { sequence: "asc" as const } },
  approvals: { orderBy: { requestedAt: "asc" as const } },
  events: { orderBy: { createdAt: "asc" as const } },
  evidence: { orderBy: { createdAt: "asc" as const } },
};
