import { createHash } from "node:crypto";
import type { Finding, FindingIdentity, PrismaClient } from "@prisma/client";
import { writeTransaction } from "./database-runtime.ts";
import { AccessDenied, authorizeProject, resolvePrincipal, type AccessPrincipal } from "./project-access.ts";
import type { AuthEnvironment } from "./auth-policy.ts";

export const MANAGEMENT_FIELDS = ["owner", "dueAt", "priority", "tags", "ticketProvider", "ticketKey", "ticketUrl", "lastNotifiedAt"] as const;
type Management = Pick<Finding, typeof MANAGEMENT_FIELDS[number]>;
type Status = "open" | "triaged" | "confirmed" | "in_progress" | "false_positive" | "fixed" | "accepted_risk";
const STATUSES: readonly string[] = ["open", "triaged", "confirmed", "in_progress", "false_positive", "fixed", "accepted_risk"];

export class FindingWorkflowError extends Error {
  status: number;
  constructor(message: string, status = 400) { super(message); this.status = status; }
}

export function findingManagement(value: Management): Management {
  return { owner: value.owner, dueAt: value.dueAt, priority: value.priority, tags: value.tags,
    ticketProvider: value.ticketProvider, ticketKey: value.ticketKey, ticketUrl: value.ticketUrl, lastNotifiedAt: value.lastNotifiedAt };
}

export function findingWorkflow(finding: Finding, identity: FindingIdentity | null) {
  const saved = identity || finding;
  const management = findingManagement(saved);
  const version = identity ? `identity:${identity.id}:${identity.workflowRevision}`
    : `observation:${createHash("sha256").update(JSON.stringify([finding.id, finding.status, management])).digest("hex")}`;
  return { ...management, status: saved.status, version, scope: identity ? "identity" : "observation",
    needsReview: identity?.workflowNeedsReview || false, reason: identity?.triageReason || "",
    actor: identity?.triageActor || "", expiresAt: identity?.triageExpiresAt || null };
}

interface WorkflowPatch {
  expectedVersion: string;
  management: Partial<Pick<Management, "owner" | "dueAt" | "priority" | "tags">>;
  status?: Status;
  reason?: string;
  expiresAt?: Date | null;
  resolveWorkflowReview: boolean;
}

function dateField(value: unknown, label: string): Date | null {
  if (value === null || value === "") return null;
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}\.\d{3}Z)?$/.test(value)) throw new FindingWorkflowError(`Invalid ${label}.`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || (value.length === 10 ? date.toISOString().slice(0, 10) !== value : date.toISOString() !== value)) throw new FindingWorkflowError(`Invalid ${label}.`);
  return date;
}

export function parseFindingWorkflowPatch(body: Record<string, unknown> | null): WorkflowPatch {
  if (!body) throw new FindingWorkflowError("Provide a bounded JSON object.");
  const fields = new Set(["expectedVersion", "status", "reason", "expiresAt", "owner", "dueAt", "priority", "tags", "resolveWorkflowReview"]);
  if (Object.keys(body).some((field) => !fields.has(field))) throw new FindingWorkflowError("Unexpected workflow field.");
  if (typeof body.expectedVersion !== "string" || !body.expectedVersion || body.expectedVersion.length > 200) throw new FindingWorkflowError("Reload the finding and supply its current workflow version.");
  const patch: WorkflowPatch = { expectedVersion: body.expectedVersion, management: {}, resolveWorkflowReview: false };
  if (body.owner !== undefined) {
    if (typeof body.owner !== "string" || body.owner.length > 200 || /[\x00-\x1f]/.test(body.owner)) throw new FindingWorkflowError("Invalid owner or team.");
    patch.management.owner = body.owner.trim();
  }
  if (body.dueAt !== undefined) patch.management.dueAt = dateField(body.dueAt, "due date");
  if (body.priority !== undefined) {
    if (typeof body.priority !== "string" || !["", "p0", "p1", "p2", "p3"].includes(body.priority)) throw new FindingWorkflowError("Invalid priority.");
    patch.management.priority = body.priority;
  }
  if (body.tags !== undefined) {
    if (!Array.isArray(body.tags) || body.tags.length > 20 || body.tags.some((tag) => typeof tag !== "string" || tag.length > 50 || /[\x00-\x1f]/.test(tag))) throw new FindingWorkflowError("Use at most 20 tags of 50 characters each.");
    patch.management.tags = JSON.stringify([...new Set((body.tags as string[]).map((tag) => tag.trim()).filter(Boolean))]);
  }
  if (body.status !== undefined) {
    if (typeof body.status !== "string" || !STATUSES.includes(body.status)) throw new FindingWorkflowError("Invalid triage status.");
    patch.status = body.status as Status;
    if (body.reason !== undefined && (typeof body.reason !== "string" || body.reason.length > 4000)) throw new FindingWorkflowError("Use a rationale of at most 4,000 characters.");
    patch.reason = typeof body.reason === "string" ? body.reason.trim() : "";
    if (["false_positive", "accepted_risk"].includes(patch.status) && !patch.reason) throw new FindingWorkflowError("A rationale is required for this decision.");
    patch.expiresAt = body.expiresAt === undefined ? null : dateField(body.expiresAt, "triage expiry");
    if (patch.expiresAt && patch.expiresAt.getTime() <= Date.now()) throw new FindingWorkflowError("Triage expiry must be in the future.");
  } else if (body.reason !== undefined || body.expiresAt !== undefined) throw new FindingWorkflowError("Include the triage status when changing its rationale or expiry.");
  if (body.resolveWorkflowReview !== undefined && typeof body.resolveWorkflowReview !== "boolean") throw new FindingWorkflowError("Invalid assignment review choice.");
  patch.resolveWorkflowReview = body.resolveWorkflowReview === true;
  if (!patch.status && !Object.keys(patch.management).length) throw new FindingWorkflowError("Provide a triage or assignment change.");
  if (patch.resolveWorkflowReview && !Object.keys(patch.management).length) throw new FindingWorkflowError("Choose the reviewed assignment before resolving its conflict.");
  return patch;
}

/** Workflow and current observations move together; historical snapshots remain. */
export async function updateFindingWorkflow(db: PrismaClient, principal: AccessPrincipal, findingId: string,
  patch: WorkflowPatch, env: AuthEnvironment = process.env) {
  return writeTransaction(db, async (tx) => {
    const currentPrincipal = await resolvePrincipal(tx, principal.userId || undefined, env);
    const finding = await tx.finding.findUnique({ where: { id: findingId }, include: { scan: { select: { projectId: true } } } });
    if (!finding || (!finding.scan.projectId && !currentPrincipal.workspaceAdmin)) throw new AccessDenied();
    const projectId = finding.scan.projectId;
    if (projectId && (await authorizeProject(tx, currentPrincipal, projectId, "triager")).archived) throw new FindingWorkflowError("Archived projects are read only.", 409);
    const identity = finding.identityId ? await tx.findingIdentity.findFirst({ where: { id: finding.identityId, projectId: projectId || "" } }) : null;
    if (finding.identityId && !identity) throw new FindingWorkflowError("Finding history is unavailable; review its project linkage.", 409);
    const before = findingWorkflow(finding, identity);
    if (patch.expectedVersion !== before.version) throw new FindingWorkflowError("This finding was updated by another action. Reload it before saving.", 409);
    if (!identity && patch.expiresAt) throw new FindingWorkflowError("Time-bounded triage requires a default-branch finding identity.");
    const actorId = currentPrincipal.userId || "development";
    const actor = currentPrincipal.email || actorId;
    const occurrenceData = { ...patch.management, ...(patch.status ? { status: patch.status } : {}) };
    if (identity) {
      const changed = await tx.findingIdentity.updateMany({ where: { id: identity.id, projectId: identity.projectId, workflowRevision: identity.workflowRevision },
        data: { ...occurrenceData, workflowRevision: { increment: 1 },
          ...(patch.resolveWorkflowReview ? { workflowNeedsReview: false } : {}),
          ...(patch.status ? { triageReason: patch.reason, triageActor: actor, triageExpiresAt: patch.expiresAt } : {}),
        } });
      if (changed.count !== 1) throw new FindingWorkflowError("This finding changed while saving. Reload it before saving.", 409);
      await tx.finding.updateMany({ where: { identityId: identity.id, isCurrent: true, scan: { projectId } }, data: occurrenceData });
      if (patch.status) await tx.findingTriageEvent.create({ data: { identityId: identity.id, fromStatus: identity.status,
        toStatus: patch.status, reason: patch.reason, actor, expiresAt: patch.expiresAt } });
    } else await tx.finding.update({ where: { id: finding.id }, data: occurrenceData });
    const assignmentBefore = { owner: before.owner, dueAt: before.dueAt, priority: before.priority, tags: before.tags };
    await tx.auditEvent.create({ data: { projectId, actorId, action: "finding.workflow.updated", targetId: identity?.id || finding.id,
      details: JSON.stringify({ findingId, scope: before.scope, fields: Object.keys(occurrenceData),
        ...(patch.status ? { fromStatus: before.status, toStatus: patch.status, reason: patch.reason } : {}),
        ...(Object.keys(patch.management).length ? { assignment: { before: assignmentBefore, after: { ...assignmentBefore, ...patch.management } } } : {}),
        assignmentReviewed: patch.resolveWorkflowReview }),
    } });
    const updated = await tx.finding.findUniqueOrThrow({ where: { id: finding.id } });
    const updatedIdentity = identity ? await tx.findingIdentity.findUniqueOrThrow({ where: { id: identity.id } }) : null;
    return { ...updated, workflow: findingWorkflow(updated, updatedIdentity) };
  });
}

export async function prepareFindingTicket(db: PrismaClient, principal: AccessPrincipal, findingId: string, env: AuthEnvironment = process.env) {
  return writeTransaction(db, async (tx) => {
    const currentPrincipal = await resolvePrincipal(tx, principal.userId || undefined, env);
    const finding = await tx.finding.findUnique({ where: { id: findingId }, include: { scan: { select: { projectId: true, repository: true, branch: true, commitSha: true } } } });
    if (!finding || (!finding.scan.projectId && !currentPrincipal.workspaceAdmin)) throw new AccessDenied();
    if (finding.scan.projectId && (await authorizeProject(tx, currentPrincipal, finding.scan.projectId, "triager")).archived) throw new FindingWorkflowError("Archived projects are read only.", 409);
    const identity = finding.identityId ? await tx.findingIdentity.findFirst({ where: { id: finding.identityId, projectId: finding.scan.projectId || "" } }) : null;
    if (finding.identityId && !identity) throw new FindingWorkflowError("Finding history is unavailable; review its project linkage.", 409);
    return {
      finding: { ...finding, ...findingManagement(identity || finding) },
      context: { findingId, identityId: identity?.id || "", projectId: finding.scan.projectId, actorId: currentPrincipal.userId || "development" },
    };
  });
}

/** Record an already completed provider action even if its original linkage changed. */
export async function recordFindingTicket(db: PrismaClient,
  context: { findingId: string; identityId: string; projectId: string | null; actorId: string },
  issue: { key: string; url: string }): Promise<{ linked: boolean }> {
  let url: URL;
  try { url = new URL(issue.url); } catch { throw new FindingWorkflowError("Invalid ticket receipt."); }
  if (!/^[A-Z][A-Z0-9_]{1,19}-\d+$/.test(issue.key) || issue.url.length > 4096
    || url.protocol !== "https:" || url.username || url.password || url.search || url.hash
    || !url.pathname.endsWith(`/browse/${issue.key}`)) throw new FindingWorkflowError("Invalid ticket receipt.");
  return writeTransaction(db, async (tx) => {
    const project = context.projectId ? await tx.project.findUnique({ where: { id: context.projectId }, select: { id: true } }) : null;
    const identity = context.identityId ? await tx.findingIdentity.findFirst({ where: { id: context.identityId, projectId: context.projectId || "" } }) : null;
    const observation = !context.identityId ? await tx.finding.findFirst({ where: { id: context.findingId, scan: { projectId: context.projectId } } }) : null;
    const target = identity || observation;
    const linked = Boolean(target && (!target.ticketKey ||
      (target.ticketProvider === "jira" && target.ticketKey === issue.key && target.ticketUrl === issue.url)));
    if (linked && target) {
      const data = { ticketProvider: "jira", ticketKey: issue.key, ticketUrl: issue.url, lastNotifiedAt: new Date() };
      if (identity) {
        await tx.findingIdentity.update({ where: { id: identity.id }, data: { ...data, workflowRevision: { increment: 1 } } });
        await tx.finding.updateMany({ where: { identityId: identity.id, isCurrent: true, scan: { projectId: identity.projectId } }, data });
      } else await tx.finding.update({ where: { id: target.id }, data });
    }
    await tx.auditEvent.create({ data: { projectId: project?.id || null, actorId: context.actorId,
      action: linked ? "finding.ticket.recorded" : "finding.ticket.link_review_required", targetId: context.identityId || context.findingId,
      details: JSON.stringify({ findingId: context.findingId, projectId: context.projectId, ticketProvider: "jira", ticketKey: issue.key, ticketUrl: issue.url, linked }),
    } });
    return { linked };
  });
}
