import { randomUUID } from "node:crypto";
import type { Prisma, PrismaClient, ScanJob } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { AccessDenied, authorizeProject, resolvePrincipal, type AccessPrincipal } from "./project-access.ts";
import type { ImportReceipt } from "./sarif-import.ts";
import { writeTransaction } from "./database-runtime.ts";

export const LEASE_MS = 120_000;
export const JOB_DEADLINE_MS = 15 * 60_000;
export const jobMetadata = {
  id: true, scanId: true, projectId: true, requestedRef: true, commitSha: true,
  sourceDigest: true, resultDigest: true, resultManifest: true, status: true, attempts: true, maxAttempts: true,
  heartbeatAt: true, nextAttemptAt: true, errorCode: true, createdAt: true, completedAt: true,
} as const;
export class LeaseLost extends Error {}
export const jobMessages: Record<string, string> = {
  queued: "Waiting for a scan worker",
  running: "Worker is analyzing an immutable source snapshot",
  retrying: "Worker interrupted; retry scheduled with the same pinned source",
  cancelled: "Scan cancelled",
  authorization_lost: "Scan permission or repository connection changed",
  attempts_exhausted: "Worker recovery attempts exhausted; start a new scan to retry",
  fetch_failed: "Repository source could not be fetched; check the requesting account's connection",
  scanner_failed: "The scanner did not produce a complete report",
  deadline_exceeded: "The scan exceeded its 15 minute budget",
  publication_failed: "Evidence publication failed; previous findings were preserved",
};

export async function enqueueScan(db: PrismaClient, access: AccessPrincipal, projectId: string, ref: string, env: AuthEnvironment, pinnedCommit = "") {
  if (!access.userId) throw new AccessDenied(401, "Sign in with a connected repository account.");
  if (!/^[A-Za-z0-9._/-]{1,255}$/.test(ref) || ref.includes("..")) throw new AccessDenied(400, "Invalid branch or ref.");
  if (pinnedCommit && !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i.test(pinnedCommit)) throw new AccessDenied(400, "Invalid pinned commit.");
  return writeTransaction(db, async (tx) => {
    const current = await resolvePrincipal(tx, access.userId || undefined, env);
    const allowed = await authorizeProject(tx, current, projectId, "maintainer");
    if (allowed.archived) throw new AccessDenied(409, "Restore the project before scanning.");
    const project = await tx.project.findUniqueOrThrow({ where: { id: projectId } });
    if (!["github", "gitlab"].includes(project.provider) || !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/.test(project.ownerSlug) || project.ownerSlug.split("/").some((part) => part === "." || part === "..")) throw new AccessDenied(400, "Connect a supported repository first.");
    const account = await tx.account.findFirst({ where: { userId: access.userId!, provider: project.provider }, select: { id: true, access_token: true } });
    if (!account?.access_token) throw new AccessDenied(400, "Connect your repository account before scanning.");
    const activeKey = `sast:${projectId}`;
    const active = await tx.scanJob.findUnique({ where: { activeKey }, select: jobMetadata });
    if (active) return { ...active, alreadyQueued: true };
    const scan = await tx.scan.create({ data: { projectId, repository: project.ownerSlug, branch: ref, commitSha: pinnedCommit, status: "pending", scanType: "sast", progressPhaseName: "queued", progressMessage: jobMessages.queued, progressUpdatedAt: new Date() } });
    const job = await tx.scanJob.create({ data: {
      scanId: scan.id, projectId, requestedBy: access.userId!, provider: project.provider,
      ownerSlug: project.ownerSlug, providerRepoId: project.providerRepoId, requestedRef: ref, commitSha: pinnedCommit, activeKey,
      events: { create: { code: "queued", message: jobMessages.queued } },
    }, select: jobMetadata });
    await tx.auditEvent.create({ data: { projectId, actorId: access.userId!, action: "scan.job.queued", targetId: job.id } });
    return { ...job, alreadyQueued: false };
  });
}

export async function assertJobPermission(tx: Prisma.TransactionClient, job: Pick<ScanJob, "projectId" | "requestedBy" | "provider" | "ownerSlug" | "providerRepoId">, env: AuthEnvironment): Promise<void> {
  const access = await resolvePrincipal(tx, job.requestedBy, env);
  const allowed = await authorizeProject(tx, access, job.projectId, "maintainer");
  const project = await tx.project.findUnique({ where: { id: job.projectId }, select: { provider: true, ownerSlug: true, providerRepoId: true } });
  if (allowed.archived || !project || project.provider !== job.provider || project.ownerSlug !== job.ownerSlug || project.providerRepoId !== job.providerRepoId) throw new AccessDenied();
}

export async function assertJobLease(tx: Prisma.TransactionClient, job: Pick<ScanJob, "id" | "leaseToken">, env: AuthEnvironment, now = new Date()) {
  if (!job.leaseToken) throw new LeaseLost("No worker lease.");
  const current = await tx.scanJob.findFirst({ where: { id: job.id, leaseToken: job.leaseToken, status: "running", cancelRequestedAt: null, leaseExpiresAt: { gt: now } }, omit: { sourceCiphertext: true, sourceManifest: true } });
  if (!current) throw new LeaseLost("Worker lease expired or was replaced.");
  await assertJobPermission(tx, current, env);
  return current;
}

async function terminateJob(tx: Prisma.TransactionClient, job: Pick<ScanJob, "id" | "scanId" | "projectId">, status: "failed" | "cancelled", code: string, actor: string, now: Date) {
  await tx.scanJob.update({ where: { id: job.id }, data: { status, activeKey: null, leaseToken: null, leaseExpiresAt: null, completedAt: now, errorCode: code } });
  await tx.scan.update({ where: { id: job.scanId }, data: { status, progressPhaseName: status, progressMessage: jobMessages[code], progressUpdatedAt: now } });
  await tx.scanJobEvent.create({ data: { jobId: job.id, code, message: jobMessages[code] } });
  await tx.auditEvent.create({ data: { projectId: job.projectId, actorId: actor, action: `scan.job.${status}`, targetId: job.id, details: JSON.stringify({ code }) } });
}

/** SQLite serializes this transaction; the lease token fences every later write. */
export async function claimScanJob(db: PrismaClient, workerId: string, env: AuthEnvironment, now = new Date()): Promise<ScanJob | null> {
  return writeTransaction(db, async (tx) => {
    for (let skipped = 0; skipped < 20; skipped++) {
      const job = await tx.scanJob.findFirst({
        where: { OR: [{ status: "queued", nextAttemptAt: { lte: now } }, { status: "running", leaseExpiresAt: { lte: now } }] },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      });
      if (!job) return null;
      if (job.attempts >= job.maxAttempts) { await terminateJob(tx, job, "failed", "attempts_exhausted", workerId, now); continue; }
      try { await assertJobPermission(tx, job, env); }
      catch (error) {
        if (!(error instanceof AccessDenied)) throw error;
        await terminateJob(tx, job, "failed", "authorization_lost", workerId, now); continue;
      }
      const claimed = await tx.scanJob.update({ where: { id: job.id }, data: {
        status: "running", attempts: { increment: 1 }, leaseToken: randomUUID(), workerId,
        leaseExpiresAt: new Date(now.getTime() + LEASE_MS), heartbeatAt: now, errorCode: "",
      } });
      await tx.scan.update({ where: { id: job.scanId }, data: { status: "running", progressPhaseName: "starting", progressMessage: jobMessages.running, progressUpdatedAt: now } });
      await tx.scanJobEvent.create({ data: { jobId: job.id, code: job.attempts ? "recovered" : "claimed", message: job.attempts ? "A new worker recovered the interrupted scan" : "Worker claimed the scan", details: JSON.stringify({ attempt: claimed.attempts }) } });
      return claimed;
    }
    return null;
  }, { timeout: 10_000 });
}

export async function heartbeatScanJob(db: PrismaClient, job: ScanJob, env: AuthEnvironment, now = new Date()): Promise<void> {
  await writeTransaction(db, async (tx) => {
    await assertJobLease(tx, job, env, now);
    await tx.scanJob.update({ where: { id: job.id }, data: { heartbeatAt: now, leaseExpiresAt: new Date(now.getTime() + LEASE_MS) } });
  });
}

export async function failScanJob(db: PrismaClient, job: ScanJob, code: string, retryable: boolean, now = new Date()): Promise<void> {
  if (!(code in jobMessages)) code = "scanner_failed";
  await writeTransaction(db, async (tx) => {
    const current = await tx.scanJob.findFirst({ where: { id: job.id, leaseToken: job.leaseToken, status: "running", leaseExpiresAt: { gt: now } } });
    if (!current) return;
    if (retryable && current.attempts < current.maxAttempts) {
      await tx.scanJob.update({ where: { id: job.id }, data: { status: "queued", leaseToken: null, leaseExpiresAt: null, errorCode: code, nextAttemptAt: new Date(now.getTime() + 5000 * 2 ** (current.attempts - 1)) } });
      await tx.scan.update({ where: { id: job.scanId }, data: { status: "pending", progressPhaseName: "retrying", progressMessage: jobMessages.retrying, progressUpdatedAt: now } });
      await tx.scanJobEvent.create({ data: { jobId: job.id, code: "retrying", message: jobMessages.retrying, details: JSON.stringify({ code, attempt: current.attempts }) } });
    } else await terminateJob(tx, current, "failed", code, job.workerId, now);
  });
}

export async function completeScanJob(tx: Prisma.TransactionClient, job: ScanJob, receipt: ImportReceipt, resultDigest: string, env: AuthEnvironment, resultManifest = "{}"): Promise<void> {
  await assertJobLease(tx, job, env);
  if (receipt.scanId !== job.scanId) throw new LeaseLost("Scan publication does not match its job.");
  if (resultManifest.length > 256_000) throw new Error("Result manifest exceeds its limit.");
  await tx.scanJob.update({ where: { id: job.id }, data: { status: receipt.status, resultDigest, resultManifest, activeKey: null, leaseToken: null, leaseExpiresAt: null, completedAt: new Date() } });
  await tx.scanJobEvent.create({ data: { jobId: job.id, code: "published", message: "Scan evidence published", details: JSON.stringify({ status: receipt.status, findings: receipt.findingsCount, resultDigest }) } });
}

export async function cancelScanJob(db: PrismaClient, access: AccessPrincipal, jobId: string, env: AuthEnvironment): Promise<void> {
  await writeTransaction(db, async (tx) => {
    const job = await tx.scanJob.findUnique({ where: { id: jobId } });
    if (!job) throw new AccessDenied();
    const current = await resolvePrincipal(tx, access.userId || undefined, env);
    await authorizeProject(tx, current, job.projectId, "maintainer");
    if (!["queued", "running"].includes(job.status)) return;
    await tx.scanJob.update({ where: { id: job.id }, data: { cancelRequestedAt: new Date() } });
    await terminateJob(tx, job, "cancelled", "cancelled", current.userId || "development", new Date());
  });
}
