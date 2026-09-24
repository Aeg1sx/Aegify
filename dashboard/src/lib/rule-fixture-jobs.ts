import { randomUUID } from "node:crypto";
import type { Prisma, PrismaClient, RuleFixtureJob } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { AccessDenied, authorizeProject, resolvePrincipal, type AccessPrincipal } from "./project-access.ts";
import { writeTransaction } from "./database-runtime.ts";
import { decrypt, encrypt } from "./crypto.ts";
import { FIXTURE_REPORT_BYTES, FIXTURE_RETENTION_MS, type FixtureInput, type FixtureReport } from "./rule-fixture-contract.ts";
import { encodeFixtureInput, fixtureDigest, fixtureInput, restoreFixtureInput } from "./rule-fixture-input.ts";

const LEASE_MS = 60_000;
const activeStatuses = ["queued", "running"];
export const fixtureJobMetadata = {
  id: true, projectId: true, contractVersion: true, inputDigest: true, resultDigest: true,
  status: true, outcome: true, attempts: true, maxAttempts: true, errorCode: true,
  heartbeatAt: true, createdAt: true, completedAt: true, expiresAt: true,
} as const;
export class FixtureLeaseLost extends Error {}
const messages: Record<string, string> = {
  queued: "Waiting for a rule fixture worker",
  claimed: "Worker is evaluating the submitted rule and source examples",
  recovered: "A new worker recovered the same saved input",
  completed: "Rule fixture report saved",
  cancelled: "Rule evaluation cancelled",
  retrying: "Worker interrupted; the same saved input is queued again",
  authorization_lost: "Project permission changed or the project was archived",
  attempts_exhausted: "Worker recovery attempts exhausted",
  deadline_exceeded: "Rule evaluation exceeded its 30 second budget",
  worker_failed: "The worker could not produce a valid report",
  input_unavailable: "Saved input could not be verified",
  expired: "Saved fixture input and report reached their seven day retention limit",
};
function metadata(job: RuleFixtureJob) {
  return Object.fromEntries(Object.keys(fixtureJobMetadata).map((key) => [key, job[key as keyof RuleFixtureJob]]));
}
async function permission(tx: Prisma.TransactionClient, job: Pick<RuleFixtureJob, "projectId" | "requestedBy">, env: AuthEnvironment) {
  const principal = await resolvePrincipal(tx, job.requestedBy, env);
  if ((await authorizeProject(tx, principal, job.projectId, "maintainer")).archived) throw new AccessDenied();
}
async function terminal(tx: Prisma.TransactionClient, job: Pick<RuleFixtureJob, "id" | "projectId">, status: "failed" | "cancelled", code: string, actorId: string, now: Date) {
  await tx.ruleFixtureJob.update({ where: { id: job.id }, data: { status, errorCode: code, activeKey: null, leaseToken: null, leaseExpiresAt: null, completedAt: now } });
  await tx.ruleFixtureJobEvent.create({ data: { jobId: job.id, code, message: messages[code] } });
  await tx.auditEvent.create({ data: { projectId: job.projectId, actorId, action: `rule.fixture.${status}`, targetId: job.id, details: JSON.stringify({ code }) } });
}
export async function enqueueRuleFixture(db: PrismaClient, access: AccessPrincipal, projectId: string, value: unknown, env: AuthEnvironment, now = new Date()) {
  if (!access.userId) throw new AccessDenied(401, "Sign in before evaluating a rule.");
  const input = fixtureInput(value);
  const material = encodeFixtureInput(input);
  const inputDigest = fixtureDigest(material);
  return writeTransaction(db, async (tx) => {
    const current = await resolvePrincipal(tx, access.userId!, env);
    if ((await authorizeProject(tx, current, projectId, "maintainer")).archived) throw new AccessDenied(409, "Restore the project before evaluating a rule.");
    const active = await tx.ruleFixtureJob.findUnique({ where: { activeKey: projectId }, select: fixtureJobMetadata });
    if (active) {
      if (active.inputDigest !== inputDigest) throw new AccessDenied(409, "This project already has an active rule evaluation. Wait or cancel it first.");
      return { ...active, alreadyQueued: true };
    }
    const recent = await tx.ruleFixtureJob.count({ where: { requestedBy: access.userId!, createdAt: { gt: new Date(now.getTime() - 3_600_000) } } });
    const retained = await tx.ruleFixtureJob.count({ where: { projectId, expiresAt: { gt: now } } });
    const activeCount = await tx.ruleFixtureJob.count({ where: { status: { in: activeStatuses } } });
    if (recent >= 10 || retained >= 25 || activeCount >= 16) throw new AccessDenied(429, "Rule evaluation capacity reached: 10 new jobs per user per hour, 25 retained jobs per project, and 16 active jobs per installation.");
    const job = await tx.ruleFixtureJob.create({ data: {
      projectId, requestedBy: access.userId!, activeKey: projectId, inputDigest,
      inputCiphertext: encrypt(material, env.ENCRYPTION_SECRET), expiresAt: new Date(now.getTime() + FIXTURE_RETENTION_MS),
      events: { create: { code: "queued", message: messages.queued } },
    }, select: fixtureJobMetadata });
    await tx.auditEvent.create({ data: { projectId, actorId: access.userId!, action: "rule.fixture.queued", targetId: job.id, details: JSON.stringify({ inputDigest }) } });
    return { ...job, alreadyQueued: false };
  });
}
export async function assertFixtureLease(tx: Prisma.TransactionClient, job: Pick<RuleFixtureJob, "id" | "leaseToken">, env: AuthEnvironment, now = new Date()) {
  if (!job.leaseToken) throw new FixtureLeaseLost();
  const current = await tx.ruleFixtureJob.findFirst({ where: { id: job.id, leaseToken: job.leaseToken, status: "running", leaseExpiresAt: { gt: now }, expiresAt: { gt: now } }, omit: { inputCiphertext: true, resultCiphertext: true } });
  if (!current) throw new FixtureLeaseLost();
  await permission(tx, current, env);
  return current;
}
export async function claimRuleFixture(db: PrismaClient, workerId: string, env: AuthEnvironment, now = new Date()): Promise<RuleFixtureJob | null> {
  return writeTransaction(db, async (tx) => {
    for (let skipped = 0; skipped < 20; skipped++) {
      const job = await tx.ruleFixtureJob.findFirst({ where: { OR: [{ status: "queued", nextAttemptAt: { lte: now } }, { status: "running", leaseExpiresAt: { lte: now } }] }, orderBy: [{ createdAt: "asc" }, { id: "asc" }] });
      if (!job) return null;
      const code = job.expiresAt <= now ? "expired" : job.attempts >= job.maxAttempts ? "attempts_exhausted" : null;
      if (code) { await terminal(tx, job, "failed", code, workerId, now); continue; }
      try { await permission(tx, job, env); }
      catch (error) {
        if (!(error instanceof AccessDenied)) throw error;
        await terminal(tx, job, "failed", "authorization_lost", workerId, now); continue;
      }
      const claimed = await tx.ruleFixtureJob.update({ where: { id: job.id }, data: { status: "running", attempts: { increment: 1 }, workerId, leaseToken: randomUUID(), leaseExpiresAt: new Date(now.getTime() + LEASE_MS), heartbeatAt: now, errorCode: "" } });
      const eventCode = job.attempts ? "recovered" : "claimed";
      await tx.ruleFixtureJobEvent.create({ data: { jobId: job.id, code: eventCode, message: messages[eventCode] } });
      return claimed;
    }
    return null;
  }, { timeout: 10_000 });
}
export async function heartbeatRuleFixture(db: PrismaClient, job: RuleFixtureJob, env: AuthEnvironment, now = new Date()) {
  await writeTransaction(db, async (tx) => {
    await assertFixtureLease(tx, job, env, now);
    await tx.ruleFixtureJob.update({ where: { id: job.id }, data: { heartbeatAt: now, leaseExpiresAt: new Date(now.getTime() + LEASE_MS) } });
  });
}
export async function failRuleFixture(db: PrismaClient, job: RuleFixtureJob, code: string, retryable = false, now = new Date()) {
  if (!job.leaseToken) return;
  if (!(code in messages)) code = "worker_failed";
  await writeTransaction(db, async (tx) => {
    const current = await tx.ruleFixtureJob.findFirst({ where: { id: job.id, leaseToken: job.leaseToken, status: "running", leaseExpiresAt: { gt: now } } });
    if (!current) return;
    if (retryable && current.attempts < current.maxAttempts && current.expiresAt > now) {
      await tx.ruleFixtureJob.update({ where: { id: job.id }, data: { status: "queued", leaseToken: null, leaseExpiresAt: null, errorCode: code, nextAttemptAt: new Date(now.getTime() + 5000) } });
      await tx.ruleFixtureJobEvent.create({ data: { jobId: job.id, code: "retrying", message: messages.retrying } });
    } else await terminal(tx, current, "failed", code, job.workerId, now);
  });
}
export async function completeRuleFixture(db: PrismaClient, job: RuleFixtureJob, raw: string, report: FixtureReport, env: AuthEnvironment) {
  if (Buffer.byteLength(raw) > FIXTURE_REPORT_BYTES || JSON.parse(raw).status !== report.status) throw new Error("Fixture report invalid.");
  const resultDigest = fixtureDigest(raw);
  // The encrypted record binds both identities even if ciphertexts are swapped.
  const payload = JSON.stringify({ version: 1, jobId: job.id, inputDigest: job.inputDigest, reportJson: raw });
  const resultCiphertext = encrypt(payload, env.ENCRYPTION_SECRET);
  await writeTransaction(db, async (tx) => {
    const current = await assertFixtureLease(tx, job, env);
    if (current.inputDigest !== job.inputDigest || current.contractVersion !== 1) throw new FixtureLeaseLost();
    await tx.ruleFixtureJob.update({ where: { id: job.id }, data: { status: "completed", outcome: report.status, resultDigest, resultCiphertext, activeKey: null, leaseToken: null, leaseExpiresAt: null, completedAt: new Date() } });
    await tx.ruleFixtureJobEvent.create({ data: { jobId: job.id, code: "completed", message: messages.completed } });
    await tx.auditEvent.create({ data: { projectId: job.projectId, actorId: `worker:${job.workerId}`, action: "rule.fixture.completed", targetId: job.id, details: JSON.stringify({ outcome: report.status, resultDigest }) } });
  });
}
async function authorized(tx: Prisma.TransactionClient, access: AccessPrincipal, projectId: string, env: AuthEnvironment, minimum: "viewer" | "maintainer" = "viewer") {
  const current = await resolvePrincipal(tx, access.userId || undefined, env);
  await authorizeProject(tx, current, projectId, minimum);
  return current;
}
export async function listRuleFixtures(db: PrismaClient, access: AccessPrincipal, projectId: string, env: AuthEnvironment) {
  return db.$transaction(async (tx) => {
    const current = await authorized(tx, access, projectId, env);
    const project = await tx.project.findUniqueOrThrow({ where: { id: projectId }, select: { name: true, archived: true } });
    let canManage = false;
    try { await authorizeProject(tx, current, projectId, "maintainer"); canManage = true; } catch (error) { if (!(error instanceof AccessDenied)) throw error; }
    const jobs = await tx.ruleFixtureJob.findMany({ where: { projectId }, select: fixtureJobMetadata, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 25 });
    const worker = await tx.scanWorker.findFirst({ where: { ruleFixturesVersion: 1, lastSeenAt: { gt: new Date(Date.now() - 45_000) } }, select: { id: true } });
    return { project, canManage, jobs, workerAvailable: Boolean(worker) };
  });
}
export async function readRuleFixture(db: PrismaClient, access: AccessPrincipal, projectId: string, jobId: string, env: AuthEnvironment, includeInput = false, now = new Date()) {
  return db.$transaction(async (tx) => {
    const current = await authorized(tx, access, projectId, env, includeInput ? "maintainer" : "viewer");
    const job = await tx.ruleFixtureJob.findFirst({ where: { id: jobId, projectId } });
    if (!job) throw new AccessDenied();
    let canManage = false;
    try { await authorizeProject(tx, current, projectId, "maintainer"); canManage = true; } catch (error) { if (!(error instanceof AccessDenied)) throw error; }
    const expired = job.expiresAt <= now;
    let report: FixtureReport | null = null;
    if (!expired && job.status === "completed" && (!job.resultCiphertext || !job.resultDigest)) throw new AccessDenied(409, "Saved report is unavailable before its retention deadline.");
    if (job.resultCiphertext && !expired) {
      try {
        // JSON wrapping can escape each report byte; reject oversized records
        // before decryption as well as after parsing.
        if (job.resultCiphertext.length > (FIXTURE_REPORT_BYTES * 2 + 1024) * 2 + 128) throw new Error();
        const saved = JSON.parse(decrypt(job.resultCiphertext, env.ENCRYPTION_SECRET));
        if (saved.version !== 1 || saved.jobId !== job.id || saved.inputDigest !== job.inputDigest || typeof saved.reportJson !== "string" || Buffer.byteLength(saved.reportJson) > FIXTURE_REPORT_BYTES || fixtureDigest(saved.reportJson) !== job.resultDigest) throw new Error();
        report = JSON.parse(saved.reportJson) as FixtureReport;
        if (report.status !== job.outcome || job.status !== "completed") throw new Error();
      } catch { throw new AccessDenied(409, "Saved report could not be verified. Check the encryption key and record integrity."); }
    }
    const events = await tx.ruleFixtureJobEvent.findMany({ where: { jobId }, select: { id: true, code: true, message: true, createdAt: true }, orderBy: { id: "asc" }, take: 30 });
    const input: FixtureInput | undefined = includeInput ? restoreFixtureInput(job, env.ENCRYPTION_SECRET, now) : undefined;
    return { job: metadata(job), report, expired, canManage, events, ...(input ? { input } : {}) };
  });
}
export async function cancelRuleFixture(db: PrismaClient, access: AccessPrincipal, projectId: string, jobId: string, env: AuthEnvironment) {
  await writeTransaction(db, async (tx) => {
    const current = await authorized(tx, access, projectId, env, "maintainer");
    const job = await tx.ruleFixtureJob.findFirst({ where: { id: jobId, projectId } });
    if (!job) throw new AccessDenied();
    if (activeStatuses.includes(job.status)) await terminal(tx, job, "cancelled", "cancelled", current.userId || "development", new Date());
  });
}
export async function expireRuleFixtures(db: PrismaClient, now = new Date()) {
  await writeTransaction(db, async (tx) => {
    const active = await tx.ruleFixtureJob.findMany({ where: { expiresAt: { lte: now }, status: { in: activeStatuses } }, take: 16 });
    for (const job of active) await terminal(tx, job, "failed", "expired", "retention", now);
    await tx.ruleFixtureJob.updateMany({ where: { expiresAt: { lte: now } }, data: { inputCiphertext: null, resultCiphertext: null } });
  });
}
