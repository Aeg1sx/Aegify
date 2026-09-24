import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { findingWorkflow, parseFindingWorkflowPatch, prepareFindingTicket, recordFindingTicket, updateFindingWorkflow } from "./finding-workflow.ts";
import { resolvePrincipal } from "./project-access.ts";

const env = { NODE_ENV: "production", AUTH_SECRET: "synthetic", AUTH_ALLOWED_DOMAINS: "example.test" };
const migration = "20260924040000_finding_workflow";

async function database(run: (db: PrismaClient, sql: ReturnType<typeof createClient>, migrate: () => Promise<void>) => Promise<void>, legacy = false) {
  const directory = await mkdtemp(join(tmpdir(), "aegify-workflow-"));
  const url = "file:" + join(directory, "workflow.db");
  const sql = createClient({ url });
  const root = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  const migrations = (await readdir(root, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name));
  const apply = async (name: string) => { await sql.executeMultiple(await readFile(join(root, name, "migration.sql"), "utf8")); };
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  try {
    for (const entry of migrations) if (!legacy || entry.name < migration) await apply(entry.name);
    await run(db, sql, async () => { for (const entry of migrations) if (entry.name >= migration) await apply(entry.name); });
  } finally { sql.close(); await db.$disconnect(); await rm(directory, { recursive: true, force: true }); }
}

async function fixture(db: PrismaClient) {
  const user = await db.user.create({ data: { email: "reviewer@example.test" } });
  const project = await db.project.create({ data: { name: "Workflow", members: { create: { userId: user.id, role: "triager" } } } });
  const scan = await db.scan.create({ data: { projectId: project.id, branch: "main", status: "completed" } });
  const identity = await db.findingIdentity.create({ data: { projectId: project.id, ruleId: "DEMO", fingerprint: "synthetic-identity",
    repositoryId: "service", modulePath: "src/app.py", filePath: "src/app.py", lastSeenScanId: scan.id } });
  const data = { scanId: scan.id, identityId: identity.id, ruleId: "DEMO", ruleName: "Synthetic", severity: "low", filePath: "src/app.py", lineStart: 1, lineEnd: 1, message: "Fixture" };
  const first = await db.finding.create({ data });
  const duplicate = await db.finding.create({ data: { ...data, lineStart: 10, lineEnd: 10 } });
  const historicalScan = await db.scan.create({ data: { projectId: project.id, branch: "main", status: "completed", createdAt: new Date(0) } });
  const historical = await db.finding.create({ data: { ...data, scanId: historicalScan.id, isCurrent: false, owner: "Historical team" } });
  return { user, project, scan, identity, first, duplicate, historical, principal: await resolvePrincipal(db, user.id, env) };
}

test("workflow decisions and assignments update current observations atomically without rewriting history", async () => database(async (db, sql) => {
  const f = await fixture(db);
  const version = findingWorkflow(f.first, f.identity).version;
  const patch = parseFindingWorkflowPatch({ expectedVersion: version, status: "confirmed", reason: "Owned evidence reviewed",
    owner: "AppSec", dueAt: "2026-12-01", priority: "p1", tags: ["owned", "owned"] });
  const updated = await updateFindingWorkflow(db, f.principal, f.first.id, patch, env);
  assert.equal(updated.workflow.scope, "identity");
  assert.equal(updated.workflow.owner, "AppSec");
  assert.notEqual(updated.workflow.version, version);
  for (const id of [f.first.id, f.duplicate.id]) {
    const current = await db.finding.findUniqueOrThrow({ where: { id } });
    assert.equal(current.status, "confirmed"); assert.equal(current.owner, "AppSec");
    assert.deepEqual(JSON.parse(current.tags), ["owned"]);
  }
  assert.deepEqual(await db.finding.findUniqueOrThrow({ where: { id: f.historical.id } }), f.historical);
  assert.equal((await db.findingTriageEvent.findFirstOrThrow()).actor, "reviewer@example.test");
  assert.equal(await db.auditEvent.count({ where: { action: "finding.workflow.updated" } }), 1);
  const audit = await db.auditEvent.findFirstOrThrow({ where: { action: "finding.workflow.updated" } });
  const assignment = JSON.parse(audit.details).assignment;
  assert.equal(assignment.before.owner, "");
  assert.equal(assignment.after.owner, "AppSec");
  assert.equal(assignment.after.dueAt, "2026-12-01T00:00:00.000Z");
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.first.id, patch, env), { status: 409 });
  assert.equal(await db.auditEvent.count(), 1);
  await sql.executeMultiple("CREATE TRIGGER fail_workflow_audit BEFORE INSERT ON AuditEvent BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END;");
  const before = await db.findingIdentity.findUniqueOrThrow({ where: { id: f.identity.id } });
  const reassignment = parseFindingWorkflowPatch({ expectedVersion: updated.workflow.version, owner: "Service team" });
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.historical.id, reassignment, env));
  assert.deepEqual(await db.findingIdentity.findUniqueOrThrow({ where: { id: f.identity.id } }), before);
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: f.first.id } })).owner, "AppSec");
  await sql.executeMultiple("DROP TRIGGER fail_workflow_audit;");
  const throughHistory = await updateFindingWorkflow(db, f.principal, f.historical.id, reassignment, env);
  assert.equal(throughHistory.owner, "Historical team");
  assert.equal(throughHistory.workflow.owner, "Service team");
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: f.duplicate.id } })).owner, "Service team");
  assert.equal(await db.findingTriageEvent.count(), 1, "Assignment-only changes are not triage decisions");
}));

test("workflow mutation rechecks membership, admission, archive state and identity project linkage", async () => database(async (db) => {
  const f = await fixture(db);
  const patch = parseFindingWorkflowPatch({ expectedVersion: findingWorkflow(f.first, f.identity).version, owner: "Changed" });
  await db.projectMember.update({ where: { projectId_userId: { projectId: f.project.id, userId: f.user.id } }, data: { role: "viewer" } });
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.first.id, patch, env), { status: 404 });
  await db.projectMember.update({ where: { projectId_userId: { projectId: f.project.id, userId: f.user.id } }, data: { role: "triager" } });
  await db.user.update({ where: { id: f.user.id }, data: { disabled: true } });
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.first.id, patch, env), { status: 401 });
  await db.user.update({ where: { id: f.user.id }, data: { disabled: false } });
  await db.project.update({ where: { id: f.project.id }, data: { archived: true } });
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.first.id, patch, env), { status: 409 });
  await db.project.update({ where: { id: f.project.id }, data: { archived: false } });
  const other = await db.project.create({ data: { name: "Private sibling" } });
  await db.findingIdentity.update({ where: { id: f.identity.id }, data: { projectId: other.id } });
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.first.id, patch, env), { status: 409 });
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: f.first.id } })).owner, "");
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: f.identity.id } })).owner, "");
  assert.equal(await db.auditEvent.count(), 0);
}));

test("simultaneous workflow writers commit one decision and reject the stale competing update", async () => database(async (db) => {
  const f = await fixture(db);
  const expectedVersion = findingWorkflow(f.first, f.identity).version;
  const results = await Promise.allSettled(["First team", "Second team"].map((owner) =>
    updateFindingWorkflow(db, f.principal, f.first.id, parseFindingWorkflowPatch({ expectedVersion, owner }), env)));
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find((result) => result.status === "rejected");
  assert.equal(rejected?.reason.status, 409);
  const identity = await db.findingIdentity.findUniqueOrThrow({ where: { id: f.identity.id } });
  assert.equal(identity.workflowRevision, 1);
  assert.equal(await db.auditEvent.count({ where: { action: "finding.workflow.updated" } }), 1);
  for (const id of [f.first.id, f.duplicate.id]) assert.equal((await db.finding.findUniqueOrThrow({ where: { id } })).owner, identity.owner);
}));

test("standalone observations use versioned local workflow and cannot imply persistent expiry", async () => database(async (db) => {
  const f = await fixture(db);
  const standalone = await db.finding.update({ where: { id: f.first.id }, data: { identityId: "" } });
  const version = findingWorkflow(standalone, null).version;
  const patch = parseFindingWorkflowPatch({ expectedVersion: version, owner: "Preview team", status: "triaged", reason: "Preview only" });
  const updated = await updateFindingWorkflow(db, f.principal, f.first.id, patch, env);
  assert.equal(updated.workflow.scope, "observation");
  assert.equal(updated.owner, "Preview team");
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.first.id, patch, env), { status: 409 });
  const expiry = parseFindingWorkflowPatch({ expectedVersion: updated.workflow.version, status: "accepted_risk", reason: "Preview only", expiresAt: new Date(Date.now() + 86_400_000).toISOString() });
  await assert.rejects(updateFindingWorkflow(db, f.principal, f.first.id, expiry, env), /default-branch finding identity/);
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: f.identity.id } })).status, "open");
}));

test("workflow validation rejects stale-format, malformed, unbounded and invalid date requests", () => {
  const base = { expectedVersion: "fixture", owner: "AppSec" };
  for (const body of [null, {}, { ...base, owner: [] }, { ...base, tags: [42] }, { ...base, priority: "critical" },
    { ...base, tags: Array(21).fill("tag") }, { ...base, owner: "x".repeat(201) }, { ...base, owner: "line\nbreak" },
    { ...base, dueAt: "2026-02-30" }, { ...base, dueAt: 42 }, { ...base, dueAt: "today" },
    { ...base, status: "false_positive" }, { ...base, status: "accepted_risk", reason: "reviewed", expiresAt: "2000-01-01" },
    { ...base, expiresAt: "2099-01-01" }, { ...base, ticketUrl: "https://example.test" },
  ]) assert.throws(() => parseFindingWorkflowPatch(body));
  assert.equal(parseFindingWorkflowPatch({ ...base, dueAt: null }).management.dueAt, null);
});

test("ticket receipts bind current identity observations and retain conflicting completed actions for review", async () => database(async (db) => {
  const f = await fixture(db);
  const prepared = await prepareFindingTicket(db, f.principal, f.first.id, env);
  assert.equal(prepared.finding.ticketKey, "");
  const issue = { key: "FIXTURE-1", url: "https://issues.example.test/browse/FIXTURE-1" };
  assert.deepEqual(await recordFindingTicket(db, prepared.context, issue), { linked: true });
  for (const id of [f.first.id, f.duplicate.id]) assert.equal((await db.finding.findUniqueOrThrow({ where: { id } })).ticketKey, issue.key);
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: f.historical.id } })).ticketKey, "");
  assert.equal((await prepareFindingTicket(db, f.principal, f.historical.id, env)).finding.ticketKey, issue.key);
  const conflict = { key: "FIXTURE-2", url: "https://issues.example.test/browse/FIXTURE-2" };
  assert.deepEqual(await recordFindingTicket(db, prepared.context, conflict), { linked: false });
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: f.identity.id } })).ticketKey, issue.key);
  const audit = await db.auditEvent.findFirstOrThrow({ where: { action: "finding.ticket.link_review_required" } });
  assert.equal(JSON.parse(audit.details).ticketKey, conflict.key);
  assert.deepEqual(await recordFindingTicket(db, prepared.context, { key: issue.key, url: `https://other-issues.example.test/browse/${issue.key}` }), { linked: false });
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: f.identity.id } })).ticketUrl, issue.url,
    "An equal key in a different Jira installation is a different ticket");
  await assert.rejects(recordFindingTicket(db, prepared.context, { key: "FIXTURE-3", url: "javascript:invalid" }), { status: 400 });
}));

test("a human assignment review clears a legacy conflict only through an explicit reviewed update", async () => database(async (db) => {
  const f = await fixture(db);
  let identity = await db.findingIdentity.update({ where: { id: f.identity.id }, data: { workflowNeedsReview: true } });
  const ordinary = parseFindingWorkflowPatch({ expectedVersion: findingWorkflow(f.first, identity).version, owner: "Proposed team" });
  await updateFindingWorkflow(db, f.principal, f.first.id, ordinary, env);
  identity = await db.findingIdentity.findUniqueOrThrow({ where: { id: identity.id } });
  assert.equal(identity.workflowNeedsReview, true);
  const reviewed = parseFindingWorkflowPatch({ expectedVersion: findingWorkflow(f.first, identity).version, owner: "Reviewed team", resolveWorkflowReview: true });
  const result = await updateFindingWorkflow(db, f.principal, f.first.id, reviewed, env);
  assert.equal(result.workflow.needsReview, false);
  assert.equal(result.owner, "Reviewed team");
}));

test("workflow migration keeps unique latest metadata, flags conflicts and never rewrites historical observations", async () => database(async (db, sql, migrate) => {
  const project = await db.project.create({ data: { name: "Legacy workflow" } });
  const scan = await db.scan.create({ data: { projectId: project.id, branch: "main", status: "completed" } });
  const oldScan = await db.scan.create({ data: { projectId: project.id, branch: "main", status: "completed", createdAt: new Date(0) } });
  const base = { scanId: scan.id, ruleId: "DEMO", ruleName: "Synthetic", severity: "low", filePath: "src/app.py", lineStart: 1, lineEnd: 1, message: "Fixture" };
  for (const id of ["unique", "conflict", "invalid", "unbound"]) {
    await sql.execute({ sql: "INSERT INTO FindingIdentity (id, projectId, fingerprint, ruleId, filePath, repositoryId, modulePath, lastSeenScanId, updatedAt) VALUES (?, ?, ?, 'DEMO', 'src/app.py', 'service', ?, ?, CURRENT_TIMESTAMP)", args: [id, project.id, id, id === "unbound" ? "" : "src/app.py", scan.id] });
    await db.finding.create({ data: { ...base, identityId: id, repositoryId: "service", modulePath: "src/app.py", owner: id === "invalid" ? "x".repeat(201) : "Reviewed team",
      dueAt: new Date("2026-12-01"), tags: '["owned"]', priority: "p1", ticketProvider: "jira", ticketKey: "FIXTURE-1", ticketUrl: "https://issues.example.test/browse/FIXTURE-1" } });
  }
  await db.finding.create({ data: { ...base, identityId: "unique" } });
  await db.finding.create({ data: { ...base, scanId: oldScan.id, identityId: "unique", owner: "Old team", isCurrent: false } });
  await db.finding.create({ data: { ...base, identityId: "conflict", owner: "Conflicting team" } });
  const before = await db.finding.findMany({ orderBy: { id: "asc" } });
  await migrate();
  const unique = await db.findingIdentity.findUniqueOrThrow({ where: { id: "unique" } });
  assert.equal(unique.owner, "Reviewed team");
  assert.equal(unique.dueAt?.toISOString().slice(0, 10), "2026-12-01");
  assert.equal(unique.ticketKey, "FIXTURE-1");
  assert.equal(unique.workflowNeedsReview, false);
  for (const id of ["conflict", "invalid", "unbound"]) {
    const identity = await db.findingIdentity.findUniqueOrThrow({ where: { id } });
    assert.equal(identity.owner, "");
    assert.equal(identity.workflowNeedsReview, true);
  }
  assert.deepEqual(await db.finding.findMany({ orderBy: { id: "asc" } }), before);
}, true));
