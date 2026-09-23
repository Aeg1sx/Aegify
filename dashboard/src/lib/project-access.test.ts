import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { AccessDenied, authorizeResource, changeProjectMember, findingScope, projectScope, resolvePrincipal, scanScope } from "./project-access.ts";
import { authenticateUploadToken, issueProjectToken, revokeProjectToken, tokenMetadata } from "./project-tokens.ts";

test("migration, project isolation, role changes and CI credentials enforce durable boundaries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-project-access-"));
  const url = "file:" + join(directory, "access.db");
  const sql = createClient({ url });
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === "20260924000000_project_access") {
      await sql.executeMultiple(`INSERT INTO "User" (id, email, updatedAt) VALUES ('legacy-owner', 'legacy@example.test', CURRENT_TIMESTAMP);
        INSERT INTO "Project" (id, name, userId, updatedAt) VALUES ('legacy-owned', 'Owned', 'legacy-owner', CURRENT_TIMESTAMP);
        INSERT INTO "Project" (id, name, updatedAt) VALUES ('legacy-unowned', 'Unowned', CURRENT_TIMESTAMP);`);
    }
    await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  }
  sql.close();
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  const env = { NODE_ENV: "production", AUTH_SECRET: "synthetic-session-secret", AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test" };
  const denied = (status = 404) => (error: unknown) => error instanceof AccessDenied && error.status === status;
  try {
    assert.deepEqual((await db.projectMember.findMany()).map((item) => [item.projectId, item.userId, item.role]), [["legacy-owned", "legacy-owner", "admin"]]);
    for (const name of ["alice", "bob", "root", "outside"]) await db.user.create({ data: { id: name, email: `${name}@example.test` } });
    const alice = await resolvePrincipal(db, "alice", env);
    const bob = await resolvePrincipal(db, "bob", env);
    const root = await resolvePrincipal(db, "root", env);
    const outside = await resolvePrincipal(db, "outside", env);
    assert.equal(alice.workspaceAdmin, false); assert.equal(root.workspaceAdmin, true);
    await assert.rejects(resolvePrincipal(db, undefined, env), denied(401));
    await assert.rejects(resolvePrincipal(db, "alice", { ...env, AUTH_ALLOWED_DOMAINS: "different.test" }), denied(401));
    const a = await db.project.create({ data: { name: "Alpha", members: { create: { userId: "alice", role: "admin" } } } });
    const b = await db.project.create({ data: { name: "Bravo", members: { create: { userId: "bob", role: "admin" } } } });
    const sa = await db.scan.create({ data: { projectId: a.id } });
    const sb = await db.scan.create({ data: { projectId: b.id } });
    const orphan = await db.scan.create({ data: {} });
    const findingData = { ruleId: "DEMO", ruleName: "Synthetic", severity: "low", filePath: "src/example.ts", lineStart: 1, lineEnd: 1, message: "Synthetic finding" };
    const fa = await db.finding.create({ data: { ...findingData, scanId: sa.id } });
    await db.finding.create({ data: { ...findingData, scanId: sb.id, filePath: "private/bravo.py" } });
    const endpoint = await db.endpoint.create({ data: { scanId: sa.id, path: "/synthetic", method: "GET", handlerFunction: "example", filePath: "src/example.ts" } });
    const job = await db.llmJob.create({ data: { scanId: sa.id, mode: "quick" } });
    const run = await db.agentRun.create({ data: { scanId: sa.id } });
    assert.deepEqual((await db.project.findMany({ where: projectScope(alice) })).map((item) => item.id), [a.id]);
    assert.equal(await db.scan.count({ where: scanScope(alice) }), 1);
    assert.equal(await db.finding.count({ where: findingScope(alice) }), 1);
    assert.equal(await db.finding.count({ where: { AND: [findingScope(alice), { scanId: sb.id }] } }), 0);
    assert.equal(await db.scan.count({ where: scanScope(outside) }), 0);
    for (const [kind, id] of [["project", a.id], ["scan", sa.id], ["finding", fa.id], ["endpoint", endpoint.id], ["llmJob", job.id], ["agentRun", run.id]] as const) {
      await authorizeResource(db, alice, kind, id, "admin");
      await assert.rejects(authorizeResource(db, bob, kind, id), denied());
      await assert.rejects(authorizeResource(db, alice, kind, "missing"), denied());
    }
    await assert.rejects(authorizeResource(db, alice, "scan", orphan.id), denied());
    await assert.rejects(authorizeResource(db, alice, "project", "legacy-unowned"), denied());
    await authorizeResource(db, root, "scan", orphan.id);
    await authorizeResource(db, root, "project", "legacy-unowned");
    await changeProjectMember(db, alice, a.id, "bob", "viewer");
    await authorizeResource(db, bob, "finding", fa.id);
    await assert.rejects(authorizeResource(db, bob, "finding", fa.id, "triager"), denied());
    await assert.rejects(changeProjectMember(db, bob, a.id, "bob", "admin"), denied());
    await changeProjectMember(db, alice, a.id, "bob", "triager");
    await authorizeResource(db, bob, "finding", fa.id, "triager");
    await assert.rejects(authorizeResource(db, bob, "scan", sa.id, "maintainer"), denied());
    await changeProjectMember(db, alice, a.id, "bob", "maintainer");
    await authorizeResource(db, bob, "scan", sa.id, "maintainer");
    await assert.rejects(changeProjectMember(db, alice, a.id, "alice", null), denied(409));
    await changeProjectMember(db, alice, a.id, "bob", null);
    await assert.rejects(authorizeResource(db, bob, "finding", fa.id), denied());

    const now = new Date("2026-09-24T00:00:00Z");
    const expiresAt = new Date(now.getTime() + 86_400_000);
    await assert.rejects(issueProjectToken(db, bob, a.id, "wrong-project", expiresAt, now), denied());
    await assert.rejects(issueProjectToken(db, alice, a.id, "too-long", new Date(now.getTime() + 91 * 86_400_000), now), denied(400));
    const issued = await issueProjectToken(db, alice, a.id, "CI fixture", expiresAt, now);
    assert.equal(issued.record.scope, "scan:upload"); assert.equal("tokenHash" in issued.record, false);
    const stored = await db.projectServiceToken.findUniqueOrThrow({ where: { id: issued.record.id } });
    assert.notEqual(stored.tokenHash, issued.token); assert.equal(stored.tokenHash.length, 64);
    assert.deepEqual(await authenticateUploadToken(db, issued.token, env, now), { projectId: a.id, actorId: `service-token:${stored.id}` });
    assert.equal(await authenticateUploadToken(db, issued.token + "x", env, now), null);
    assert.equal(await authenticateUploadToken(db, issued.token, env, expiresAt), null);
    const legacy = { ...env, AEGIFY_UPLOAD_TOKEN: "synthetic-legacy-token" };
    assert.equal(await authenticateUploadToken(db, legacy.AEGIFY_UPLOAD_TOKEN, legacy, now), null, "Legacy tokens without a project binding are rejected");
    assert.deepEqual(await authenticateUploadToken(db, legacy.AEGIFY_UPLOAD_TOKEN, { ...legacy, AEGIFY_UPLOAD_PROJECT_ID: b.id }, now), { projectId: b.id, actorId: "legacy-upload-token" });
    await db.project.update({ where: { id: a.id }, data: { archived: true } });
    assert.equal(await authenticateUploadToken(db, issued.token, env, now), null);
    await assert.rejects(issueProjectToken(db, alice, a.id, "archived", expiresAt, now), denied(409));
    await db.project.update({ where: { id: a.id }, data: { archived: false } });
    await assert.rejects(revokeProjectToken(db, bob, b.id, stored.id), denied());
    await revokeProjectToken(db, alice, a.id, stored.id);
    assert.equal(await authenticateUploadToken(db, issued.token, env, now), null);
    const metadata = await db.projectServiceToken.findMany({ select: tokenMetadata });
    assert.equal(JSON.stringify(metadata).includes(issued.token), false);
    const events = await db.auditEvent.findMany({ where: { projectId: a.id } });
    assert.ok(events.some((event) => event.action === "service_token.revoke"));
    assert.ok(events.some((event) => event.action === "project.member.remove"));
    assert.equal(JSON.stringify(events).includes(issued.token), false);
    await db.project.delete({ where: { id: a.id } });
    assert.equal(await db.projectServiceToken.count(), 0);
    assert.equal(await db.auditEvent.count({ where: { projectId: a.id } }), events.length, "Deletion retains the audit trail");
    await db.user.update({ where: { id: "alice" }, data: { disabled: true } });
    await assert.rejects(resolvePrincipal(db, "alice", env), denied(401));
  } finally { await db.$disconnect(); await rm(directory, { recursive: true, force: true }); }
});
