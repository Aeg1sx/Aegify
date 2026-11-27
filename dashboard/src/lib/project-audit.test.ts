import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { exportAuditSnapshot, readAuditPage } from "./project-audit.ts";
import { AccessDenied } from "./project-access.ts";

test("a WAL snapshot stays consistent across a backdated insert and a role revocation between batches", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-audit-snapshot-"));
  const url = "file:" + join(directory, "audit.db");
  const sql = createClient({ url });
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  try {
    const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
    for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
      await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
    }
    await sql.execute("PRAGMA journal_mode=WAL");
    await db.user.create({ data: { id: "admin", email: "admin@example.test" } });
    const project = await db.project.create({ data: { name: "Audit fixture", members: { create: { userId: "admin", role: "admin" } } } });
    const env = { NODE_ENV: "production", AUTH_SECRET: "test-fixture", AUTH_ALLOWED_DOMAINS: "example.test" };
    const events = Array.from({ length: 205 }, (_, index) => ({
      id: String(index).padStart(3, "0"), actorId: "admin", projectId: project.id, action: "export.test",
      targetId: project.id, createdAt: new Date("2026-01-02T12:00:00.000Z"),
    }));
    await db.auditEvent.createMany({ data: events });
    let batches = 0;
    // Use a second connection for the concurrent commit. The extra row sorts
    // after the first batch, so independent per-page reads would include it.
    const reader = db.$extends({ query: { auditEvent: { async findMany({ args, query }) {
      const rows = await query(args);
      if (++batches === 1) {
        await sql.batch([
          { sql: "INSERT INTO AuditEvent (id, projectId, actorId, action, targetId, createdAt) VALUES ('000-late', ?, 'admin', 'audit.concurrent', ?, '2026-01-01T00:00:00.000+00:00')", args: [project.id, project.id] },
          { sql: "UPDATE ProjectMember SET role = 'viewer' WHERE projectId = ? AND userId = 'admin'", args: [project.id] },
        ], "write");
      }
      return rows;
    } } } });
    const snapshot = await exportAuditSnapshot(reader as unknown as PrismaClient, project.id, "admin", env, new AbortController().signal);
    let text = "";
    for await (const chunk of snapshot.file.createReadStream({ start: 0, autoClose: true })) text += chunk;
    assert.equal(batches, 3);
    assert.equal(snapshot.count, events.length);
    assert.equal(snapshot.bytes, Buffer.byteLength(text));
    assert.deepEqual(text.trimEnd().split("\n").map((line) => JSON.parse(line).id), events.map((event) => event.id).reverse());
    assert.equal(await db.auditEvent.count({ where: { projectId: project.id } }), events.length + 1);
    const denied = (error: unknown) => error instanceof AccessDenied && error.status === 404;
    await assert.rejects(readAuditPage(db, project.id, "admin", env, new URLSearchParams()), denied);
    await assert.rejects(exportAuditSnapshot(db, project.id, "admin", env, new AbortController().signal), denied);
    await db.projectMember.updateMany({ where: { projectId: project.id }, data: { role: "admin" } });
    const controller = new AbortController();
    controller.abort(new Error("Download cancelled"));
    await assert.rejects(exportAuditSnapshot(db, project.id, "admin", env, controller.signal), /Download cancelled/);
  } finally {
    await db.$disconnect();
    sql.close();
    await rm(directory, { recursive: true, force: true });
  }
});
