import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { importSarif, validateSarifReport } from "./sarif-import.ts";

function report(message = "Synthetic candidate", status = "completed") {
  return {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Aegify", version: "test", rules: [{ id: "DEMO", name: "Synthetic" }] } },
      results: [{ ruleId: "DEMO", level: "warning", message: { text: message }, partialFingerprints: { "aegifyFingerprint/v1": "synthetic-stable-fingerprint" }, locations: [{ physicalLocation: { artifactLocation: { uri: "app.py" }, region: { startLine: 1 } } }] }],
      invocations: [{ executionSuccessful: status === "completed" }],
      properties: { analysisStatus: status, analysisScope: "repository", evaluatedRules: ["DEMO"], analyzedFiles: ["app.py"], callGraph: { nodes: [{ qualifiedName: "demo", filePath: "app.py" }], edges: [] }, endpoints: [{ path: "/demo", method: "GET", handlerFunction: "demo", filePath: "app.py" }] },
    }],
  };
}

test("SARIF artifact publication rolls back every artifact and baseline on late failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-publication-"));
  const url = "file:" + join(directory, "publication.db");
  const sql = createClient({ url });
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  try {
    const project = await db.project.create({ data: { name: "Synthetic", defaultBranch: "main" } });
    const context = { projectId: project.id, repository: "synthetic", branch: "main", commitSha: "fixture", actorId: "fixture", authorize: async () => {} };
    const first = await importSarif(db, report(), context);
    const original = await db.findingIdentity.findFirstOrThrow();
    assert.equal(original.occurrenceCount, 1);
    const scans = await db.scan.count();
    const graphs = await db.callGraphNode.count();
    const audits = await db.auditEvent.count();
    await sql.executeMultiple('CREATE TRIGGER fail_late BEFORE INSERT ON Endpoint BEGIN SELECT RAISE(ABORT, \'injected late artifact failure\'); END;');
    await assert.rejects(importSarif(db, report("Changed evidence"), context));
    assert.equal(await db.scan.count(), scans);
    assert.equal(await db.callGraphNode.count(), graphs);
    assert.equal(await db.auditEvent.count(), audits);
    assert.deepEqual(await db.findingIdentity.findFirstOrThrow(), original);
    assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: first.scanId } })).isCurrent, true);
    await sql.executeMultiple('DROP TRIGGER fail_late;');
    await assert.rejects(importSarif(db, report("Rejected by fence"), { ...context, onPublished: async () => { throw new Error("lost lease"); } }));
    assert.deepEqual(await db.findingIdentity.findFirstOrThrow(), original);
    assert.equal(await db.scan.count(), scans);
    await assert.rejects(importSarif(db, report(), { ...context, authorize: async () => { throw new Error("revoked"); } }));
    assert.equal(await db.scan.count(), scans);
    const second = await importSarif(db, report("New evidence"), context);
    assert.equal((await db.findingIdentity.findFirstOrThrow()).occurrenceCount, 2);
    assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: first.scanId } })).isCurrent, false);
    assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: second.scanId } })).isCurrent, true);
    const failed = await importSarif(db, report("Incomplete failure evidence", "failed"), context);
    assert.equal((await db.findingIdentity.findFirstOrThrow()).lastSeenScanId, second.scanId);
    assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: failed.scanId } })).isCurrent, false);
    // A previously reserved job finishing late must not overwrite the latest baseline.
    const reserved = await db.scan.create({ data: { projectId: project.id, branch: "main", status: "running", createdAt: new Date(0) } });
    const late = await importSarif(db, report("Old job's evidence"), { ...context, scanId: reserved.id });
    assert.equal((await db.findingIdentity.findFirstOrThrow()).lastSeenScanId, second.scanId);
    assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: late.scanId } })).isCurrent, false);
  } finally { sql.close(); await db.$disconnect(); await rm(directory, { recursive: true, force: true }); }
});

test("SARIF validation rejects ambiguous runs, oversized graphs and invalid ranges", () => {
  assert.throws(() => validateSarifReport({ ...report(), runs: [] }));
  assert.throws(() => validateSarifReport({ ...report(), version: "unexpected" }));
  const invalid = report();
  invalid.runs[0].results[0].locations[0].physicalLocation.region.startLine = 0;
  assert.throws(() => validateSarifReport(invalid));
  const oversized = report();
  oversized.runs[0].properties.callGraph.nodes = Array.from({ length: 50_001 }, () => ({ qualifiedName: "demo", filePath: "app.py" }));
  assert.throws(() => validateSarifReport(oversized));
});
