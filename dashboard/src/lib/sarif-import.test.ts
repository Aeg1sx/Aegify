import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { importSarif, validateSarifReport } from "./sarif-import.ts";
import { findingMessageDigest } from "./finding-lifecycle.ts";

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

const identityMigration = "20260924030000_finding_identity_scope";
const snippet = "before\nreview(value)\nafter";

function scopedReport(options: { root?: string; repositoryId?: string; ruleId?: string; empty?: boolean; producer?: string; hint?: string } = {}) {
  const filePath = `${options.root || "/checkout/new"}/src/app.py`;
  const repositoryId = options.repositoryId || "service-a";
  const ruleId = options.ruleId || "DEMO";
  const base = report();
  const run = base.runs[0];
  return { ...base, runs: [{ ...run,
    tool: { driver: { ...run.tool.driver, rules: [{ id: ruleId, name: "Synthetic" }] } },
    results: options.empty ? [] : [{ ...run.results[0], ruleId,
      partialFingerprints: options.producer === "opaque"
        ? { primaryLocationLineHash: options.hint || "shared-producer-hint" }
        : { "aegifyFingerprint/v2": "recomputed-by-importer", "aegifyFingerprint/v1": options.hint || "new-root-v1" },
      locations: [{ physicalLocation: { artifactLocation: { uri: filePath },
        region: { startLine: 12, endLine: 12, snippet: { text: "review(value)" } },
        contextRegion: { startLine: 11, endLine: 13, snippet: { text: snippet } } } }],
      properties: { provenance: { repository_id: repositoryId, module_path: "src/app.py" } },
    }],
    properties: { ...run.properties, evaluatedRules: [ruleId], analyzedFiles: [filePath],
      sourceIdentityVersion: 1,
      analyzedSources: [{ repositoryId, modulePath: "src/app.py", filePath }],
    },
  }] };
}

async function identityDatabase(run: (db: PrismaClient, sql: ReturnType<typeof createClient>, applyMigration: () => Promise<void>) => Promise<void>, legacy = false) {
  const directory = await mkdtemp(join(tmpdir(), "aegify-identity-"));
  const url = "file:" + join(directory, "identities.db");
  const sql = createClient({ url });
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  const entries = (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name));
  const applyMigration = async () => {
    for (const entry of entries.filter((item) => item.name >= identityMigration)) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  };
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  try {
    for (const entry of entries) {
      if (!legacy || entry.name < identityMigration) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
    }
    await run(db, sql, applyMigration);
  } finally { sql.close(); await db.$disconnect(); await rm(directory, { recursive: true, force: true }); }
}

async function legacyIdentity(db: PrismaClient, sql: ReturnType<typeof createClient>, projectId: string,
  options: { id: string; fingerprint?: string; repositoryId?: string; modulePath?: string; ruleId?: string; status?: string; filePath?: string }) {
  const scan = await db.scan.create({ data: { projectId, branch: "main", status: "completed", createdAt: new Date(0) } });
  const fingerprint = options.fingerprint || `sarif:aegifyFingerprint/v1:${options.id}`;
  const status = options.status || "accepted_risk";
  const ruleId = options.ruleId || "DEMO";
  const filePath = options.filePath || `/old/${options.id}/src/app.py`;
  // Seed the pre-migration table using only columns that actually existed then.
  await sql.execute({ sql: `INSERT INTO FindingIdentity
    (id, projectId, fingerprint, ruleId, filePath, lastSeenScanId, status, lastSeverity,
     lastEvidenceState, lastMessageDigest, triageReason, triageActor, updatedAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'medium', 'candidate', ?, 'Reviewed fixture', 'fixture', CURRENT_TIMESTAMP)`,
  args: [options.id, projectId, fingerprint, ruleId, filePath, scan.id, status, findingMessageDigest("Synthetic candidate")] });
  const occurrence = await db.finding.create({ data: { scanId: scan.id, ruleId, ruleName: "Synthetic", severity: "medium",
    filePath, lineStart: 2, lineEnd: 2, codeSnippet: snippet, message: "Synthetic candidate",
    identityId: options.id, fingerprint, status, repositoryId: options.repositoryId || "service-a", modulePath: options.modulePath ?? "src/app.py" } });
  await db.findingTriageEvent.create({ data: { identityId: options.id, fromStatus: "open", toStatus: status, reason: "Reviewed fixture", actor: "fixture" } });
  return { scan, occurrence };
}

const importContext = (projectId: string) => ({ projectId, repository: "synthetic", branch: "main", commitSha: "fixture", actorId: "fixture", authorize: async () => {} });

test("legacy database upgrade retains triage across checkouts and rolls back identity migration with artifacts", async () => identityDatabase(async (db, sql, applyMigration) => {
  const project = await db.project.create({ data: { name: "Synthetic", defaultBranch: "main" } });
  const old = await legacyIdentity(db, sql, project.id, { id: "legacy-reviewed", modulePath: "./src\\app.py" });
  await applyMigration();
  const original = await db.findingIdentity.findUniqueOrThrow({ where: { id: "legacy-reviewed" } });
  assert.equal(original.repositoryId, "service-a");
  assert.equal(original.modulePath, "src/app.py");
  const context = importContext(project.id);
  await sql.executeMultiple("CREATE TRIGGER fail_identity_artifact BEFORE INSERT ON Endpoint BEGIN SELECT RAISE(ABORT, 'injected failure'); END;");
  await assert.rejects(importSarif(db, scopedReport(), context));
  assert.deepEqual(await db.findingIdentity.findUniqueOrThrow({ where: { id: original.id } }), original);
  assert.equal(await db.scan.count(), 1);
  assert.equal(await db.auditEvent.count(), 0);
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: old.occurrence.id } })).isCurrent, true);
  await sql.executeMultiple("DROP TRIGGER fail_identity_artifact;");
  const receipt = await importSarif(db, scopedReport(), context);
  assert.equal(receipt.status, "completed");
  const current = await db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId } });
  assert.equal(current.identityId, original.id);
  assert.equal(current.status, "accepted_risk");
  assert.equal(current.baselineState, "unchanged");
  assert.equal(current.codeSnippet, snippet, "Full context must survive the producer region slice");
  const migrated = await db.findingIdentity.findUniqueOrThrow({ where: { id: original.id } });
  assert.match(migrated.fingerprint, /^aegify-finding\/v2:[a-f0-9]{64}$/);
  assert.equal(migrated.triageReason, original.triageReason);
  assert.equal(migrated.firstSeenAt.getTime(), original.firstSeenAt.getTime());
  assert.equal(migrated.occurrenceCount, 2);
  assert.equal(await db.findingIdentity.count(), 1);
  assert.equal(await db.findingTriageEvent.count(), 1);
  assert.equal(await db.auditEvent.count({ where: { action: "finding.identity.migrated" } }), 1);
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: old.occurrence.id } })).isCurrent, false);
  const partial = scopedReport({ root: "/another/checkout" });
  partial.runs[0].properties.analysisStatus = "partial";
  const next = await importSarif(db, partial, context);
  assert.equal(next.status, "partial");
  assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: next.scanId } })).identityId, original.id);
  assert.equal(await db.finding.count({ where: { isCurrent: true } }), 1);
}, true));

test("conflicting legacy decisions remain distinct and make an ambiguous upgrade partial", async () => identityDatabase(async (db, sql, applyMigration) => {
  const project = await db.project.create({ data: { name: "Ambiguity", defaultBranch: "main" } });
  await legacyIdentity(db, sql, project.id, { id: "first-root", status: "false_positive" });
  await legacyIdentity(db, sql, project.id, { id: "second-root", status: "confirmed" });
  await applyMigration();
  const receipt = await importSarif(db, scopedReport(), importContext(project.id));
  assert.equal(receipt.status, "partial");
  const current = await db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId } });
  assert.equal(current.status, "open");
  assert.ok(!["first-root", "second-root"].includes(current.identityId));
  for (const [id, status] of [["first-root", "false_positive"], ["second-root", "confirmed"]]) {
    const retained = await db.findingIdentity.findUniqueOrThrow({ where: { id } });
    assert.equal(retained.status, status);
    assert.equal(retained.absentAt, null);
    assert.match(retained.fingerprint, /^sarif:/);
  }
  assert.equal(await db.findingTriageEvent.count(), 2);
  assert.equal(await db.finding.count({ where: { isCurrent: true } }), 3);
  assert.equal(await db.auditEvent.count({ where: { action: "scan.identity_migration.review_required" } }), 1);
  assert.match((await db.scan.findUniqueOrThrow({ where: { id: receipt.scanId } })).progressMessage, /finding_identity_review_required/);
}, true));

test("a bound legacy producer hint survives checkout movement without crossing rule or repository scopes", async () => identityDatabase(async (db, sql, applyMigration) => {
  const project = await db.project.create({ data: { name: "Producer compatibility", defaultBranch: "main" } });
  await legacyIdentity(db, sql, project.id, { id: "producer-history", fingerprint: "sarif:primaryLocationLineHash:shared-producer-hint", status: "confirmed" });
  await applyMigration();
  const receipt = await importSarif(db, scopedReport({ producer: "opaque" }), importContext(project.id));
  const finding = await db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId } });
  assert.equal(receipt.status, "completed");
  assert.equal(finding.identityId, "producer-history");
  assert.equal(finding.status, "confirmed");
  for (const different of [{ repositoryId: "other" }, { ruleId: "OTHER" }]) {
    const other = await importSarif(db, scopedReport({ producer: "opaque", ...different }), importContext(project.id));
    assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: other.scanId } })).status, "open");
  }
  assert.equal(await db.findingIdentity.count(), 3);
}, true));

test("legacy evidence limits count UTF-8 bytes and preserve oversized decisions for review", async () => identityDatabase(async (db, sql, applyMigration) => {
  const project = await db.project.create({ data: { name: "Retained evidence budget", defaultBranch: "main" } });
  const { occurrence } = await legacyIdentity(db, sql, project.id, { id: "long-evidence" });
  const unicodeSnippet = `before\n${"가".repeat(6000)}\nafter`;
  await db.finding.update({ where: { id: occurrence.id }, data: { codeSnippet: unicodeSnippet } });
  await applyMigration();
  const incoming = scopedReport();
  incoming.runs[0].results[0].locations[0].physicalLocation.contextRegion.snippet.text = unicodeSnippet;
  const receipt = await importSarif(db, incoming, importContext(project.id));
  assert.equal(receipt.status, "partial");
  assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId } })).status, "open");
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: "long-evidence" } })).status, "accepted_risk");
  assert.equal(await db.findingTriageEvent.count(), 1);
}, true));

test("legacy producer collisions across repositories never transfer a decision", async () => identityDatabase(async (db, sql, applyMigration) => {
  const project = await db.project.create({ data: { name: "Collision", defaultBranch: "main" } });
  const { scan, occurrence } = await legacyIdentity(db, sql, project.id, { id: "shared", status: "false_positive" });
  await db.finding.create({ data: { ...occurrence, id: "other-repository-occurrence", scanId: scan.id, repositoryId: "service-b", filePath: "/old/service-b/src/app.py" } });
  await applyMigration();
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: "shared" } })).modulePath, "");
  const receipt = await importSarif(db, scopedReport({ hint: "shared" }), importContext(project.id));
  assert.equal(receipt.status, "partial");
  const finding = await db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId } });
  assert.notEqual(finding.identityId, "shared");
  assert.equal(finding.status, "open");
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: "shared" } })).status, "false_positive");
}, true));

test("repository and rule namespaces isolate producer hashes and checkout-independent absence", async () => identityDatabase(async (db) => {
  const project = await db.project.create({ data: { name: "Namespace", defaultBranch: "main" } });
  const context = importContext(project.id);
  const first = await importSarif(db, scopedReport({ producer: "opaque" }), context);
  const firstFinding = await db.finding.findFirstOrThrow({ where: { scanId: first.scanId } });
  await db.findingIdentity.update({ where: { id: firstFinding.identityId }, data: { status: "false_positive" } });
  const other = await importSarif(db, scopedReport({ repositoryId: "service-b", producer: "opaque", root: "/checkout/b" }), context);
  const otherFinding = await db.finding.findFirstOrThrow({ where: { scanId: other.scanId } });
  assert.notEqual(otherFinding.identityId, firstFinding.identityId);
  assert.equal(otherFinding.status, "open");
  const differentRule = await importSarif(db, scopedReport({ repositoryId: "service-b", ruleId: "OTHER", producer: "opaque" }), context);
  assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: differentRule.scanId } })).status, "open");
  assert.equal(await db.findingIdentity.count(), 3);
  const empty = scopedReport({ root: "/checkout/moved-again", empty: true });
  const legacyEmpty = { ...empty, runs: [{ ...empty.runs[0], properties: {
    analysisStatus: "completed", analysisScope: "repository", evaluatedRules: ["DEMO", "OTHER"],
    analyzedFiles: ["/checkout/new/src/app.py", "/checkout/b/src/app.py"],
  } }] };
  await importSarif(db, legacyEmpty, context);
  assert.equal(await db.finding.count({ where: { isCurrent: true } }), 3, "An unqualified legacy inventory cannot erase known repository scopes");
  const invalid = structuredClone(empty);
  invalid.runs[0].properties.analyzedSources.push({ ...invalid.runs[0].properties.analyzedSources[0], repositoryId: "service-b" });
  assert.equal((await importSarif(db, invalid, context)).status, "partial");
  assert.equal(await db.finding.count({ where: { isCurrent: true } }), 3);
  await importSarif(db, empty, context);
  assert.ok((await db.findingIdentity.findUniqueOrThrow({ where: { id: firstFinding.identityId } })).absentAt);
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: firstFinding.id } })).isCurrent, false);
  assert.equal((await db.findingIdentity.findUniqueOrThrow({ where: { id: otherFinding.identityId } })).absentAt, null);
  assert.equal((await db.finding.findUniqueOrThrow({ where: { id: otherFinding.id } })).isCurrent, true);
  // A matching namespace in a different project cannot inherit that triage either.
  const sibling = await db.project.create({ data: { name: "Sibling", defaultBranch: "main" } });
  const siblingReceipt = await importSarif(db, scopedReport({ producer: "opaque" }), importContext(sibling.id));
  assert.equal((await db.finding.findFirstOrThrow({ where: { scanId: siblingReceipt.scanId } })).status, "open");
}));

test("SARIF rejects malformed identity hints and unbounded or non-relative provenance", () => {
  for (const override of [
    { ruleId: " DEMO " },
    { partialFingerprints: { primaryLocationLineHash: 42 } },
    { partialFingerprints: { primaryLocationLineHash: "x".repeat(4097) } },
    { properties: { provenance: { repository_id: " service" } } },
    { properties: { provenance: { module_path: "../sibling/app.py" } } },
    { properties: { provenance: { module_path: "/absolute/app.py" } } },
  ]) {
    const invalid = scopedReport();
    Object.assign(invalid.runs[0].results[0], override);
    assert.throws(() => validateSarifReport(invalid));
  }
});

test("imports carry identity management and expire a triage decision only once", async () => identityDatabase(async (db) => {
  const project = await db.project.create({ data: { name: "Workflow carry", defaultBranch: "main" } });
  const context = importContext(project.id);
  const first = await importSarif(db, scopedReport(), context);
  const observation = await db.finding.findFirstOrThrow({ where: { scanId: first.scanId } });
  await db.findingIdentity.update({ where: { id: observation.identityId }, data: {
    status: "accepted_risk", triageReason: "Time bounded fixture", triageActor: "fixture", triageExpiresAt: new Date(0),
    owner: "AppSec", dueAt: new Date("2026-12-01"), priority: "p1", tags: '["owned"]',
    ticketProvider: "jira", ticketKey: "FIXTURE-1", ticketUrl: "https://issues.example.test/browse/FIXTURE-1",
  } });
  for (const root of ["/new/root", "/next/root"]) {
    const receipt = await importSarif(db, scopedReport({ root }), context);
    const finding = await db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId } });
    assert.equal(finding.status, "open");
    assert.equal(finding.owner, "AppSec");
    assert.equal(finding.priority, "p1");
    assert.equal(finding.ticketKey, "FIXTURE-1");
    assert.deepEqual(JSON.parse(finding.tags), ["owned"]);
    const identity = await db.findingIdentity.findUniqueOrThrow({ where: { id: finding.identityId } });
    assert.equal(identity.triageExpiresAt, null);
    assert.equal(identity.triageReason, "");
    assert.equal(identity.workflowRevision, 1);
    assert.equal(await db.findingTriageEvent.count(), 1);
  }
}));

test("contradictory finding and inventory namespaces roll back the entire report", async () => identityDatabase(async (db) => {
  const project = await db.project.create({ data: { name: "Contradictory scope", defaultBranch: "main" } });
  const invalid = scopedReport();
  invalid.runs[0].results[0].properties.provenance.repository_id = "other-repository";
  await assert.rejects(importSarif(db, invalid, importContext(project.id)), /contradicts/);
  assert.equal(await db.scan.count(), 0);
  assert.equal(await db.findingIdentity.count(), 0);
  assert.equal(await db.auditEvent.count(), 0);
}));

test("legacy migration budget preserves every old decision and marks the whole incoming scope partial", async () => identityDatabase(async (db) => {
  const project = await db.project.create({ data: { name: "Migration budget", defaultBranch: "main" } });
  for (let offset = 0; offset < 5001; offset += 200) {
    await db.findingIdentity.createMany({ data: Array.from({ length: Math.min(200, 5001 - offset) }, (_, index) => ({
      id: `legacy-${offset + index}`, projectId: project.id, fingerprint: `legacy:${offset + index}`,
      ruleId: "DEMO", repositoryId: "service-a", modulePath: "src/app.py", filePath: "/old/src/app.py", status: "confirmed",
    })) });
  }
  const incoming = scopedReport();
  const second = structuredClone(incoming.runs[0].results[0]);
  second.locations[0].physicalLocation.contextRegion.snippet.text = "before\nreview(other)\nafter";
  incoming.runs[0].results.push(second);
  const receipt = await importSarif(db, incoming, importContext(project.id));
  assert.equal(receipt.status, "partial");
  assert.equal(await db.findingIdentity.count({ where: { status: "confirmed", absentAt: null } }), 5001);
  assert.equal(await db.finding.count({ where: { scanId: receipt.scanId, status: "open" } }), 2);
  const audit = await db.auditEvent.findFirstOrThrow({ where: { action: "scan.identity_migration.review_required" } });
  assert.deepEqual(JSON.parse(audit.details).reason, "migration_budget");
  assert.equal(JSON.parse(audit.details).findings, 2);
  assert.equal(await db.auditEvent.count({ where: { action: "finding.identity.migrated" } }), 0);
}));

test("real Python source reports retain one identity through fresh checkout roots and import", { skip: process.env.AEGIFY_TEST_SCANNER_CLI !== "1" }, async () => identityDatabase(async (db) => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-source-roots-"));
  const project = await db.project.create({ data: { name: "Real scanner", defaultBranch: "main" } });
  const python = fileURLToPath(new URL("../../../scanner/.venv/bin/python", import.meta.url));
  const script = [
    "import json, sys", "from pathlib import Path", "from aegify.config import AegifyConfig",
    "from aegify.scanner.engine import ScanEngine", "from aegify.reporter.sarif import SARIFReporter",
    "config = AegifyConfig.model_construct()", "config.scan.max_workers = 1",
    "config.rules.severity_threshold = 'low'", "config.scan.max_findings_per_rule = 0", "config.scan.max_findings_per_file = 0",
    "result = ScanEngine(config=config).scan(Path(sys.argv[1]))",
    "print(json.dumps(SARIFReporter().generate(result)))",
  ].join("\n");
  try {
    const receipts = [];
    const emitted = [];
    for (const name of ["checkout-a", "checkout-b"]) {
      const root = join(directory, name);
      await mkdir(join(root, "src"), { recursive: true });
      await writeFile(join(root, "src", "app.py"), "from flask import request\nraise RuntimeError('STATIC INPUT MUST NEVER EXECUTE')\ndef read_document():\n    value = request.args.get('path')\n    return open(value)\n");
      const { stdout } = await promisify(execFile)(python, ["-I", "-c", script, root], {
        timeout: 60_000, maxBuffer: 8 * 1024 * 1024,
        env: { NODE_ENV: "test", PATH: process.env.PATH, PYTHONDONTWRITEBYTECODE: "1", TMPDIR: directory },
      });
      const sarif = validateSarifReport(JSON.parse(stdout));
      const candidate = sarif.runs[0].results.find((result) => result.ruleId === "AEG-PATH-001");
      assert.ok(candidate, "The owned fixture must exercise a real detector");
      emitted.push(candidate);
      receipts.push(await importSarif(db, sarif, importContext(project.id)));
    }
    assert.equal(emitted[0].partialFingerprints?.["aegifyFingerprint/v2"], emitted[1].partialFingerprints?.["aegifyFingerprint/v2"]);
    assert.notEqual(emitted[0].partialFingerprints?.["aegifyFingerprint/v1"], emitted[1].partialFingerprints?.["aegifyFingerprint/v1"]);
    const [old, current] = await Promise.all(receipts.map((receipt) => db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId, ruleId: "AEG-PATH-001" } })));
    assert.equal(old.identityId, current.identityId);
    assert.equal(old.isCurrent, false);
    assert.equal(current.isCurrent, true);
    assert.equal(current.fingerprint, `aegify-finding/v2:${emitted[1].partialFingerprints?.["aegifyFingerprint/v2"]}`);
    assert.equal(current.modulePath, "src/app.py");
  } finally { await rm(directory, { recursive: true, force: true }); }
}));
