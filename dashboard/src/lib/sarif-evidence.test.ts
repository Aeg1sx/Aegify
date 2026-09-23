import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { PrismaLibSql } from "@prisma/adapter-libsql";
import { PrismaClient } from "@prisma/client";
import { createClient } from "@libsql/client";
import { finalizeScanImport } from "./scan-reconciliation.ts";

import {
  canReconcileScanAbsence,
  normalizeFindingClassification,
  normalizeFindingEvidence,
  normalizeSourceSnippet,
  scanHealthForRun,
  workspaceSnapshotForRun,
} from "./sarif-evidence.ts";

test("failed, partial, malformed and legacy reports cannot resolve absent findings", () => {
  const properties = { analysisStatus: "completed", analysisScope: "repository", evaluatedRules: ["AEG-ONE"], analyzedFiles: ["app.py"], analysisGaps: [] };
  const complete = scanHealthForRun(properties, { executionSuccessful: true });
  assert.equal(canReconcileScanAbsence(complete, "main", "main"), true);
  for (const health of [
    scanHealthForRun(properties, { executionSuccessful: false }),
    scanHealthForRun({ ...properties, analysisStatus: "partial" }, { executionSuccessful: false }),
    scanHealthForRun({ ...properties, analysisStatus: "invented" }, { executionSuccessful: true }),
    scanHealthForRun({ ...properties, analysisScope: "files" }, { executionSuccessful: true }),
    scanHealthForRun({ ...properties, analyzedFiles: [] }, { executionSuccessful: true }),
    scanHealthForRun({ ...properties, analyzedFiles: [42] }, { executionSuccessful: true }),
    scanHealthForRun({ ...properties, analysisGaps: [{ code: "limit", stage: "rules", message: "truncated", affected_count: 2 }] }, { executionSuccessful: true }),
    scanHealthForRun({ ...properties, analysisGaps: "malformed" }, { executionSuccessful: true }),
    scanHealthForRun(undefined, { executionSuccessful: true }),
  ]) assert.equal(canReconcileScanAbsence(health, "main", "main"), false);
  assert.equal(canReconcileScanAbsence(complete, "feature", "main"), false);
  assert.equal(canReconcileScanAbsence(complete, "", "main"), false);
  assert.equal(scanHealthForRun({ analysisStatus: "partial" }, { executionSuccessful: false }).status, "partial");
});

test("imports a SARIF context region without moving the reported finding", () => {
  assert.deepEqual(normalizeSourceSnippet({ region: { startLine: 12, endLine: 12, snippet: { text: "reported" } }, contextRegion: { startLine: 11, endLine: 13, snippet: { text: "before\nreported\nafter" } } }), { codeSnippet: "before\nreported\nafter", snippetStartLine: 11 });
  assert.deepEqual(normalizeSourceSnippet({ region: { startLine: 12, endLine: 12, snippet: { text: "before\nreported\nafter" } } }), { codeSnippet: "before\nreported\nafter", snippetStartLine: null });
  assert.deepEqual(normalizeSourceSnippet({ region: { startLine: 12, snippet: { text: "reported" } }, contextRegion: { startLine: 15, snippet: { text: "wrong context" } } }), { codeSnippet: "reported", snippetStartLine: 12 });
});

test("logical coverage requires a canonical one-to-one source inventory", () => {
  const source = { repositoryId: "api", modulePath: "src/app.py", filePath: "/runner/checkout/src/app.py" };
  const properties = { analysisStatus: "completed", analysisScope: "repository", evaluatedRules: ["AEG-ONE"], analyzedFiles: [source.filePath],
    sourceIdentityVersion: 1, analyzedSources: [source] };
  const complete = scanHealthForRun(properties, { executionSuccessful: true });
  assert.equal(complete.status, "completed");
  assert.deepEqual(complete.analyzedSources, [source]);
  for (const patch of [
    { sourceIdentityVersion: 2 }, { analyzedSources: [] },
    { analyzedSources: [source, source] },
    { analyzedSources: [source, { ...source, repositoryId: "other" }] },
    { analyzedSources: [{ ...source, modulePath: "../app.py" }] },
    { analyzedSources: [{ ...source, modulePath: "src//app.py" }] },
    { analyzedSources: [{ ...source, repositoryId: " api " }] },
    { analyzedSources: [{ ...source, filePath: "/runner/unscanned.py" }] },
    { analyzedFiles: [source.filePath, "/runner/missing.py"] },
  ]) {
    const health = scanHealthForRun({ ...properties, ...patch }, { executionSuccessful: true });
    assert.equal(health.status, "partial");
    assert.equal(health.analyzedSources, undefined);
    assert.equal(canReconcileScanAbsence(health, "main", "main"), false);
    assert.ok(health.gaps.some((gap) => gap.code === "invalid_source_identity_scope"));
  }
});

test("large logical inventories are bounded without a quadratic membership lookup", () => {
  const sources = Array.from({ length: 20_000 }, (_, index) => ({ repositoryId: "api", modulePath: `src/${index}.py`, filePath: `/checkout/src/${index}.py` }));
  const started = performance.now();
  const health = scanHealthForRun({ analysisStatus: "completed", analysisScope: "repository", evaluatedRules: ["AEG-ONE"],
    analyzedFiles: sources.map((source) => source.filePath), sourceIdentityVersion: 1, analyzedSources: sources }, { executionSuccessful: true });
  assert.equal(health.status, "completed");
  assert.equal(health.analyzedSources?.length, 20_000);
  assert.ok(performance.now() - started < 5000, "20,000 sources must stay within a broad regression budget");
});

test("prefers the run-level snapshot and accepts invocation fallback", () => {
  assert.equal(
    workspaceSnapshotForRun(
      { workspaceSnapshot: "sha256:run" },
      { workspaceSnapshot: "sha256:invocation" },
    ),
    "sha256:run",
  );
  assert.equal(
    workspaceSnapshotForRun(undefined, {
      workspaceSnapshot: "sha256:invocation",
    }),
    "sha256:invocation",
  );
});

test("normalizes the scanner provenance contract for database insertion", () => {
  const normalized = normalizeFindingEvidence({
    provenance: {
      contract_version: 1,
      producer: "aegify.YAMLRule",
      repository_id: "orders",
      module_path: "src/OrderController.kt",
      evidence_id: "ev:1234",
    },
  });

  assert.equal(normalized.evidenceId, "ev:1234");
  assert.equal(normalized.repositoryId, "orders");
  assert.equal(normalized.modulePath, "src/OrderController.kt");
  assert.deepEqual(JSON.parse(normalized.provenance), {
    contract_version: 1,
    producer: "aegify.YAMLRule",
    repository_id: "orders",
    module_path: "src/OrderController.kt",
    evidence_id: "ev:1234",
  });
});

test("legacy SARIF without provenance remains uploadable", () => {
  assert.deepEqual(normalizeFindingEvidence(undefined), {
    evidenceId: "",
    repositoryId: "",
    modulePath: "",
    provenance: "{}",
  });
});

test("normalizes scanner evidence state and gate disposition", () => {
  assert.deepEqual(
    normalizeFindingClassification({
      evidenceState: "reachable",
      disposition: "advisory",
      blocksCi: false,
    }),
    { evidenceState: "reachable", disposition: "advisory" },
  );
});

test("legacy or malformed classification remains visible without blocking", () => {
  assert.deepEqual(normalizeFindingClassification(undefined), {
    evidenceState: "candidate",
    disposition: "advisory",
  });
  assert.deepEqual(
    normalizeFindingClassification({
      evidenceState: "invented",
      disposition: "ignored",
    }),
    { evidenceState: "candidate", disposition: "advisory" },
  );
});

test("fresh migration history persists normalized evidence with Prisma", async () => {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), "aegify-evidence-"));
  const databasePath = join(temporaryDirectory, "integration.db");
  const databaseUrl = `file:${databasePath}`;
  const migrationRoot = join(process.cwd(), "prisma", "migrations");
  const migrationDirectories = (await readdir(migrationRoot, {
    withFileTypes: true,
  }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const migrationClient = createClient({ url: databaseUrl });
  for (const migrationDirectory of migrationDirectories) {
    const sql = await readFile(
      join(migrationRoot, migrationDirectory, "migration.sql"),
      "utf8",
    );
    await migrationClient.executeMultiple(sql);
  }
  migrationClient.close();

  const prisma = new PrismaClient({
    adapter: new PrismaLibSql({ url: databaseUrl }),
  });
  try {
    const user = await prisma.user.create({
      data: { email: "integration@example.test" },
    });
    const project = await prisma.project.create({
      data: { name: "commerce", userId: user.id },
    });
    const scan = await prisma.scan.create({
      data: {
        repository: "commerce",
        status: "completed",
        workspaceSnapshot: "sha256:workspace",
        projectId: project.id,
      },
    });
    const llmJob = await prisma.llmJob.create({
      data: { scanId: scan.id, activeKey: scan.id, mode: "quick" },
    });
    await assert.rejects(
      prisma.llmJob.create({
        data: { scanId: scan.id, activeKey: scan.id, mode: "deep" },
      }),
      /Unique constraint failed/,
    );
    await prisma.llmJob.update({
      where: { id: llmJob.id },
      data: { status: "completed", activeKey: null },
    });
    const nextLlmJob = await prisma.llmJob.create({
      data: { scanId: scan.id, activeKey: scan.id, mode: "deep" },
    });
    const rule = await prisma.rule.create({
      data: {
        id: "AEG-INTEGRATION-001",
        name: "Evidence integration",
        severity: "high",
      },
    });
    const evidence = normalizeFindingEvidence({
      provenance: {
        contract_version: 1,
        producer: "aegify.YAMLRule",
        repository_id: "orders",
        module_path: "api/OrderController.kt",
        evidence_id: "ev:integration",
      },
    });
    const classification = normalizeFindingClassification({
      evidenceState: "reachable",
      disposition: "blocking",
    });
    const identity = await prisma.findingIdentity.create({
      data: {
        projectId: project.id,
        fingerprint: "sha256:integration",
        ruleId: "AEG-INTEGRATION-001",
        filePath: "api/OrderController.kt",
        repositoryId: evidence.repositoryId,
        modulePath: evidence.modulePath,
        lastSeenScanId: scan.id,
        lastSeverity: "high",
        lastEvidenceState: "reachable",
        lastMessageDigest: "sha256:message",
      },
    });
    await prisma.findingTriageEvent.create({
      data: {
        identityId: identity.id,
        fromStatus: "open",
        toStatus: "confirmed",
        reason: "fixture evidence reviewed",
        actor: "integration@example.test",
      },
    });
    const finding = await prisma.finding.create({
      data: {
        scanId: scan.id,
        ruleId: "AEG-INTEGRATION-001",
        ruleName: "Evidence integration",
        severity: "high",
        filePath: "api/OrderController.kt",
        lineStart: 7,
        lineEnd: 7,
        message: "integration evidence",
        fingerprint: identity.fingerprint,
        baselineState: "new",
        identityId: identity.id,
        ...evidence,
        ...classification,
      },
      include: { scan: true },
    });
    const agentRun = await prisma.agentRun.create({
      data: {
        scanId: scan.id,
        mode: "deep",
        status: "awaiting_approval",
        workspaceSnapshot: scan.workspaceSnapshot,
        artifactDigest: `sha256:${"a".repeat(64)}`,
      },
    });
    const agentStage = await prisma.agentStage.create({
      data: {
        runId: agentRun.id,
        sequence: 2,
        role: "dynamic",
        agentCode: "salgwaengi",
        agentName: "살쾡이",
        status: "waiting_approval",
      },
    });
    const approval = await prisma.agentApproval.create({
      data: {
        runId: agentRun.id,
        resourceId: "plan-fixture",
        scopeDigest: `sha256:${"b".repeat(64)}`,
      },
    });
    const runtimeEvidence = await prisma.agentEvidenceRecord.create({
      data: {
        runId: agentRun.id,
        approvalId: approval.id,
        kind: "dynamic_harness",
        producer: "aegify-http-harness",
        status: "passed",
        digest: `sha256:${"c".repeat(64)}`,
        payload: "{}",
      },
    });
    const managedFinding = await prisma.finding.update({
      where: { id: finding.id },
      data: {
        owner: "appsec",
        priority: "p1",
        tags: JSON.stringify(["internet-facing"]),
        ticketProvider: "jira",
        ticketKey: "SEC-123",
        ticketUrl: "https://company.atlassian.net/browse/SEC-123",
      },
    });

    assert.equal(finding.evidenceId, "ev:integration");
    assert.equal(finding.repositoryId, "orders");
    assert.equal(finding.evidenceState, "reachable");
    assert.equal(finding.disposition, "blocking");
    assert.equal(finding.scan.workspaceSnapshot, "sha256:workspace");
    assert.equal(JSON.parse(finding.provenance).contract_version, 1);
    assert.equal(llmJob.status, "pending");
    assert.equal(nextLlmJob.activeKey, scan.id);
    assert.ok(rule.updatedAt instanceof Date);
    assert.equal(project.userId, user.id);
    const persistedIdentity = await prisma.findingIdentity.findUnique({
      where: { id: identity.id },
      include: { triageEvents: true },
    });
    assert.equal(persistedIdentity?.triageEvents[0].reason, "fixture evidence reviewed");
    assert.equal(finding.identityId, identity.id);
    assert.equal(agentStage.agentName, "살쾡이");
    assert.equal(runtimeEvidence.approvalId, approval.id);
    assert.equal(managedFinding.owner, "appsec");
    assert.equal(managedFinding.ticketKey, "SEC-123");

    // Real database regression: an incomplete or differently scoped upload
    // cannot turn a previously recorded observation into a resolved absence.
    await prisma.scan.update({ where: { id: scan.id }, data: { branch: "main" } });
    const excluded = await prisma.findingIdentity.create({ data: {
      projectId: project.id, fingerprint: "excluded", ruleId: rule.id, filePath: "excluded.kt",
    } });
    const disabled = await prisma.findingIdentity.create({ data: {
      projectId: project.id, fingerprint: "disabled", ruleId: "AEG-DISABLED", filePath: finding.filePath,
    } });
    const health = scanHealthForRun({
      analysisStatus: "completed", analysisScope: "repository",
      evaluatedRules: [rule.id], analyzedFiles: [finding.filePath],
      sourceIdentityVersion: 1,
      analyzedSources: [{ repositoryId: finding.repositoryId, modulePath: finding.modulePath, filePath: finding.filePath }],
    }, { executionSuccessful: true });
    for (const branch of ["feature", "main"]) {
      const imported = await prisma.scan.create({ data: { projectId: project.id, branch, status: "running" } });
      const scanHealth = branch === "main" ? { ...health, status: "partial" as const } : health;
      await finalizeScanImport(prisma, { scanId: imported.id, projectId: project.id, branch, defaultBranch: "main", health: scanHealth });
      assert.equal((await prisma.findingIdentity.findUniqueOrThrow({ where: { id: identity.id } })).absentAt, null);
      assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: finding.id } })).isCurrent, true);
      assert.equal((await prisma.scan.findUniqueOrThrow({ where: { id: imported.id } })).status, scanHealth.status);
    }
    // Terminal-status failure rolls back every absence mutation.
    await assert.rejects(finalizeScanImport(prisma, {
      scanId: "missing-scan", projectId: project.id, branch: "main", defaultBranch: "main", health,
    }));
    assert.equal((await prisma.findingIdentity.findUniqueOrThrow({ where: { id: identity.id } })).absentAt, null);
    assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: finding.id } })).isCurrent, true);

    const completed = await prisma.scan.create({ data: { projectId: project.id, branch: "main", status: "running" } });
    // Audit persistence and absence must also commit together.
    await prisma.$executeRawUnsafe(`CREATE TRIGGER reject_import_audit BEFORE INSERT ON AuditEvent WHEN NEW.action = 'scan.import.finished' BEGIN SELECT RAISE(ABORT, 'synthetic audit outage'); END`);
    await assert.rejects(finalizeScanImport(prisma, { scanId: completed.id, projectId: project.id, branch: "main", defaultBranch: "main", health, audit: { actorId: "fixture", findings: 0 } }));
    assert.equal((await prisma.scan.findUniqueOrThrow({ where: { id: completed.id } })).status, "running");
    assert.equal((await prisma.findingIdentity.findUniqueOrThrow({ where: { id: identity.id } })).absentAt, null);
    await prisma.$executeRawUnsafe("DROP TRIGGER reject_import_audit");
    await finalizeScanImport(prisma, { scanId: completed.id, projectId: project.id, branch: "main", defaultBranch: "main", health });
    assert.ok((await prisma.findingIdentity.findUniqueOrThrow({ where: { id: identity.id } })).absentAt);
    assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: finding.id } })).isCurrent, false);
    for (const id of [excluded.id, disabled.id]) {
      assert.equal((await prisma.findingIdentity.findUniqueOrThrow({ where: { id } })).absentAt, null);
    }
  } finally {
    await prisma.$disconnect();
  }
});
