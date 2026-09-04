import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { PrismaLibSql } from "@prisma/adapter-libsql";
import { PrismaClient } from "@prisma/client";
import { createClient } from "@libsql/client";

import {
  normalizeFindingClassification,
  normalizeFindingEvidence,
  workspaceSnapshotForRun,
} from "./sarif-evidence.ts";

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
  } finally {
    await prisma.$disconnect();
  }
});
