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
  scanCoverageForRun,
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

test("solver truncation survives a successful invocation and a missing top-level gap", () => {
  const done = { executionSuccessful: true };
  for (const summary of [{ truncated: true }, { limits_reached: ["contexts"] }, { limits_reached: ["iterations"] }]) {
    const health = scanHealthForRun({ analysisStatus: "completed", taintAnalysis: summary }, done);
    assert.equal(health.status, "partial");
    assert.deepEqual(health.gaps.map((gap) => gap.code), ["taint_limit"]);
    const repeated = scanHealthForRun({ taintAnalysis: summary, analysisGaps: health.gaps }, done);
    assert.deepEqual(repeated.gaps, health.gaps);
  }
  assert.equal(scanHealthForRun({ taintAnalysis: { truncated: false, limits_reached: [] } }, done).status, "completed");
  const legacy = { truncated: true, contexts_analyzed: 10000, warnings: ["global taint hit the 10000-context bound"] };
  const generic = [{ code: "taint_limit", stage: "taint", message: "Taint analysis reached its configured bound", affected_count: 1 }];
  assert.match(scanHealthForRun({ analysisGaps: generic, taintAnalysis: legacy }, done).gaps[0].message, /limit of 10,000 call contexts/);
  assert.doesNotMatch(scanHealthForRun({ taintAnalysis: { ...legacy, contexts_analyzed: 700 } }, done).gaps[0].message, /700|10,000/);
  assert.match(scanHealthForRun({ taintAnalysis: { limits_reached: ["iterations"], iteration_limit: 3, iterations: 3 } }, done).gaps[0].message, /after 3 passes/);
});

test("coverage receipts distinguish missing inventories, empty arrays and bounded diagnostics", () => {
  const run = { analysisScope: "files", analyzedFiles: ["one.py", "one.py"], evaluatedRules: ["RULE", "RULE"] };
  const invocation = { properties: { analysisGaps: Array(105).fill({ code: "incomplete" }) }, executionSuccessful: true };
  const health = scanHealthForRun(run, invocation);
  health.gaps.push({ code: "identity", stage: "import", message: "import gap", affected_count: 1 });
  assert.deepEqual(scanCoverageForRun(health, run, invocation.properties), { scope: "files", files: 1, rules: 1, gaps: 106 });
  for (const [input, expected] of [
    [{}, { scope: "unknown", files: null, rules: null, gaps: null }],
    [{ analyzedFiles: [false], evaluatedRules: ["lower case"] }, { scope: "unknown", files: null, rules: null, gaps: null }],
    [{ analyzedFiles: [], evaluatedRules: [], analysisGaps: [] }, { scope: "unknown", files: 0, rules: 0, gaps: 0 }],
  ] as const) assert.deepEqual(scanCoverageForRun(scanHealthForRun(input), input), expected);
});

test("all invocation statuses and diagnostics constrain completion and absence", () => {
  const run = { analysisStatus: "completed", analysisScope: "workspace", analyzedFiles: ["app.py"], evaluatedRules: ["RULE"], analysisGaps: [] };
  const done = { executionSuccessful: true, properties: { analysisStatus: "completed", analysisGaps: [] } };
  const clean = scanHealthForRun(run, [done, done]);
  assert.equal(canReconcileScanAbsence(clean, "main", "main"), true);
  for (const [last, status] of [
    [{ executionSuccessful: true, properties: { analysisStatus: "failed" } }, "failed"],
    [{ executionSuccessful: true, properties: { analysisStatus: "partial" } }, "partial"],
    [{ executionSuccessful: false, properties: { analysisStatus: "partial" } }, "partial"],
    [{ executionSuccessful: false, properties: { analysisStatus: "completed" } }, "failed"],
    [{ executionSuccessful: true, properties: { analysisStatus: null } }, "failed"],
    [{}, "failed"],
    [{ executionSuccessful: true, properties: { analysisGaps: [{ code: "parse_error" }] } }, "partial"],
    [{ executionSuccessful: true, properties: { analysisGaps: "malformed" } }, "partial"],
    [{ executionSuccessful: true, properties: { taintAnalysis: { truncated: true } } }, "partial"],
  ] as const) {
    for (const invocations of [[done, last], [last, done]]) {
      const health = scanHealthForRun(run, invocations);
      assert.equal(health.status, status);
      assert.equal(canReconcileScanAbsence(health, "main", "main"), false);
    }
  }
  assert.equal(scanHealthForRun(run, []).status, "failed");
  assert.equal(scanHealthForRun({ ...run, analysisStatus: "partial" }, [done, {
    executionSuccessful: true, properties: { analysisStatus: "failed" },
  }]).status, "failed");
});

test("mirrored diagnostics retain within-report multiplicity and count later invocation-only gaps", () => {
  const gap = { code: "budget", stage: "analysis", message: "Bound reached", affected_count: 1 };
  const repeated = Array(105).fill(gap);
  const run = { analysisGaps: repeated };
  const first = { executionSuccessful: true, properties: { analysisGaps: [...repeated] } };
  const last = { executionSuccessful: true, properties: { analysisGaps: [gap, { ...gap, message: "Different bound" }] } };
  const health = scanHealthForRun(run, [first, last]);
  assert.equal(health.gaps.length, 100);
  assert.equal(scanCoverageForRun(health, run, [first, last]).gaps, 106);
  assert.equal(scanCoverageForRun(scanHealthForRun(run, first), run, first.properties).gaps, 105);
  assert.equal(scanCoverageForRun(scanHealthForRun(run, first), run, first).gaps, 105);
  assert.equal(scanCoverageForRun(scanHealthForRun({}, [first, last]), {}, [first, last]).gaps, 106);
});

test("large diagnostic inventories retain exact mirrored counts and omit unverified totals", () => {
  const entries = Array.from({ length: 2_000 }, (_, index) => ({ code: "parse", message: String(index) }));
  const run = { analysisGaps: entries };
  const invoke = (analysisGaps: typeof entries) => ({ executionSuccessful: true, properties: { analysisGaps } });
  for (const list of [[...entries], entries.slice(0, 1_500)]) {
    const health = scanHealthForRun(run, invoke(list));
    const retry = { ...health, gaps: [...health.gaps] };
    assert.equal(retry.gaps.length, 100);
    assert.equal(scanCoverageForRun(retry).gaps, entries.length);
  }
  const mixed = scanHealthForRun(run, invoke([...entries].reverse()));
  assert.equal(mixed.status, "partial");
  assert.equal(mixed.gaps.length, 100);
  assert.equal(scanCoverageForRun(mixed).gaps, null);
});

test("workspace coverage verifies qualified counts including empty repositories", () => {
  const source = { repositoryId: "web", modulePath: "app.py", filePath: "/workspace/web/app.py" };
  const api = { ...source, repositoryId: "api-2", filePath: "/workspace/api/app.py" };
  const rows = [
    { repositoryId: "web", analyzedFiles: 1, discoveryErrors: 0 },
    { repositoryId: "api-2", analyzedFiles: 1, discoveryErrors: 0 },
    { repositoryId: "config_only", analyzedFiles: 0, discoveryErrors: 0 },
  ];
  const run = { analysisStatus: "completed", analysisScope: "workspace", evaluatedRules: ["RULE"],
    analyzedFiles: [source.filePath, api.filePath], sourceIdentityVersion: 1, analyzedSources: [source, api],
    repositoryCoverage: { version: 1, repositories: rows } };
  const done = { executionSuccessful: true };
  const health = scanHealthForRun(run, done);
  assert.deepEqual(health.repositoryCoverage, rows);
  assert.equal(canReconcileScanAbsence(health, "main", "main"), true);

  const incomplete = { ...run, repositoryCoverage: { version: 1, repositories: [rows[0], rows[1], { ...rows[2], discoveryErrors: 2 }] } };
  const discoveryGap = { code: "source_discovery_error", stage: "discovery", message: "Could not enumerate directory", affected_count: 2 };
  for (const invocation of [done, { ...done, properties: { analysisGaps: [discoveryGap] } }]) {
    const partial = scanHealthForRun(incomplete, invocation);
    assert.equal(partial.status, "partial");
    assert.deepEqual(partial.repositoryCoverage, incomplete.repositoryCoverage.repositories);
    assert.deepEqual(partial.gaps.map((gap) => gap.code), ["source_discovery_error"]);
    assert.equal(partial.gaps[0].affected_count, 2);
    assert.equal(canReconcileScanAbsence(partial, "main", "main"), false);
  }
  const fullDiagnostics = Array(105).fill({ code: "parser", message: "parse gap" }).concat([discoveryGap]);
  const truncatedDisplay = scanHealthForRun({ ...incomplete, analysisGaps: fullDiagnostics }, done);
  assert.equal(truncatedDisplay.gaps.length, 100);
  assert.ok(truncatedDisplay.gaps.some((gap) => gap.code === "source_discovery_error"));
  assert.equal(scanCoverageForRun(truncatedDisplay).gaps, 106);
  const emptyRun = { ...run, analyzedFiles: [], analyzedSources: [], repositoryCoverage: { version: 1, repositories: [rows[2]] } };
  assert.deepEqual(scanHealthForRun(emptyRun, done).repositoryCoverage, [rows[2]]);
  for (const patch of [{ analyzedFiles: undefined }, { analyzedFiles: false }, { analyzedFiles: [false] },
    { sourceIdentityVersion: undefined }, { analyzedSources: undefined }]) {
    assert.equal(scanHealthForRun({ ...emptyRun, ...patch }, done).repositoryCoverage, undefined);
  }
  for (const patch of [
    { analysisScope: "repository" }, { analysisScope: "files" }, { analysisScope: undefined },
    { sourceIdentityVersion: 2 }, { analyzedFiles: undefined }, { analyzedFiles: [source.filePath, api.filePath, api.filePath] },
    { analyzedSources: undefined }, { analyzedSources: [] }, { analyzedSources: [source, source] },
    { analyzedSources: [source, { ...api, repositoryId: "" }] },
    { analyzedSources: [source, { ...api, repositoryId: "orphan" }] },
    { repositoryCoverage: rows }, { repositoryCoverage: null }, { repositoryCoverage: { version: 2, repositories: rows } },
    { repositoryCoverage: { version: 1 } },
    { repositoryCoverage: { version: 1, repositories: rows.concat(Array.from({ length: 4_094 }, (_, i) =>
      ({ repositoryId: `extra-${i}`, analyzedFiles: 0, discoveryErrors: 0 }))) } },
    ...[[], [rows[0]], [...rows, rows[2]], [rows[0], rows[1], false],
      [rows[0], { ...rows[1], analyzedFiles: 0 }, { ...rows[2], analyzedFiles: 1 }],
      ...["", " leading", ".leading", "slash/id", "a".repeat(129)].map((id) => [rows[0], rows[1], { ...rows[2], repositoryId: id }]),
      ...[-1, 2.5, "2", 2_147_483_648].flatMap((n) => [
        [rows[0], rows[1], { ...rows[2], discoveryErrors: n }],
        [rows[0], rows[1], { ...rows[2], analyzedFiles: n }],
      ]),
    ].map((repositories) => ({ repositoryCoverage: { version: 1, repositories } })),
  ]) {
    const invalid = scanHealthForRun({ ...run, ...patch }, done);
    assert.equal(invalid.repositoryCoverage, undefined, JSON.stringify(patch));
    assert.equal(invalid.status, "partial");
    assert.ok(invalid.gaps.some((gap) => gap.code === "invalid_repository_coverage"));
    assert.equal(canReconcileScanAbsence(invalid, "main", "main"), false);
  }
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
