// Run with Node's TypeScript stripping and the scanner environment installed.
// Uses owned checkout source, a disposable database and a scripted provider transport.
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { arch, platform, tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, URL } from "node:url";
import { parseArgs } from "node:util";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createEncryptedBackup, restoreEncryptedBackup, verifyEncryptedBackup } from "../src/lib/backup.ts";
import { encrypt } from "../src/lib/crypto.ts";
import { configureDatabase, writeTransaction } from "../src/lib/database-runtime.ts";
import {
  AiLeaseLost,
  AI_LEASE_MS,
  claimLlmJob,
  enqueueLlmJob,
  heartbeatLlmJob,
} from "../src/lib/llm-jobs.ts";
import { resolvePrincipal } from "../src/lib/project-access.ts";
import { claimScanJob, enqueueScan, heartbeatScanJob, LeaseLost, LEASE_MS } from "../src/lib/scan-jobs.ts";
import { makeSourceSnapshot } from "../src/lib/scan-worker.ts";

const args = parseArgs({ options: { projects: { type: "string", default: "24" } } });
const projects = Number(args.values.projects);
if (!Number.isInteger(projects) || projects < 4 || projects > 100)
  throw new Error("--projects must be between 4 and 100");
const started = performance.now();
const components = fileURLToPath(new URL("../src/components/", import.meta.url));
async function componentFiles(relative = "") {
  const files = [];
  for (const item of await readdir(join(components, relative), { withFileTypes: true })) {
    const path = relative ? relative + "/" + item.name : item.name;
    if (item.isDirectory()) files.push(...(await componentFiles(path)));
    else if (item.isFile() && /\.tsx?$/.test(item.name)) {
      files.push({ path: "src/components/" + path, content: await readFile(join(components, path), "utf8") });
    }
  }
  return files;
}
const files = (await componentFiles()).sort((a, b) => (a.path < b.path ? -1 : 1));
files.push({
  path: "wrangler.jsonc",
  content: '{"name":"billing","vars":{"API_TOKEN":"owned-configuration-placeholder"}}',
});
const serializedFiles = JSON.stringify(files);
const commit = createHash("sha1").update(serializedFiles).digest("hex");
const sourceSha256 = createHash("sha256").update(serializedFiles).digest("hex");
const rehearsalHash = createHash("sha256");
for (const path of [
  "./measure-worker-recovery.mjs",
  "./recovery-pool-worker.mjs",
  "../package-lock.json",
  "../src/lib/backup.ts",
  "../src/lib/database-runtime.ts",
  "../src/lib/llm-jobs.ts",
  "../src/lib/llm-worker.ts",
  "../src/lib/scan-jobs.ts",
  "../src/lib/scan-worker.ts",
  "../src/lib/worker-registry.ts",
]) {
  rehearsalHash.update(path + "\0").update(
    createHash("sha256")
      .update(await readFile(new URL(path, import.meta.url)))
      .digest(),
  );
}
const bytes = files.reduce((count, file) => count + globalThis.Buffer.byteLength(file.content), 0);
const historicalRows = 24_000;
const directory = await mkdtemp(join(tmpdir(), "aegify-worker-rehearsal-"));
const databasePath = join(directory, "queue.db");
const archivePath = join(directory, "backup.aegify");
const outputPath = join(directory, "restored.db");
const keys = {
  backupKey: randomBytes(32).toString("hex"),
  encryptionSecret: randomBytes(32).toString("hex"),
};
const env = {
  NODE_ENV: "production",
  AUTH_SECRET: "owned-auth",
  AUTH_ALLOWED_DOMAINS: "example.test",
  ENCRYPTION_SECRET: keys.encryptionSecret,
};
process.env.ENCRYPTION_SECRET = keys.encryptionSecret;
const connect = (path) => new PrismaClient({ adapter: new PrismaLibSql({ url: "file:" + path }) });
const db = connect(databasePath);
const children = [];
let restored;

function launch(queue, worker, incident) {
  const path = fileURLToPath(new URL("./recovery-pool-worker.mjs", import.meta.url));
  const child = fork(path, [], {
    execArgv: ["--experimental-strip-types"],
    stdio: ["ignore", "ignore", "pipe", "ipc"],
    env: {
      ...env,
      DATABASE_URL: "file:" + databasePath,
      TMPDIR: directory,
      PATH: process.env.PATH,
      LANG: "C.UTF-8",
    },
  });
  const peer = {
    child,
    worker,
    queue,
    incident,
    ready: false,
    crashJob: null,
    claims: [],
    processed: [],
    commits: [],
    dispatches: [],
    ended: false,
    stderr: "",
  };
  children.push(peer);
  child.stderr.on("data", (part) => {
    peer.stderr = (peer.stderr + part.toString()).slice(-1800);
  });
  peer.exited = new Promise((resolve) => {
    child.once("error", (error) => {
      peer.error = error;
    });
    child.once("close", (code, signal) => {
      peer.ended = true;
      peer.exit = { code, signal };
      resolve(peer.exit);
    });
  });
  child.on("message", (message) => {
    if (message.type === "ready") peer.ready = true;
    if (message.type === "crash-point") peer.crashJob = message.jobId;
    if (message.type === "claim") peer.claims.push(message);
    if (message.type === "processed") peer.processed.push(message);
    if (message.type === "commit") peer.commits.push(message);
    if (message.type === "transport") peer.dispatches.push(message);
  });
  child.send({ databasePath, worker, incident, queue });
  return peer;
}

async function until(check, label, timeout = 90_000) {
  const end = performance.now() + timeout;
  while (performance.now() < end) {
    for (const peer of children) {
      if (peer.error) throw peer.error;
      if (peer.ended && !peer.expectedExit)
        throw new Error(peer.worker + " exited during " + label + ": " + peer.stderr);
    }
    if (await check()) return;
    await delay(100);
  }
  throw new Error("Timed out waiting for " + label);
}
async function start(peers) {
  await until(() => peers.every((peer) => peer.ready), "worker startup");
  for (const peer of peers) peer.child.send("start");
}
async function killAt(peer, id) {
  await until(() => peer.crashJob, peer.worker + " interruption");
  assert.equal(peer.crashJob, id);
  peer.expectedExit = true;
  peer.child.kill("SIGKILL");
  assert.deepEqual(await peer.exited, { code: null, signal: "SIGKILL" });
}
async function timed(operation) {
  const before = performance.now();
  const value = await operation();
  return { value, ms: Math.round(performance.now() - before) };
}
function distribution(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const quantile = (p) => Math.round(sorted[Math.ceil(p * sorted.length) - 1] * 100) / 100;
  return { samples: sorted.length, medianMs: quantile(0.5), p95Ms: quantile(0.95), maxMs: quantile(1) };
}
async function enqueue(principal, index, { withSource = true, findings = 1 } = {}) {
  const repository = "owned/billing-" + index;
  const project = await db.project.create({
    data: {
      name: repository,
      ownerSlug: repository,
      provider: "github",
      members: { create: { userId: principal.userId, role: "maintainer" } },
    },
  });
  let source;
  if (withSource) {
    source = await enqueueScan(db, principal, project.id, "main", env, commit);
    const snapshot = makeSourceSnapshot(
      { provider: "github", ownerSlug: repository, commitSha: commit },
      { ref: commit, files, truncated: false },
    );
    await db.scanJob.update({
      where: { id: source.id },
      data: {
        sourceDigest: snapshot.sourceDigest,
        sourceCiphertext: encrypt(JSON.stringify(snapshot)),
        sourceManifest: JSON.stringify({
          version: 1,
          commit,
          sourceDigest: snapshot.sourceDigest,
          files: snapshot.files.map(({ path, sha256 }) => ({ path, sha256 })),
        }),
      },
    });
  }
  const scan = await db.scan.create({
    data: { projectId: project.id, repository, commitSha: commit, status: "completed" },
  });
  await db.finding.createMany({
    data: Array.from({ length: findings }, (_, i) => ({
      scanId: scan.id,
      ruleId: "OWNED-PROJECTION",
      ruleName: "Review receipt fields",
      severity: "low",
      filePath: "receipts.py",
      lineStart: i + 1,
      lineEnd: i + 1,
      codeSnippet: "return formatter(receipt)",
      message: "Check the returned fields.",
      status: "triaged",
    })),
  });
  const ai = await enqueueLlmJob(db, principal, scan.id, "deep", false, env);
  return { source, ai };
}
const reviewEvidence = (client, jobId) =>
  client.llmReview.findMany({
    where: { jobId },
    orderBy: { ordinal: "asc" },
    select: { id: true, findingId: true, callId: true, evidenceDigest: true, payloadDigest: true },
  });
const activeSource = { status: { in: ["queued", "running"] } };
const activeReview = { status: { in: ["pending", "running"] } };

try {
  const sql = createClient({ url: "file:" + databasePath });
  try {
    const path = fileURLToPath(new URL("../prisma/migrations/", import.meta.url));
    const entries = (await readdir(path, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    for (const name of entries)
      await sql.executeMultiple(await readFile(join(path, name, "migration.sql"), "utf8"));
  } finally {
    sql.close();
  }
  await configureDatabase(db);
  for (let i = 0; i < historicalRows; i += 500) {
    await db.auditEvent.createMany({
      data: Array.from({ length: 500 }, (_, offset) => ({
        actorId: "historical-fixture",
        action: "scan.completed",
        targetId: "run-" + (i + offset),
        details: JSON.stringify({ repository: "owned/billing", ref: "main", result: "published", commit }),
      })),
    });
  }
  const user = await db.user.create({ data: { email: "reviewer@example.test" } });
  await db.account.create({
    data: {
      userId: user.id,
      type: "oauth",
      provider: "github",
      providerAccountId: "owned",
      access_token: "unused-fixture",
    },
  });
  await db.setting.createMany({
    data: Object.entries({
      "llm.enabled": "true",
      "llm.provider": "anthropic",
      "llm.model": "fixture-model",
      "llm.anthropic_api_key": "owned-placeholder",
    }).map(([key, value]) => ({ key, value })),
  });
  const principal = await resolvePrincipal(db, user.id, env);
  const incident = await enqueue(principal, "interrupted", { findings: 51 });
  const sourceCrash = launch("source", "source-interrupted", "after-claim");
  const dispatchCrash = launch("ai", "ai-dispatched", "after-dispatch");
  await start([sourceCrash, dispatchCrash]);
  await Promise.all([killAt(sourceCrash, incident.source.id), killAt(dispatchCrash, incident.ai.id)]);
  const next = await enqueue(principal, "undispatched", { withSource: false });
  const beforeDispatch = launch("ai", "ai-undispatched", "after-claim");
  await start([beforeDispatch]);
  await killAt(beforeDispatch, next.ai.id);
  const abandonedScan = await db.scanJob.findUniqueOrThrow({ where: { id: incident.source.id } });
  const abandonedReview = await db.llmJob.findUniqueOrThrow({ where: { id: incident.ai.id } });
  const pendingReview = await db.llmJob.findUniqueOrThrow({ where: { id: next.ai.id } });
  assert.equal(abandonedReview.reviewedCount, 50);
  const evidence = await reviewEvidence(db, incident.ai.id);
  assert.equal(evidence.length, 50);
  assert.equal(await db.llmCall.count({ where: { jobId: next.ai.id } }), 0);
  assert.equal(await db.llmCall.count({ where: { jobId: incident.ai.id, status: "dispatched" } }), 1);
  assert.equal(await claimScanJob(db, "early-observer", env), null);
  assert.equal(await claimLlmJob(db, "early-observer", env), null);

  const work = [];
  for (let n = 0; n < projects; n++) work.push(await enqueue(principal, n));
  const pool = [
    launch("source", "source-1"),
    launch("source", "source-2"),
    launch("ai", "ai-1"),
    launch("ai", "ai-2"),
  ];
  const beginDrain = performance.now();
  await start(pool);
  await until(
    () =>
      ["source", "ai"].every((queue) =>
        pool.some((peer) => peer.queue === queue && peer.processed.length > 0),
      ),
    "first publications",
  );
  const writer = launch("audit", "audit-writer");
  await start([writer]);
  await until(() => writer.commits.length >= 3, "concurrent audit writes");
  const marker = () =>
    writeTransaction(db, (tx) =>
      tx.auditEvent.create({
        data: { actorId: "fixture", action: "rehearsal.boundary", targetId: "backup" },
      }),
    );
  const before = await marker();
  const backup = await timed(() => createEncryptedBackup({ ...keys, databasePath, outputPath: archivePath }));
  const after = await marker();
  const committedAtBackup = writer.commits.length;
  await until(() => writer.commits.length >= committedAtBackup + 3, "writes after backup");
  writer.expectedExit = true;
  writer.child.send("stop");
  assert.deepEqual(await writer.exited, { code: 0, signal: null });
  const verified = await timed(() => verifyEncryptedBackup({ ...keys, archivePath }));
  const recovery = await timed(() => restoreEncryptedBackup({ ...keys, archivePath, outputPath }));
  assert.equal(verified.value.databaseDigest, backup.value.databaseDigest);
  assert.equal(recovery.value.manifest.databaseDigest, backup.value.databaseDigest);
  restored = connect(outputPath);
  assert.ok(await restored.auditEvent.findUnique({ where: { id: before.id } }));
  assert.equal(await restored.auditEvent.findUnique({ where: { id: after.id } }), null);
  assert.equal(await restored.auditEvent.count({ where: { actorId: "historical-fixture" } }), historicalRows);
  const copiedRows = await restored.auditEvent.findMany({
    where: { actorId: "rehearsal-concurrent-writer" },
    select: { action: true, targetId: true },
  });
  const copiedPairs = copiedRows.length / 2;
  assert.ok(Number.isInteger(copiedPairs) && copiedPairs >= 3 && copiedPairs < writer.commits.length);
  const copied = new Set(copiedRows.map((row) => row.targetId + "/" + row.action));
  for (let i = 1; i <= copiedPairs; i++) {
    assert.ok(
      copied.has(i + "/opened") && copied.has(i + "/closed"),
      "Restored an incomplete audit transaction",
    );
  }
  assert.deepEqual(await reviewEvidence(restored, incident.ai.id), evidence);
  const uncertain = await restored.llmJob.findUniqueOrThrow({ where: { id: incident.ai.id } });
  assert.deepEqual([uncertain.status, uncertain.reviewedCount, uncertain.activeKey], ["partial", 50, null]);
  assert.equal(await restored.llmCall.count({ where: { jobId: incident.ai.id, status: "unknown" } }), 1);
  assert.equal(
    (await restored.scanJob.findUniqueOrThrow({ where: { id: incident.source.id } })).errorCode,
    "recovered_cancelled",
  );
  assert.equal((await restored.user.findUniqueOrThrow({ where: { id: user.id } })).disabled, true);
  assert.equal(await restored.scanJob.count({ where: activeSource }), 0);
  assert.equal(await restored.llmJob.count({ where: activeReview }), 0);
  assert.equal(await restored.scanWorker.count(), 0);
  assert.equal(await restored.llmWorker.count(), 0);
  const sourceIds = work.map((job) => job.source.id);
  const reviewIds = work.map((job) => job.ai.id);
  await until(
    async () => {
      const [sourceStates, aiStates] = await Promise.all([
        db.scanJob.findMany({ where: { id: { in: sourceIds } }, select: { status: true, errorCode: true } }),
        db.llmJob.findMany({ where: { id: { in: reviewIds } }, select: { status: true, errorCode: true } }),
      ]);
      for (const job of [...sourceStates, ...aiStates]) {
        if (!["completed", "pending", "queued", "running"].includes(job.status))
          throw new Error("Ordinary publication ended " + job.status + " (" + job.errorCode + ")");
      }
      return [...sourceStates, ...aiStates].every((job) => job.status === "completed");
    },
    "ordinary publications",
    600_000,
  );
  const drainMs = Math.round(performance.now() - beginDrain);
  process.stderr.write(
    "Ordinary jobs published and encrypted restore checked; waiting for the original worker leases.\n",
  );
  await until(
    async () =>
      (await db.scanJob.count({ where: activeSource })) === 0 &&
      (await db.llmJob.count({ where: activeReview })) === 0,
    "original lease expiration and recovery",
    Math.max(LEASE_MS, AI_LEASE_MS) + 90_000,
  );
  for (const peer of pool) {
    peer.expectedExit = true;
    peer.child.send("stop");
  }
  for (const peer of pool) assert.deepEqual(await peer.exited, { code: 0, signal: null });
  const sourceJobs = await db.scanJob.findMany({
    include: { scan: { select: { status: true, filesScanned: true } } },
  });
  assert.equal(sourceJobs.length, projects + 1);
  assert.equal(new Set(sourceJobs.map((job) => job.scanId)).size, sourceJobs.length);
  let scanner;
  for (const job of sourceJobs) {
    assert.equal(job.status, "completed", job.errorCode);
    assert.equal(job.scan.status, "completed");
    assert.equal(job.scan.filesScanned, files.length);
    const manifest = JSON.parse(job.resultManifest);
    assert.equal(job.commitSha, commit);
    assert.equal(manifest.sourceDigest, job.sourceDigest);
    assert.match(manifest.engineDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(manifest.rulesDigest, /^sha256:[0-9a-f]{64}$/);
    const identity = {
      version: manifest.engine,
      python: manifest.python,
      treeSitter: manifest.treeSitter,
      engineDigest: manifest.engineDigest,
      rulesDigest: manifest.rulesDigest,
    };
    if (scanner) assert.deepEqual(identity, scanner);
    else scanner = identity;
    assert.equal(job.attempts, job.id === incident.source.id ? 2 : 1);
    assert.equal(await db.scanJobEvent.count({ where: { jobId: job.id, code: "published" } }), 1);
  }
  const configurations = await db.finding.findMany({
    where: {
      scanId: { in: sourceJobs.map((job) => job.scanId) },
      ruleId: "AEG-CF-001",
      filePath: "wrangler.jsonc",
    },
    select: { scanId: true, codeSnippet: true },
  });
  assert.equal(configurations.length, sourceJobs.length);
  assert.equal(new Set(configurations.map((record) => record.scanId)).size, sourceJobs.length);
  for (const record of configurations) {
    assert.match(record.codeSnippet, /vars\.API_TOKEN = \[withheld\]/);
    assert.ok(!record.codeSnippet.includes("owned-configuration-placeholder"));
  }
  const reviews = await db.llmJob.findMany({
    include: { calls: { orderBy: { batchIndex: "asc" }, select: { status: true } } },
  });
  const dispatches = children.flatMap((peer) => peer.dispatches);
  assert.equal(reviews.length, projects + 2);
  assert.equal(dispatches.length, projects + 3);
  assert.equal(beforeDispatch.dispatches.length, 0);
  assert.equal(dispatchCrash.dispatches.length, 2);
  const replayedDispatches =
    dispatches.length - new Set(dispatches.map((event) => event.jobId + "/" + event.digest)).size;
  assert.equal(replayedDispatches, 0);
  for (const job of reviews) {
    assert.equal(dispatches.filter((event) => event.jobId === job.id).length, job.calls.length);
    assert.equal(job.attempts, job.id === next.ai.id ? 2 : 1);
    if (job.id === incident.ai.id) {
      assert.deepEqual(
        [job.status, job.errorCode, job.reviewedCount],
        ["partial", "provider_outcome_unknown", 50],
      );
      assert.deepEqual(
        job.calls.map((c) => c.status),
        ["completed", "unknown"],
      );
    } else {
      assert.equal(job.status, "completed", job.errorCode);
      assert.equal(job.reviewedCount, 1);
      assert.deepEqual(
        job.calls.map((c) => c.status),
        ["completed"],
      );
    }
  }
  assert.deepEqual(await reviewEvidence(db, incident.ai.id), evidence);
  await assert.rejects(heartbeatScanJob(db, abandonedScan, env), LeaseLost);
  for (const job of [abandonedReview, pendingReview])
    await assert.rejects(heartbeatLlmJob(db, job, env), AiLeaseLost);
  const resumed = await db.scanJob.findUniqueOrThrow({ where: { id: incident.source.id } });
  const resumedAi = await db.llmJob.findUniqueOrThrow({ where: { id: next.ai.id } });
  const sourceRecovery = await db.scanJobEvent.findFirstOrThrow({
    where: { jobId: resumed.id, code: "recovered" },
  });
  const aiRecovery = await db.llmJobEvent.findFirstOrThrow({
    where: { jobId: resumedAi.id, code: "recovered" },
  });
  assert.ok(sourceRecovery.createdAt >= abandonedScan.leaseExpiresAt);
  assert.ok(aiRecovery.createdAt >= pendingReview.leaseExpiresAt);
  const ordinary = Object.fromEntries(
    ["source", "ai"].map((queue) => {
      const peers = pool.filter((peer) => peer.queue === queue);
      const ids = new Set(queue === "source" ? sourceIds : reviewIds);
      const claims = peers.flatMap((peer) => peer.claims.filter((c) => ids.has(c.jobId)));
      assert.equal(claims.length, projects);
      assert.equal(new Set(claims.map((c) => c.jobId)).size, projects);
      assert.ok(peers.every((peer) => peer.claims.some((c) => ids.has(c.jobId))));
      const service = peers.flatMap((peer) => peer.processed.filter((c) => ids.has(c.jobId)));
      assert.equal(service.length, projects);
      return [
        queue,
        {
          claimsPerProcess: peers.map((peer) => peer.claims.filter((c) => ids.has(c.jobId)).length),
          claim: distribution(claims.map((c) => c.claimMs)),
          service: distribution(service.map((c) => c.serviceMs)),
        },
      ];
    }),
  );
  const snapshotWindow = {
    gte: new Date(backup.value.snapshotStartedAt),
    lte: new Date(backup.value.snapshotCompletedAt),
  };
  const report = {
    version: 1,
    testedAt: new Date().toISOString(),
    platform: platform(),
    architecture: arch(),
    node: process.version,
    implementation: { rehearsalSha256: rehearsalHash.digest("hex"), scanner },
    workload: {
      ordinaryProjects: projects,
      drainProcesses: pool.length,
      terminatedProcesses: 3,
      source: "Aegify dashboard TypeScript components and a synthetic Wrangler manifest",
      filesPerSource: files.length,
      sourceBytesPerJob: bytes,
      sourceSha256,
      fixtureCommit: commit,
      historicalAuditEvents: historicalRows,
      provider: "scripted in-process transport",
    },
    ordinary,
    drainMs,
    totalMs: Math.round(performance.now() - started),
    source: {
      published: sourceJobs.length,
      redactedConfigurationFindings: configurations.length,
      interruptedAttempts: resumed.attempts,
      leaseMs: LEASE_MS,
      afterExpiryMs: sourceRecovery.createdAt - abandonedScan.leaseExpiresAt,
    },
    ai: {
      jobs: reviews.length,
      leaseMs: AI_LEASE_MS,
      resumedBeforeDispatchAttempts: resumedAi.attempts,
      afterExpiryMs: aiRecovery.createdAt - pendingReview.leaseExpiresAt,
      interruptedAfterDispatch: "partial",
      publishedBeforeInterruption: evidence.length,
      transportEntries: dispatches.length,
      unresolvedDispatches: 1,
      replayedDispatches,
    },
    backup: {
      snapshotMs: snapshotWindow.lte - snapshotWindow.gte,
      archiveMs: backup.ms,
      verifyMs: verified.ms,
      restoreMs: recovery.ms,
      archiveBytes: (await stat(archivePath)).size,
      auditTransactions: writer.commits.length,
      copiedAuditTransactions: copiedPairs,
      auditTransactionsWhollyInsideSnapshot: writer.commits.filter(
        (row) => row.begin > +snapshotWindow.gte && row.end < +snapshotWindow.lte,
      ).length,
      restoredSourceJobs: await restored.scanJob.count(),
      restoredReviewJobs: await restored.llmJob.count(),
      restoredReviews: await restored.llmReview.count(),
      bothBoundaryMarkersChecked: true,
      activeRestoredJobs: 0,
      interruptedReviewsPreserved: evidence.length,
      restoredAccountDisabled: true,
    },
  };
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
} finally {
  for (const peer of children) if (!peer.ended && peer.child.connected) peer.child.send("stop");
  await Promise.all(
    children.map(async (peer) => {
      if (peer.ended) return;
      const timeout = globalThis.setTimeout(() => peer.child.kill("SIGKILL"), 3000);
      try {
        await peer.exited;
      } finally {
        globalThis.clearTimeout(timeout);
      }
    }),
  );
  await Promise.allSettled([db, ...(restored ? [restored] : [])].map((client) => client.$disconnect()));
  await rm(directory, { recursive: true, force: true });
}
