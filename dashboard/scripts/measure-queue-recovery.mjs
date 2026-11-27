// Measures local queue claims and encrypted recovery on disposable SQLite data.
import assert from "node:assert/strict";
import { log } from "node:console";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { arch, platform, tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { version } from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, URL } from "node:url";
import { parseArgs } from "node:util";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { configureDatabase } from "../src/lib/database-runtime.ts";
import { resolvePrincipal } from "../src/lib/project-access.ts";
import { cancelScanJob, claimScanJob, enqueueScan } from "../src/lib/scan-jobs.ts";
import { createEncryptedBackup, restoreEncryptedBackup, verifyEncryptedBackup } from "../src/lib/backup.ts";

const projects = 24;
const workers = 4;
const { values } = parseArgs({ options: { "service-ms": { type: "string", default: "0" } } });
const serviceMs = Number(values["service-ms"]);
if (!Number.isInteger(serviceMs) || serviceMs < 0 || serviceMs > 1000) throw new Error("--service-ms must be an integer between 0 and 1000");
const directory = await mkdtemp(join(tmpdir(), "aegify-queue-recovery-"));
const databasePath = join(directory, "queue.db");
const archivePath = join(directory, "backup.aegify");
const outputPath = join(directory, "restored.db");
const connect = (path) => new PrismaClient({ adapter: new PrismaLibSql({ url: "file:" + path }) });
const db = connect(databasePath);
const peers = Array.from({ length: workers }, () => connect(databasePath));
const environment = { NODE_ENV: "production", AUTH_SECRET: "owned-fixture", AUTH_ALLOWED_DOMAINS: "example.test" };
const keys = { backupKey: randomBytes(32).toString("hex"), encryptionSecret: randomBytes(32).toString("hex") };
let restored;

async function timed(operation) {
  const start = performance.now();
  const result = await operation();
  return { result, ms: Math.round((performance.now() - start) * 100) / 100 };
}

try {
  const sql = createClient({ url: "file:" + databasePath });
  try {
    const migrations = fileURLToPath(new URL("../prisma/migrations/", import.meta.url));
    const names = (await readdir(migrations, { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    for (const name of names) await sql.executeMultiple(await readFile(join(migrations, name, "migration.sql"), "utf8"));
  } finally { sql.close(); }
  await configureDatabase(db);
  for (const peer of peers) await configureDatabase(peer);
  const user = await db.user.create({ data: { email: "reviewer@example.test" } });
  await db.account.create({ data: { userId: user.id, type: "oauth", provider: "github", providerAccountId: "owned", access_token: "unused-fixture" } });
  const principal = await resolvePrincipal(db, user.id, environment);
  const queued = new Set();
  let project;
  for (let index = 0; index < projects; index++) {
    project = await db.project.create({ data: {
      name: "Queue fixture " + index, provider: "github", ownerSlug: "fixture/project-" + index,
      members: { create: { userId: user.id, role: "maintainer" } },
    } });
    const job = await enqueueScan(db, principal, project.id, "main", environment);
    queued.add(job.id);
  }
  const claimed = new Set();
  const latency = [];
  const emptyPollMs = [];
  const counts = Array(workers).fill(0);
  const drain = await timed(async () => {
    const results = await Promise.allSettled(peers.map(async (peer, index) => {
      for (;;) {
        const claim = await timed(() => claimScanJob(peer, "worker-" + index, environment));
        const job = claim.result;
        if (!job) { emptyPollMs.push(claim.ms); return; }
        assert.ok(queued.has(job.id) && !claimed.has(job.id));
        assert.equal(job.attempts, 1);
        claimed.add(job.id);
        counts[index]++;
        latency.push(claim.ms);
        if (serviceMs > 0) await delay(serviceMs);
        await cancelScanJob(peer, principal, job.id, environment);
      }
    }));
    for (const result of results) if (result.status === "rejected") throw result.reason;
  });
  assert.equal(claimed.size, projects);
  assert.equal(await db.scanJob.count({ where: { status: "cancelled" } }), projects);
  const pending = await enqueueScan(db, principal, project.id, "recovery", environment);
  const backup = await timed(() => createEncryptedBackup({ ...keys, databasePath, outputPath: archivePath }));
  const verify = await timed(() => verifyEncryptedBackup({ ...keys, archivePath }));
  const restore = await timed(() => restoreEncryptedBackup({ ...keys, archivePath, outputPath }));
  assert.equal(verify.result.databaseDigest, backup.result.databaseDigest);
  assert.equal(restore.result.manifest.databaseDigest, backup.result.databaseDigest);
  restored = connect(outputPath);
  assert.equal(await restored.project.count(), projects);
  assert.equal(await restored.scanJob.count({ where: { status: "cancelled" } }), projects + 1);
  assert.equal((await restored.scanJob.findUniqueOrThrow({ where: { id: pending.id } })).errorCode, "recovered_cancelled");
  assert.equal((await restored.user.findUniqueOrThrow({ where: { id: user.id } })).disabled, true);
  assert.equal((await db.scanJob.findUniqueOrThrow({ where: { id: pending.id } })).status, "queued");
  latency.sort((a, b) => a - b);
  log(JSON.stringify({
    workload: "owned-queue-recovery-v1", testedAt: new Date().toISOString(), platform: platform(), arch: arch(), node: version,
    workers, projects, serviceMs, claimsPerWorker: counts, uniqueClaims: claimed.size, claimMs: latency, emptyPollMs,
    claimP50Ms: latency[Math.ceil(latency.length * 0.5) - 1], claimP95Ms: latency[Math.ceil(latency.length * 0.95) - 1],
    drainMs: drain.ms, archiveBytes: (await stat(archivePath)).size, backupMs: backup.ms,
    verifyMs: verify.ms, restoreMs: restore.ms, restoredJobs: projects + 1, restoredAccountDisabled: true,
  }, null, 2));
} finally {
  await Promise.allSettled([db, ...peers, ...(restored ? [restored] : [])].map((client) => client.$disconnect()));
  await rm(directory, { recursive: true, force: true });
}
