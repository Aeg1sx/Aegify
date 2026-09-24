import assert from "node:assert/strict";
import test, { after } from "node:test";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { resolvePrincipal } from "./project-access.ts";
import { configureDatabase } from "./database-runtime.ts";
import { AiLeaseLost, cancelLlmJob, claimLlmJob, enqueueLlmJob, heartbeatLlmJob, loadReviewSnapshot, publishLlmBatch, startLlmCall } from "./llm-jobs.ts";
import { runClaimedLlmJob, runLlmWorkerOnce } from "./llm-worker.ts";
import { callProviderDetailed } from "./provider-receipt.ts";
import { parseReviewResults, REVIEW_LIMITS } from "./ai-review-contract.ts";
import type { ProviderTransport } from "./public-https.ts";

const previousSecret = process.env.ENCRYPTION_SECRET;
process.env.ENCRYPTION_SECRET = "owned-ai-fixture-encryption-secret";
after(() => { if (previousSecret === undefined) delete process.env.ENCRYPTION_SECRET; else process.env.ENCRYPTION_SECRET = previousSecret; });
const env = { NODE_ENV: "production", AUTH_SECRET: "owned-auth", AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test" } as const;
const result = (id: string) => ({ findingId: id, verdict: "needs_review", confidence: 0.2, reasoning: "Static fixture evidence only.", remediation: "Review input constraints.", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["Runtime behavior was not observed."] });
function responseFor(request: Parameters<ProviderTransport>[0], count?: number) {
  const ids = (JSON.parse(JSON.parse(request.body).messages[0].content).findings as Array<{ id: string }>).map((finding) => finding.id);
  return { status: 200, text: JSON.stringify({ id: "owned-response", model: "fixture-model", stop_reason: "end_turn", usage: { input_tokens: 100, output_tokens: 40, cache_read_input_tokens: 0 }, content: [{ type: "text", text: JSON.stringify(ids.slice(0, count ?? ids.length).map(result)) }] }) };
}
const successful: ProviderTransport = async (request) => responseFor(request);
async function migrate(sql: ReturnType<typeof createClient>, legacy = false) {
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
    if (legacy && entry.name === "20260924060000_durable_ai_reviews") {
      await sql.execute('INSERT INTO "Scan" (id,repository) VALUES (\'legacy-scan\',\'owned\')');
      await sql.execute('INSERT INTO "LlmJob" (id,scanId,mode,status,activeKey) VALUES (\'legacy-job\',\'legacy-scan\',\'quick\',\'running\',\'legacy-scan\')');
    }
    await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  }
}
async function fixture(count = 2) {
  const directory = await mkdtemp(join(tmpdir(), "aegify-ai-jobs-"));
  const url = "file:" + join(directory, "jobs.db");
  const sql = createClient({ url }); await migrate(sql); sql.close();
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) }); await configureDatabase(db);
  for (const id of ["alice", "bob"]) await db.user.create({ data: { id, email: id + "@example.test" } });
  const project = await db.project.create({ data: { name: "Owned AI fixture", members: { create: [{ userId: "alice", role: "maintainer" }, { userId: "bob", role: "viewer" }] } } });
  const scan = await db.scan.create({ data: { projectId: project.id, status: "completed", repository: "owned/fixture", commitSha: "a".repeat(40) } });
  for (let i = 0; i < count; i++) await db.finding.create({ data: { id: "finding-" + String(i).padStart(4, "0"), scanId: scan.id, ruleId: "OWNED", ruleName: "Owned review", severity: "low", filePath: "fixture.py", lineStart: i + 1, lineEnd: i + 1, codeSnippet: "value = 'owned fixture'", message: "Static fixture", status: "triaged", owner: "fixture owner", priority: "low", ticketKey: "OWNED-1" } });
  for (const [key, value] of Object.entries({ "llm.enabled": "true", "llm.provider": "anthropic", "llm.model": "fixture-model", "llm.anthropic_api_key": "owned-provider-placeholder" })) await db.setting.create({ data: { key, value } });
  const alice = await resolvePrincipal(db, "alice", env); const bob = await resolvePrincipal(db, "bob", env);
  return { db, url, scan, project, alice, bob, queue: () => enqueueLlmJob(db, alice, scan.id, "deep", false, env), close: async () => { await db.$disconnect(); await rm(directory, { recursive: true, force: true }); } };
}

test("review reconnects, claims once, fences stale workers, binds receipts and preserves workflow", async () => {
  const f = await fixture();
  try {
    await assert.rejects(enqueueLlmJob(f.db, f.bob, f.scan.id, "quick", false, env));
    const queued = await f.queue(); assert.equal((await f.queue()).id, queued.id);
    assert.equal("inputCiphertext" in queued, false); assert.equal("configDigest" in queued, false);
    const stored = await f.db.llmJob.findUniqueOrThrow({ where: { id: queued.id } });
    assert.ok(stored.inputCiphertext && !stored.inputCiphertext.includes("owned fixture"));
    assert.equal(loadReviewSnapshot(stored).findings.length, 2);
    const peer = new PrismaClient({ adapter: new PrismaLibSql({ url: f.url }) });
    const claims = await Promise.all([claimLlmJob(f.db, "one", env), claimLlmJob(peer, "two", env)]).finally(() => peer.$disconnect());
    assert.equal(claims.filter(Boolean).length, 1); const old = claims.find(Boolean)!;
    await f.db.llmJob.update({ where: { id: old.id }, data: { leaseExpiresAt: new Date(0) } });
    const fresh = new PrismaClient({ adapter: new PrismaLibSql({ url: f.url }) });
    try {
      const recovered = await claimLlmJob(fresh, "restarted", env); assert.ok(recovered);
      assert.equal(recovered.attempts, 2); assert.notEqual(old.leaseToken, recovered.leaseToken);
      await assert.rejects(heartbeatLlmJob(f.db, old, env), AiLeaseLost);
      await runClaimedLlmJob(fresh, recovered, env, new AbortController().signal, { transport: successful });
    } finally { await fresh.$disconnect(); }
    const job = await f.db.llmJob.findUniqueOrThrow({ where: { id: queued.id } });
    assert.equal(job.status, "completed"); assert.equal(job.reviewedCount, 2); assert.equal(job.callsStarted, 1); assert.equal(job.activeKey, null);
    assert.equal(job.outputTokensReserved, 4096); assert.ok(job.promptBytes > 0);
    const call = await f.db.llmCall.findFirstOrThrow({ where: { jobId: job.id } }); assert.equal(call.status, "completed");
    const receipt = JSON.parse(call.receipt); assert.equal(receipt.reportedUsage.input_tokens, 100); assert.equal(receipt.reportedUsage.cache_read_input_tokens, 0); assert.equal(receipt.costUsd, null);
    const finding = await f.db.finding.findUniqueOrThrow({ where: { id: "finding-0000" } });
    assert.equal(finding.status, "triaged"); assert.equal(finding.owner, "fixture owner"); assert.equal(finding.priority, "low"); assert.equal(finding.ticketKey, "OWNED-1");
    assert.equal(finding.aiVerdict, "needs_review"); assert.equal(finding.aiReviewStatus, "suggested"); assert.equal(JSON.parse(finding.llmAnalysis!).inputDigest, job.inputDigest);
    const events = await f.db.llmJobEvent.findMany({ where: { jobId: job.id } }); assert.ok(events.some((event) => event.code === "recovered")); assert.ok(events.some((event) => event.code === "batch_published"));
    assert.ok(await f.db.auditEvent.count({ where: { targetId: job.id, action: "ai.review.batch_published" } }));
  } finally { await f.close(); }
});

test("crash after dispatch is terminal uncertain and never automatically replays a paid request", async () => {
  const f = await fixture();
  try {
    await f.queue(); const job = await claimLlmJob(f.db, "first", env); assert.ok(job); const snapshot = loadReviewSnapshot(job);
    await startLlmCall(f.db, job, snapshot, 0, env);
    await f.db.llmJob.update({ where: { id: job.id }, data: { leaseExpiresAt: new Date(0) } });
    let calls = 0;
    assert.equal(await runLlmWorkerOnce(f.db, "restarted", env, new AbortController().signal, { transport: async (request) => { calls++; return responseFor(request); } }), false);
    assert.equal(calls, 0);
    const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } }); assert.equal(saved.status, "failed"); assert.equal(saved.errorCode, "provider_outcome_unknown"); assert.equal(saved.activeKey, null);
    assert.equal((await f.db.llmCall.findFirstOrThrow({ where: { jobId: job.id } })).status, "unknown");
    await assert.rejects(startLlmCall(f.db, job, snapshot, 0, env), AiLeaseLost);
  } finally { await f.close(); }
});

test("completed batches survive restart and only the next undispatched batch is called", async () => {
  const f = await fixture(51);
  try {
    await f.queue(); const job = await claimLlmJob(f.db, "first", env); assert.ok(job); const snapshot = loadReviewSnapshot(job); assert.equal(snapshot.batches.length, 2);
    const started = await startLlmCall(f.db, job, snapshot, 0, env);
    const response = await callProviderDetailed(started.config, snapshot.system, started.user, new AbortController().signal, successful);
    await publishLlmBatch(f.db, job, snapshot, 0, started.callId, parseReviewResults(response.text, snapshot.batches[0]), response.receipt, env);
    await f.db.llmJob.update({ where: { id: job.id }, data: { leaseExpiresAt: new Date(0) } });
    let calls = 0;
    await runLlmWorkerOnce(f.db, "restarted", env, new AbortController().signal, { transport: async (request) => { calls++; const ids = JSON.parse(JSON.parse(request.body).messages[0].content).findings; assert.equal(ids.length, 1); assert.equal(ids[0].id, "finding-0050"); return responseFor(request); } });
    assert.equal(calls, 1); const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } });
    assert.equal(saved.status, "completed"); assert.equal(saved.reviewedCount, 51); assert.equal(saved.callsStarted, 2); assert.equal(saved.attempts, 2);
  } finally { await f.close(); }
});

test("role, account, archive, settings, digest, deadline and recovery caps stop queued provider access", async () => {
  for (const boundary of ["role", "disabled", "archive", "settings", "digest", "deadline", "attempts"]) {
    const f = await fixture();
    try {
      const job = await f.queue();
      if (boundary === "role") await f.db.projectMember.update({ where: { projectId_userId: { projectId: f.project.id, userId: "alice" } }, data: { role: "viewer" } });
      if (boundary === "disabled") await f.db.user.update({ where: { id: "alice" }, data: { disabled: true } });
      if (boundary === "archive") await f.db.project.update({ where: { id: f.project.id }, data: { archived: true } });
      if (boundary === "settings") await f.db.setting.update({ where: { key: "llm.model" }, data: { value: "different-model" } });
      if (boundary === "digest") await f.db.llmJob.update({ where: { id: job.id }, data: { inputDigest: "sha256:invalid" } });
      if (boundary === "deadline") await f.db.llmJob.update({ where: { id: job.id }, data: { deadlineAt: new Date(0) } });
      if (boundary === "attempts") await f.db.llmJob.update({ where: { id: job.id }, data: { attempts: 3 } });
      let calls = 0; await runLlmWorkerOnce(f.db, "worker", env, new AbortController().signal, { transport: async (request) => { calls++; return responseFor(request); } });
      assert.equal(calls, 0, boundary); assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).status, "failed", boundary);
    } finally { await f.close(); }
  }
});

test("cancel, revoke, source and config changes in flight fence publication and retain usage", async () => {
  for (const boundary of ["cancel", "role", "source", "settings"]) {
    const f = await fixture();
    try {
      const job = await f.queue();
      await runLlmWorkerOnce(f.db, "worker", env, new AbortController().signal, { transport: async (request) => {
        if (boundary === "cancel") { await assert.rejects(cancelLlmJob(f.db, f.bob, job.id, env)); await cancelLlmJob(f.db, f.alice, job.id, env); }
        if (boundary === "role") await f.db.projectMember.update({ where: { projectId_userId: { projectId: f.project.id, userId: "alice" } }, data: { role: "viewer" } });
        if (boundary === "source") await f.db.finding.update({ where: { id: "finding-0001" }, data: { codeSnippet: "changed source" } });
        if (boundary === "settings") await f.db.setting.update({ where: { key: "llm.model" }, data: { value: "different-model" } });
        return responseFor(request);
      } });
      const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } }); assert.equal(saved.status, boundary === "cancel" ? "cancelled" : "failed", boundary); assert.equal(saved.reviewedCount, 0); assert.equal(saved.activeKey, null);
      assert.equal(await f.db.finding.count({ where: { aiReviewStatus: "suggested" } }), 0);
      const call = await f.db.llmCall.findFirstOrThrow({ where: { jobId: job.id } }); assert.equal(call.status, "discarded"); assert.equal(JSON.parse(call.receipt).reportedUsage.input_tokens, 100);
    } finally { await f.close(); }
  }
});

test("heartbeat aborts an in-flight request after cancellation and preserves unknown charges", async () => {
  const f = await fixture();
  try {
    const job = await f.queue(); let aborted = false;
    await runLlmWorkerOnce(f.db, "worker", env, new AbortController().signal, { heartbeatMs: 20, transport: async (request) => {
      await cancelLlmJob(f.db, f.alice, job.id, env);
      return new Promise((_resolve, reject) => { const stop = () => { aborted = true; reject(new Error("owned interruption")); }; if (request.signal?.aborted) stop(); else request.signal?.addEventListener("abort", stop, { once: true }); });
    } });
    assert.equal(aborted, true); const call = await f.db.llmCall.findFirstOrThrow({ where: { jobId: job.id } }); assert.equal(call.status, "unknown"); assert.equal(JSON.parse(call.receipt).costUsd, null);
    assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).status, "cancelled");
  } finally { await f.close(); }
});

test("partial output is explicit and accepted AI decisions remain unchanged", async () => {
  const f = await fixture(3);
  try {
    await f.db.finding.update({ where: { id: "finding-0000" }, data: { aiReviewStatus: "accepted", aiVerdict: "likely_false_positive", llmAnalysis: "{\"humanAccepted\":true}" } });
    const job = await f.queue(); await runLlmWorkerOnce(f.db, "worker", env, new AbortController().signal, { transport: async (request) => responseFor(request, 2) });
    const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } }); assert.equal(saved.status, "partial"); assert.equal(saved.reviewedCount, 1); assert.equal(saved.errorCount, 2);
    const accepted = await f.db.finding.findUniqueOrThrow({ where: { id: "finding-0000" } }); assert.equal(accepted.aiReviewStatus, "accepted"); assert.equal(accepted.llmAnalysis, "{\"humanAccepted\":true}"); assert.equal(accepted.status, "triaged");
  } finally { await f.close(); }
});

test("duplicate IDs, foreign IDs, truncated completion and transport errors never publish or retry", async () => {
  for (const boundary of ["duplicate", "unknown", "incomplete", "transport"]) {
    const f = await fixture();
    try {
      const job = await f.queue(); let calls = 0;
      await runLlmWorkerOnce(f.db, "worker", env, new AbortController().signal, { transport: async (request) => {
        calls++; if (boundary === "transport") throw new Error("private provider body"); const response = responseFor(request); const body = JSON.parse(response.text);
        if (boundary === "duplicate") body.content[0].text = JSON.stringify([result("finding-0000"), result("finding-0000")]);
        if (boundary === "unknown") body.content[0].text = JSON.stringify([result("foreign-finding")]);
        if (boundary === "incomplete") body.stop_reason = "max_tokens";
        return { ...response, text: JSON.stringify(body) };
      } });
      assert.equal(calls, 1); assert.equal(await f.db.finding.count({ where: { aiReviewStatus: "suggested" } }), 0);
      const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } }); assert.equal(saved.status, "failed"); assert.ok(!saved.errorMessage.includes("private provider"));
      const receipt = JSON.parse((await f.db.llmCall.findFirstOrThrow({ where: { jobId: job.id } })).receipt);
      assert.equal(receipt.costUsd, null); assert.equal(receipt.reportedUsage?.input_tokens ?? null, boundary === "transport" ? null : 100);
    } finally { await f.close(); }
  }
});

test("migration closes legacy unfinished jobs without inferring a requester or replaying", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-ai-upgrade-")); const sql = createClient({ url: "file:" + join(directory, "legacy.db") });
  try {
    await migrate(sql, true); const row = (await sql.execute('SELECT status,activeKey,errorCode,requestedBy FROM "LlmJob"')).rows[0];
    assert.equal(row.status, "failed"); assert.equal(row.activeKey, null); assert.equal(row.requestedBy, null); assert.equal(row.errorCode, "legacy_interrupted");
    assert.equal((await sql.execute('SELECT COUNT(*) AS n FROM "LlmJobEvent"')).rows[0].n, 1);
  } finally { sql.close(); await rm(directory, { recursive: true, force: true }); }
});

test("hard call/output/prompt caps reject dispatch without reporting an empty success", async () => {
  for (const data of [{ maxCalls: 0 }, { outputTokensReserved: REVIEW_LIMITS.outputTokens }, { promptBytes: REVIEW_LIMITS.totalPromptBytes }]) {
    const f = await fixture();
    try {
      const job = await f.queue(); await f.db.llmJob.update({ where: { id: job.id }, data }); let calls = 0;
      await runLlmWorkerOnce(f.db, "worker", env, new AbortController().signal, { transport: async (request) => { calls++; return responseFor(request); } });
      assert.equal(calls, 0); assert.equal(await f.db.llmCall.count(), 0);
      const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } }); assert.equal(saved.status, "failed"); assert.equal(saved.errorCode, "budget_exceeded");
    } finally { await f.close(); }
  }
});

test("late database publication failure rolls back the whole batch but retains its call receipt", async () => {
  const f = await fixture();
  try {
    const job = await f.queue();
    await f.db.$executeRawUnsafe("CREATE TRIGGER owned_ai_publication_failure BEFORE UPDATE OF llmAnalysis ON Finding WHEN NEW.id = 'finding-0001' BEGIN SELECT RAISE(ABORT, 'owned fixture failure'); END");
    await runLlmWorkerOnce(f.db, "worker", env, new AbortController().signal, { transport: successful });
    assert.equal(await f.db.finding.count({ where: { aiReviewStatus: "suggested" } }), 0);
    assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).reviewedCount, 0);
    const call = await f.db.llmCall.findFirstOrThrow({ where: { jobId: job.id } }); assert.equal(call.status, "discarded"); assert.equal(JSON.parse(call.receipt).outcome, "received");
  } finally { await f.close(); }
});

test("the production AI worker entry reconciles an expired queue in a separate process without network", async () => {
  const f = await fixture();
  const directory = await mkdtemp(join(tmpdir(), "aegify-ai-process-"));
  try {
    const job = await f.queue(); await f.db.llmJob.update({ where: { id: job.id }, data: { deadlineAt: new Date(0) } });
    const script = fileURLToPath(new URL("../../scripts/llm-worker.mjs", import.meta.url));
    const child = spawn(process.execPath, [script, "--once"], { env: { ...process.env, ...env, DATABASE_URL: f.url, TMPDIR: directory }, stdio: ["ignore", "pipe", "pipe"] });
    let output = ""; for (const stream of [child.stdout, child.stderr]) stream.on("data", (data) => { output = (output + data.toString()).slice(-4000); });
    const timeout = setTimeout(() => child.kill("SIGKILL"), 15_000);
    const code = await new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); }).finally(() => clearTimeout(timeout));
    assert.equal(code, 0, output); assert.match(output, /AI review worker ready/);
    assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).errorCode, "deadline_exceeded");
    assert.equal(await f.db.llmCall.count(), 0); assert.equal(await f.db.llmWorker.count(), 0);
    assert.ok(await readFile(join(directory, "aegify-ai-worker-health"), "utf8"));
  } finally { await f.close(); await rm(directory, { recursive: true, force: true }); }
});
