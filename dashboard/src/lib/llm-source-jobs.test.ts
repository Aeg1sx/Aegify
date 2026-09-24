import assert from "node:assert/strict";
import test, { after } from "node:test";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { configureDatabase } from "./database-runtime.ts";
import { resolvePrincipal } from "./project-access.ts";
import { encrypt, decrypt } from "./crypto.ts";
import { sourceDigest } from "./source-snapshot.ts";
import { callProviderDetailed, sha256 } from "./provider-receipt.ts";
import { cancelLlmJob, claimLlmJob, completeLlmToolTurn, enqueueLlmJob, expireLlmInputs, llmCallMetadata, loadReviewSnapshot, startLlmCall } from "./llm-jobs.ts";
import { runLlmWorkerOnce } from "./llm-worker.ts";
import { parseSourceResponse } from "./ai-source-review.ts";
import { listReviewHistory, readReviewHistory } from "./ai-review-history.ts";
import { createEncryptedBackup, verifyEncryptedBackup } from "./backup.ts";
import type { ProviderTransport } from "./public-https.ts";

const savedSecret = process.env.ENCRYPTION_SECRET;
process.env.ENCRYPTION_SECRET = "owned-source-review-encryption-fixture";
after(() => { if (savedSecret === undefined) delete process.env.ENCRYPTION_SECRET; else process.env.ENCRYPTION_SECRET = savedSecret; });
const env = { NODE_ENV: "production", AUTH_SECRET: "owned", AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test" } as const;
const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
async function fixture(count = 2, source = true) {
  const directory = await mkdtemp(join(tmpdir(), "aegify-source-jobs-")), databasePath = join(directory, "source.db"), url = "file:" + databasePath;
  const sql = createClient({ url });
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  sql.close();
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) }); await configureDatabase(db);
  for (const id of ["alice", "bob"]) await db.user.create({ data: { id, email: id + "@example.test" } });
  const project = await db.project.create({ data: { name: "Owned source review", members: { create: [{ userId: "alice", role: "maintainer" }, { userId: "bob", role: "viewer" }] } } });
  const scan = await db.scan.create({ data: { projectId: project.id, status: "completed", repository: "owned/fixture", commitSha: "a".repeat(40) } });
  for (let index = 0; index < count; index++) await db.finding.create({ data: { id: "finding-" + index, scanId: scan.id, ruleId: "OWNED", ruleName: "Owned static review", severity: "low", filePath: "main.py", lineStart: 1, lineEnd: 1, codeSnippet: "value = normalize(value)", message: "Owned source fixture" } });
  const base = { version: 1 as const, provider: "github", repository: scan.repository, commit: scan.commitSha, truncated: false,
    files: [{ path: "main.py", content: "value = normalize(value)\nreturn value\n" }, { path: "lib/helper.py", content: "def normalize(value):\n    return 'OWNED_HELPER_EVIDENCE' + str(value)\n" }].map((file) => ({ ...file, sha256: createHash("sha256").update(file.content).digest("hex") })) };
  const raw = { ...base, sourceDigest: sourceDigest(base) };
  if (source) await db.scanJob.create({ data: { scanId: scan.id, projectId: project.id, requestedBy: "alice", provider: "github", ownerSlug: scan.repository, requestedRef: "main", commitSha: scan.commitSha,
    sourceDigest: raw.sourceDigest, sourceCiphertext: encrypt(JSON.stringify(raw)), resultManifest: JSON.stringify({ version: 1, sourceDigest: raw.sourceDigest, commit: raw.commit }), status: "completed" } });
  for (const [key, value] of Object.entries({ "llm.enabled": "true", "llm.provider": "anthropic", "llm.model": "owned-model", "llm.anthropic_api_key": "owned-unused-placeholder" })) await db.setting.create({ data: { key, value } });
  const alice = await resolvePrincipal(db, "alice", env), bob = await resolvePrincipal(db, "bob", env);
  return { db, directory, databasePath, raw, scan, project, alice, bob,
    queue: (ids?: string[]) => enqueueLlmJob(db, alice, scan.id, "source", false, env, ids),
    close: async () => { await db.$disconnect(); await rm(directory, { recursive: true, force: true }); } };
}
type Input = { findings: Array<{ id: string; finding_source: { file_id: string } }>; source_progress: { round: number; tool_results: Array<{ tool: string; evidence: { files?: Array<{ file_id: string }>; citation?: { citation_id: string } } }> } };
const inputFor = (request: Parameters<ProviderTransport>[0]): Input => JSON.parse(JSON.parse(request.body).messages[0].content);
function reply(value: unknown) { return { status: 200, text: JSON.stringify({ id: "owned-response", model: "owned-model", stop_reason: "end_turn", usage: { input_tokens: 100, output_tokens: 40 }, content: [{ type: "text", text: JSON.stringify(value) }] }) }; }
function finalFor(input: Input, citations?: string[]) {
  return { kind: "review", reviews: input.findings.map(({ id }) => ({ findingId: id, verdict: "likely_false_positive", confidence: 0.8, reasoning: "Owned source and helper were read; static evidence only.", remediation: "Review caller constraints.", adjustedSeverity: null,
    evidenceFor: [], evidenceAgainst: ["The admitted helper was inspected."], evidenceGaps: ["Runtime behavior was not observed."], citationIds: citations || input.source_progress.tool_results.flatMap((span) => span.evidence.citation ? [span.evidence.citation.citation_id] : []) })) };
}
const firstTools = (input: Input) => ({ kind: "tools", requests: [
  { name: "source_read", arguments: { file_id: input.findings[0].finding_source.file_id, line_start: 1, line_end: 2 } },
  { name: "source_list", arguments: { prefix: "lib/" } },
] });
const navigating: ProviderTransport = async (request) => {
  const input = inputFor(request);
  if (input.source_progress.round === 1) { assert.ok(!request.body.includes("OWNED_HELPER_EVIDENCE")); return reply(firstTools(input)); }
  if (input.source_progress.round === 2) {
    assert.ok(!request.body.includes("OWNED_HELPER_EVIDENCE"));
    const file = input.source_progress.tool_results.find((span) => span.tool === "source_list")!.evidence.files![0];
    return reply({ kind: "tools", requests: [{ name: "source_read", arguments: { file_id: file.file_id, line_start: 1, line_end: 2 } }] });
  }
  assert.ok(request.body.includes("OWNED_HELPER_EVIDENCE"));
  return reply(finalFor(input));
};
async function completeFirst(f: Awaited<ReturnType<typeof fixture>>) {
  const job = await claimLlmJob(f.db, "first-worker", env); assert.ok(job);
  const snapshot = loadReviewSnapshot(job), started = await startLlmCall(f.db, job, snapshot, 0, env);
  const response = await callProviderDetailed(started.config, snapshot.system, started.user, new AbortController().signal, navigating);
  const turn = parseSourceResponse(response.text, snapshot.batches[0]); assert.equal(turn.kind, "tools");
  await completeLlmToolTurn(f.db, job, snapshot, 0, started.callId, turn.requests, response.receipt, env);
  return { job, callId: started.callId };
}

test("durable source review navigates multiple files, retains bound encrypted evidence and three receipts", async () => {
  const f = await fixture();
  try {
    const queued = await f.queue();
    await runLlmWorkerOnce(f.db, "owned-worker", env, new AbortController().signal, { transport: navigating });
    const job = await f.db.llmJob.findUniqueOrThrow({ where: { id: queued.id } });
    assert.equal(job.status, "completed"); assert.equal(job.callsStarted, 3); assert.equal(job.reviewedCount, 2); assert.equal(job.contractVersion, 2);
    const calls = await f.db.llmCall.findMany({ where: { jobId: job.id }, orderBy: { roundIndex: "asc" } });
    assert.deepEqual(calls.map((call) => [call.roundIndex, call.responseKind, call.status]), [[0, "tools", "completed"], [1, "tools", "completed"], [2, "review", "completed"]]);
    for (const call of calls) { assert.equal(JSON.parse(call.receipt).reportedUsage.input_tokens, 100); assert.equal(JSON.parse(call.receipt).costUsd, null); }
    const history = await listReviewHistory(f.db, f.bob, job.id), detail = await readReviewHistory(f.db, f.bob, job.id, history.reviews[0].id);
    assert.equal(detail.record.result.verdict, "likely_false_positive"); assert.equal(detail.record.sourceEvidence?.tools_used.length, 3);
    assert.equal(detail.record.sourceEvidence?.citations.length, 2); assert.equal(detail.record.sourceEvidence?.trace.model_calls, 3);
    assert.equal(detail.record.sourceEvidence?.catalog.sourceDigest, f.raw.sourceDigest);
    assert.ok(JSON.stringify(detail).includes("OWNED_HELPER_EVIDENCE"));
    const publicCalls = await f.db.llmCall.findMany({ select: llmCallMetadata }), events = await f.db.llmJobEvent.findMany();
    for (const value of [publicCalls, events, job.inputCiphertext, await f.db.llmReview.findMany(), (await f.db.finding.findMany()).map((finding) => finding.llmAnalysis)]) assert.ok(!JSON.stringify(value).includes("OWNED_HELPER_EVIDENCE"));
    assert.ok(!JSON.stringify(publicCalls).includes("continuationCiphertext"));
    await f.db.projectMember.delete({ where: { projectId_userId: { projectId: f.project.id, userId: "bob" } } });
    await assert.rejects(readReviewHistory(f.db, await resolvePrincipal(f.db, "bob", env), job.id, history.reviews[0].id), { status: 404 });
  } finally { await f.close(); }
});

test("expired worker resumes the completed tool journal without repeating a paid provider call", async () => {
  const f = await fixture();
  try {
    await f.queue(); const { job, callId } = await completeFirst(f);
    await f.db.llmJob.update({ where: { id: job.id }, data: { leaseExpiresAt: new Date(0) } });
    let calls = 0;
    await runLlmWorkerOnce(f.db, "recovered-worker", env, new AbortController().signal, { transport: async (request, ...rest) => { calls++; assert.notEqual(inputFor(request).source_progress.round, 1); return navigating(request, ...rest); } });
    const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } });
    assert.equal(saved.status, "completed"); assert.equal(saved.callsStarted, 3); assert.equal(saved.attempts, 2); assert.equal(calls, 2);
    assert.equal((await f.db.llmCall.findUniqueOrThrow({ where: { id: callId } })).leaseToken, job.leaseToken);
  } finally { await f.close(); }
});

test("unknown provider outcome after a completed source turn is never replayed", async () => {
  const f = await fixture();
  try {
    await f.queue(); const { job } = await completeFirst(f);
    await startLlmCall(f.db, job, loadReviewSnapshot(job), 0, env);
    await f.db.llmJob.update({ where: { id: job.id }, data: { leaseExpiresAt: new Date(0) } });
    let requests = 0;
    await runLlmWorkerOnce(f.db, "recovery", env, new AbortController().signal, { transport: async () => { requests++; throw new Error("Must not dispatch"); } });
    assert.equal(requests, 0); assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).errorCode, "provider_outcome_unknown");
    assert.equal(await f.db.llmReview.count(), 0);
  } finally { await f.close(); }
});

test("source absence, identity drift and selection outside the scan fail before any provider dispatch", async () => {
  for (const boundary of ["absent", "expired", "commit", "digest", "result", "provider", "namespace", "selection", "duplicate", "many"]) {
    const f = await fixture(boundary === "many" ? 26 : 2, boundary !== "absent");
    try {
      if (boundary === "expired") await f.db.scanJob.updateMany({ data: { sourceCiphertext: null } });
      if (boundary === "commit") await f.db.scanJob.updateMany({ data: { commitSha: "b".repeat(40) } });
      if (boundary === "digest") await f.db.scanJob.updateMany({ data: { sourceDigest: "sha256:" + "b".repeat(64) } });
      if (boundary === "result") await f.db.scanJob.updateMany({ data: { resultManifest: "{}" } });
      if (boundary === "provider") await f.db.scanJob.updateMany({ data: { provider: "gitlab" } });
      if (boundary === "namespace") await f.db.finding.updateMany({ data: { repositoryId: "different/repository" } });
      await assert.rejects(f.queue(boundary === "selection" ? ["not-in-this-scan"] : boundary === "duplicate" ? ["finding-0", "finding-0"] : undefined));
      assert.equal(await f.db.llmJob.count(), 0, boundary); assert.equal(await f.db.llmCall.count(), 0, boundary);
      if (boundary === "many") assert.equal((await f.queue(["finding-0", "finding-25"])).totalFindings, 2);
    } finally { await f.close(); }
  }
});

test("malformed or rebound source continuations stop recovery without a new model request", async () => {
  for (const boundary of ["ciphertext", "digest", "job", "prompt", "output", "receipt", "round"]) {
    const f = await fixture();
    try {
      await f.queue(); const { job, callId } = await completeFirst(f);
      const call = await f.db.llmCall.findUniqueOrThrow({ where: { id: callId } });
      if (boundary === "ciphertext") await f.db.llmCall.update({ where: { id: callId }, data: { continuationCiphertext: "changed" } });
      if (boundary === "digest") await f.db.llmCall.update({ where: { id: callId }, data: { continuationDigest: "sha256:" + "b".repeat(64) } });
      if (boundary === "prompt") await f.db.llmCall.update({ where: { id: callId }, data: { promptDigest: "sha256:" + "b".repeat(64) } });
      if (boundary === "receipt") await f.db.llmCall.update({ where: { id: callId }, data: { receipt: "{}" } });
      if (boundary === "round") await f.db.llmCall.update({ where: { id: callId }, data: { roundIndex: 1 } });
      if (boundary === "job" || boundary === "output") {
        const value = JSON.parse(decrypt(call.continuationCiphertext!));
        if (boundary === "job") value.jobId = "other-job"; else value.spans[0].evidence.content = "changed";
        const text = JSON.stringify(value);
        await f.db.llmCall.update({ where: { id: callId }, data: { continuationCiphertext: encrypt(text), continuationDigest: sha256(text) } });
      }
      await f.db.llmJob.update({ where: { id: job.id }, data: { leaseExpiresAt: new Date(0) } });
      let requests = 0;
      await runLlmWorkerOnce(f.db, "recovery", env, new AbortController().signal, { transport: async () => { requests++; throw new Error("Must not dispatch"); } });
      assert.equal(requests, 0, boundary); assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).errorCode, "input_invalid", boundary);
    } finally { await f.close(); }
  }
});

test("forged citations and unapproved actions fail; ungrounded likelihood is retained only as needs_review", async () => {
  for (const boundary of ["forged", "shell", "empty", "no-read"]) {
    const f = await fixture();
    try {
      const job = await f.queue();
      await runLlmWorkerOnce(f.db, "owned", env, new AbortController().signal, { transport: async (request) => {
        const input = inputFor(request);
        return reply(boundary === "shell" ? { kind: "tools", requests: [{ name: "shell", arguments: { command: "owned" } }] }
          : boundary === "empty" ? { kind: "tools", requests: [] } : finalFor(input, boundary === "forged" ? ["sha256:" + "f".repeat(64)] : []));
      } });
      const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } });
      assert.equal(saved.callsStarted, 1);
      if (boundary === "no-read") {
        assert.equal(saved.status, "completed"); assert.ok((await f.db.finding.findMany()).every((finding) => finding.aiVerdict === "needs_review" && finding.aiConfidence === 0));
      } else { assert.equal(saved.errorCode, "invalid_review"); assert.equal(await f.db.llmReview.count(), 0); }
    } finally { await f.close(); }
  }
});

test("source turn publication rechecks cancellation, settings, authorization and source changes", async () => {
  for (const boundary of ["cancel", "settings", "permission", "source"]) {
    const f = await fixture();
    try {
      const job = await f.queue();
      await runLlmWorkerOnce(f.db, "owned", env, new AbortController().signal, { transport: async (request) => {
        if (boundary === "cancel") await cancelLlmJob(f.db, f.alice, job.id, env);
        if (boundary === "settings") await f.db.setting.update({ where: { key: "llm.model" }, data: { value: "changed-model" } });
        if (boundary === "permission") await f.db.projectMember.update({ where: { projectId_userId: { projectId: f.project.id, userId: "alice" } }, data: { role: "viewer" } });
        if (boundary === "source") await f.db.scan.update({ where: { id: f.scan.id }, data: { commitSha: "b".repeat(40) } });
        return reply(firstTools(inputFor(request)));
      } });
      const call = await f.db.llmCall.findFirstOrThrow(); assert.equal(call.status, "discarded"); assert.equal(call.continuationCiphertext, null);
      assert.equal(await f.db.llmReview.count(), 0); assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).callsStarted, 1);
    } finally { await f.close(); }
  }
});

test("the fourth model turn requires a final answer; source budget exhaustion is explicit", async () => {
  const f = await fixture();
  try {
    const job = await f.queue();
    await runLlmWorkerOnce(f.db, "owned", env, new AbortController().signal, { transport: async () => reply({ kind: "tools", requests: [{ name: "source_list", arguments: {} }] }) });
    const saved = await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } });
    assert.equal(saved.callsStarted, 4); assert.equal(saved.errorCode, "budget_exceeded"); assert.equal(await f.db.llmReview.count(), 0);
    assert.equal(await f.db.llmCall.count({ where: { responseKind: "tools", status: "completed" } }), 3);
  } finally { await f.close(); }
});

test("a failed continuation transaction retains the received receipt without another provider dispatch", async () => {
  const f = await fixture();
  try {
    const job = await f.queue();
    await f.db.$executeRawUnsafe("CREATE TRIGGER owned_continuation_failure BEFORE UPDATE ON LlmCall WHEN NEW.responseKind = 'tools' BEGIN SELECT RAISE(ABORT, 'owned fixture failure'); END");
    let calls = 0;
    await runLlmWorkerOnce(f.db, "owned", env, new AbortController().signal, { transport: async (request) => { calls++; return reply(firstTools(inputFor(request))); } });
    const call = await f.db.llmCall.findFirstOrThrow();
    assert.equal(calls, 1); assert.equal(call.status, "discarded"); assert.equal(JSON.parse(call.receipt).outcome, "received"); assert.equal(call.continuationCiphertext, null);
    assert.equal(await f.db.llmJobEvent.count({ where: { code: "source_tools_completed" } }), 0);
    assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).errorCode, "publication_failed");
  } finally { await f.close(); }
});

test("source history survives full-input expiry; backup checks a continuation-only installation key", async () => {
  const f = await fixture();
  try {
    const job = await f.queue(); await completeFirst(f);
    await f.db.llmJob.updateMany({ data: { inputCiphertext: null } }); await f.db.scanJob.updateMany({ data: { sourceCiphertext: null } });
    const archivePath = join(f.directory, "source.aegify"), keys = { backupKey: "a".repeat(64), encryptionSecret: process.env.ENCRYPTION_SECRET! };
    assert.equal((await createEncryptedBackup({ ...keys, databasePath: f.databasePath, outputPath: archivePath })).encryptionKeyCheck, "stored_ciphertext");
    await verifyEncryptedBackup({ ...keys, archivePath });
    await assert.rejects(verifyEncryptedBackup({ ...keys, encryptionSecret: "wrong-owned-key", archivePath }));
    assert.equal((await f.db.llmJob.findUniqueOrThrow({ where: { id: job.id } })).status, "running");
  } finally { await f.close(); }
  const g = await fixture();
  try {
    const job = await g.queue(); await runLlmWorkerOnce(g.db, "owned", env, new AbortController().signal, { transport: navigating });
    const history = await listReviewHistory(g.db, g.alice, job.id), before = await readReviewHistory(g.db, g.alice, job.id, history.reviews[0].id);
    await g.db.llmJob.updateMany({ data: { completedAt: new Date(0) } });
    assert.deepEqual(await expireLlmInputs(g.db), { jobs: 1, calls: 2 });
    await g.db.scanJob.updateMany({ data: { sourceCiphertext: null } });
    const after = await readReviewHistory(g.db, g.alice, job.id, history.reviews[0].id);
    assert.deepEqual(after.record, before.record); assert.ok(JSON.stringify(after.record).includes("OWNED_HELPER_EVIDENCE"));
    assert.equal(await g.db.llmCall.count({ where: { continuationCiphertext: { not: null } } }), 0);
  } finally { await g.close(); }
});

test("populated single-turn call migration preserves history and allows unique subsequent turns", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-source-upgrade-")), sql = createClient({ url: "file:" + join(directory, "upgrade.db") });
  try {
    for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.name === "20260924100000_ai_source_tools") {
        await sql.executeMultiple(`INSERT INTO Scan(id) VALUES ('scan');
          INSERT INTO LlmJob(id,scanId,mode) VALUES ('job','scan','quick');
          INSERT INTO LlmCall(id,jobId,batchIndex,leaseToken,promptDigest,status) VALUES ('call','job',0,'owned','prompt','completed');
          INSERT INTO LlmReview(id,jobId,callId,findingId,batchIndex,ordinal,publication,ruleId,ruleName,severity,filePath,lineStart,verdict,confidence,evidenceDigest,payloadDigest,payloadCiphertext) VALUES ('history','job','call','finding',0,0,'published','OWNED','Owned','low','main.py',1,'needs_review',0.2,'evidence','payload','encrypted-owned');`);
      }
      await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
    }
    const call = (await sql.execute("SELECT * FROM LlmCall WHERE id='call'")).rows[0];
    assert.equal(call.roundIndex, 0); assert.equal(call.responseKind, "review"); assert.equal(call.continuationCiphertext, null);
    assert.equal((await sql.execute("SELECT callId FROM LlmReview WHERE id='history'")).rows[0].callId, "call");
    await sql.execute("INSERT INTO LlmCall(id,jobId,batchIndex,roundIndex,leaseToken,promptDigest) VALUES ('next','job',0,1,'owned','next-prompt')");
    await assert.rejects(sql.execute("INSERT INTO LlmCall(id,jobId,batchIndex,roundIndex,leaseToken,promptDigest) VALUES ('duplicate','job',0,1,'owned','next-prompt')"));
    assert.deepEqual((await sql.execute("PRAGMA foreign_key_check")).rows, []);
  } finally { sql.close(); await rm(directory, { recursive: true, force: true }); }
});
