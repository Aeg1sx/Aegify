import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { AccessDenied, resolvePrincipal } from "./project-access.ts";
import { configureDatabase } from "./database-runtime.ts";
import { decrypt } from "./crypto.ts";
import { cancelRuleFixture, claimRuleFixture, completeRuleFixture, enqueueRuleFixture, expireRuleFixtures, failRuleFixture, FixtureLeaseLost, heartbeatRuleFixture, listRuleFixtures, readRuleFixture } from "./rule-fixture-jobs.ts";
import { encodeFixtureInput, fixtureDigest, fixtureInput, restoreFixtureInput } from "./rule-fixture-input.ts";
import { parseFixtureReport, runClaimedRuleFixture, runPythonFixture } from "./rule-fixture-worker.ts";
import { ruleFixtureExamples } from "./rule-fixture-examples.ts";
import { FIXTURE_RETENTION_MS, type FixtureReport } from "./rule-fixture-contract.ts";

const env = { NODE_ENV: "production", AUTH_SECRET: "synthetic", AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test", ENCRYPTION_SECRET: "owned-fixture-job-encryption-key" };
const errorReport: FixtureReport = { schema_version: 1, status: "error", issues: ["invalid_rule"], diagnostics: [], suite_id: "", rule_id: "", positive_cases: 0, negative_cases: 0, cases: [], metrics: null, manifest: {}, result_digest: "" };
async function workspace() {
  const directory = await mkdtemp(join(tmpdir(), "aegify-fixture-jobs-"));
  const url = "file:" + join(directory, "jobs.db");
  const sql = createClient({ url });
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  sql.close();
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  await configureDatabase(db);
  for (const id of ["alice", "bob", "outside"]) await db.user.create({ data: { id, email: `${id}@example.test` } });
  const project = await db.project.create({ data: { name: "Rule lab", members: { create: [{ userId: "alice", role: "maintainer" }, { userId: "bob", role: "viewer" }] } } });
  const alice = await resolvePrincipal(db, "alice", env), bob = await resolvePrincipal(db, "bob", env), outside = await resolvePrincipal(db, "outside", env);
  return { db, url, project, alice, bob, outside, close: async () => { await db.$disconnect(); await rm(directory, { recursive: true, force: true }); } };
}
const status = (expected: number) => (error: unknown) => error instanceof AccessDenied && error.status === expected;

test("fixture input preserves strict worker JSON and enforces byte/Unicode bounds", () => {
  assert.deepEqual(fixtureInput(ruleFixtureExamples.call), ruleFixtureExamples.call);
  assert.throws(() => fixtureInput({ ...ruleFixtureExamples.call, extra: "unsupported" }), status(400));
  assert.throws(() => fixtureInput({ ...ruleFixtureExamples.call, ruleYaml: "한".repeat(50_000) }), status(400));
  assert.throws(() => fixtureInput({ ...ruleFixtureExamples.call, suiteJson: "x".repeat(2 * 1024 * 1024 + 1) }), status(400));
  assert.throws(() => fixtureInput({ ...ruleFixtureExamples.call, ruleYaml: "\ud800" }), status(400));
  const duplicate = { ruleYaml: "owned", suiteJson: '{"cases":[],"cases":[]}' };
  assert.equal(fixtureInput(duplicate).suiteJson, duplicate.suiteJson, "The worker must receive duplicate keys unchanged and reject them");
});

test("fixture jobs survive restart, fence stale workers, hide inputs, and enforce project permissions", async () => {
  const w = await workspace(); const { db, project, alice, bob, outside } = w;
  try {
    await assert.rejects(enqueueRuleFixture(db, bob, project.id, ruleFixtureExamples.call, env), status(404));
    await assert.rejects(enqueueRuleFixture(db, outside, project.id, ruleFixtureExamples.call, env), status(404));
    const job = await enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env);
    assert.equal("inputCiphertext" in job, false); assert.equal("leaseToken" in job, false);
    assert.equal(job.inputDigest, fixtureDigest(encodeFixtureInput(ruleFixtureExamples.call)));
    const stored = await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: job.id } });
    assert.ok(stored.inputCiphertext); assert.equal(stored.inputCiphertext.includes("review_target"), false);
    assert.deepEqual(restoreFixtureInput(stored, env.ENCRYPTION_SECRET), ruleFixtureExamples.call);
    assert.equal((await enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env)).id, job.id);
    await assert.rejects(enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.taint, env), status(409));
    const peer = new PrismaClient({ adapter: new PrismaLibSql({ url: w.url }) });
    const claims = await Promise.all([claimRuleFixture(db, "one", env), claimRuleFixture(peer, "two", env)]).finally(() => peer.$disconnect());
    assert.equal(claims.filter(Boolean).length, 1);
    const old = claims.find(Boolean)!;
    await db.ruleFixtureJob.update({ where: { id: job.id }, data: { leaseExpiresAt: new Date(0) } });
    const restarted = new PrismaClient({ adapter: new PrismaLibSql({ url: w.url }) });
    const recovered = await claimRuleFixture(restarted, "three", env).finally(() => restarted.$disconnect());
    assert.ok(recovered); assert.equal(recovered.id, job.id); assert.equal(recovered.inputDigest, old.inputDigest); assert.equal(recovered.attempts, 2);
    await assert.rejects(heartbeatRuleFixture(db, old, env), FixtureLeaseLost);
    await assert.rejects(completeRuleFixture(db, old, JSON.stringify(errorReport), errorReport, env), FixtureLeaseLost);
    await failRuleFixture(db, old, "worker_failed");
    assert.equal((await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: job.id } })).status, "running");
    await assert.rejects(cancelRuleFixture(db, bob, project.id, job.id, env), status(404));
    await assert.rejects(readRuleFixture(db, outside, project.id, job.id, env), status(404));
    await assert.rejects(readRuleFixture(db, bob, project.id, job.id, env, true), status(404));
    await cancelRuleFixture(db, alice, project.id, job.id, env);
    await assert.rejects(heartbeatRuleFixture(db, recovered, env), FixtureLeaseLost);
    const detail = await readRuleFixture(db, bob, project.id, job.id, env);
    assert.equal(detail.job.status, "cancelled"); assert.ok(detail.events.some((item) => item.code === "recovered"));
    assert.equal("inputCiphertext" in detail.job, false); assert.equal("workerId" in detail.job, false); assert.equal("input" in detail, false);
    assert.deepEqual((await readRuleFixture(db, alice, project.id, job.id, env, true)).input, ruleFixtureExamples.call);
    await db.scanWorker.create({ data: { id: "old", version: "0.3.0" } });
    assert.equal((await listRuleFixtures(db, alice, project.id, env)).workerAvailable, false, "An older worker cannot advertise fixture support");
    await db.scanWorker.create({ data: { id: "new", version: "0.3.0", ruleFixturesVersion: 1 } });
    assert.equal((await listRuleFixtures(db, alice, project.id, env)).workerAvailable, true);
  } finally { await w.close(); }
});

test("membership revocation, account disablement, archive, and publication-time revocation stop jobs", async () => {
  const w = await workspace(); const { db, project, alice } = w;
  try {
    for (const boundary of ["member", "disabled", "archived", "publish"]) {
      const queued = await enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env);
      const claimed = boundary === "publish" ? await claimRuleFixture(db, "publisher", env) : null;
      if (boundary === "member" || boundary === "publish") await db.projectMember.updateMany({ where: { projectId: project.id, userId: "alice" }, data: { role: "viewer" } });
      if (boundary === "disabled") await db.user.update({ where: { id: "alice" }, data: { disabled: true } });
      if (boundary === "archived") await db.project.update({ where: { id: project.id }, data: { archived: true } });
      await assert.rejects(enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env));
      if (claimed) {
        await assert.rejects(heartbeatRuleFixture(db, claimed, env), AccessDenied);
        await assert.rejects(completeRuleFixture(db, claimed, JSON.stringify(errorReport), errorReport, env), AccessDenied);
        await runClaimedRuleFixture(db, claimed, env, new AbortController().signal);
      } else assert.equal(await claimRuleFixture(db, "revoked", env), null);
      const stopped = await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: queued.id } });
      assert.equal(stopped.status, "failed"); assert.equal(stopped.errorCode, "authorization_lost"); assert.equal(stopped.resultCiphertext, null);
      await db.projectMember.updateMany({ where: { projectId: project.id, userId: "alice" }, data: { role: "maintainer" } });
      await db.user.update({ where: { id: "alice" }, data: { disabled: false } });
      await db.project.update({ where: { id: project.id }, data: { archived: false } });
    }
  } finally { await w.close(); }
});

test("encrypted report identity, retention read gate, purge and queue quotas are enforced", async () => {
  const w = await workspace(); const { db, project, alice, bob } = w;
  try {
    const queued = await enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env);
    const job = await claimRuleFixture(db, "publisher", env); assert.ok(job);
    const raw = JSON.stringify(errorReport);
    await completeRuleFixture(db, job, raw, errorReport, env);
    const detail = await readRuleFixture(db, bob, project.id, job.id, env);
    assert.equal(detail.report?.status, "error"); assert.equal(detail.job.resultDigest, fixtureDigest(raw));
    const saved = await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: job.id } });
    const payload = JSON.parse(decrypt(saved.resultCiphertext!, env.ENCRYPTION_SECRET));
    assert.equal(payload.jobId, job.id); assert.equal(payload.inputDigest, queued.inputDigest);
    await db.ruleFixtureJob.update({ where: { id: job.id }, data: { resultCiphertext: null } });
    await assert.rejects(readRuleFixture(db, bob, project.id, job.id, env), status(409));
    await db.ruleFixtureJob.update({ where: { id: job.id }, data: { resultCiphertext: saved.resultCiphertext } });
    assert.throws(() => restoreFixtureInput({ ...saved, inputCiphertext: null }, env.ENCRYPTION_SECRET), status(409));
    assert.equal(await db.scan.count(), 0); assert.equal(await db.finding.count(), 0, "Fixture findings cannot enter project vulnerability findings");
    await assert.rejects(readRuleFixture(db, alice, project.id, job.id, { ...env, ENCRYPTION_SECRET: "different-owned-test-key" }), status(409));
    const copy = await enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.taint, env);
    await db.ruleFixtureJob.update({ where: { id: copy.id }, data: { resultCiphertext: saved.resultCiphertext, resultDigest: saved.resultDigest, outcome: saved.outcome, status: "completed", activeKey: null } });
    await assert.rejects(readRuleFixture(db, bob, project.id, copy.id, env), status(409));
    await db.ruleFixtureJob.update({ where: { id: copy.id }, data: { inputDigest: "sha256:" + "0".repeat(64) } });
    assert.throws(() => restoreFixtureInput({ ...saved, inputDigest: "changed" }, env.ENCRYPTION_SECRET), status(409));
    const expires = new Date(Date.now() + FIXTURE_RETENTION_MS + 1000);
    assert.equal((await readRuleFixture(db, bob, project.id, job.id, env, false, expires)).report, null);
    await assert.rejects(readRuleFixture(db, alice, project.id, job.id, env, true, expires), status(410));
    const stillQueued = await enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env);
    await expireRuleFixtures(db, expires);
    const expired = await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: stillQueued.id } });
    assert.equal(expired.errorCode, "expired"); assert.equal(expired.activeKey, null);
    assert.equal(await db.ruleFixtureJob.count({ where: { OR: [{ inputCiphertext: { not: null } }, { resultCiphertext: { not: null } }] } }), 0);
    for (let index = 0; index < 7; index++) { const added = await enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env); await cancelRuleFixture(db, alice, project.id, added.id, env); }
    await assert.rejects(enqueueRuleFixture(db, alice, project.id, ruleFixtureExamples.call, env), status(429));
  } finally { await w.close(); }
});

test("real fixture worker evaluates call/taint, reports mismatches and gaps, and rejects malformed input", { skip: process.env.AEGIFY_TEST_SCANNER_CLI !== "1" }, async () => {
  for (const example of ["call", "taint"] as const) {
    const result = await runPythonFixture(ruleFixtureExamples[example], new AbortController().signal);
    assert.equal(result.report.status, "passed"); assert.equal(result.report.metrics?.precision, 1); assert.equal(result.report.metrics?.recall, 1);
    assert.equal(result.report.cases.length, 4); assert.equal(result.report.manifest.source_execution, false);
    if (example === "taint") assert.ok(result.report.cases.some((item) => item.id === "cross-file-query" && item.actual.some((finding) => finding.taint_flow?.source.file_path === "handler.py" && finding.taint_flow.sink.file_path === "helper.py")));
    const tampered = structuredClone(result.report); tampered.manifest.rule_digest = "changed";
    assert.throws(() => parseFixtureReport(JSON.stringify(tampered), ruleFixtureExamples[example]));
  }
  const suite = JSON.parse(ruleFixtureExamples.call.suiteJson);
  suite.cases[0].expected[0].line_start = 1;
  const mismatch = await runPythonFixture({ ...ruleFixtureExamples.call, suiteJson: JSON.stringify(suite) }, new AbortController().signal);
  assert.equal(mismatch.report.status, "failed"); assert.equal(mismatch.report.metrics?.false_positives, 1); assert.equal(mismatch.report.metrics?.false_negatives, 1);
  suite.cases[1].files.push({ path: "unsupported.php", content: "<?php // owned unsupported example\n" });
  const gap = await runPythonFixture({ ...ruleFixtureExamples.call, suiteJson: JSON.stringify(suite) }, new AbortController().signal);
  assert.equal(gap.report.status, "incomplete"); assert.equal(gap.report.metrics, null);
  for (const input of [
    { ...ruleFixtureExamples.call, suiteJson: '{"cases":[],"cases":[]}' },
    { ...ruleFixtureExamples.call, suiteJson: '{} , "timeout_seconds":120' },
    { ...ruleFixtureExamples.call, ruleYaml: ruleFixtureExamples.call.ruleYaml + "unsupported_contract_field: true\n" },
  ]) assert.equal((await runPythonFixture(input, new AbortController().signal)).report.status, "error");
  const control = new AbortController(); const pending = runPythonFixture(ruleFixtureExamples.taint, control.signal); setTimeout(() => control.abort(), 100);
  await assert.rejects(pending, { name: "AbortError" });
});

test("real fixture job publishes encrypted actual evidence for viewers without model or repository access", { skip: process.env.AEGIFY_TEST_SCANNER_CLI !== "1" }, async () => {
  const w = await workspace();
  try {
    const queued = await enqueueRuleFixture(w.db, w.alice, w.project.id, ruleFixtureExamples.taint, env);
    const job = await claimRuleFixture(w.db, "real-worker", env); assert.ok(job);
    await runClaimedRuleFixture(w.db, job, env, new AbortController().signal);
    const detail = await readRuleFixture(w.db, w.bob, w.project.id, queued.id, env);
    assert.equal(detail.job.status, "completed"); assert.equal(detail.report?.status, "passed"); assert.equal(detail.report.metrics?.true_positives, 2);
    assert.ok(detail.events.some((event) => event.code === "completed"));
    assert.equal(await w.db.account.count(), 0); assert.equal(await w.db.llmCall.count(), 0); assert.equal(await w.db.finding.count(), 0);
  } finally { await w.close(); }
});
