import assert from "node:assert/strict";
import process from "node:process";
import { Buffer } from "node:buffer";
import { log } from "node:console";
import { prisma } from "../src/lib/prisma.ts";
import { encrypt } from "../src/lib/crypto.ts";
import { enqueueScan } from "../src/lib/scan-jobs.ts";
import { resolvePrincipal } from "../src/lib/project-access.ts";
import { makeSourceSnapshot } from "../src/lib/scan-worker.ts";
import { enqueueRuleFixture, readRuleFixture } from "../src/lib/rule-fixture-jobs.ts";
import { ruleFixtureExamples } from "../src/lib/rule-fixture-examples.ts";

// Only called with a fresh CI volume. The worker itself runs without networking.
try {
  if (process.argv[2] === "setup") {
    const email = process.env.AUTH_ADMIN_EMAILS.split(",")[0];
    await prisma.user.create({ data: { id: "worker-ci-fixture", email } });
    await prisma.account.create({ data: { userId: "worker-ci-fixture", type: "oauth", provider: "github", providerAccountId: "worker-ci-fixture", access_token: "synthetic-unused-token" } });
    const project = await prisma.project.create({ data: { id: "worker-ci-fixture", name: "Worker CI fixture", provider: "github", ownerSlug: "fixture/repository" } });
    const queued = await enqueueScan(prisma, await resolvePrincipal(prisma, "worker-ci-fixture", process.env), project.id, "main", process.env, "a".repeat(40));
    const job = await prisma.scanJob.findUniqueOrThrow({ where: { id: queued.id } });
    const files = [{ path: "app.py", content: "from flask import request\ndef read_document():\n    return open(request.args.get('path'))\n" }, { path: "unsupported.php", content: "<?php // Unsupported fixture\n" }].map((file) => ({ ...file, sizeBytes: Buffer.byteLength(file.content) }));
    const snapshot = makeSourceSnapshot(job, { files, ref: job.commitSha, truncated: false, selection: "source-and-config", totalBytes: files.reduce((count, file) => count + file.sizeBytes, 0), skippedFiles: 0, omittedFiles: 0, fetchedAt: new Date().toISOString() });
    await prisma.scanJob.update({ where: { id: job.id }, data: { sourceCiphertext: encrypt(JSON.stringify(snapshot)), sourceDigest: snapshot.sourceDigest, status: "running", attempts: 1, leaseToken: "expired-fixture-lease", leaseExpiresAt: new Date(0) } });
    log("Prepared a persisted interrupted source scan.");
  } else if (process.argv[2] === "verify") {
    const job = await prisma.scanJob.findFirstOrThrow({ where: { projectId: "worker-ci-fixture" } });
    assert.equal(job.status, "partial"); assert.equal(job.attempts, 2);
    assert.match(job.resultDigest, /^sha256:[a-f0-9]{64}$/);
    assert.ok(await prisma.finding.findFirst({ where: { scanId: job.scanId, ruleId: "AEG-PATH-001", filePath: "app.py" } }));
    assert.ok(await prisma.scanJobEvent.findFirst({ where: { jobId: job.id, code: "recovered" } }));
    log("New worker process recovered and published the pinned source scan with partial coverage.");
  } else if (process.argv[2] === "fixture-setup") {
    const access = await resolvePrincipal(prisma, "worker-ci-fixture", process.env);
    const job = await enqueueRuleFixture(prisma, access, "worker-ci-fixture", ruleFixtureExamples.taint, process.env);
    await prisma.ruleFixtureJob.update({ where: { id: job.id }, data: { status: "running", attempts: 1, leaseToken: "expired-fixture-lease", leaseExpiresAt: new Date(0) } });
    log("Prepared a persisted interrupted rule fixture evaluation.");
  } else if (process.argv[2] === "fixture-verify") {
    const job = await prisma.ruleFixtureJob.findFirstOrThrow({ where: { projectId: "worker-ci-fixture" } });
    const access = await resolvePrincipal(prisma, "worker-ci-fixture", process.env);
    const detail = await readRuleFixture(prisma, access, job.projectId, job.id, process.env, true);
    assert.equal(job.status, "completed"); assert.equal(job.outcome, "passed"); assert.equal(job.attempts, 2);
    assert.deepEqual(detail.input, ruleFixtureExamples.taint);
    assert.equal(detail.report.metrics.true_positives, 2);
    assert.equal(detail.report.manifest.source_execution, false);
    assert.ok(detail.report.cases.some((item) => item.id === "cross-file-query" && item.actual.some((finding) => finding.taint_flow?.sink.file_path === "helper.py")));
    assert.ok(detail.events.some((item) => item.code === "recovered"));
    assert.ok(job.resultCiphertext); assert.match(job.resultDigest, /^sha256:[a-f0-9]{64}$/);
    log("New worker process recovered encrypted rule input and published actual multi-file taint evidence without networking.");
  } else throw new Error("Choose setup, verify, fixture-setup or fixture-verify.");
} finally { await prisma.$disconnect(); }
