import assert from "node:assert/strict";
import process from "node:process";
import { Buffer } from "node:buffer";
import { log } from "node:console";
import { prisma } from "../src/lib/prisma.ts";
import { encrypt } from "../src/lib/crypto.ts";
import { enqueueScan } from "../src/lib/scan-jobs.ts";
import { resolvePrincipal } from "../src/lib/project-access.ts";
import { makeSourceSnapshot } from "../src/lib/scan-worker.ts";

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
  } else throw new Error("Choose setup or verify.");
} finally { await prisma.$disconnect(); }
