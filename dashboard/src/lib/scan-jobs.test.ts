import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { authorizeProject, resolvePrincipal } from "./project-access.ts";
import { assertJobLease, cancelScanJob, claimScanJob, enqueueScan, failScanJob, heartbeatScanJob, LeaseLost } from "./scan-jobs.ts";
import { makeSourceSnapshot, pinJobCommit, runClaimedScan, runPythonSnapshot } from "./scan-worker.ts";
import { configureDatabase } from "./database-runtime.ts";
import { freezeFinding, reviewFindingSelect } from "./ai-review-contract.ts";
import { captureReviewSources } from "./ai-source-tools.ts";
import { decrypt } from "./crypto.ts";
import { buildFindingPrompt } from "./llm.ts";

test("durable jobs fence stale workers, preserve commits, recover, cancel and respect revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-jobs-"));
  const url = "file:" + join(directory, "jobs.db");
  const sql = createClient({ url });
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  sql.close();
  let db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  const env = { NODE_ENV: "production", AUTH_SECRET: "synthetic", AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test" };
  try {
    await configureDatabase(db);
    for (const user of ["alice", "bob"]) await db.user.create({ data: { id: user, email: `${user}@example.test` } });
    await db.account.create({ data: { userId: "alice", provider: "github", providerAccountId: "alice-fixture", type: "oauth", access_token: "synthetic-oauth-placeholder" } });
    const project = await db.project.create({ data: { name: "Fixture", provider: "github", ownerSlug: "fixture/repository", members: { create: [{ userId: "alice", role: "maintainer" }, { userId: "bob", role: "viewer" }] } } });
    const alice = await resolvePrincipal(db, "alice", env);
    const bob = await resolvePrincipal(db, "bob", env);
    await assert.rejects(enqueueScan(db, bob, project.id, "main", env));
    const queued = await enqueueScan(db, alice, project.id, "main", env);
    assert.equal((await enqueueScan(db, alice, project.id, "main", env)).id, queued.id);
    const peer = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
    const claims = await Promise.all([claimScanJob(db, "worker-a", env), claimScanJob(peer, "worker-b", env)]).finally(() => peer.$disconnect());
    assert.equal(claims.filter(Boolean).length, 1, "Concurrent workers must claim exactly once");
    const first = claims.find(Boolean);
    assert.ok(first); assert.equal(first.attempts, 1);
    assert.equal(await claimScanJob(db, "worker-b", env), null);
    await pinJobCommit(db, first, "a".repeat(40), env);
    await assert.rejects(pinJobCommit(db, first, "b".repeat(40), env));
    await db.scanJob.update({ where: { id: first.id }, data: { leaseExpiresAt: new Date(0) } });
    // A fresh database client represents a restarted worker process.
    await db.$disconnect();
    db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
    const recovered = await claimScanJob(db, "worker-b", env);
    assert.ok(recovered); assert.equal(recovered.id, first.id); assert.equal(recovered.attempts, 2);
    assert.equal(recovered.commitSha, "a".repeat(40));
    assert.notEqual(recovered.leaseToken, first.leaseToken);
    await assert.rejects(heartbeatScanJob(db, first, env), LeaseLost);
    await assert.rejects(db.$transaction((tx) => assertJobLease(tx, first, env)), LeaseLost);
    await failScanJob(db, first, "scanner_failed", false);
    assert.equal((await db.scanJob.findUniqueOrThrow({ where: { id: first.id } })).status, "running");
    await heartbeatScanJob(db, recovered, env);
    await assert.rejects(cancelScanJob(db, bob, queued.id, env));
    await cancelScanJob(db, alice, queued.id, env);
    await assert.rejects(heartbeatScanJob(db, recovered, env), LeaseLost);
    assert.equal((await db.scan.findUniqueOrThrow({ where: { id: queued.scanId } })).status, "cancelled");

    const orphan = await enqueueScan(db, alice, project.id, "main", env);
    await db.scanJob.update({ where: { id: orphan.id }, data: { status: "running", attempts: 1, leaseExpiresAt: null } });
    const replacement = await claimScanJob(db, "worker-c", env);
    assert.equal(replacement?.id, orphan.id);
    assert.equal(replacement?.attempts, 2);
    await cancelScanJob(db, alice, orphan.id, env);

    const revoked = await enqueueScan(db, alice, project.id, "main", env);
    await db.projectMember.update({ where: { projectId_userId: { projectId: project.id, userId: "alice" } }, data: { role: "viewer" } });
    assert.equal(await claimScanJob(db, "worker-c", env), null);
    assert.equal((await db.scanJob.findUniqueOrThrow({ where: { id: revoked.id } })).errorCode, "authorization_lost");
    await assert.rejects(authorizeProject(db, alice, project.id, "maintainer"));
    await db.projectMember.update({ where: { projectId_userId: { projectId: project.id, userId: "alice" } }, data: { role: "maintainer" } });

    const exhausted = await enqueueScan(db, alice, project.id, "main", env);
    await db.scanJob.update({ where: { id: exhausted.id }, data: { maxAttempts: 1 } });
    const last = await claimScanJob(db, "worker-d", env);
    assert.ok(last);
    await db.scanJob.update({ where: { id: last.id }, data: { leaseExpiresAt: new Date(0) } });
    assert.equal(await claimScanJob(db, "worker-e", env), null);
    assert.equal((await db.scanJob.findUniqueOrThrow({ where: { id: last.id } })).errorCode, "attempts_exhausted");
    const events = await db.scanJobEvent.findMany({ where: { jobId: first.id }, orderBy: { id: "asc" } });
    assert.ok(events.some((event) => event.code === "source_pinned"));
    assert.ok(events.some((event) => event.code === "recovered"));
    assert.ok(events.some((event) => event.code === "cancelled"));
  } finally { await db.$disconnect(); await rm(directory, { recursive: true, force: true }); }
});

test("owned source snapshot runs through the real Python engine and publishes partial coverage", { skip: process.env.AEGIFY_TEST_SCANNER_CLI !== "1" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-engine-job-"));
  const url = "file:" + join(directory, "job.db");
  const sql = createClient({ url });
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((item) => item.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  sql.close();
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  const env = { NODE_ENV: "production", AUTH_SECRET: "synthetic", AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test" };
  const originalFetch = globalThis.fetch;
  const originalSecret = process.env.ENCRYPTION_SECRET;
  process.env.ENCRYPTION_SECRET = "synthetic-encryption-key-only-for-isolated-database";
  const commit = "a".repeat(40); const tree = "c".repeat(40);
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    assert.equal(new URL(url).origin, "https://api.github.com", "Only intercepted fixture-provider requests are permitted");
    assert.equal(init?.redirect, "manual");
    if (url.includes("/commits/main")) return Response.json({ sha: commit, commit: { tree: { sha: tree } } });
    if (url.includes("/git/trees/")) return Response.json({ tree: ["app.py", "signing.py", "configured.py", "unsupported.php", "wrangler.jsonc"].map((path) => ({ path, type: "blob", mode: "100644" })) });
    if (url.includes("/contents/wrangler.jsonc")) return new Response('{"vars":{"API_TOKEN":"owned-configuration-canary"}}');
    if (url.includes("/contents/app.py")) return new Response("from flask import request\ndef read_document():\n    value = request.args.get('path')\n    return open(value)\n");
    if (url.includes("/contents/signing.py")) return new Response("from jwt import encode\nmaterial = 'marker-signing-review-only'\ndef issue(data): return encode(data,material)\n");
    if (url.includes("/contents/configured.py")) return new Response("from jwt import encode\ndef issue(data, material): return encode(data, material)\n");
    if (url.includes("/contents/unsupported.php")) return new Response("<?php // Synthetic unsupported source\n");
    throw new Error("Unexpected fixture request");
  };
  try {
    await db.user.create({ data: { id: "alice", email: "alice@example.test" } });
    await db.account.create({ data: { userId: "alice", provider: "github", providerAccountId: "alice-fixture", type: "oauth", access_token: "synthetic-oauth-placeholder" } });
    const project = await db.project.create({ data: { name: "Fixture", provider: "github", ownerSlug: "fixture/repository", members: { create: { userId: "alice", role: "admin" } } } });
    await enqueueScan(db, await resolvePrincipal(db, "alice", env), project.id, "main", env);
    const job = await claimScanJob(db, "fixture-worker", env); assert.ok(job);
    const cancellation = new AbortController();
    const syntheticFiles = Array.from({ length: 16 }, (_, index) => ({ path: `cancel_${index}.py`, content: "value = 1\n".repeat(500), sizeBytes: 5000 }));
    const snapshot = makeSourceSnapshot({ ...job, commitSha: commit }, { ref: commit, files: syntheticFiles, totalBytes: syntheticFiles.reduce((sum, file) => sum + file.sizeBytes, 0), fetchedAt: new Date().toISOString(), truncated: false, skippedFiles: 0, omittedFiles: 0, selection: "source-and-config" });
    let cancellationRequested = false;
    await assert.rejects(runPythonSnapshot(snapshot, cancellation.signal, async () => {
      if (!cancellationRequested) {
        cancellationRequested = true;
        // Allow parser children to start before cancelling the owned group.
        await new Promise((resolve) => setTimeout(resolve, 100));
        cancellation.abort();
      }
    }), { name: "AbortError" });
    assert.equal(cancellationRequested, true, "Cancellation must interrupt a running engine");
    assert.equal((await db.finding.count({ where: { scanId: job.scanId } })), 0);
    await runClaimedScan(db, job, env, new AbortController().signal);
    const saved = await db.scanJob.findUniqueOrThrow({ where: { id: job.id } });
    assert.equal(saved.status, "partial", saved.errorCode);
    assert.equal(saved.commitSha, commit);
    assert.match(saved.sourceDigest, /^sha256:[a-f0-9]{64}$/);
    assert.match(saved.resultDigest, /^sha256:[a-f0-9]{64}$/);
    assert.ok(saved.sourceCiphertext && !saved.sourceCiphertext.includes("from flask"));
    assert.ok(!saved.sourceManifest.includes("request.args"));
    const scan = await db.scan.findUniqueOrThrow({ where: { id: job.scanId } });
    assert.equal(scan.scanType, "sast"); assert.equal(scan.status, "partial");
    assert.match(scan.progressMessage, /unsupported/);
    const findings = await db.finding.findMany({ where: { scanId: job.scanId } });
    assert.ok(findings.some((finding) => finding.ruleId === "AEG-PATH-001" && finding.filePath === "app.py"));
    const signing = findings.find((finding) => finding.ruleId === "AEG-A02-001" && finding.filePath === "signing.py");
    assert.equal(signing?.lineStart, 2);
    assert.ok(!JSON.stringify([saved, findings]).includes("marker-signing-review-only"));
    const retained = JSON.parse(decrypt(saved.sourceCiphertext!));
    const masks = JSON.parse(saved.resultManifest).signingKeyReviewV1;
    const configured = retained.files.find((file: { path: string }) => file.path === "configured.py");
    assert.ok(configured);
    assert.ok(!Object.hasOwn(masks, configured.sha256));
    const review = captureReviewSources(retained, retained, [], masks);
    assert.equal(review.unverifiedSigningKeyFiles, 1);
    assert.ok(!review.files.some((file) => file.path === "configured.py"));
    const signingSource = review.files.find((file) => file.path === "signing.py");
    assert.equal(signingSource?.content.split("\n")[1], "[REDACTED_SIGNING_KEY]");
    assert.match(signingSource?.content || "", /return encode\(data,material\)/);
    const configuration = findings.find((finding) => finding.ruleId === "AEG-CF-001");
    assert.ok(configuration);
    assert.equal(configuration.filePath, "wrangler.jsonc");
    assert.equal(JSON.parse(configuration.provenance).analysis_kind, "configuration");
    assert.match(configuration.codeSnippet, /vars\.API_TOKEN = \[withheld\]/);
    const fields = await db.finding.findUniqueOrThrow({ where: { id: configuration.id }, select: reviewFindingSelect });
    assert.equal(freezeFinding(fields).data.codeSnippet, configuration.codeSnippet);
    assert.equal(JSON.parse(buildFindingPrompt(fields)).finding.codeSnippet, configuration.codeSnippet);
    const raw = "owned-configuration-canary";
    const imported = { ...fields, filePath: "app\\wrangler.toml", modulePath: "", message: raw,
      codeSnippet: 'SIGNING_KEY = "' + raw + '"', ruleName: raw, callChain: JSON.stringify([raw]) };
    for (const context of [imported, { ...imported, filePath: "archived.txt", modulePath: "src/wrangler.jsonc" }]) {
      const prompt = buildFindingPrompt(context, JSON.stringify([raw]));
      assert.ok(!prompt.includes(raw));
      assert.equal(JSON.parse(prompt).finding.lineStart, fields.lineStart);
    }
    const code = { ...fields, filePath: "app.ts", modulePath: "app.ts", callChain: null, codeSnippet: "const value = 1" };
    assert.match(buildFindingPrompt(code, '["recordedCaller"]'), /recordedCaller/);
    assert.match(buildFindingPrompt(code), /const value = 1/);
    const legacy = freezeFinding({ ...fields, codeSnippet: "value = 'owned-configuration-canary'", message: "owned-configuration-canary" });
    assert.ok(!JSON.stringify(legacy).includes("owned-configuration-canary"));
    assert.ok(!JSON.stringify([saved, ...findings]).includes("owned-configuration-canary"));
    assert.ok(findings.every((finding) => !finding.filePath.startsWith("/") && !finding.filePath.includes("../")));
    assert.ok((await db.scanJobEvent.findMany({ where: { jobId: job.id } })).some((event) => event.code === "published"));
  } finally {
    globalThis.fetch = originalFetch;
    if (originalSecret === undefined) delete process.env.ENCRYPTION_SECRET; else process.env.ENCRYPTION_SECRET = originalSecret;
    await db.$disconnect(); await rm(directory, { recursive: true, force: true });
  }
});
