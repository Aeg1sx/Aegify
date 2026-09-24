import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createEncryptedBackup, databasePathFromUrl, enableRecoveredUser, listRecoveryAccounts, restoreEncryptedBackup, verifyEncryptedBackup } from "./backup.ts";
import { decrypt, encrypt } from "./crypto.ts";
import { hashPassword, verifyPassword } from "./password.ts";
import { authenticateUploadToken, issueProjectToken } from "./project-tokens.ts";
import { resolvePrincipal } from "./project-access.ts";
import { createLocalAuthService } from "./local-auth.ts";
import { prepareReviewHistory, readReviewHistory, type SavedReview } from "./ai-review-history.ts";
import { freezeFinding, reviewFindingSelect, scanEvidenceDigest } from "./ai-review-contract.ts";
import { sha256 } from "./provider-receipt.ts";

const environment = { AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test" };
const originalPassword = "Owned original recovery phrase 2026";
const newPassword = "Owned replacement recovery phrase 2026";

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "aegify-recovery-test-"));
  const databasePath = join(directory, "source.db");
  const sql = createClient({ url: "file:" + databasePath });
  const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === "20260924020000_recovery_session_epoch") {
      await sql.execute('INSERT INTO "User" (id,email,sessionVersion,updatedAt) VALUES (\'legacy\',\'legacy@example.test\',7,CURRENT_TIMESTAMP)');
    }
    await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  }
  await sql.execute("PRAGMA journal_mode=WAL");
  await sql.execute("PRAGMA wal_autocheckpoint=0");
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url: "file:" + databasePath }) });
  const keys = { backupKey: randomBytes(32).toString("hex"), encryptionSecret: randomBytes(32).toString("hex") };
  await db.user.create({ data: { id: "root", email: "root@example.test", emailVerified: new Date(), username: "root", passwordHash: await hashPassword(originalPassword) } });
  await db.user.create({ data: { id: "sso", email: "sso@example.test" } });
  const project = await db.project.create({ data: { id: "project", name: "Owned recovery fixture", members: { create: [{ userId: "root", role: "admin" }, { userId: "sso", role: "viewer" }] } } });
  const scan = await db.scan.create({ data: { id: "completed", projectId: project.id, repository: "owned", status: "completed" } });
  await db.finding.create({ data: { id: "retained-finding", scanId: scan.id, ruleId: "OWNED", ruleName: "Owned fixture", severity: "low", filePath: "fixture.py", lineStart: 1, lineEnd: 1, status: "accepted_risk", message: "Synthetic historical evidence" } });
  await db.auditEvent.create({ data: { actorId: "root", action: "fixture.original", targetId: "retained-finding" } });
  await db.scan.create({ data: { id: "active", projectId: project.id, repository: "owned", status: "running" } });
  await db.scanJob.create({ data: { id: "job", scanId: "active", projectId: project.id, requestedBy: "root", provider: "github", ownerSlug: "owned/fixture", requestedRef: "main", status: "running", activeKey: project.id, leaseToken: "owned-lease", leaseExpiresAt: new Date(Date.now() + 60_000), workerId: "worker" } });
  await db.scanWorker.create({ data: { id: "worker", version: "fixture" } });
  await db.ruleFixtureJob.create({ data: { id: "rule-evaluation", projectId: project.id, requestedBy: "root", inputDigest: sha256("owned-rule-input"), status: "running", activeKey: project.id, leaseToken: "owned-rule-lease", leaseExpiresAt: new Date(Date.now() + 60_000), expiresAt: new Date(Date.now() + 86_400_000) } });
  await db.ruleFixtureJob.create({ data: { id: "saved-rule-evaluation", projectId: project.id, requestedBy: "root", inputDigest: sha256("owned-saved-rule-input"), status: "completed", outcome: "passed", resultDigest: sha256("owned-rule-report"), expiresAt: new Date(Date.now() + 86_400_000) } });
  await db.llmJob.create({ data: { id: "review", scanId: scan.id, mode: "quick", status: "running", activeKey: scan.id, leaseToken: "owned-ai-lease", leaseExpiresAt: new Date(Date.now() + 60_000), inputCiphertext: encrypt("owned-review-snapshot", keys.encryptionSecret), calls: { create: { batchIndex: 0, leaseToken: "owned-ai-lease", promptDigest: "owned-prompt" } } } });
  await db.llmWorker.create({ data: { id: "owned-ai-worker", version: "fixture" } });
  const savedJob = await db.llmJob.create({ data: { id: "saved-review", scanId: scan.id, projectId: project.id, mode: "quick", status: "completed", historyVersion: 1,
    inputDigest: sha256("owned-input"), provider: "anthropic", model: "owned-recovery-model", totalFindings: 1, reviewedCount: 1,
    calls: { create: { id: "saved-call", batchIndex: 0, leaseToken: "finished-fixture", promptDigest: sha256("owned-prompt"), responseDigest: sha256("owned-response"), status: "completed" } } } });
  const savedRecord: SavedReview = { version: 1, id: "saved-narrative", jobId: savedJob.id, callId: "saved-call", scanId: scan.id, projectId: project.id,
    batchIndex: 0, ordinal: 0, publication: "published", provider: savedJob.provider, model: savedJob.model, mode: savedJob.mode,
    inputDigest: savedJob.inputDigest, scanDigest: scanEvidenceDigest(scan), promptDigest: sha256("owned-prompt"), responseDigest: sha256("owned-response"), createdAt: new Date().toISOString(),
    finding: freezeFinding(await db.finding.findUniqueOrThrow({ where: { id: "retained-finding" }, select: reviewFindingSelect })),
    result: { findingId: "retained-finding", verdict: "needs_review", confidence: 0.2, reasoning: "Owned retained review explanation.", remediation: "Review supplied facts.", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["Static evidence only."] } };
  await db.llmReview.create({ data: prepareReviewHistory([savedRecord], keys.encryptionSecret)[0] });
  await db.agentRun.create({ data: { id: "agent", scanId: scan.id, status: "awaiting_approval", stages: { create: { sequence: 0, role: "static", agentCode: "fixture", agentName: "Fixture" } }, approvals: { create: { resourceId: "owned-plan", status: "approved", scopeDigest: "fixture" } } } });
  const principal = await resolvePrincipal(db, "root", environment);
  const issued = await issueProjectToken(db, principal, project.id, "Owned CI fixture", new Date(Date.now() + 60_000));
  const ciphertext = encrypt("owned-integration-placeholder", keys.encryptionSecret);
  await db.setting.create({ data: { key: "fixture.encrypted", value: ciphertext, encrypted: true } });
  const archivePath = join(directory, "backup.aegify");
  return { directory, databasePath, archivePath, db, sql, keys, issued, close: async () => { await db.$disconnect(); sql.close(); await rm(directory, { recursive: true, force: true }); } };
}

test("encrypted WAL snapshot restores history while invalidating accounts, credentials and unfinished work", async () => {
  const owned = await fixture();
  let restored: PrismaClient | undefined;
  try {
    assert.equal((await owned.db.user.findUniqueOrThrow({ where: { id: "legacy" } })).sessionEpoch, "", "Legacy migration preserves sessions until recovery");
    assert.ok((await stat(owned.databasePath + "-wal")).size > 0);
    const manifest = await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: owned.archivePath });
    assert.equal(manifest.encryptionKeyCheck, "stored_ciphertext");
    assert.ok(Date.parse(manifest.snapshotStartedAt) <= Date.parse(manifest.snapshotCompletedAt));
    assert.equal((await stat(owned.archivePath)).mode & 0o777, 0o600);
    const archiveBytes = await readFile(owned.archivePath);
    for (const plaintext of ["Owned recovery fixture", "Synthetic historical evidence", "root@example.test"]) {
      assert.ok(!archiveBytes.includes(Buffer.from(plaintext)), "Database contents must be encrypted in the archive");
    }
    assert.deepEqual(await verifyEncryptedBackup({ ...owned.keys, archivePath: owned.archivePath }), manifest);
    // Later writes must not contaminate the saved snapshot.
    await owned.db.project.create({ data: { name: "After backup" } });
    await owned.db.user.update({ where: { id: "legacy" }, data: { sessionVersion: 8 } });
    const outputPath = join(owned.directory, "restored.db");
    const result = await restoreEncryptedBackup({ ...owned.keys, archivePath: owned.archivePath, outputPath });
    assert.notEqual(result.restoredDigest, manifest.databaseDigest, "Recovery state changes are explicit");
    assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
    restored = new PrismaClient({ adapter: new PrismaLibSql({ url: "file:" + outputPath }) });
    assert.equal(await restored.project.count(), 1);
    assert.equal((await restored.finding.findUniqueOrThrow({ where: { id: "retained-finding" } })).status, "accepted_risk");
    assert.equal((await restored.scan.findUniqueOrThrow({ where: { id: "completed" } })).status, "completed");
    assert.equal((await restored.scan.findUniqueOrThrow({ where: { id: "active" } })).status, "cancelled");
    assert.equal((await restored.scanJob.findUniqueOrThrow({ where: { id: "job" } })).leaseToken, null);
    assert.equal(await restored.scanWorker.count(), 0);
    const restoredFixture = await restored.ruleFixtureJob.findUniqueOrThrow({ where: { id: "rule-evaluation" } });
    assert.equal(restoredFixture.status, "cancelled"); assert.equal(restoredFixture.leaseToken, null); assert.equal(restoredFixture.activeKey, null);
    assert.ok(await restored.ruleFixtureJobEvent.count({ where: { code: "recovered_cancelled" } }));
    assert.deepEqual(await restored.ruleFixtureJob.findUniqueOrThrow({ where: { id: "saved-rule-evaluation" } }), await owned.db.ruleFixtureJob.findUniqueOrThrow({ where: { id: "saved-rule-evaluation" } }));
    assert.equal((await restored.llmJob.findUniqueOrThrow({ where: { id: "review" } })).status, "failed");
    assert.equal((await restored.llmJob.findUniqueOrThrow({ where: { id: "review" } })).leaseToken, null);
    assert.equal((await restored.llmCall.findFirstOrThrow({ where: { jobId: "review" } })).status, "unknown");
    assert.equal(await restored.llmWorker.count(), 0);
    const savedReview = await restored.llmReview.findUniqueOrThrow({ where: { id: "saved-narrative" } });
    assert.deepEqual(savedReview, await owned.db.llmReview.findUniqueOrThrow({ where: { id: "saved-narrative" } }));
    assert.equal(JSON.parse(decrypt(savedReview.payloadCiphertext, owned.keys.encryptionSecret)).result.reasoning, "Owned retained review explanation.");
    await assert.rejects(restored.llmReview.update({ where: { id: savedReview.id }, data: { confidence: 1 } }), "Restored history keeps its append-only constraint");
    assert.ok(await restored.llmJobEvent.count({ where: { code: "recovered_cancelled" } }));
    assert.equal((await restored.agentRun.findUniqueOrThrow({ where: { id: "agent" } })).status, "cancelled");
    assert.equal((await restored.agentApproval.findFirstOrThrow()).status, "expired");
    assert.equal(await restored.user.count({ where: { disabled: true } }), 3);
    const legacy = await restored.user.findUniqueOrThrow({ where: { id: "legacy" } });
    assert.equal(legacy.sessionVersion, 7); assert.ok(legacy.sessionEpoch.length >= 32);
    assert.equal(await authenticateUploadToken(restored, owned.issued.token, environment), null);
    assert.equal(await authenticateUploadToken(restored, "synthetic-legacy", { ...environment, AEGIFY_UPLOAD_TOKEN: "synthetic-legacy", AEGIFY_UPLOAD_PROJECT_ID: "project" }), null);
    assert.ok(await authenticateUploadToken(owned.db, owned.issued.token, environment), "Live source credentials are unchanged");
    assert.equal((await owned.db.scanJob.findUniqueOrThrow({ where: { id: "job" } })).status, "running");
    assert.equal(await restored.auditEvent.count({ where: { action: "fixture.original" } }), 1);
    assert.equal(await restored.auditEvent.count({ where: { action: "recovery.restored" } }), 1);
    assert.equal(decrypt((await restored.setting.findUniqueOrThrow({ where: { key: "fixture.encrypted" } })).value, owned.keys.encryptionSecret), "owned-integration-placeholder");
    const accounts = await listRecoveryAccounts(outputPath);
    assert.equal(accounts.length, 3); assert.ok(!JSON.stringify(accounts).includes("passwordHash"));
    await assert.rejects(enableRecoveredUser({ databasePath: outputPath, email: "root@example.test", environment }), /new AEGIFY_RECOVERY_PASSWORD/);
    await assert.rejects(enableRecoveredUser({ databasePath: outputPath, email: "root@example.test", password: originalPassword, environment }), /different password/);
    await enableRecoveredUser({ databasePath: outputPath, email: "root@example.test", password: newPassword, environment });
    const priorSecret = process.env.ENCRYPTION_SECRET;
    try {
      process.env.ENCRYPTION_SECRET = owned.keys.encryptionSecret;
      const reviewer = await resolvePrincipal(restored, "root", environment);
      const saved = await readReviewHistory(restored, reviewer, "saved-review", "saved-narrative");
      assert.equal(saved.record.result.reasoning, "Owned retained review explanation.");
      assert.equal(saved.current?.status, "accepted_risk");
    } finally { if (priorSecret === undefined) delete process.env.ENCRYPTION_SECRET; else process.env.ENCRYPTION_SECRET = priorSecret; }
    const root = await restored.user.findUniqueOrThrow({ where: { id: "root" } });
    assert.equal(root.disabled, false); assert.ok(await verifyPassword(newPassword, root.passwordHash));
    assert.equal(await verifyPassword(originalPassword, root.passwordHash), false);
    const local = createLocalAuthService(restored, environment, async () => { throw new Error("Recovery must not send email"); });
    assert.ok(await local.authenticate("root", newPassword));
    assert.equal(await local.authenticate("root", originalPassword), null);
    assert.notEqual(root.sessionEpoch, legacy.sessionEpoch);
    await assert.rejects(enableRecoveredUser({ databasePath: outputPath, email: "sso@example.test", password: newPassword, environment }), /SSO-only/);
    await enableRecoveredUser({ databasePath: outputPath, email: "sso@example.test", environment });
    assert.equal((await restored.user.findUniqueOrThrow({ where: { id: "sso" } })).disabled, false);
    assert.ok((await readdir(owned.directory)).every((name) => !name.startsWith(".aegify-")));
  } finally { await restored?.$disconnect(); await owned.close(); }
});

test("wrong keys, truncation, tampering, existing destinations and late restore failures never publish", async () => {
  const owned = await fixture();
  try {
    await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: owned.archivePath });
    const wrongSourceKey = join(owned.directory, "wrong-source-key.aegify");
    await assert.rejects(createEncryptedBackup({ ...owned.keys, encryptionSecret: randomBytes(32).toString("hex"), databasePath: owned.databasePath, outputPath: wrongSourceKey }), /cannot authenticate/);
    await assert.rejects(stat(wrongSourceKey), { code: "ENOENT" });
    const destination = join(owned.directory, "candidate.db");
    const raw = await readFile(owned.archivePath);
    for (const mode of ["key", "installation", "truncated", "tampered", "header"]) {
      const input = join(owned.directory, mode + ".aegify");
      const bytes = Buffer.from(raw);
      if (mode === "tampered") bytes[bytes.length - 1] ^= 1;
      if (mode === "header") bytes.writeUInt32BE(0xffffffff, Buffer.byteLength("AEGIFY-BACKUP/1\n"));
      await writeFile(input, mode === "truncated" ? bytes.subarray(0, bytes.length - 8) : bytes);
      const keys = { ...owned.keys, ...(mode === "key" ? { backupKey: randomBytes(32).toString("hex") } : {}), ...(mode === "installation" ? { encryptionSecret: randomBytes(32).toString("hex") } : {}) };
      await assert.rejects(restoreEncryptedBackup({ ...keys, archivePath: input, outputPath: destination }));
      await assert.rejects(stat(destination), { code: "ENOENT" });
      assert.ok((await readdir(owned.directory)).every((name) => !name.startsWith(".aegify-")));
    }
    await writeFile(destination, "keep existing data");
    await assert.rejects(restoreEncryptedBackup({ ...owned.keys, archivePath: owned.archivePath, outputPath: destination }), /already exists/);
    await assert.rejects(createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: destination }), /already exists/);
    assert.equal(await readFile(destination, "utf8"), "keep existing data");
    await owned.sql.execute("CREATE TRIGGER fail_recovery_audit BEFORE INSERT ON AuditEvent BEGIN SELECT RAISE(ABORT, 'owned late failure'); END");
    const failedArchive = join(owned.directory, "late-failure.aegify");
    await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: failedArchive });
    const failedOutput = join(owned.directory, "failed.db");
    await assert.rejects(restoreEncryptedBackup({ ...owned.keys, archivePath: failedArchive, outputPath: failedOutput }));
    await assert.rejects(stat(failedOutput), { code: "ENOENT" });
    assert.equal((await owned.db.user.findUniqueOrThrow({ where: { id: "root" } })).disabled, false);
  } finally { await owned.close(); }
});

test("concurrent publication has one winner and the operator CLI emits no key material", async () => {
  const owned = await fixture();
  try {
    await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: owned.archivePath });
    const outputPath = join(owned.directory, "concurrent.db");
    const results = await Promise.allSettled([1, 2].map(() => restoreEncryptedBackup({ ...owned.keys, archivePath: owned.archivePath, outputPath })));
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    assert.ok((await readdir(owned.directory)).every((name) => !name.startsWith(".aegify-")));
    const script = fileURLToPath(new URL("../../scripts/recovery.mjs", import.meta.url));
    const command = spawnSync(process.execPath, [script, "verify", "--archive", owned.archivePath], { encoding: "utf8", timeout: 30_000, env: { ...process.env, AEGIFY_BACKUP_KEY: owned.keys.backupKey, ENCRYPTION_SECRET: owned.keys.encryptionSecret } });
    assert.equal(command.status, 0, command.stderr);
    assert.equal(JSON.parse(command.stdout).status, "backup_verified");
    assert.ok(!command.stdout.includes(owned.keys.backupKey) && !command.stdout.includes(owned.keys.encryptionSecret));
    await owned.db.setting.delete({ where: { key: "fixture.encrypted" } });
    const aiArchive = join(owned.directory, "ai-key-check.aegify");
    assert.equal((await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: aiArchive })).encryptionKeyCheck, "stored_ciphertext");
    assert.equal((await verifyEncryptedBackup({ ...owned.keys, archivePath: aiArchive })).encryptionKeyCheck, "stored_ciphertext");
    await owned.db.llmJob.update({ where: { id: "review" }, data: { inputCiphertext: null } });
    const historyArchive = join(owned.directory, "history-key-check.aegify");
    assert.equal((await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: historyArchive })).encryptionKeyCheck, "stored_ciphertext");
    await assert.rejects(createEncryptedBackup({ ...owned.keys, encryptionSecret: "owned-wrong-installation-key", databasePath: owned.databasePath, outputPath: join(owned.directory, "wrong-history-key.aegify") }));
    await owned.db.llmJob.delete({ where: { id: "saved-review" } });
    const emptyManifest = await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: join(owned.directory, "no-encrypted-records.aegify") });
    assert.equal(emptyManifest.encryptionKeyCheck, "no_encrypted_records");
    await owned.db.ruleFixtureJob.update({ where: { id: "rule-evaluation" }, data: { inputCiphertext: encrypt("owned-rule-input", owned.keys.encryptionSecret) } });
    const ruleArchive = join(owned.directory, "rule-key-check.aegify");
    assert.equal((await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: ruleArchive })).encryptionKeyCheck, "stored_ciphertext");
    await assert.rejects(verifyEncryptedBackup({ ...owned.keys, encryptionSecret: "owned-wrong-rule-key", archivePath: ruleArchive }));
    await owned.db.ruleFixtureJob.update({ where: { id: "rule-evaluation" }, data: { inputCiphertext: null } });
    await owned.db.ruleFixtureJob.update({ where: { id: "saved-rule-evaluation" }, data: { resultCiphertext: encrypt("owned-rule-report", owned.keys.encryptionSecret) } });
    const reportArchive = join(owned.directory, "rule-report-key-check.aegify");
    assert.equal((await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: reportArchive })).encryptionKeyCheck, "stored_ciphertext");
    await owned.db.ruleFixtureJob.update({ where: { id: "saved-rule-evaluation" }, data: { resultCiphertext: null } });
    await owned.db.scanJob.update({ where: { id: "job" }, data: { sourceCiphertext: encrypt("owned-source-placeholder", owned.keys.encryptionSecret) } });
    const sourceArchive = join(owned.directory, "source-key-check.aegify");
    assert.equal((await createEncryptedBackup({ ...owned.keys, databasePath: owned.databasePath, outputPath: sourceArchive })).encryptionKeyCheck, "stored_ciphertext");
    assert.equal((await verifyEncryptedBackup({ ...owned.keys, archivePath: sourceArchive })).encryptionKeyCheck, "stored_ciphertext");
    for (const url of [undefined, "libsql://example.test", "file::memory:", "file:./data.db?mode=ro", "file://host/path.db"]) assert.throws(() => databasePathFromUrl(url));
    assert.ok(databasePathFromUrl("file:./fixture.db").endsWith("fixture.db"));
  } finally { await owned.close(); }
});
