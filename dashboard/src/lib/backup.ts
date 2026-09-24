/** Operator-only SQLite recovery. Never imported into a web route. */
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, randomUUID } from "node:crypto";
import { constants, createReadStream, createWriteStream } from "node:fs";
import { chmod, link, lstat, mkdtemp, open, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createClient, type Client, type InStatement } from "@libsql/client";
import { emailAllowed, normalizeEmail, type AuthEnvironment } from "./auth-policy.ts";
import { hashPassword, verifyPassword } from "./password.ts";
import { RECOVERY_RECEIPT_KEY } from "./recovery-policy.ts";
import { decrypt } from "./crypto.ts";

const MAGIC = Buffer.from("AEGIFY-BACKUP/1\n");
const MAX_HEADER_BYTES = 16_384;
const MAX_DATABASE_BYTES = 8 * 1024 ** 3;
const RESTORE_SETTING = RECOVERY_RECEIPT_KEY;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const TABLES = ["User", "Project", "Scan", "Finding", "AuditEvent"] as const;

export interface BackupKeys { backupKey: string; encryptionSecret: string }
export interface BackupManifest {
  format: "aegify.sqlite.v1";
  algorithm: "AES-256-GCM-HKDF-SHA256";
  createdAt: string;
  snapshotStartedAt: string;
  snapshotCompletedAt: string;
  databaseBytes: number;
  databaseDigest: string;
  schemaDigest: string;
  encryptionKeyBinding: string;
  encryptionKeyCheck: "stored_ciphertext" | "no_encrypted_records";
  salt: string;
  iv: string;
  counts: Record<string, number>;
}

function sha256(value: string | Buffer): string { return "sha256:" + createHash("sha256").update(value).digest("hex"); }

function requireKeys(keys: BackupKeys): void {
  if (!/^[a-fA-F0-9]{64}$/.test(keys.backupKey)) throw new Error("AEGIFY_BACKUP_KEY must be a separate 32-byte random key encoded as 64 hex characters.");
  if (keys.encryptionSecret.length < 32 || keys.encryptionSecret.length > 4096) throw new Error("Provide the installation's ENCRYPTION_SECRET (32..4096 characters).");
  if (keys.backupKey.toLowerCase() === keys.encryptionSecret.toLowerCase()) throw new Error("Use a backup key distinct from ENCRYPTION_SECRET.");
}

function archiveKey(key: string, salt: string): Buffer {
  return Buffer.from(hkdfSync("sha256", Buffer.from(key, "hex"), Buffer.from(salt, "hex"), "aegify.sqlite.backup.v1", 32));
}

function encryptionBinding(keys: BackupKeys, salt: string): string {
  // Do not expose an unkeyed password/secret verifier in the plaintext header.
  return "hmac-sha256:" + createHmac("sha256", archiveKey(keys.backupKey, salt)).update("aegify.installation-key.v1\0").update(keys.encryptionSecret).digest("hex");
}

export function databasePathFromUrl(value: string | undefined): string {
  if (!value?.startsWith("file:") || !value.slice(5) || /[?#\x00-\x1f]/.test(value) || value.includes(":memory:")) throw new Error("Set DATABASE_URL to a local SQLite file, without URI query parameters.");
  const path = value.slice(5);
  if (path.startsWith("//")) throw new Error("Use file:/absolute/path.db or file:./relative/path.db.");
  return resolve(path);
}

async function inputFile(path: string): Promise<string> {
  const resolved = resolve(path);
  const info = await lstat(resolved);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("Input must be a regular file, not a symbolic link.");
  return join(await realpath(dirname(resolved)), basename(resolved));
}

async function newOutput(path: string): Promise<string> {
  if (!isAbsolute(path)) throw new Error("Choose an absolute output path in an existing private directory.");
  const output = join(await realpath(dirname(path)), basename(path));
  try { await lstat(output); }
  catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return output;
    throw error;
  }
  throw new Error("Output already exists; recovery never overwrites an existing file.");
}

async function digestFile(path: string): Promise<string> {
  const digest = createHash("sha256");
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { for await (const chunk of file.createReadStream()) digest.update(chunk); }
  finally { await file.close(); }
  return "sha256:" + digest.digest("hex");
}

async function publishFile(path: string, output: string): Promise<void> {
  const file = await open(path, "r");
  try { await file.sync(); } finally { await file.close(); }
  // Same-directory staging makes hard-link publication atomic and no-clobber,
  // even if another process creates the destination after the initial check.
  await link(path, output);
  const directory = await open(dirname(output), "r");
  try { await directory.sync(); } finally { await directory.close(); }
}

async function inspectDatabase(client: Client): Promise<{ schemaDigest: string; counts: Record<string, number> }> {
  const integrity = await client.execute("PRAGMA integrity_check(1)");
  if (integrity.rows.length !== 1 || integrity.rows[0][0] !== "ok") throw new Error("SQLite integrity check failed.");
  if ((await client.execute("SELECT * FROM pragma_foreign_key_check LIMIT 1")).rows.length) throw new Error("SQLite foreign-key check failed.");
  const columns = await client.execute('PRAGMA table_info("User")');
  if (!columns.rows.some((row) => row.name === "sessionEpoch")) throw new Error("Apply current Aegify migrations before using recovery tooling.");
  const schema = await client.execute("SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY type, name LIMIT 1001");
  if (schema.rows.length > 1000) throw new Error("Database schema exceeds the recovery manifest limit.");
  const counts: Record<string, number> = {};
  for (const table of TABLES) counts[table] = Number((await client.execute(`SELECT count(*) AS count FROM "${table}"`)).rows[0].count);
  return { schemaDigest: sha256(JSON.stringify(schema.rows)), counts };
}

async function checkInstallationKey(client: Client, secret: string): Promise<BackupManifest["encryptionKeyCheck"]> {
  // One authenticated ciphertext proves the supplied installation key. Do not
  // claim that this checks every historical integration or source snapshot.
  let sample = (await client.execute('SELECT length(value) AS bytes, CASE WHEN length(value) <= 67108864 THEN value ELSE NULL END AS value FROM "Setting" WHERE encrypted = 1 ORDER BY key LIMIT 1')).rows[0];
  if (!sample) sample = (await client.execute('SELECT length(sourceCiphertext) AS bytes, CASE WHEN length(sourceCiphertext) <= 67108864 THEN sourceCiphertext ELSE NULL END AS value FROM "ScanJob" WHERE sourceCiphertext IS NOT NULL ORDER BY id LIMIT 1')).rows[0];
  if (!sample && (await client.execute('PRAGMA table_info("LlmJob")')).rows.some((row) => row.name === "inputCiphertext")) sample = (await client.execute('SELECT length(inputCiphertext) AS bytes, CASE WHEN length(inputCiphertext) <= 67108864 THEN inputCiphertext ELSE NULL END AS value FROM "LlmJob" WHERE inputCiphertext IS NOT NULL ORDER BY id LIMIT 1')).rows[0];
  if (!sample && (await client.execute('PRAGMA table_info("LlmReview")')).rows.some((row) => row.name === "payloadCiphertext")) sample = (await client.execute('SELECT length(payloadCiphertext) AS bytes, CASE WHEN length(payloadCiphertext) <= 67108864 THEN payloadCiphertext ELSE NULL END AS value FROM "LlmReview" ORDER BY id LIMIT 1')).rows[0];
  if (!sample && (await client.execute('PRAGMA table_info("LlmCall")')).rows.some((row) => row.name === "continuationCiphertext")) sample = (await client.execute('SELECT length(continuationCiphertext) AS bytes, CASE WHEN length(continuationCiphertext) <= 67108864 THEN continuationCiphertext ELSE NULL END AS value FROM "LlmCall" WHERE continuationCiphertext IS NOT NULL ORDER BY id LIMIT 1')).rows[0];
  if (!sample) return "no_encrypted_records";
  if (typeof sample.value !== "string") throw new Error("Stored ciphertext exceeds the installation-key check limit.");
  try { decrypt(sample.value, secret); }
  catch { throw new Error("ENCRYPTION_SECRET cannot authenticate the stored key-check sample."); }
  return "stored_ciphertext";
}

export async function createEncryptedBackup(options: BackupKeys & { databasePath: string; outputPath: string }): Promise<BackupManifest> {
  requireKeys(options);
  const database = await inputFile(options.databasePath);
  const output = await newOutput(options.outputPath);
  if ((await stat(database)).size > MAX_DATABASE_BYTES) throw new Error("Database exceeds the 8 GiB recovery limit.");
  const staging = await mkdtemp(join(dirname(output), ".aegify-backup-"));
  const snapshot = join(staging, "snapshot.db");
  const archive = join(staging, "archive.aegify");
  let source: Client | undefined;
  try {
    source = createClient({ url: "file:" + database });
    await source.execute("PRAGMA busy_timeout=5000");
    await source.execute("PRAGMA synchronous=FULL");
    const snapshotStartedAt = new Date().toISOString();
    await source.execute({ sql: "VACUUM main INTO ?", args: [snapshot] });
    const snapshotCompletedAt = new Date().toISOString();
    await chmod(snapshot, 0o600);
    const size = (await stat(snapshot)).size;
    if (size > MAX_DATABASE_BYTES) throw new Error("Snapshot exceeds the 8 GiB recovery limit.");
    const copy = createClient({ url: "file:" + snapshot });
    let inspected;
    let encryptionKeyCheck;
    try { inspected = await inspectDatabase(copy); encryptionKeyCheck = await checkInstallationKey(copy, options.encryptionSecret); }
    finally { copy.close(); }
    const salt = randomBytes(32).toString("hex");
    const manifest: BackupManifest = {
      format: "aegify.sqlite.v1", algorithm: "AES-256-GCM-HKDF-SHA256", createdAt: new Date().toISOString(),
      snapshotStartedAt, snapshotCompletedAt, encryptionKeyCheck,
      databaseBytes: size, databaseDigest: await digestFile(snapshot), ...inspected,
      encryptionKeyBinding: encryptionBinding(options, salt), salt, iv: randomBytes(12).toString("hex"),
    };
    const header = Buffer.from(JSON.stringify(manifest));
    if (header.length > MAX_HEADER_BYTES) throw new Error("Backup manifest exceeds its limit.");
    const length = Buffer.alloc(4); length.writeUInt32BE(header.length);
    const prefix = Buffer.concat([MAGIC, length, header]);
    const cipher = createCipheriv("aes-256-gcm", archiveKey(options.backupKey, manifest.salt), Buffer.from(manifest.iv, "hex"), { authTagLength: 16 });
    cipher.setAAD(prefix);
    const destination = await open(archive, "wx", 0o600);
    try {
      await destination.writeFile(prefix);
    } finally { await destination.close(); }
    await pipeline(createReadStream(snapshot), cipher, createWriteStream(archive, { start: prefix.length, flags: "r+" }));
    const finalized = await open(archive, "r+");
    try {
      await finalized.write(cipher.getAuthTag(), 0, 16, prefix.length + size);
      await finalized.sync();
    } finally { await finalized.close(); }
    await publishFile(archive, output);
    return manifest;
  } finally { source?.close(); await rm(staging, { recursive: true, force: true }); }
}

function parseManifest(value: unknown): BackupManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid backup manifest.");
  const item = value as Record<string, unknown>;
  if (item.format !== "aegify.sqlite.v1" || item.algorithm !== "AES-256-GCM-HKDF-SHA256"
    || typeof item.createdAt !== "string" || !Number.isFinite(Date.parse(item.createdAt))
    || typeof item.snapshotStartedAt !== "string" || !Number.isFinite(Date.parse(item.snapshotStartedAt))
    || typeof item.snapshotCompletedAt !== "string" || !Number.isFinite(Date.parse(item.snapshotCompletedAt))
    || !["stored_ciphertext", "no_encrypted_records"].includes(String(item.encryptionKeyCheck))
    || typeof item.databaseBytes !== "number" || !Number.isSafeInteger(item.databaseBytes) || item.databaseBytes < 100 || item.databaseBytes > MAX_DATABASE_BYTES
    || !SHA256.test(String(item.databaseDigest)) || !SHA256.test(String(item.schemaDigest)) || typeof item.encryptionKeyBinding !== "string" || !/^hmac-sha256:[a-f0-9]{64}$/.test(item.encryptionKeyBinding)
    || typeof item.salt !== "string" || !/^[a-f0-9]{64}$/.test(item.salt)
    || typeof item.iv !== "string" || !/^[a-f0-9]{24}$/.test(item.iv)
    || !item.counts || typeof item.counts !== "object" || Array.isArray(item.counts)) throw new Error("Invalid or unsupported backup manifest.");
  const counts = item.counts as Record<string, unknown>;
  if (TABLES.some((table) => typeof counts[table] !== "number" || !Number.isSafeInteger(counts[table]) || Number(counts[table]) < 0)) throw new Error("Invalid backup row counts.");
  return item as unknown as BackupManifest;
}

async function decodeArchive(archivePath: string, databasePath: string, keys: BackupKeys): Promise<BackupManifest> {
  requireKeys(keys);
  const archive = await open(await inputFile(archivePath), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await archive.stat();
    if (!info.isFile() || info.size > MAX_DATABASE_BYTES + MAX_HEADER_BYTES + MAGIC.length + 20) throw new Error("Backup exceeds the recovery size limit.");
    const prefix = Buffer.alloc(MAGIC.length + 4);
    if ((await archive.read(prefix, 0, prefix.length, 0)).bytesRead !== prefix.length || !prefix.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error("Unrecognized backup format.");
    const headerSize = prefix.readUInt32BE(MAGIC.length);
    if (headerSize < 2 || headerSize > MAX_HEADER_BYTES) throw new Error("Invalid backup header size.");
    const header = Buffer.alloc(headerSize);
    if ((await archive.read(header, 0, headerSize, prefix.length)).bytesRead !== headerSize) throw new Error("Truncated backup header.");
    const manifest = parseManifest(JSON.parse(header.toString("utf8")));
    const start = prefix.length + headerSize;
    if (start + manifest.databaseBytes + 16 !== info.size) throw new Error("Truncated backup or mismatched payload size.");
    const tag = Buffer.alloc(16);
    await archive.read(tag, 0, 16, info.size - 16);
    const decipher = createDecipheriv("aes-256-gcm", archiveKey(keys.backupKey, manifest.salt), Buffer.from(manifest.iv, "hex"), { authTagLength: 16 });
    decipher.setAAD(Buffer.concat([prefix, header])); decipher.setAuthTag(tag);
    const digest = createHash("sha256");
    let bytes = 0;
    const checked = new Transform({ transform(chunk: Buffer, _encoding, next) {
      bytes += chunk.length;
      if (bytes > manifest.databaseBytes) { next(new Error("Decrypted data exceeds declared size.")); return; }
      digest.update(chunk); next(null, chunk);
    } });
    try {
      await pipeline(archive.createReadStream({ start, end: info.size - 17 }), decipher, checked, createWriteStream(databasePath, { flags: "wx", mode: 0o600 }));
    } catch { throw new Error("Backup decryption/authentication failed; no database was published."); }
    if (bytes !== manifest.databaseBytes || "sha256:" + digest.digest("hex") !== manifest.databaseDigest) throw new Error("Backup database digest does not match.");
    if (encryptionBinding(keys, manifest.salt) !== manifest.encryptionKeyBinding) throw new Error("ENCRYPTION_SECRET does not match this backup's installation.");
    const copy = createClient({ url: "file:" + databasePath });
    try {
      const inspected = await inspectDatabase(copy);
      if (inspected.schemaDigest !== manifest.schemaDigest || TABLES.some((table) => inspected.counts[table] !== manifest.counts[table])) throw new Error("Backup schema or row counts do not match.");
      if (await checkInstallationKey(copy, keys.encryptionSecret) !== manifest.encryptionKeyCheck) throw new Error("Backup installation-key check does not match.");
    } finally { copy.close(); }
    return manifest;
  } finally { await archive.close(); }
}

export async function verifyEncryptedBackup(options: BackupKeys & { archivePath: string }): Promise<BackupManifest> {
  const staging = await mkdtemp(join(tmpdir(), "aegify-backup-check-"));
  try { return await decodeArchive(options.archivePath, join(staging, "verify.db"), options); }
  finally { await rm(staging, { recursive: true, force: true }); }
}

export async function restoreEncryptedBackup(options: BackupKeys & { archivePath: string; outputPath: string }): Promise<{ manifest: BackupManifest; restoreId: string; restoredDigest: string }> {
  requireKeys(options);
  const output = await newOutput(options.outputPath);
  const staging = await mkdtemp(join(dirname(output), ".aegify-restore-"));
  const candidate = join(staging, "restored.db");
  try {
    const manifest = await decodeArchive(options.archivePath, candidate, options);
    const restoreId = randomUUID();
    const now = new Date().toISOString();
    const receipt = { restoreId, restoredAt: now, backupCreatedAt: manifest.createdAt, backupDigest: manifest.databaseDigest, access: "disabled_until_operator_review" };
    const copy = createClient({ url: "file:" + candidate });
    try {
      const durableAi = (await copy.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name='LlmCall'")).rows.length > 0;
      const statements: InStatement[] = [
        { sql: 'UPDATE "User" SET disabled = 1, sessionEpoch = ?, updatedAt = ?', args: [randomUUID(), now] },
        'DELETE FROM "Session"', 'DELETE FROM "VerificationToken"', 'DELETE FROM "AuthActionToken"',
        { sql: 'UPDATE "ProjectServiceToken" SET revokedAt = ? WHERE revokedAt IS NULL', args: [now] },
        { sql: 'INSERT INTO "ScanJobEvent" (jobId, code, message, details, createdAt) SELECT id, ?, ?, ?, ? FROM "ScanJob" WHERE status IN (\'queued\', \'running\')', args: ["recovered_cancelled", "Cancelled during backup recovery", JSON.stringify({ restoreId }), now] },
        { sql: 'UPDATE "Scan" SET status = \'cancelled\', progressPhaseName = \'recovered_cancelled\', progressMessage = ?, progressUpdatedAt = ? WHERE status IN (\'pending\', \'running\')', args: ["Cancelled during backup recovery", now] },
        { sql: 'UPDATE "ScanJob" SET status = \'cancelled\', activeKey = NULL, leaseToken = NULL, leaseExpiresAt = NULL, errorCode = \'recovered_cancelled\', completedAt = ?, updatedAt = ? WHERE status IN (\'queued\', \'running\')', args: [now, now] },
        'DELETE FROM "ScanWorker"',
        ...(durableAi ? [
          { sql: 'INSERT INTO "LlmJobEvent" (id, jobId, code, message, details, createdAt) SELECT ? || id, id, ?, ?, ?, ? FROM "LlmJob" WHERE status IN (\'pending\', \'running\')', args: [restoreId + "-ai-", "recovered_cancelled", "Interrupted by backup recovery; provider outcome may be unknown", JSON.stringify({ restoreId }), now] },
          { sql: 'UPDATE "LlmCall" SET status = \'unknown\', errorCode = \'provider_outcome_unknown\' WHERE status = \'dispatched\'', args: [] },
          { sql: 'UPDATE "LlmJob" SET leaseToken = NULL, leaseExpiresAt = NULL, cancelRequestedAt = ?, errorCode = \'recovered_cancelled\' WHERE status IN (\'pending\', \'running\')', args: [now] },
          'DELETE FROM "LlmWorker"',
        ] : []),
        { sql: 'UPDATE "LlmJob" SET status = \'failed\', activeKey = NULL, errorMessage = ?, completedAt = ? WHERE status IN (\'pending\', \'running\')', args: ["Interrupted by backup recovery; start a new review", now] },
        { sql: 'UPDATE "AgentRun" SET status = \'cancelled\', errorMessage = ?, completedAt = ? WHERE status IN (\'running\', \'awaiting_approval\')', args: ["Cancelled during backup recovery", now] },
        { sql: 'UPDATE "AgentStage" SET status = \'failed\', errorMessage = ?, completedAt = ? WHERE status IN (\'pending\', \'running\', \'waiting_approval\')', args: ["Interrupted by backup recovery", now] },
        { sql: 'UPDATE "AgentApproval" SET status = \'expired\', decisionNote = ?, decidedAt = ? WHERE status IN (\'pending\', \'approved\')', args: ["Invalidated during backup recovery", now] },
        { sql: 'INSERT INTO "Setting" (key, value, encrypted, updatedAt) VALUES (?, ?, 0, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, encrypted=0, updatedAt=excluded.updatedAt', args: [RESTORE_SETTING, JSON.stringify(receipt), now] },
        { sql: 'INSERT INTO "AuditEvent" (id, actorId, action, targetId, details, createdAt) VALUES (?, ?, ?, ?, ?, ?)', args: [randomUUID(), "operator:recovery", "recovery.restored", restoreId, JSON.stringify(receipt), now] },
      ];
      await copy.batch(statements, "write");
      await copy.execute("PRAGMA wal_checkpoint(TRUNCATE)");
      await copy.execute("PRAGMA journal_mode=DELETE");
      await inspectDatabase(copy);
    } finally { copy.close(); }
    const restoredDigest = await digestFile(candidate);
    await publishFile(candidate, output);
    return { manifest, restoreId, restoredDigest };
  } finally { await rm(staging, { recursive: true, force: true }); }
}

export async function listRecoveryAccounts(databasePath: string): Promise<Array<Record<string, unknown>>> {
  const client = createClient({ url: "file:" + await inputFile(databasePath) });
  try {
    if (!(await client.execute({ sql: 'SELECT value FROM "Setting" WHERE key = ?', args: [RESTORE_SETTING] })).rows.length) throw new Error("This database has no recovery receipt.");
    return (await client.execute('SELECT id, email, disabled, (passwordHash IS NOT NULL) AS localLogin FROM "User" ORDER BY email LIMIT 1001')).rows.map((row) => ({ ...row }));
  } finally { client.close(); }
}

export async function enableRecoveredUser(options: { databasePath: string; email: string; password?: string; environment: AuthEnvironment }): Promise<{ id: string; email: string }> {
  const email = normalizeEmail(options.email);
  if (!email || !emailAllowed(email, options.environment)) throw new Error("Account must satisfy the current installation's admission policy.");
  const client = createClient({ url: "file:" + await inputFile(options.databasePath) });
  try {
    const receipt = await client.execute({ sql: 'SELECT value FROM "Setting" WHERE key = ?', args: [RESTORE_SETTING] });
    if (!receipt.rows.length) throw new Error("This database has no recovery receipt.");
    const users = await client.execute({ sql: 'SELECT id, passwordHash, disabled, sessionEpoch FROM "User" WHERE lower(email) = ? LIMIT 2', args: [email] });
    if (users.rows.length !== 1) throw new Error("Choose one existing, unambiguous recovery account.");
    const user = users.rows[0];
    if (!user.disabled) throw new Error("Account is already enabled.");
    let password = user.passwordHash;
    if (password !== null) {
      if (!options.password) throw new Error("Local accounts require a new AEGIFY_RECOVERY_PASSWORD before reactivation.");
      if (await verifyPassword(options.password, String(password))) throw new Error("Choose a different password from the backed-up credential.");
      password = await hashPassword(options.password);
    } else if (options.password) throw new Error("A password cannot be added to an SSO-only recovery account.");
    const now = new Date().toISOString();
    const transaction = await client.transaction("write");
    try {
      const updated = await transaction.execute({ sql: 'UPDATE "User" SET disabled = 0, passwordHash = ?, sessionEpoch = ?, updatedAt = ? WHERE id = ? AND disabled = 1 AND sessionEpoch = ?', args: [password, randomUUID(), now, user.id, user.sessionEpoch] });
      if (updated.rowsAffected !== 1) throw new Error("Account changed during recovery review; reload it before trying again.");
      await transaction.execute({ sql: 'INSERT INTO "AuditEvent" (id, actorId, action, targetId, details, createdAt) VALUES (?, ?, ?, ?, ?, ?)', args: [randomUUID(), "operator:recovery", "recovery.account.enabled", user.id, JSON.stringify({ emailDigest: sha256(email) }), now] });
      await transaction.commit();
    } catch (error) { await transaction.rollback(); throw error; }
    finally { transaction.close(); }
    return { id: String(user.id), email };
  } finally { client.close(); }
}
