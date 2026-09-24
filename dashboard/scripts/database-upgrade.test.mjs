import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath, URL } from "node:url";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { decrypt, encrypt } from "../src/lib/crypto.ts";
import { authorizeProject, resolvePrincipal } from "../src/lib/project-access.ts";
import { authenticateUploadToken } from "../src/lib/project-tokens.ts";

const dashboard = fileURLToPath(new URL("../", import.meta.url));
const migrations = join(dashboard, "prisma/migrations");
const schema = join(dashboard, "prisma/schema.prisma");
const correction = "20260924090000_schema_parity";
const priorRelease = "20260924070000_ai_review_history";
const environment = { NODE_ENV: "production", AUTH_SECRET: "owned-fixture-only", AUTH_ALLOWED_DOMAINS: "example.test" };

// These tests only accept freshly allocated private temporary databases. Never
// inherit DATABASE_URL, .env settings, operator credentials or a remote database.
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "aegify-migration-test-"));
  const url = "file:" + join(directory, "owned.db");
  const priorMigrations = join(directory, "prior-migrations");
  const names = (await readdir(migrations, { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  assert.ok(names.includes(priorRelease) && names.includes(correction));
  for (const name of [...names.filter((name) => name <= priorRelease), "migration_lock.toml"]) {
    await cp(join(migrations, name), join(priorMigrations, name), { recursive: true });
  }
  const config = async (name, migrationPath) => {
    const path = join(directory, name + ".config.ts");
    await writeFile(path, "export default " + JSON.stringify({ schema, migrations: { path: migrationPath }, datasource: { url } }) + ";\n");
    return path;
  };
  const priorConfig = await config("prior", priorMigrations);
  const latestConfig = await config("latest", migrations);
  const run = async (configPath, command, expectedStatus = 0) => {
    const result = await new Promise((resolve) => execFile(process.execPath, [join(dashboard, "node_modules/prisma/build/index.js"), ...command, "--config", configPath], {
      cwd: directory,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: directory, DATABASE_URL: url, CHECKPOINT_DISABLE: "1", PRISMA_HIDE_UPDATE_MESSAGE: "1" },
      encoding: "utf8", timeout: 60_000, maxBuffer: 1024 * 1024,
    }, (error, stdout, stderr) => resolve({ error, stdout, stderr })));
    if (result.error && typeof result.error.code !== "number") throw result.error;
    assert.equal(result.error?.code ?? 0, expectedStatus, `${command.join(" ")}: ${result.stdout}\n${result.stderr}`);
    return result.stdout + result.stderr;
  };
  return { directory, url, priorMigrations, names, config, priorConfig, latestConfig, run, close: () => rm(directory, { recursive: true, force: true }) };
}

// An independent SQLite connection lets the test fully close statement handles
// before Prisma deploys, matching the documented stopped-service upgrade.
function openDatabase(url) {
  // Give the owned reader a bounded wait for migration/rollback locks. A
  // persistent lock still fails; every data and rollback assertion remains.
  const connection = new DatabaseSync(fileURLToPath(url), { timeout: 5000 });
  let closed = false;
  return {
    async execute(input) {
      const { sql, args = [] } = typeof input === "string" ? { sql: input } : input;
      const statement = connection.prepare(sql);
      const columns = statement.columns().map((column) => column.name);
      const rows = columns.length ? statement.all(...args) : (statement.run(...args), []);
      return { columns, rows };
    },
    async executeMultiple(sql) { connection.exec(sql); },
    close() { if (!closed) { connection.close(); closed = true; } },
  };
}

function quotedIdentifier(value) {
  assert.match(value, /^[A-Za-z_][A-Za-z0-9_]*$/, "Only fixture schema identifiers are used in queries");
  return '"' + value + '"';
}

async function snapshot(sql, previous) {
  const tables = previous ? Object.keys(previous) : (await sql.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name <> '_prisma_migrations' ORDER BY name")).rows.map((row) => row.name);
  const data = {};
  for (const table of tables) {
    // Project the old columns so a future additive migration can retain this
    // upgrade fixture. Schema parity checks validate the latest structure.
    const projection = previous ? previous[table].columns.map(quotedIdentifier).join(",") : "*";
    const result = await sql.execute(`SELECT ${projection} FROM ${quotedIdentifier(table)}`);
    data[table] = { columns: result.columns, rows: result.rows.map((row) => JSON.stringify(result.columns.map((column) => row[column]))).sort() };
  }
  return data;
}

async function migrationHistory(sql) {
  return (await sql.execute('SELECT migration_name, checksum, finished_at, rolled_back_at FROM "_prisma_migrations" ORDER BY migration_name')).rows.map((row) => ({ ...row }));
}

async function assertIntegrity(sql) {
  assert.deepEqual((await sql.execute("PRAGMA foreign_key_check")).rows, []);
  assert.deepEqual((await sql.execute("PRAGMA integrity_check")).rows.map((row) => row.integrity_check), ["ok"]);
}

async function seed(sql) {
  await sql.execute("PRAGMA foreign_keys=ON");
  await sql.execute("PRAGMA journal_mode=WAL");
  await sql.executeMultiple(`
    INSERT INTO "User" (id,email,disabled,sessionVersion,sessionEpoch,updatedAt) VALUES
      ('owner','owner@example.test',0,7,'owned-epoch',CURRENT_TIMESTAMP),
      ('viewer','viewer@example.test',0,2,'viewer-epoch',CURRENT_TIMESTAMP),
      ('outside','outside@example.test',0,0,'',CURRENT_TIMESTAMP),
      ('disabled','disabled@example.test',1,4,'disabled-epoch',CURRENT_TIMESTAMP);
    INSERT INTO "Project" (id,name,userId,archived) VALUES
      ('project-a','Owned upgrade fixture','owner',0),
      ('project-b','Other archived project','outside',1),
      ('unowned','Legacy project without an owner',NULL,0);
    INSERT INTO "ProjectMember" (projectId,userId,role,updatedAt) VALUES
      ('project-a','owner','admin',CURRENT_TIMESTAMP),
      ('project-a','viewer','viewer',CURRENT_TIMESTAMP),
      ('project-a','disabled','maintainer',CURRENT_TIMESTAMP),
      ('project-b','outside','admin',CURRENT_TIMESTAMP);
    INSERT INTO "Account" (id,userId,type,provider,providerAccountId) VALUES ('account','owner','oauth','owned','fixture');
    INSERT INTO "Session" (id,sessionToken,userId,expires) VALUES ('session','owned-nonworking-session','owner','2099-01-01');
    INSERT INTO "Rule" (id,name,severity) VALUES ('LEGACY','Legacy epoch sentinel','low');
    INSERT INTO "Rule" (id,name,severity,cweId,owaspCategory,languages,enabled,findingCount,yamlContent,description,sourceFile,updatedAt)
      VALUES ('CUSTOM','팀 규칙','medium',20,'A03','python,typescript',false,37,'id: CUSTOM','Retained custom rule','custom/owned.yml','2026-01-02 03:04:05');
    INSERT INTO "Rule" (id,name,severity,updatedAt) VALUES ('NUMERIC','Recorded numeric timestamp','high',1767323045123);
    INSERT INTO "Scan" (id,projectId,repository,status) VALUES
      ('completed','project-a','owned/repository','completed'), ('active','project-a','owned/repository','running');
    INSERT INTO "FindingIdentity" (id,projectId,fingerprint,ruleId,filePath,status,triageReason,triageActor,owner,priority,workflowRevision,updatedAt)
      VALUES ('identity','project-a','owned-fingerprint','CUSTOM','src/owned.py','accepted_risk','Owned review decision','owner','viewer','high',4,CURRENT_TIMESTAMP);
    INSERT INTO "FindingTriageEvent" (id,identityId,fromStatus,toStatus,reason,actor)
      VALUES ('triage','identity','open','accepted_risk','Owned review decision','owner');
    INSERT INTO "Finding" (id,scanId,identityId,ruleId,ruleName,severity,status,filePath,lineStart,lineEnd,message,owner)
      VALUES ('finding','completed','identity','CUSTOM','팀 규칙','medium','accepted_risk','src/owned.py',5,6,'Synthetic retained evidence','viewer');
    INSERT INTO "AuditEvent" (id,projectId,actorId,action,targetId,details)
      VALUES ('audit','project-a','owner','finding.triage','finding','{"to":"accepted_risk"}');
    INSERT INTO "ScanJob" (id,scanId,projectId,requestedBy,provider,ownerSlug,requestedRef,status,activeKey,leaseToken,updatedAt)
      VALUES ('source-job','active','project-a','owner','github','owned/repository','main','running','project-a','owned-lease',CURRENT_TIMESTAMP);
    INSERT INTO "ScanJobEvent" (jobId,code,message) VALUES ('source-job','worker.claimed','Owned fixture');
    INSERT INTO "LlmJob" (id,scanId,projectId,requestedBy,mode,status,historyVersion,provider,model)
      VALUES ('review-job','completed','project-a','owner','quick','completed',1,'anthropic','owned-model');
    INSERT INTO "LlmCall" (id,jobId,batchIndex,leaseToken,promptDigest,status)
      VALUES ('review-call','review-job',0,'owned-review-lease','owned-prompt','completed');
    INSERT INTO "LlmJobEvent" (id,jobId,code,message) VALUES ('review-event','review-job','job.completed','Owned fixture');
  `);
  const secret = randomBytes(32).toString("hex");
  const plaintext = "Owned encrypted migration evidence";
  const ciphertext = encrypt(plaintext, secret);
  await sql.execute({ sql: 'INSERT INTO "Setting" (key,value,encrypted) VALUES (?,?,true)', args: ["owned.encrypted", ciphertext] });
  await sql.execute({ sql: 'UPDATE "ScanJob" SET sourceCiphertext=? WHERE id=?', args: [ciphertext, "source-job"] });
  await sql.execute({ sql: `INSERT INTO "LlmReview" (id,jobId,callId,findingId,batchIndex,ordinal,publication,ruleId,ruleName,severity,filePath,lineStart,verdict,confidence,evidenceDigest,payloadDigest,payloadCiphertext)
    VALUES ('review','review-job','review-call','finding',0,0,'human_decision_preserved','CUSTOM','팀 규칙','medium','src/owned.py',5,'needs_review',0.2,'owned-evidence','owned-payload',?)`, args: [ciphertext] });
  const tokens = { active: randomBytes(32).toString("base64url"), revoked: randomBytes(32).toString("base64url") };
  for (const [id, token] of Object.entries(tokens)) {
    await sql.execute({ sql: 'INSERT INTO "ProjectServiceToken" (id,projectId,name,tokenHash,prefix,createdBy,expiresAt,revokedAt) VALUES (?,?,?,?,?,?,?,?)',
      // Match the installed Prisma adapter's ISO date representation.
      args: [id, "project-a", "Owned token fixture", createHash("sha256").update(token).digest("hex"), token.slice(0, 8), "owner", new Date(Date.now() + 86_400_000).toISOString(), id === "revoked" ? new Date().toISOString() : null] });
  }
  await assertIntegrity(sql);
  return { secret, plaintext, tokens };
}

test("fresh Prisma deployment matches the model and a second deploy changes nothing", { timeout: 180_000 }, async () => {
  const owned = await fixture();
  let sql;
  try {
    await owned.run(owned.latestConfig, ["migrate", "deploy"]);
    await owned.run(owned.latestConfig, ["migrate", "diff", "--from-config-datasource", "--to-schema", schema, "--exit-code"]);
    sql = openDatabase(owned.url);
    await assertIntegrity(sql);
    const history = await migrationHistory(sql);
    assert.equal(history.length, owned.names.length);
    assert.ok(history.every((row) => row.finished_at !== null && row.rolled_back_at === null));
    sql.close();
    await owned.run(owned.latestConfig, ["migrate", "deploy"]);
    sql = openDatabase(owned.url);
    assert.deepEqual(await migrationHistory(sql), history);
  } finally { sql?.close(); await owned.close(); }
});

test("populated upgrade retains ownership, permissions, credentials, triage and encrypted history", { timeout: 180_000 }, async () => {
  const owned = await fixture();
  let sql;
  let db;
  try {
    await owned.run(owned.priorConfig, ["migrate", "deploy"]);
    sql = openDatabase(owned.url);
    const retained = await seed(sql);
    const before = await snapshot(sql);
    const history = await migrationHistory(sql);
    assert.equal((await sql.execute('SELECT updatedAt FROM "Rule" WHERE id=\'LEGACY\'')).rows[0].updatedAt, "1970-01-01 00:00:00");
    // A negative control proves diff actually observes the earlier mismatch.
    const drift = await owned.run(owned.priorConfig, ["migrate", "diff", "--from-config-datasource", "--to-schema", schema, "--exit-code"], 2);
    assert.match(drift, /Rule/);
    sql.close();
    await owned.run(owned.latestConfig, ["migrate", "deploy"]);
    sql = openDatabase(owned.url);
    assert.deepEqual(await snapshot(sql, before), before);
    assert.deepEqual((await migrationHistory(sql)).filter((row) => row.migration_name <= priorRelease), history);
    await assertIntegrity(sql);
    await owned.run(owned.latestConfig, ["migrate", "diff", "--from-config-datasource", "--to-schema", schema, "--exit-code"]);
    const afterHistory = await migrationHistory(sql);
    sql.close();
    await owned.run(owned.latestConfig, ["migrate", "deploy"]);
    sql = openDatabase(owned.url);
    assert.deepEqual(await snapshot(sql, before), before);
    assert.deepEqual(await migrationHistory(sql), afterHistory);

    db = new PrismaClient({ adapter: new PrismaLibSql({ url: owned.url }) });
    const owner = await resolvePrincipal(db, "owner", environment);
    const viewer = await resolvePrincipal(db, "viewer", environment);
    const outside = await resolvePrincipal(db, "outside", environment);
    await authorizeProject(db, owner, "project-a", "admin");
    await authorizeProject(db, viewer, "project-a");
    for (const [principal, project, role] of [[viewer, "project-a", "triager"], [outside, "project-a", "viewer"], [owner, "project-b", "viewer"], [owner, "unowned", "viewer"]]) {
      await assert.rejects(authorizeProject(db, principal, project, role), { status: 404 });
    }
    await assert.rejects(resolvePrincipal(db, "disabled", environment), { status: 401 });
    assert.deepEqual(await authenticateUploadToken(db, retained.tokens.active, environment), { projectId: "project-a", actorId: "service-token:active" });
    assert.equal(await authenticateUploadToken(db, retained.tokens.revoked, environment), null);
    assert.equal(await authenticateUploadToken(db, "unknown-owned-token", environment), null);
    for (const value of [
      (await db.setting.findUniqueOrThrow({ where: { key: "owned.encrypted" } })).value,
      (await db.scanJob.findUniqueOrThrow({ where: { id: "source-job" } })).sourceCiphertext,
      (await db.llmReview.findUniqueOrThrow({ where: { id: "review" } })).payloadCiphertext,
    ]) assert.equal(decrypt(value, retained.secret), retained.plaintext);

    const protectedRows = await snapshot(sql);
    await assert.rejects(db.user.delete({ where: { id: "owner" } }), { code: "P2003" });
    await assert.rejects(sql.execute('UPDATE "ProjectMember" SET role=\'invalid\' WHERE userId=\'viewer\''), /CHECK constraint failed/);
    await assert.rejects(sql.execute('UPDATE "LlmReview" SET verdict=\'changed\' WHERE id=\'review\''), /Saved AI reviews are immutable/);
    assert.deepEqual(await snapshot(sql, protectedRows), protectedRows, "Rejected mutations cannot cascade or alter retained records");
    const ownerFk = (await sql.execute('PRAGMA foreign_key_list("Project")')).rows.find((row) => row.from === "userId");
    assert.equal(ownerFk.on_delete, "NO ACTION");
    const ruleTimestamp = (await sql.execute('PRAGMA table_info("Rule")')).rows.find((row) => row.name === "updatedAt");
    assert.equal(ruleTimestamp.dflt_value, "CURRENT_TIMESTAMP");
    const started = Date.now();
    await sql.execute('INSERT INTO "Rule" (id,name,severity) VALUES (\'FUTURE\',\'New timestamp default\',\'low\')');
    const timestamp = (await db.rule.findUniqueOrThrow({ where: { id: "FUTURE" } })).updatedAt.getTime();
    assert.ok(timestamp >= started - 1000 && timestamp <= Date.now());
    await assertIntegrity(sql);
  } finally { await db?.$disconnect(); sql?.close(); await owned.close(); }
});

test("failure after dropping the old Rule table rolls back data and blocks further deploys", { timeout: 180_000 }, async () => {
  const owned = await fixture();
  let sql;
  try {
    await owned.run(owned.priorConfig, ["migrate", "deploy"]);
    sql = openDatabase(owned.url);
    await seed(sql);
    const before = await snapshot(sql);
    const beforeSchema = (await sql.execute("SELECT sql FROM sqlite_schema WHERE name='Rule'")).rows[0].sql;
    sql.close();
    const source = await readFile(join(migrations, correction, "migration.sql"), "utf8");
    const rename = 'ALTER TABLE "new_Rule" RENAME TO "Rule";';
    assert.ok(source.includes(rename));
    await cp(join(migrations, correction), join(owned.priorMigrations, correction), { recursive: true });
    // Inject a statement failure in the private migration copy, after DROP and
    // before rename/commit. The real Prisma CLI must close and roll back the SQL.
    await writeFile(join(owned.priorMigrations, correction, "migration.sql"), source.replace(rename, 'SELECT owned_migration_interruption();\n' + rename));
    const failure = await owned.run(owned.priorConfig, ["migrate", "deploy"], 1);
    assert.match(failure, /owned_migration_interruption/);
    sql = openDatabase(owned.url);
    assert.deepEqual(await snapshot(sql, before), before);
    assert.equal((await sql.execute("SELECT sql FROM sqlite_schema WHERE name='Rule'")).rows[0].sql, beforeSchema);
    assert.equal((await sql.execute("SELECT name FROM sqlite_schema WHERE name='new_Rule'")).rows.length, 0);
    await assertIntegrity(sql);
    sql.close();
    const blocked = await owned.run(owned.latestConfig, ["migrate", "deploy"], 1);
    assert.match(blocked, /P3009/);
    sql = openDatabase(owned.url);
    assert.deepEqual(await snapshot(sql, before), before);
  } finally { sql?.close(); await owned.close(); }
});
