// Two independent rehearsals using new local databases, credentials and ports.
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { log } from "node:console";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { arch, platform, tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, URL, URLSearchParams } from "node:url";
import { parseArgs, promisify } from "node:util";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { encrypt } from "../src/lib/crypto.ts";
import { hashPassword } from "../src/lib/password.ts";
import { ruleFixtureExamples } from "../src/lib/rule-fixture-examples.ts";
import { makeSourceSnapshot, runPythonSnapshot } from "../src/lib/scan-worker.ts";

const dashboard = fileURLToPath(new URL("../", import.meta.url));
const execute = promisify(execFile);
const elapsed = (start) => Math.round(performance.now() - start);
const random = () => randomBytes(32).toString("hex");
const admin = "operator@example.test";
const reader = "reviewer@example.test";

async function freePort() {
  const socket = createServer();
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.listen(0, "127.0.0.1", resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve, reject) => socket.close((error) => (error ? reject(error) : resolve())));
  return port;
}

async function runNode(args, env) {
  const { stdout } = await execute(process.execPath, args, {
    cwd: dashboard,
    env,
    timeout: 90_000,
    maxBuffer: 1_048_576,
  });
  return stdout;
}

async function prepare(env) {
  await runNode(["node_modules/prisma/build/index.js", "migrate", "deploy"], env);
  await runNode(["scripts/prepare-database.mjs"], env);
}

function launch(args, env, processes) {
  const child = spawn(process.execPath, args, { cwd: dashboard, env, stdio: "ignore" });
  const closed = new Promise((resolve) => {
    child.once("error", resolve);
    child.once("close", resolve);
  });
  const entry = { child, closed };
  processes.add(entry);
  return entry;
}

async function stopAll(processes) {
  const active = [...processes];
  let forced = 0;
  for (const { child } of active)
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
  await Promise.all(
    active.map(async ({ child, closed }) => {
      const timely = await Promise.race([closed.then(() => true), delay(8000, false, { ref: false })]);
      if (!timely) {
        forced++;
        child.kill("SIGKILL");
        await closed;
      }
    }),
  );
  processes.clear();
  return forced;
}

async function waitFor(label, sample, accepted, milliseconds = 40_000) {
  const until = performance.now() + milliseconds;
  do {
    const value = await sample();
    if (accepted(value)) return value;
    await delay(160);
  } while (performance.now() < until);
  throw new Error("Timed out waiting for " + label);
}

async function http(origin, path, { method = "GET", body, cookie, token, status = 200 } = {}) {
  const headers = { origin };
  if (cookie) headers.cookie = cookie;
  if (token) headers.authorization = "Bearer " + token;
  if (body !== undefined) headers["content-type"] = "application/json";
  const res = await globalThis.fetch(origin + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
    signal: globalThis.AbortSignal.timeout(10_000),
  });
  assert.equal(res.status, status, method + " " + path.split("?")[0] + " returned " + res.status);
  return res.json();
}

async function signIn(origin, identifier, password, accepted = true) {
  const csrf = await globalThis.fetch(origin + "/api/auth/csrf", {
    redirect: "error",
    signal: globalThis.AbortSignal.timeout(5000),
  });
  assert.equal(csrf.status, 200);
  const { csrfToken } = await csrf.json();
  assert.ok(csrfToken);
  const cookies = (response) => response.headers.getSetCookie().map((line) => line.split(";")[0]);
  const jar = new Map();
  for (const pair of cookies(csrf)) {
    const split = pair.indexOf("=");
    jar.set(pair.slice(0, split), pair.slice(split + 1));
  }
  const csrfCookie = [...jar.entries()].find(([key]) => key.endsWith("authjs.csrf-token"))?.[1];
  assert.ok(csrfCookie, "The CSRF response must set the verification cookie");
  assert.ok(
    decodeURIComponent(csrfCookie).split("|")[0] === csrfToken,
    "A clean client must receive a CSRF cookie matching the issued token",
  );
  const response = await globalThis.fetch(origin + "/api/auth/callback/credentials", {
    method: "POST",
    redirect: "manual",
    signal: globalThis.AbortSignal.timeout(10_000),
    headers: {
      origin,
      cookie: [...jar.entries()].map(([key, value]) => key + "=" + value).join("; "),
      "content-type": "application/x-www-form-urlencoded",
      "X-Auth-Return-Redirect": "1",
    },
    body: new URLSearchParams({ csrfToken, identifier, password, callbackUrl: origin + "/projects" }),
  });
  const session = cookies(response)
    .filter((value) => /^authjs\.session-token(?:\.\d+)?=.+$/.test(value))
    .join("; ");
  const redirect =
    (await response.json().catch(() => null))?.url || response.headers.get("location") || origin;
  const result = new URL(redirect, origin).searchParams.get("error") || "no error returned";
  assert.equal(
    Boolean(session),
    accepted,
    "Credential sign-in result differed from expected account state (" +
      response.status +
      ", " +
      (/^[a-zA-Z ]{1,32}$/.test(result) ? result : "provider error") +
      ")",
  );
  if (!accepted)
    assert.equal(result, "CredentialsSignin", "The server must reject the credentials explicitly");
  return session;
}

async function serve(env, origin, port, processes) {
  const { child } = launch(
    ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)],
    env,
    processes,
  );
  await waitFor(
    "local production dashboard",
    async () => {
      if (child.exitCode !== null || child.signalCode !== null)
        throw new Error("Dashboard exited during startup");
      try {
        const res = await globalThis.fetch(origin + "/api/auth/config", {
          signal: globalThis.AbortSignal.timeout(1000),
        });
        return res.ok && (await res.json()).local;
      } catch {
        return false;
      }
    },
    Boolean,
  );
}

function startWorkers(env, processes) {
  launch(["scripts/scan-worker.mjs"], env, processes);
  launch(["scripts/llm-worker.mjs"], env, processes);
}

async function workerStatus(origin, project, cookie) {
  const [source, ai] = await Promise.all([
    http(origin, project + "/rule-fixtures", { cookie }),
    http(origin, "/api/llm-jobs", { cookie }),
  ]);
  return { source: source.workerAvailable, ai: ai.workerReady };
}

async function exercise(report) {
  const port = await freePort();
  const directory = await mkdtemp(join(tmpdir(), "aegify-cutover-"));
  const processes = new Set();
  const origin = "http://127.0.0.1:" + port;
  const database = join(directory, "original.db");
  const candidate = join(directory, "restored.db");
  const archive = join(directory, "checkpoint.aegify");
  const env = {
    PATH: process.env.PATH,
    TMPDIR: directory,
    NODE_ENV: "production",
    LANG: "C",
    NEXT_TELEMETRY_DISABLED: "1",
    CHECKPOINT_DISABLE: "1",
    AUTH_URL: origin,
    AUTH_TRUST_HOST: "true",
    DATABASE_URL: "file:" + database,
    ENCRYPTION_SECRET: random(),
    AUTH_SECRET: random(),
    AUTH_LOCAL_ENABLED: "true",
    AUTH_ALLOWED_EMAILS: [admin, reader].join(","),
    AUTH_ADMIN_EMAILS: admin,
    AUTH_EMAIL_FROM: "rehearsal@example.test",
    RESEND_API_KEY: "fixture-unused-mail-transport",
  };
  const recovered = { ...env, DATABASE_URL: "file:" + candidate };
  const backupKey = random(),
    previousPassword = random(),
    nextPassword = random(),
    readerPassword = random();
  const operator = async (command, environment, args = [], extra = {}) =>
    JSON.parse(await runNode(["scripts/recovery.mjs", command, ...args], { ...environment, ...extra }));
  const record = { durationsMs: {} };
  try {
    await prepare(env);
    const original = new PrismaClient({ adapter: new PrismaLibSql({ url: env.DATABASE_URL }) });
    try {
      for (const [email, password] of [
        [admin, previousPassword],
        [reader, readerPassword],
      ]) {
        await original.user.create({
          data: { email, emailVerified: new Date(), passwordHash: await hashPassword(password) },
        });
      }
      await original.setting.create({
        data: {
          key: "exercise.storage-key-check",
          encrypted: true,
          value: encrypt("test setting", env.ENCRYPTION_SECRET),
        },
      });
    } finally {
      await original.$disconnect();
    }

    await serve(env, origin, port, processes);
    startWorkers(env, processes);
    const oldSession = await signIn(origin, admin, previousPassword);
    const oldReader = await signIn(origin, reader, readerPassword);
    const before = await http(origin, "/api/projects", {
      cookie: oldSession,
      method: "POST",
      body: { name: "Notifications", defaultBranch: "main" },
      status: 201,
    });
    const project = "/api/projects/" + before.id;
    await http(origin, project + "/members", {
      cookie: oldSession,
      method: "PUT",
      body: { email: reader, role: "viewer" },
    });
    assert.equal((await http(origin, project, { cookie: oldReader })).accessRole, "viewer");
    await waitFor(
      "original workers",
      () => workerStatus(origin, project, oldSession),
      (v) => v.source && v.ai,
    );
    const issue = (cookie) =>
      http(origin, project + "/tokens", {
        cookie,
        method: "POST",
        status: 201,
        body: { name: "Release pipeline", expiresAt: new Date(Date.now() + 86_400_000).toISOString() },
      });
    const upload = (token, status = 200, branch = "main") =>
      http(
        origin,
        "/api/upload?projectId=" + before.id + "&repository=ops%2Fnotifications&branch=" + branch,
        { token, method: "POST", body: report, status },
      );
    const oldToken = (await issue(oldSession)).token;
    const initial = await upload(oldToken);
    assert.equal(initial.findingsCount, 1);
    const results = await http(origin, "/api/findings?scanId=" + initial.scanId, { cookie: oldSession });
    const finding = results.findings[0];
    assert.equal(finding.ruleId, "AEG-A02-005");
    const evidencePath = "/api/findings/" + finding.id;
    const reason = "The notification team will configure the mail relay context.";
    const first = await http(origin, evidencePath, { cookie: oldSession });
    await http(origin, evidencePath, {
      cookie: oldSession,
      method: "PATCH",
      body: {
        expectedVersion: first.workflow.version,
        owner: "Notifications",
        status: "in_progress",
        reason,
      },
    });
    const retained = await http(origin, evidencePath, { cookie: oldReader });
    assert.equal(retained.workflow.reason, reason);
    assert.equal(retained.filePath, "services/mail.py");
    assert.equal(retained.lineStart, 4);
    assert.ok(retained.codeSnippet.includes("client.starttls()"));
    const saved = await operator("backup", env, ["--output", archive], { AEGIFY_BACKUP_KEY: backupKey });
    const verified = await operator("verify", env, ["--archive", archive], { AEGIFY_BACKUP_KEY: backupKey });
    assert.deepEqual(verified.manifest, saved.manifest);
    assert.equal(saved.manifest.encryptionKeyCheck, "stored_ciphertext");
    const marker = await http(origin, "/api/projects", {
      cookie: oldSession,
      method: "POST",
      body: { name: "After checkpoint" },
      status: 201,
    });
    assert.equal((await http(origin, "/api/projects/" + marker.id, { cookie: oldSession })).id, marker.id);

    const cutover = performance.now();
    record.snapshotAgeAtStopMs = Date.now() - Date.parse(saved.manifest.snapshotStartedAt);
    assert.equal(await stopAll(processes), 0, "Dashboard and workers must terminate gracefully");
    record.durationsMs.stopServices = elapsed(cutover);
    const reachable = await globalThis
      .fetch(origin + "/api/auth/config", { signal: globalThis.AbortSignal.timeout(1000) })
      .then(
        () => true,
        () => false,
      );
    assert.equal(reachable, false, "Original listener must close before switching databases");
    const restored = await operator("restore", recovered, ["--archive", archive, "--output", candidate], {
      AEGIFY_BACKUP_KEY: backupKey,
    });
    assert.deepEqual(restored.manifest, verified.manifest);
    record.durationsMs.restoreCommand = restored.durationMs;
    const startup = performance.now();
    await prepare(recovered);
    await serve(recovered, origin, port, processes);
    record.durationsMs.candidatePreparationAndStart = elapsed(startup);
    await http(origin, "/api/projects", { cookie: oldSession, status: 401 });
    await http(origin, "/api/projects", { cookie: oldReader, status: 401 });
    await upload(oldToken, 401);
    const accounts = await operator("accounts", recovered);
    assert.deepEqual(
      accounts.accounts.map((a) => [a.email, Number(a.disabled)]),
      [
        [admin, 1],
        [reader, 1],
      ],
    );
    const activation = performance.now();
    await operator("enable-user", recovered, ["--email", admin], { AEGIFY_RECOVERY_PASSWORD: nextPassword });
    await http(origin, "/api/projects", { cookie: oldSession, status: 401 });
    await signIn(origin, admin, previousPassword, false);
    const session = await signIn(origin, admin, nextPassword);
    const projects = (await http(origin, "/api/projects", { cookie: session })).projects;
    assert.deepEqual(
      projects.map((p) => p.id),
      [before.id],
    );
    record.durationsMs.activationAndFreshLogin = elapsed(activation);
    record.durationsMs.stopToAdmittedRead = elapsed(cutover);
    const evidence = await http(origin, evidencePath, { cookie: session });
    for (const key of [
      "id",
      "ruleId",
      "filePath",
      "lineStart",
      "codeSnippet",
      "evidenceState",
      "remediation",
    ])
      assert.deepEqual(evidence[key], retained[key]);
    assert.equal(evidence.workflow.reason, reason);
    assert.equal(evidence.workflow.owner, "Notifications");
    assert.equal(evidence.workflow.status, "in_progress");
    assert.equal((await http(origin, project, { cookie: session })).accessRole, "admin");
    assert.equal(
      (await http(origin, project + "/members", { cookie: session })).members.find(
        (m) => m.user.email === reader,
      )?.user.disabled,
      true,
    );
    await signIn(origin, reader, readerPassword, false);
    await upload(oldToken, 401);
    const delivery = await upload((await issue(session)).token, 200, "recovery-check");
    assert.notEqual(delivery.scanId, initial.scanId);
    assert.equal(delivery.findingsCount, 1);
    assert.equal(
      (await http(origin, "/api/findings?scanId=" + delivery.scanId, { cookie: session })).findings[0].ruleId,
      finding.ruleId,
    );
    record.durationsMs.stopToNewCiDelivery = elapsed(cutover);
    assert.deepEqual(await workerStatus(origin, project, session), { source: false, ai: false });
    startWorkers(recovered, processes);
    await waitFor(
      "recovered workers",
      () => workerStatus(origin, project, session),
      (v) => v.source && v.ai,
    );
    const lab = project + "/rule-fixtures";
    const job = await http(origin, lab, {
      cookie: session,
      method: "POST",
      body: ruleFixtureExamples.call,
      status: 202,
    });
    const completed = await waitFor(
      "fresh rule fixture",
      () => http(origin, lab + "/" + job.id, { cookie: session }),
      (value) => ["completed", "failed", "cancelled"].includes(value.job.status),
    );
    assert.equal(completed.report?.status, "passed");
    assert.equal(completed.report.positive_cases, 1);
    assert.equal(completed.report.negative_cases, 3);
    assert.deepEqual(
      completed.report.cases.map((item) => item.status),
      Array(4).fill("passed"),
    );
    record.durationsMs.stopToVerifiedWorkerResult = elapsed(cutover);
    const audit = await http(origin, project + "/audit", { cookie: session });
    assert.ok(audit.events.some((entry) => entry.action === "project.create"));
    Object.assign(record, {
      snapshotBytes: saved.manifest.databaseBytes,
      snapshotCounts: saved.manifest.counts,
      archiveCreationMs: saved.durationMs,
      archiveVerificationMs: verified.durationMs,
      accountsQuarantined: accounts.accounts.length,
      accountsReactivated: 1,
      retainedFindingsChecked: 1,
      laterProjectExcluded: true,
      previousSessionRejectedAfterActivation: true,
      previousCiCredentialRejected: true,
      newCredentialDelivery: true,
      recoveredWorkerQueues: ["source", "ai"],
      newRuleFixture: {
        positive: completed.report.positive_cases,
        negative: completed.report.negative_cases,
        outcome: completed.report.status,
      },
    });
    return record;
  } finally {
    await stopAll(processes);
    await rm(directory, { recursive: true, force: true });
  }
}

const { values } = parseArgs({ options: { runs: { type: "string", default: "2" } } });
if (!/^[1-5]$/.test(values.runs)) throw new Error("Choose one to five local rehearsals.");
const commit = "a".repeat(40);
const source = makeSourceSnapshot(
  { provider: "github", ownerSlug: "ops/notifications", commitSha: commit },
  {
    ref: commit,
    truncated: false,
    files: [
      {
        path: "services/mail.py",
        content: "import smtplib\n\ndef upgrade(client: smtplib.SMTP):\n    client.starttls()\n",
      },
    ],
  },
);
const { report } = await runPythonSnapshot(source, globalThis.AbortSignal.timeout(60_000), async () => {});
const trials = [];
for (let i = 0; i < Number(values.runs); i++) trials.push(await exercise(report));
log(
  JSON.stringify(
    {
      version: 1,
      exercise: "local-service-cutover",
      environment: {
        platform: platform(),
        arch: arch(),
        node: process.version,
        nextBuild: (await readFile(join(dashboard, ".next/BUILD_ID"), "utf8")).trim(),
        scriptSha256: createHash("sha256")
          .update(await readFile(fileURLToPath(import.meta.url)))
          .digest("hex"),
      },
      trials,
    },
    null,
    2,
  ),
);
