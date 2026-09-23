// Real production HTTP checks with synthetic accounts, no external IdP or AI calls.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, URL } from "node:url";
import process from "node:process";
import { setTimeout } from "node:timers";
import { log } from "node:console";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { createClient } from "@libsql/client";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { encode } from "next-auth/jwt";

export async function runAccessIntegration({ verifyBrowser } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "aegify-access-http-"));
  const dbUrl = "file:" + join(directory, "workspace.db");
  const sql = createClient({ url: dbUrl });
  const migrations = fileURLToPath(new URL("../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  sql.close();
  const db = new PrismaClient({ adapter: new PrismaLibSql({ url: dbUrl }) });
  let server;
  let serverOutput = "";
  let checks = 0;
  try {
    const listener = createServer();
    await new Promise((resolve, reject) => { listener.once("error", reject); listener.listen(0, "127.0.0.1", resolve); });
    const port = listener.address().port;
    await new Promise((resolve) => listener.close(resolve));
    const origin = `http://127.0.0.1:${port}`;
    const secret = randomBytes(32).toString("hex");
    const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(AUTH_|AEGIFY_UPLOAD_|RESEND_|DATABASE_URL)/.test(key)));
    Object.assign(environment, { NODE_ENV: "production", DATABASE_URL: dbUrl, NEXT_TELEMETRY_DISABLED: "1", AUTH_SECRET: secret, ENCRYPTION_SECRET: randomBytes(32).toString("hex"), AUTH_URL: origin, AUTH_ALLOWED_DOMAINS: "example.test", AUTH_ADMIN_EMAILS: "root@example.test", AUTH_GITHUB_ID: "synthetic-client", AUTH_GITHUB_SECRET: "synthetic-provider-secret", AUTH_LOCAL_ENABLED: "false", AEGIFY_UPLOAD_TOKEN: "", AEGIFY_UPLOAD_PROJECT_ID: "" });
    const cookies = {};
    for (const id of ["root", "alice", "bob", "outside"]) {
      await db.user.create({ data: { id, email: `${id}@example.test` } });
      cookies[id] = await encode({ secret, salt: "authjs.session-token", maxAge: 3600, token: { sub: id, sessionVersion: 0, authStartedAt: Date.now(), provider: "github" } });
    }
    const a = await db.project.create({ data: { name: "Alpha application", members: { create: [{ userId: "alice", role: "admin" }, { userId: "bob", role: "viewer" }] } } });
    const b = await db.project.create({ data: { name: "Bravo private", members: { create: [{ userId: "bob", role: "admin" }] } } });
    const sa = await db.scan.create({ data: { projectId: a.id, repository: "alpha", status: "completed" } });
    const sb = await db.scan.create({ data: { projectId: b.id, repository: "bravo", status: "completed" } });
    const finding = { ruleId: "SHARED", ruleName: "Synthetic fixture", severity: "low", lineStart: 1, lineEnd: 1, message: "Synthetic" };
    const fa = await db.finding.create({ data: { ...finding, scanId: sa.id, filePath: "alpha.ts" } });
    const fb = await db.finding.create({ data: { ...finding, scanId: sb.id, filePath: "bravo.py", codeSnippet: "BRAVO_PRIVATE_MARKER" } });
    const eb = await db.endpoint.create({ data: { scanId: sb.id, path: "/bravo", method: "GET", handlerFunction: "bravo", filePath: "bravo.py", framework: "bravo-only" } });
    await db.endpoint.create({ data: { scanId: sa.id, path: "/alpha", method: "GET", handlerFunction: "alpha", filePath: "alpha.ts", framework: "alpha-only" } });
    const jb = await db.llmJob.create({ data: { scanId: sb.id, mode: "quick", status: "completed" } });
    const rb = await db.agentRun.create({ data: { scanId: sb.id, status: "completed" } });
    await db.rule.create({ data: { id: "SHARED", name: "Workspace rule", severity: "low", yamlContent: "original-rule" } });
    server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", String(port)], { cwd: fileURLToPath(new URL("../", import.meta.url)), env: environment, stdio: ["ignore", "pipe", "pipe"] });
    for (const stream of [server.stdout, server.stderr]) stream.on("data", (chunk) => { serverOutput = (serverOutput + chunk.toString()).slice(-20_000); });
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (server.exitCode !== null) throw new Error("Production server exited during startup: " + serverOutput);
      try { if ((await globalThis.fetch(origin + "/api/auth/config", { signal: globalThis.AbortSignal.timeout(1000) })).ok) { ready = true; break; } } catch { /* bounded startup polling */ }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    assert.ok(ready, "Production server must start");
    async function call(path, { user = "alice", method = "GET", body, token, status = 200, requestOrigin = origin } = {}) {
      const headers = {};
      if (user) headers.cookie = `authjs.session-token=${cookies[user]}`;
      if (method !== "GET") headers.origin = requestOrigin;
      if (body !== undefined) headers["content-type"] = "application/json";
      if (token) headers.authorization = `Bearer ${token}`;
      const response = await globalThis.fetch(origin + path, { method, headers, redirect: "manual", body: body === undefined ? undefined : JSON.stringify(body) });
      const text = await response.text();
      assert.equal(response.status, status, `${method} ${path} (${user || "anonymous"}) expected ${status}, got ${response.status}: ${text.slice(0, 250)}`);
      if (status === 200 && method === "GET") assert.ok(response.headers.get("cache-control")?.includes("no-store"), "Project data must not be cached by shared proxies");
      checks++;
      return text ? JSON.parse(text) : null;
    }
    for (const path of ["/api/projects", "/api/scans", "/api/findings", "/api/stats", "/api/endpoints", "/api/agent-runs", "/api/llm-jobs", "/api/settings", "/api/rules"]) await call(path, { user: null, status: 401 });
    assert.deepEqual((await call("/api/projects")).projects.map((project) => project.id), [a.id]);
    assert.equal((await call("/api/projects", { user: "outside" })).projects.length, 0);
    assert.equal((await call("/api/stats")).totalFindings, 1);
    assert.deepEqual((await call("/api/findings/languages")).languages, ["TypeScript"]);
    assert.equal((await call("/api/findings/rules")).rules[0].findingCount, 1, "Rule filters cannot reveal other projects' counts");
    assert.deepEqual((await call("/api/endpoints")).frameworks, ["alpha-only"]);
    assert.equal((await call("/api/agent-runs")).runs.length, 0);
    assert.equal((await call("/api/llm-jobs")).jobs.length, 0);
    assert.equal((await call("/api/repos")).repos.length, 0, "Repository discovery uses only the caller's OAuth account");
    for (const path of [`/api/findings?projectId=${b.id}&language=Python&search=BRAVO`, `/api/scans?projectId=${b.id}`, `/api/endpoints?projectId=${b.id}`]) assert.equal((await call(path)).total, 0);
    for (const path of [`/api/projects/${b.id}`, `/api/scans/${sb.id}`, `/api/scans/${sb.id}/progress`, `/api/findings/${fb.id}`, `/api/findings/${fb.id}/graph`, `/api/findings/${fb.id}/report`, `/api/graph/${sb.id}`, `/api/endpoints/${eb.id}`, `/api/endpoints/import-openapi?scanId=${sb.id}`, `/api/agent-runs/${rb.id}`, `/api/llm-jobs/${jb.id}`, `/api/llm-scan/${sb.id}`, `/api/projects/${b.id}/members`, `/api/projects/${b.id}/tokens`, `/api/projects/${b.id}/audit`]) await call(path, { status: 404 });
    await call(`/api/findings/${fa.id}`, { user: "bob" });
    await call(`/api/findings/${fa.id}`, { user: "bob", method: "PATCH", body: { status: "triaged" }, status: 404 });
    await call(`/api/projects/${a.id}/tokens`, { user: "bob", method: "POST", body: { name: "denied", expiresAt: new Date(Date.now() + 86_400_000).toISOString() }, status: 404 });
    for (const [path, body] of [["/api/llm-jobs", { scanId: sb.id, mode: "quick" }], ["/api/llm-scan", { scanId: sb.id, mode: "quick" }], ["/api/agent-runs", { scanId: sb.id }], ["/api/findings/analyze-batch", { ids: [fa.id, fb.id] }]]) await call(path, { method: "POST", body, status: 404 });
    await call(`/api/projects/${a.id}`, { method: "DELETE", status: 403, requestOrigin: "https://unrelated.example.test" });
    await call("/api/settings", { status: 403 });
    await call("/api/settings", { user: "root" });
    await call("/api/rules", { status: 403 });
    await call("/api/projects", { method: "POST", body: { name: "Denied" }, status: 403 });
    await call(`/api/projects/${a.id}/members`, { method: "PUT", body: { email: "bob@example.test", role: "triager" } });
    await call(`/api/findings/${fa.id}`, { user: "bob", method: "PATCH", body: { status: "triaged" } });
    await call(`/api/projects/${a.id}/members`, { method: "DELETE", body: { userId: "alice" }, status: 409 });
    const issued = await call(`/api/projects/${a.id}/tokens`, { method: "POST", body: { name: "CI integration check", expiresAt: new Date(Date.now() + 86_400_000).toISOString() }, status: 201 });
    const listing = await call(`/api/projects/${a.id}/tokens`);
    assert.ok(!JSON.stringify(listing).includes(issued.token)); assert.equal("tokenHash" in listing.tokens[0], false);
    const sarif = { version: "2.1.0", runs: [{ tool: { driver: { name: "Aegify", version: "test", rules: [{ id: "SHARED", properties: { yamlContent: "must-not-overwrite-workspace" } }] } }, results: [], invocations: [{ executionSuccessful: false }], properties: { analysisStatus: "partial", analysisGaps: [{ code: "unsupported.php", stage: "parse", message: "PHP is outside this synthetic scope.", count: 1 }] } }] };
    await call(`/api/upload?projectId=${b.id}`, { user: null, token: issued.token, method: "POST", body: sarif, status: 404 });
    await call(`/api/upload?projectId=${a.id}`, { user: "bob", method: "POST", body: sarif, status: 404 });
    await call("/api/projects", { user: null, token: issued.token, status: 401 });
    await call("/api/upload", { user: null, token: "invalid-project-token", method: "POST", body: sarif, status: 401 });
    const uploaded = await call("/api/upload?branch=main", { user: null, token: issued.token, method: "POST", body: sarif });
    assert.equal((await db.scan.findUniqueOrThrow({ where: { id: uploaded.scanId } })).projectId, a.id);
    assert.equal((await db.scan.findUniqueOrThrow({ where: { id: uploaded.scanId } })).status, "partial");
    assert.equal((await db.rule.findUniqueOrThrow({ where: { id: "SHARED" } })).yamlContent, "original-rule");
    const reportPath = join(directory, "synthetic.sarif");
    await writeFile(reportPath, JSON.stringify(sarif));
    // The optional local CLI check uses the same endpoint and synthetic credential.
    if (process.env.AEGIFY_SCANNER_PYTHON) {
      const child = spawn(process.env.AEGIFY_SCANNER_PYTHON, ["-c", "from aegify.cli import app; app()", "upload", reportPath, "--dashboard-url", origin, "--project-id", a.id], { env: { ...environment, AEGIFY_UPLOAD_TOKEN: issued.token }, stdio: ["ignore", "pipe", "pipe"] });
      let output = ""; for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { output += chunk.toString(); });
      const exit = await new Promise((resolve) => child.once("close", resolve));
      assert.equal(exit, 0, output); assert.ok(!output.includes(issued.token)); checks++;
    }
    await call(`/api/projects/${a.id}/tokens`, { method: "DELETE", body: { tokenId: issued.record.id } });
    await call("/api/upload", { user: null, token: issued.token, method: "POST", body: sarif, status: 401 });
    await call(`/api/projects/${a.id}/members`, { method: "DELETE", body: { userId: "bob" } });
    await call(`/api/findings/${fa.id}`, { user: "bob", status: 404 });
    const audit = await call(`/api/projects/${a.id}/audit`);
    assert.ok(audit.events.some((event) => event.action === "scan.import.finished"));
    assert.ok(!JSON.stringify(audit).includes(issued.token));
    if (verifyBrowser) await verifyBrowser({ origin, cookies, projectId: a.id, reportPath });
    await db.user.update({ where: { id: "bob" }, data: { disabled: true } });
    await call("/api/projects", { user: "bob", status: 401 });
    log(`Project access: ${checks} production HTTP/CLI checks passed; project isolation, roles, CSRF, scoped CI delivery and revocation verified.`);
  } finally {
    if (server && server.exitCode === null) { server.kill("SIGTERM"); await new Promise((resolve) => server.once("exit", resolve)); }
    await db.$disconnect(); await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await runAccessIntegration();
