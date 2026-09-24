// Real production HTTP checks with synthetic accounts, no external IdP or AI calls.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
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
import { configureDatabase } from "../src/lib/database-runtime.ts";
import { recordFindingTicket } from "../src/lib/finding-workflow.ts";
import { runLlmWorkerOnce } from "../src/lib/llm-worker.ts";
import { ruleFixtureExamples } from "../src/lib/rule-fixture-examples.ts";

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
    await configureDatabase(db);
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
    const fixturePath = `/api/projects/${a.id}/rule-fixtures`;
    await call(fixturePath, { user: null, status: 401 });
    await call(fixturePath, { user: "outside", status: 404 });
    await call(fixturePath, { user: "bob", method: "POST", body: ruleFixtureExamples.call, status: 404 });
    await call(fixturePath, { method: "POST", body: ruleFixtureExamples.call, requestOrigin: "https://foreign.example.test", status: 403 });
    await call(fixturePath, { method: "POST", body: ruleFixtureExamples.call, token: "owned-unused-token", status: 401 });
    await call(fixturePath, { method: "POST", body: { ...ruleFixtureExamples.call, extra: "unsupported" }, status: 400 });
    const fixtureJob = await call(fixturePath, { method: "POST", body: ruleFixtureExamples.call, status: 202 });
    assert.equal(fixtureJob.status, "queued"); assert.equal("inputCiphertext" in fixtureJob, false); assert.equal("leaseToken" in fixtureJob, false);
    assert.equal((await call(fixturePath, { user: "bob" })).jobs[0].id, fixtureJob.id);
    const fixtureDetailPath = `${fixturePath}/${fixtureJob.id}`;
    await call(`/api/projects/${b.id}/rule-fixtures/${fixtureJob.id}`, { user: "bob", status: 404 });
    await call(fixtureDetailPath, { user: "outside", status: 404 });
    await call(fixtureDetailPath + "?input=1", { user: "bob", status: 404 });
    assert.deepEqual((await call(fixtureDetailPath + "?input=1")).input, ruleFixtureExamples.call);
    await call(fixtureDetailPath + "?input=1&input=1", { status: 400 });
    await call(fixtureDetailPath, { user: "bob", method: "POST", body: { action: "cancel" }, status: 404 });
    await call(fixtureDetailPath, { method: "POST", body: { action: "cancel" } });
    assert.equal((await call(fixtureDetailPath, { user: "bob" })).job.status, "cancelled");
    const rerunFixture = await call(fixtureDetailPath, { method: "POST", body: { action: "rerun" }, status: 202 });
    assert.notEqual(rerunFixture.id, fixtureJob.id); assert.equal(rerunFixture.inputDigest, fixtureJob.inputDigest);
    await call(`${fixturePath}/${rerunFixture.id}`, { method: "POST", body: { action: "cancel" } });
    await db.ruleFixtureJob.update({ where: { id: fixtureJob.id }, data: { expiresAt: new Date(0) } });
    await call(fixtureDetailPath + "?input=1", { status: 410 });
    await call(fixtureDetailPath, { method: "POST", body: { action: "rerun" }, status: 410 });
    // Both public AI entry points enqueue durable work; no request-lifetime task calls a model.
    for (const [key, value] of Object.entries({ "llm.enabled": "true", "llm.provider": "anthropic", "llm.model": "owned-fixture-model", "llm.anthropic_api_key": "owned-nonworking-placeholder" })) await db.setting.create({ data: { key, value } });
    const queuedReview = await call("/api/llm-jobs", { method: "POST", body: { scanId: sa.id, mode: "deep" }, status: 202 });
    assert.equal(queuedReview.status, "pending"); assert.equal(queuedReview.contractVersion, 1);
    assert.equal("inputCiphertext" in queuedReview, false); assert.equal("configDigest" in queuedReview, false); assert.equal("leaseToken" in queuedReview, false);
    assert.ok((await db.llmJob.findUniqueOrThrow({ where: { id: queuedReview.id } })).inputCiphertext);
    assert.equal(await db.llmCall.count({ where: { jobId: queuedReview.id } }), 0, "The web request must never dispatch a provider call");
    const reviewDetail = await call(`/api/llm-jobs/${queuedReview.id}`);
    assert.equal(reviewDetail.workerReady, false); assert.equal(reviewDetail.permissions.canCancel, true);
    assert.equal(reviewDetail.events[0].code, "queued"); assert.equal("inputCiphertext" in reviewDetail, false);
    assert.equal((await call(`/api/llm-jobs/${queuedReview.id}`, { user: "bob" })).permissions.canCancel, false);
    await call(`/api/llm-jobs/${queuedReview.id}`, { user: "bob", method: "POST", body: { action: "cancel" }, status: 404 });
    await call(`/api/llm-jobs/${queuedReview.id}`, { method: "POST", body: { action: "cancel" }, requestOrigin: "https://unrelated.example.test", status: 403 });
    await call("/api/llm-scan", { method: "POST", body: { scanId: sa.id, mode: "quick" }, status: 409 });
    await call(`/api/llm-jobs/${queuedReview.id}`, { method: "POST", body: { action: "cancel" } });
    assert.equal((await call(`/api/llm-jobs/${queuedReview.id}`)).status, "cancelled");
    const compatibilityReview = await call("/api/llm-scan", { method: "POST", body: { scanId: sa.id, mode: "quick" }, status: 202 });
    assert.equal(compatibilityReview.findingsCount, 1); assert.ok(compatibilityReview.jobId);
    await call(`/api/llm-jobs/${compatibilityReview.jobId}`, { method: "POST", body: { action: "cancel" } });
    const historyJob = await call("/api/llm-jobs", { method: "POST", body: { scanId: sa.id, mode: "quick" }, status: 202 });
    const previousEncryptionSecret = process.env.ENCRYPTION_SECRET;
    try {
      process.env.ENCRYPTION_SECRET = environment.ENCRYPTION_SECRET;
      await runLlmWorkerOnce(db, "owned-http-review-worker", environment, new globalThis.AbortController().signal, { transport: async (request) => {
        const input = JSON.parse(JSON.parse(request.body).messages[0].content).findings;
        const reviews = input.map(({ id }) => ({ findingId: id, verdict: "needs_review", confidence: 0.2, reasoning: "Owned HTTP history evidence.", remediation: "Review supplied constraints.", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["No runtime observation."] }));
        return { status: 200, text: JSON.stringify({ id: "owned-http-response", model: "owned-fixture-model", stop_reason: "end_turn", content: [{ type: "text", text: JSON.stringify(reviews) }] }) };
      } });
    } finally { if (previousEncryptionSecret === undefined) delete process.env.ENCRYPTION_SECRET; else process.env.ENCRYPTION_SECRET = previousEncryptionSecret; }
    const savedHistory = await call(`/api/llm-jobs/${historyJob.id}/reviews?limit=1`, { user: "bob" });
    assert.equal(savedHistory.saved, 1); assert.equal(savedHistory.historyVersion, 1);
    assert.equal("payloadCiphertext" in savedHistory.reviews[0], false);
    const savedPath = `/api/llm-jobs/${historyJob.id}/reviews/${savedHistory.reviews[0].id}`;
    const savedDetail = await call(savedPath, { user: "bob" });
    assert.equal(savedDetail.record.result.reasoning, "Owned HTTP history evidence."); assert.equal(savedDetail.current.state, "current");
    await call(savedPath, { user: "outside", status: 404 });
    await call(savedPath, { method: "PATCH", body: { verdict: "likely_false_positive" }, status: 405 });
    await call(`/api/llm-jobs/${historyJob.id}/reviews?limit=21`, { status: 400 });
    await call(`/api/llm-jobs/${historyJob.id}/reviews?cursor=missing-row`, { status: 400 });
    await call(`/api/llm-jobs/${queuedReview.id}/reviews/${savedHistory.reviews[0].id}`, { status: 404 });
    const cacheCheck = await globalThis.fetch(origin + savedPath, { headers: { Cookie: `authjs.session-token=${cookies.bob}` } });
    assert.equal(cacheCheck.status, 200); assert.equal(cacheCheck.headers.get("cache-control"), "private, no-store"); checks++;
    await db.llmWorker.deleteMany({ where: { id: "owned-http-review-worker" } });
    await call("/api/llm-jobs?limit=NaN", { status: 400 });
    await db.setting.deleteMany({ where: { key: { startsWith: "llm." } } });
    assert.equal((await call("/api/repos")).repos.length, 0, "Repository discovery uses only the caller's OAuth account");
    for (const path of [`/api/findings?projectId=${b.id}&language=Python&search=BRAVO`, `/api/scans?projectId=${b.id}`, `/api/endpoints?projectId=${b.id}`]) assert.equal((await call(path)).total, 0);
    for (const path of [`/api/projects/${b.id}`, `/api/scans/${sb.id}`, `/api/scans/${sb.id}/progress`, `/api/findings/${fb.id}`, `/api/findings/${fb.id}/graph`, `/api/findings/${fb.id}/report`, `/api/graph/${sb.id}`, `/api/endpoints/${eb.id}`, `/api/endpoints/import-openapi?scanId=${sb.id}`, `/api/agent-runs/${rb.id}`, `/api/llm-jobs/${jb.id}`, `/api/llm-jobs/${jb.id}/reviews`, `/api/llm-jobs/${jb.id}/reviews/${savedHistory.reviews[0].id}`, `/api/llm-scan/${sb.id}`, `/api/projects/${b.id}/members`, `/api/projects/${b.id}/tokens`, `/api/projects/${b.id}/audit`]) await call(path, { status: 404 });
    const viewerFinding = await call(`/api/findings/${fa.id}`, { user: "bob" });
    assert.equal(viewerFinding.permissions.canTriage, false);
    await call(`/api/findings/${fa.id}`, { user: "bob", method: "PATCH", body: { status: "triaged" }, status: 404 });
    await call(`/api/projects/${a.id}/tokens`, { user: "bob", method: "POST", body: { name: "denied", expiresAt: new Date(Date.now() + 86_400_000).toISOString() }, status: 404 });
    for (const [path, body] of [["/api/llm-jobs", { scanId: sb.id, mode: "quick" }], ["/api/llm-scan", { scanId: sb.id, mode: "quick" }], ["/api/agent-runs", { scanId: sb.id }], ["/api/findings/analyze-batch", { ids: [fa.id, fb.id] }]]) await call(path, { method: "POST", body, status: 404 });
    await call(`/api/projects/${a.id}`, { method: "DELETE", status: 403, requestOrigin: "https://unrelated.example.test" });
    await call("/api/settings", { status: 403 });
    await call("/api/settings", { user: "root" });
    await call("/api/rules", { status: 403 });
    await call("/api/projects", { method: "POST", body: { name: "Denied" }, status: 403 });
    await call(`/api/projects/${a.id}/members`, { method: "PUT", body: { email: "bob@example.test", role: "triager" } });
    await call(`/api/findings/${fa.id}`, { user: "bob", method: "PATCH", body: { status: "triaged", expectedVersion: viewerFinding.workflow.version } });
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
    // Import preserves bounded producer evidence without converting an AI suggestion into triage.
    const digest = (value) => "sha256:" + createHash("sha256").update(value).digest("hex");
    const excerpt = "    return name";
    const sourceReference = { repository_id: "service", path: "src/app.py", source_digest: digest("def greet(name):\n" + excerpt + "\n"), excerpt_digest: digest(excerpt), line_start: 2, line_end: 2 };
    const citation = { citation_id: digest(JSON.stringify(sourceReference)), ...sourceReference };
    const aiReview = { verdict: "likely_false_positive", confidence: 0.7, reasoning: "Synthetic source-only review.", model: "scripted-fixture", citations: [{ ...citation, request_id: "tool-1" }], tools_used: [{ tool: "source_read", request_id: "tool-1", ok: true, round: 1, duration_ms: 0.1, arguments: { repository_id: "service", path: "src/app.py", line_start: 2, line_end: 2 }, evidence: { citation, content: excerpt } }], trace: { model_calls: 2, tool_calls: 1, stop_reason: "final_review", source_manifest: digest("synthetic-source-catalog") } };
    const aiSarif = globalThis.structuredClone(sarif);
    aiSarif.runs[0].results = [{ ruleId: "SHARED", message: { text: "AI evidence import fixture" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.py" }, region: { startLine: 2, endLine: 2 } } }], properties: { severity: "low", evidenceState: "candidate", disposition: "advisory", aiReview, remediation: "Scanner-authored remediation" } }];
    const aiUpload = await call("/api/upload?branch=main", { user: null, token: issued.token, method: "POST", body: aiSarif });
    const aiFinding = await db.finding.findFirstOrThrow({ where: { scanId: aiUpload.scanId } });
    const aiDetail = await call(`/api/findings/${aiFinding.id}`);
    assert.deepEqual(JSON.parse(aiDetail.llmAnalysis), aiReview);
    assert.equal(aiDetail.aiReviewStatus, "suggested"); assert.equal(aiDetail.status, "open");
    assert.equal(aiDetail.evidenceState, "candidate"); assert.equal(aiDetail.remediation, "Scanner-authored remediation");
    await call(`/api/findings/${aiFinding.id}`, { user: "outside", status: 404 });
    // Project-bound CI imports retain a human decision across checkout roots.
    const identityReport = (root, empty = false) => {
      const filePath = `${root}/src/review.py`;
      const source = { repositoryId: "review-service", modulePath: "src/review.py", filePath };
      return { version: "2.1.0", runs: [{
        tool: { driver: { name: "Aegify", version: "fixture", rules: [{ id: "IDENTITY-DEMO" }] } },
        invocations: [{ executionSuccessful: true }],
        properties: { analysisStatus: "completed", analysisScope: "repository", analyzedFiles: [filePath],
          evaluatedRules: ["IDENTITY-DEMO"], sourceIdentityVersion: 1, analyzedSources: [source] },
        results: empty ? [] : [{ ruleId: "IDENTITY-DEMO", level: "note", message: { text: "Review fixture" },
          partialFingerprints: { "aegifyFingerprint/v2": "recomputed", "aegifyFingerprint/v1": root },
          locations: [{ physicalLocation: { artifactLocation: { uri: filePath }, region: { startLine: 1, snippet: { text: "review(value)" } } } }],
          properties: { provenance: { repository_id: source.repositoryId, module_path: source.modulePath } },
        }],
      }] };
    };
    const beforeMove = await call("/api/upload?branch=main", { user: null, token: issued.token, method: "POST", body: identityReport("/runner/a") });
    const originalIdentityFinding = await db.finding.findFirstOrThrow({ where: { scanId: beforeMove.scanId } });
    const beforeTriage = await call(`/api/findings/${originalIdentityFinding.id}`, { user: "bob" });
    assert.equal(beforeTriage.permissions.canTriage, true);
    const triageUpdate = await call(`/api/findings/${originalIdentityFinding.id}`, { user: "bob", method: "PATCH", body: {
      expectedVersion: beforeTriage.workflow.version,
      status: "false_positive", reason: "Owned evidence reviewed", owner: "AppSec fixture team",
      dueAt: "2026-12-01", priority: "p1", tags: ["owned-fixture"],
    } });
    const afterMove = await call("/api/upload?branch=main", { user: null, token: issued.token, method: "POST", body: identityReport("/runner/b") });
    const movedFinding = await db.finding.findFirstOrThrow({ where: { scanId: afterMove.scanId } });
    const movedDetail = await call(`/api/findings/${movedFinding.id}`);
    assert.equal(movedDetail.identityId, originalIdentityFinding.identityId);
    assert.equal(movedDetail.status, "false_positive");
    assert.equal(movedDetail.owner, "AppSec fixture team");
    assert.equal(movedDetail.dueAt.slice(0, 10), "2026-12-01");
    assert.equal(movedDetail.priority, "p1");
    assert.deepEqual(JSON.parse(movedDetail.tags), ["owned-fixture"]);
    assert.equal(movedDetail.workflow.version, triageUpdate.workflow.version, "An unchanged scan must not cause edit conflicts");
    assert.equal(movedDetail.identity.triageEvents[0].reason, "Owned evidence reviewed");
    assert.equal(movedDetail.baselineState, "unchanged");
    assert.equal((await db.finding.findUniqueOrThrow({ where: { id: originalIdentityFinding.id } })).isCurrent, false);
    await call(`/api/findings/${movedFinding.id}`, { user: "outside", status: 404 });
    await call(`/api/findings/${movedFinding.id}`, { user: "bob", method: "PATCH", body: { owner: "Stale edit", expectedVersion: beforeTriage.workflow.version }, status: 409 });
    for (const body of [null, [], {}, { owner: "Missing version" }, { expectedVersion: movedDetail.workflow.version, owner: "x".repeat(40_000) }]) {
      await call(`/api/findings/${movedFinding.id}`, { user: "bob", method: "PATCH", body, status: 400 });
    }
    const fromHistory = await call(`/api/findings/${originalIdentityFinding.id}`, { user: "bob", method: "PATCH", body: { owner: "Service fixture team", expectedVersion: movedDetail.workflow.version } });
    assert.equal(fromHistory.owner, "AppSec fixture team", "Historical observation retains its saved assignment");
    assert.equal(fromHistory.workflow.owner, "Service fixture team");
    assert.equal((await db.finding.findUniqueOrThrow({ where: { id: movedFinding.id } })).owner, "Service fixture team");
    // A synthetic completed receipt exercises storage; Jira stays disabled and
    // no external ticket or message is sent by this integration harness.
    const issue = { key: "FIXTURE-1", url: "https://issues.example.test/browse/FIXTURE-1" };
    assert.deepEqual(await recordFindingTicket(db, { findingId: movedFinding.id, identityId: movedFinding.identityId, projectId: a.id, actorId: "alice" }, issue), { linked: true });
    assert.deepEqual(await call(`/api/findings/${originalIdentityFinding.id}/jira`, { method: "POST" }), issue);
    await call("/api/upload?branch=main", { user: null, token: issued.token, method: "POST", body: identityReport("/runner/c", true) });
    assert.ok((await db.findingIdentity.findUniqueOrThrow({ where: { id: movedFinding.identityId } })).absentAt);
    const reappeared = await call("/api/upload?branch=main", { user: null, token: issued.token, method: "POST", body: identityReport("/runner/d") });
    const regression = await db.finding.findFirstOrThrow({ where: { scanId: reappeared.scanId } });
    const regressionDetail = await call(`/api/findings/${regression.id}`);
    assert.equal(regressionDetail.status, "open");
    assert.equal(regressionDetail.owner, "Service fixture team");
    assert.equal(regressionDetail.priority, "p1");
    assert.equal(regressionDetail.ticketKey, issue.key);
    assert.equal(regressionDetail.workflow.ticketUrl, issue.url);
    assert.deepEqual(JSON.parse(regressionDetail.tags), ["owned-fixture"]);
    assert.equal(regressionDetail.baselineState, "regressed");
    assert.equal(regressionDetail.identity.triageEvents.length, 2);
    const reportPath = join(directory, "synthetic.sarif");
    await writeFile(reportPath, JSON.stringify(sarif));
    // The optional local CLI check uses the same endpoint and synthetic credential.
    if (process.env.AEGIFY_TEST_SCANNER_CLI === "1") {
      const interpreter = fileURLToPath(new URL("../../scanner/.venv/bin/python", import.meta.url));
      const child = spawn(interpreter, ["-c", "from aegify.cli import app; app()", "upload", reportPath, "--dashboard-url", origin, "--project-id", a.id], { env: { ...environment, AEGIFY_UPLOAD_TOKEN: issued.token }, stdio: ["ignore", "pipe", "pipe"] });
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
    await db.project.update({ where: { id: a.id }, data: { provider: "github", ownerSlug: "fixture/repository" } });
    await db.account.create({ data: { userId: "alice", provider: "github", providerAccountId: "alice-fixture", type: "oauth", access_token: "synthetic-unused-token" } });
    for (const body of [null, [], { branch: 123 }, { branch: "x".repeat(5000) }]) await call(`/api/projects/${a.id}/scan`, { method: "POST", body, status: 400 });
    const queued = await call(`/api/projects/${a.id}/scan`, { method: "POST", body: {}, status: 202 });
    assert.equal((await call(`/api/projects/${a.id}/scan`, { method: "POST", body: {}, status: 202 })).scanId, queued.scanId);
    const job = await call(`/api/scans/${queued.scanId}/job`);
    assert.equal(job.job.status, "queued"); assert.equal(job.workerAvailable, false);
    assert.ok(!JSON.stringify(job).includes("leaseToken")); assert.ok(!JSON.stringify(job).includes("sourceCiphertext"));
    for (const body of [null, [], { action: "x".repeat(5000) }]) await call(`/api/scans/${queued.scanId}/job`, { method: "POST", body, status: 400 });
    await call(`/api/scans/${queued.scanId}/job`, { user: "bob", status: 404 });
    await call(`/api/scans/${queued.scanId}/job`, { user: "bob", method: "POST", body: { action: "cancel" }, status: 404 });
    await call(`/api/scans/${queued.scanId}/progress`, { method: "PATCH", body: { status: "completed" }, status: 409 });
    await call(`/api/scans/${queued.scanId}/job`, { method: "POST", body: { action: "cancel" }, requestOrigin: "https://unrelated.example.test", status: 403 });
    await call(`/api/scans/${queued.scanId}/job`, { method: "POST", body: { action: "cancel" } });
    assert.equal((await call(`/api/scans/${queued.scanId}/job`)).job.status, "cancelled");
    const retry = await call(`/api/scans/${queued.scanId}/job`, { method: "POST", body: { action: "retry" }, status: 202 });
    assert.notEqual(retry.scanId, queued.scanId);
    if (verifyBrowser) await verifyBrowser({ origin, cookies, projectId: a.id, reportPath, queuedScanId: retry.scanId, aiFindingId: aiFinding.id, workflowFindingId: regression.id, historicalFindingId: originalIdentityFinding.id, reviewJobId: queuedReview.id, reviewScanId: sa.id, db, environment });
    // Recovery rotates an epoch even if a restored session counter repeats.
    const recoveredEpoch = randomBytes(16).toString("hex");
    await db.user.update({ where: { id: "alice" }, data: { sessionEpoch: recoveredEpoch } });
    await call("/api/projects", { user: "alice", status: 401 });
    cookies.alice = await encode({ secret, salt: "authjs.session-token", maxAge: 3600, token: { sub: "alice", sessionVersion: 0, sessionEpoch: recoveredEpoch, authStartedAt: Date.now(), provider: "github" } });
    await call("/api/projects", { user: "alice" });
    await db.user.update({ where: { id: "bob" }, data: { disabled: true } });
    await call("/api/projects", { user: "bob", status: 401 });
    log(`Project access: ${checks} production HTTP/CLI checks passed; project isolation, roles, CSRF, scoped CI delivery and revocation verified.`);
  } finally {
    if (server && server.exitCode === null) { server.kill("SIGTERM"); await new Promise((resolve) => server.once("exit", resolve)); }
    await db.$disconnect(); await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await runAccessIntegration();
