// Owned production fixture only. Requires the locked docs dependencies and a local
// Puppeteer browser: npm ci --ignore-scripts in docs; provision the browser separately.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { URL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import process from "node:process";
import { log } from "node:console";
import { runAccessIntegration } from "./test-project-access.mjs";
import { runLlmWorkerOnce } from "../src/lib/llm-worker.ts";
const requireDocs = createRequire(new URL("../../docs/package.json", import.meta.url));
const { default: puppeteer } = await import(requireDocs.resolve("puppeteer"));
const browser = await puppeteer.launch({ executablePath: process.env.AEGIFY_TEST_BROWSER || await puppeteer.executablePath(), headless: true });
let checks = 0;
const errors = [];
async function elementWithText(page, selector, text) {
  for (const element of await page.$$(selector)) if ((await element.evaluate((node) => node.textContent || "")).includes(text)) return element;
  throw new Error("Missing fixture control: " + text);
}
async function waitText(page, text) { await page.waitForFunction((value) => globalThis.document.body.innerText.includes(value), { timeout: 15_000 }, text); checks++; }
try {
  await runAccessIntegration({ verifyBrowser: async ({ origin, cookies, projectId, reviewScanId, db, environment }) => {
    const previous = process.env.ENCRYPTION_SECRET;
    process.env.ENCRYPTION_SECRET = environment.ENCRYPTION_SECRET;
    const context = await browser.createBrowserContext();
    try {
      await context.setCookie({ name: "authjs.session-token", value: cookies.alice, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
      const page = await context.newPage();
      page.on("pageerror", (error) => errors.push(error.message));
      await page.setRequestInterception(true);
      page.on("request", (request) => { if (request.url().startsWith(origin + "/") || request.url().startsWith("data:")) void request.continue(); else void request.abort(); });
      await page.setViewport({ width: 1280, height: 1000 });
      await page.goto(origin + "/llm-scan", { waitUntil: "networkidle0" });
      await waitText(page, "No AI worker is online");
      for (const [key, value] of Object.entries({ "llm.enabled": "true", "llm.provider": "anthropic", "llm.model": "owned-browser-model", "llm.anthropic_api_key": "owned-nonworking-placeholder" })) await db.setting.upsert({ where: { key }, create: { key, value }, update: { value } });
      await page.select("#review-project", projectId);
      await page.waitForSelector(`#review-scan option[value="${reviewScanId}"]`);
      await page.select("#review-scan", reviewScanId);
      await (await elementWithText(page, "button", "Start Quick Review")).click();
      await waitText(page, "Cancel review");
      await (await elementWithText(page, "button", "Cancel review")).click();
      await page.waitForFunction(() => globalThis.document.querySelector('[aria-label="AI review job"]')?.innerText.includes("cancelled"), { timeout: 15_000 }); checks++;
      const cancelled = await db.llmJob.findFirstOrThrow({ where: { scanId: reviewScanId }, orderBy: { createdAt: "desc" } });
      assert.equal(cancelled.status, "cancelled"); assert.equal(await db.llmCall.count({ where: { jobId: cancelled.id } }), 0); checks += 2;
      await (await elementWithText(page, "button", "Start Quick Review")).click();
      let queued;
      for (let i = 0; i < 100; i++) { queued = await db.llmJob.findFirst({ where: { scanId: reviewScanId, status: "pending" } }); if (queued) break; await delay(50); }
      assert.ok(queued);
      await runLlmWorkerOnce(db, "owned-browser-worker", environment, new globalThis.AbortController().signal, { transport: async (request) => {
        const findings = JSON.parse(JSON.parse(request.body).messages[0].content).findings;
        const reviews = findings.map(({ id }) => ({ findingId: id, verdict: "needs_review", confidence: 0.3, reasoning: "Owned static fixture, no runtime conclusion.", remediation: "Review the implementation constraints.", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["Runtime evidence was not supplied."] }));
        return { status: 200, text: JSON.stringify({ id: "owned-browser-response", model: "owned-browser-model", stop_reason: "end_turn", usage: { input_tokens: 120, output_tokens: 80, cache_read_input_tokens: 0 }, content: [{ type: "text", text: JSON.stringify(reviews) }] }) };
      } });
      await waitText(page, "Batch 1 · completed");
      await (await elementWithText(page, "summary", "Usage and receipt")).click();
      await waitText(page, "input_tokens"); await waitText(page, "Unknown — check provider billing");
      await waitText(page, "30% model estimate");
      assert.equal((await db.llmJob.findUniqueOrThrow({ where: { id: queued.id } })).reviewedCount, 1); checks++;
      await page.screenshot({ path: "/private/tmp/aegify-durable-ai-desktop.png", fullPage: true });
      await page.setViewport({ width: 390, height: 844 });
      assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.window.innerWidth), "Mobile review must not overflow"); checks++;
      await page.screenshot({ path: "/private/tmp/aegify-durable-ai-mobile.png", fullPage: true });
      await db.projectMember.upsert({ where: { projectId_userId: { projectId, userId: "bob" } }, create: { projectId, userId: "bob", role: "viewer" }, update: { role: "viewer" } });
      await context.setCookie({ name: "authjs.session-token", value: cookies.bob, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
      await page.goto(origin + "/llm-scan", { waitUntil: "networkidle0" });
      await page.select("#review-project", projectId); await page.waitForSelector(`#review-scan option[value="${reviewScanId}"]`); await page.select("#review-scan", reviewScanId);
      await waitText(page, "maintainer access are required");
      assert.equal(await (await elementWithText(page, "button", "Start Quick Review")).evaluate((node) => node.disabled), true); checks++;
      assert.deepEqual(errors, [], "No client runtime errors"); checks++;
    } finally {
      if (previous === undefined) delete process.env.ENCRYPTION_SECRET; else process.env.ENCRYPTION_SECRET = previous;
      await context.close();
    }
  } });
  log(`AI review browser: ${checks} checks passed; enqueue, cancellation, worker publication, native usage, mobile layout and viewer controls verified with synthetic input.`);
} finally { await browser.close(); }
