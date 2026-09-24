// Real owned production UI and Python worker. No target applications, external
// providers or paid models. Uses the locked docs Puppeteer dependency.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { URL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import process from "node:process";
import { log } from "node:console";
import { writeFile } from "node:fs/promises";
import { runAccessIntegration } from "./test-project-access.mjs";
import { runRuleFixtureWorkerOnce } from "../src/lib/rule-fixture-worker.ts";
import { ruleFixtureExamples } from "../src/lib/rule-fixture-examples.ts";
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
  await runAccessIntegration({ verifyBrowser: async ({ origin, cookies, projectId, db, environment }) => {
    const context = await browser.createBrowserContext();
    try {
      await context.setCookie({ name: "authjs.session-token", value: cookies.alice, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
      const page = await context.newPage();
      page.on("pageerror", (error) => errors.push(error.message));
      await page.setRequestInterception(true);
      page.on("request", (request) => { if (request.url().startsWith(origin + "/") || request.url().startsWith("data:") || request.url().startsWith("blob:")) void request.continue(); else void request.abort(); });
      await page.setViewport({ width: 1440, height: 1200 });
      await page.goto(`${origin}/projects/${projectId}`, { waitUntil: "networkidle0" });
      await (await elementWithText(page, "a", "Rule lab")).click();
      await waitText(page, "Waiting for an evaluation worker.");
      await (await elementWithText(page, "button", "Taint & cross-file helper")).click();
      await waitText(page, "cross-file-query");
      await page.screenshot({ path: "/private/tmp/aegify-rule-fixture-authoring-desktop.png", fullPage: true });
      async function runExpected(outcome) {
        await (await elementWithText(page, "button", "Run evaluation")).click();
        let queued;
        for (let attempt = 0; attempt < 100; attempt++) { queued = await db.ruleFixtureJob.findFirst({ where: { projectId, status: "queued" } }); if (queued) break; await delay(50); }
        assert.ok(queued);
        assert.equal(await runRuleFixtureWorkerOnce(db, "owned-browser-fixture-worker", environment, new globalThis.AbortController().signal), true);
        const saved = await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: queued.id } });
        assert.equal(saved.status, "completed"); assert.equal(saved.outcome, outcome); checks += 2;
        await page.waitForFunction((expected) => globalThis.document.querySelector('[aria-label="Evaluation history"] [role="status"]')?.textContent === expected, { timeout: 15_000 }, outcome); checks++;
        return saved;
      }
      const first = await runExpected("passed");
      await waitText(page, "Fixture precision");
      await (await elementWithText(page, "summary", "cross-file-query")).click();
      await waitText(page, "Static data flow"); await waitText(page, "helper.py:2");
      const reportSection = await page.$('section[aria-label="Evaluation history"]');
      await page.setViewport({ width: 1440, height: 1800 });
      await reportSection.screenshot({ path: "/private/tmp/aegify-rule-fixture-results-desktop.png" });
      await page.setViewport({ width: 390, height: 844 });
      assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.window.innerWidth), "Mobile rule lab must not overflow horizontally"); checks++;
      assert.deepEqual(await page.evaluate(() => [...globalThis.document.querySelectorAll('main, section')].filter((node) => node.scrollWidth > node.clientWidth + 2).map((node) => node.getAttribute('aria-label') || node.tagName)), [], "Mobile panels must fit their own content box"); checks++;
      await page.setViewport({ width: 390, height: 2500 });
      await reportSection.screenshot({ path: "/private/tmp/aegify-rule-fixture-results-mobile.png" });
      await page.setViewport({ width: 1280, height: 1100 });
      await (await elementWithText(page, "button", "Suite JSON")).click();
      const mismatch = JSON.parse(ruleFixtureExamples.taint.suiteJson);
      mismatch.cases[0].expected[0].line_start = 1;
      const editor = await page.$('textarea[aria-label="Fixture suite JSON"]');
      await editor.focus(); await editor.evaluate((node) => node.select());
      await page.keyboard.type(JSON.stringify(mismatch, null, 2));
      await waitText(page, "The draft has changed since this run.");
      const second = await runExpected("failed");
      await waitText(page, "Missed expected locations"); await waitText(page, "Unexpected detected locations");
      await page.select('select[aria-label="Evaluation history"]', first.id);
      await page.waitForFunction(() => globalThis.document.querySelector('[aria-label="Evaluation history"] [role="status"]')?.textContent === "passed", { timeout: 15_000 }); checks++;
      assert.equal((await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: first.id } })).resultDigest, first.resultDigest); checks++;
      await (await elementWithText(page, "button", "Load saved input")).click();
      await page.waitForFunction((original) => globalThis.document.querySelector('textarea[aria-label="Fixture suite JSON"]')?.value === original, { timeout: 15_000 }, ruleFixtureExamples.taint.suiteJson); checks++;
      await (await elementWithText(page, "button", "Run evaluation")).click();
      await waitText(page, "Cancel evaluation");
      await (await elementWithText(page, "button", "Cancel evaluation")).click();
      await page.waitForFunction(() => globalThis.document.querySelector('[aria-label="Evaluation history"] [role="status"]')?.textContent === "cancelled", { timeout: 15_000 }); checks++;
      await db.projectMember.upsert({ where: { projectId_userId: { projectId, userId: "bob" } }, create: { projectId, userId: "bob", role: "viewer" }, update: { role: "viewer" } });
      await context.setCookie({ name: "authjs.session-token", value: cookies.bob, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
      await page.goto(`${origin}/projects/${projectId}/rule-lab`, { waitUntil: "networkidle0" });
      await waitText(page, "Viewer access");
      assert.equal(await (await elementWithText(page, "button", "Run evaluation")).evaluate((node) => node.disabled), true); checks++;
      await page.select('select[aria-label="Evaluation history"]', second.id); await waitText(page, "Missed expected locations");
      await db.projectMember.delete({ where: { projectId_userId: { projectId, userId: "bob" } } });
      await (await elementWithText(page, "button", "Refresh")).click();
      await waitText(page, "Resource not found.");
      await page.waitForFunction(() => !globalThis.document.body.innerText.includes("Fixture precision"), { timeout: 15_000 }); checks++;
      assert.equal(await db.llmCall.count({ where: { job: { projectId, inputDigest: first.inputDigest } } }), 0); checks++;
      assert.deepEqual(errors, [], "No client runtime errors"); checks++;
    } catch (error) {
      const page = (await context.pages())[0];
      if (page) {
        await page.screenshot({ path: "/private/tmp/aegify-rule-fixture-browser-failure.png", fullPage: true });
        const state = await page.evaluate(() => ({ text: globalThis.document.body.innerText, suite: globalThis.document.querySelector('textarea[aria-label="Fixture suite JSON"]')?.value, disabled: globalThis.document.querySelector('textarea[aria-label="Fixture suite JSON"]')?.disabled, overflows: [...globalThis.document.querySelectorAll('main, section, label, div')].filter((node) => node.scrollWidth > node.clientWidth + 2).map((node) => ({ tag: node.tagName, className: node.className, width: node.clientWidth, scroll: node.scrollWidth })).slice(0, 20) }));
        await writeFile("/private/tmp/aegify-rule-fixture-browser-failure.json", JSON.stringify({ errors, ...state }, null, 2));
      }
      throw error;
    } finally { await context.close(); }
  } });
  log(`Rule fixture browser: ${checks} checks passed with real Python: project navigation, guided/JSON editing, taint paths, exact-location mismatches, retained history, restore input, cancellation, viewer controls, revocation and mobile layout.`);
} finally { await browser.close(); }
