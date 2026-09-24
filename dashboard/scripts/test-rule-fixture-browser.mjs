// Real owned production UI and Python worker. No target applications, external
// providers or paid models. Uses the locked docs Puppeteer dependency.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath, URL } from "node:url";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import process from "node:process";
import { log } from "node:console";
import { mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
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
    const exportDirectory = await mkdtemp(join(tmpdir(), "aegify-rule-fixture-export-"));
    let context;
    try {
      context = await browser.createBrowserContext({ downloadBehavior: { policy: "allow", downloadPath: exportDirectory } });
      await context.setCookie({ name: "authjs.session-token", value: cookies.alice, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
      const page = await context.newPage();
      page.on("pageerror", (error) => errors.push(error.message));
      await page.setRequestInterception(true);
      page.on("request", (request) => { if (request.url().startsWith(origin + "/") || request.url().startsWith("data:") || request.url().startsWith("blob:")) void request.continue(); else void request.abort(); });
      await page.setViewport({ width: 1440, height: 1200 });
      async function downloaded(name, button) {
        await (await elementWithText(page, "button", button)).click();
        for (let attempt = 0; attempt < 100; attempt++) {
          try { return await readFile(join(exportDirectory, name), "utf8"); }
          catch (error) { if (error.code !== "ENOENT") throw error; }
          await delay(50);
        }
        throw new Error("Rule lab download did not complete: " + name);
      }
      async function verifyExport(outcome, exitCode, suite) {
        assert.equal(await downloaded("rule.yml", "Export rule"), ruleFixtureExamples.taint.ruleYaml); checks++;
        assert.deepEqual(JSON.parse(await downloaded("fixtures.json", "Export fixtures")), suite); checks++;
        const report = JSON.parse(await downloaded("rule-fixture-report.json", "Report JSON"));
        assert.equal(report.status, outcome); checks++;
        const interpreter = fileURLToPath(new URL("../../scanner/.venv/bin/python", import.meta.url));
        const command = "from pathlib import Path; from aegify.quality.rule_fixtures import FixtureReport, result_digest; report = FixtureReport.model_validate_json(Path('rule-fixture-report.json').read_text()); assert result_digest(report) == report.result_digest, 'Exported report digest changed'; from aegify.cli import app; app()";
        const cli = spawnSync(interpreter, ["-I", "-c", command, "test-rule", "rule.yml", "--fixtures", "fixtures.json", "--timeout-seconds", "30", "--json"], {
          cwd: exportDirectory, encoding: "utf8", timeout: 45_000, maxBuffer: 5 * 1024 * 1024,
          env: { PATH: "/usr/local/bin:/usr/bin:/bin", LANG: "C.UTF-8", PYTHONDONTWRITEBYTECODE: "1" },
        });
        assert.equal(cli.error, undefined); assert.equal(cli.status, exitCode, cli.stderr); checks++;
        const replay = JSON.parse(cli.stdout);
        assert.equal(replay.result_digest, report.result_digest); checks++;
        assert.deepEqual(replay.manifest, report.manifest); checks++;
        const evidence = (value) => value.cases.map((item) => Object.fromEntries(Object.entries(item).filter(([key]) => key !== "duration_seconds")));
        assert.deepEqual(evidence(replay), evidence(report)); checks++;
        for (const name of ["rule.yml", "fixtures.json", "rule-fixture-report.json"]) await unlink(join(exportDirectory, name));
      }
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
      await verifyExport("failed", 1, mismatch);
      await page.select('select[aria-label="Evaluation history"]', first.id);
      await page.waitForFunction(() => globalThis.document.querySelector('[aria-label="Evaluation history"] [role="status"]')?.textContent === "passed", { timeout: 15_000 }); checks++;
      assert.equal((await db.ruleFixtureJob.findUniqueOrThrow({ where: { id: first.id } })).resultDigest, first.resultDigest); checks++;
      await (await elementWithText(page, "button", "Load saved input")).click();
      await page.waitForFunction((original) => globalThis.document.querySelector('textarea[aria-label="Fixture suite JSON"]')?.value === original, { timeout: 15_000 }, ruleFixtureExamples.taint.suiteJson); checks++;
      await verifyExport("passed", 0, JSON.parse(ruleFixtureExamples.taint.suiteJson));
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
      const page = (await context?.pages())?.[0];
      if (page) {
        await page.screenshot({ path: "/private/tmp/aegify-rule-fixture-browser-failure.png", fullPage: true });
        const state = await page.evaluate(() => ({ text: globalThis.document.body.innerText, suite: globalThis.document.querySelector('textarea[aria-label="Fixture suite JSON"]')?.value, disabled: globalThis.document.querySelector('textarea[aria-label="Fixture suite JSON"]')?.disabled, overflows: [...globalThis.document.querySelectorAll('main, section, label, div')].filter((node) => node.scrollWidth > node.clientWidth + 2).map((node) => ({ tag: node.tagName, className: node.className, width: node.clientWidth, scroll: node.scrollWidth })).slice(0, 20) }));
        await writeFile("/private/tmp/aegify-rule-fixture-browser-failure.json", JSON.stringify({ errors, ...state }, null, 2));
      }
      throw error;
    } finally { await context?.close(); await rm(exportDirectory, { recursive: true, force: true }); }
  } });
  log(`Rule fixture browser: ${checks} checks passed with real Python: project navigation, guided/JSON editing, taint paths, exact-location mismatches, downloaded inputs/report replayed through CLI pass/fail gates, retained history, restore input, cancellation, viewer controls, revocation and mobile layout.`);
} finally { await browser.close(); }
