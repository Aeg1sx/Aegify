// Uses the same owned production database and synthetic users as the project access tests.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import process from "node:process";
import { URL } from "node:url";
import { log } from "node:console";
import { runAccessIntegration } from "./test-project-access.mjs";

const requireDocs = createRequire(new URL("../../docs/package.json", import.meta.url));
const puppeteer = requireDocs("puppeteer");
await runAccessIntegration({ async verifyBrowser({ origin, cookies, projectId, gatewayScanId, db }) {
  const browser = await puppeteer.launch({
    headless: true, executablePath: process.env.AEGIFY_TEST_BROWSER || await puppeteer.executablePath(),
  });
  try {
    const context = await browser.createBrowserContext();
    await context.setCookie({ name: "authjs.session-token", value: cookies.alice, domain: "127.0.0.1", path: "/", httpOnly: true });
    const page = await context.newPage();
    const scans = await db.scan.findMany({ where: { projectId }, select: { id: true },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }] });
    const index = scans.findIndex(({ id }) => id === gatewayScanId);
    assert.ok(index >= 0);
    await page.goto(origin + "/projects/" + projectId + "?page=" + (Math.floor(index / 10) + 1));
    const link = await page.waitForSelector('a[href="/scans/' + gatewayScanId + '#gateway-inventory"]');
    assert.match(await link.evaluate((element) => element.textContent), /1 resolved.*1 unresolved/);
    await link.click();
    const panel = await page.waitForSelector("#gateway-inventory");
    const text = await panel.evaluate((element) => element.innerText);
    assert.match(text, /edge · deploy\/kong.yml/);
    assert.match(text, /catalog-service/);
    assert.match(text, /Document 1 · Line 9/);
    assert.match(text, /Kong Upstream pool membership needs review/);
    const routeNames = () => panel.$$eval('ul[aria-label="Gateway route declarations"] > li', (rows) => rows.map((row) => row.querySelector("span").textContent));
    const [file, status] = await panel.$$("select");
    await status.select("ambiguous");
    await page.waitForFunction((element) => element.querySelector("[aria-live]").textContent.includes("of 26 declarations"), {}, panel);
    assert.equal((await routeNames()).length, 25);
    assert.match(await panel.evaluate((element) => element.innerText), /platform · spring\/application.yml/);
    await page.locator('::-p-aria(Next[role="button"])').click();
    assert.deepEqual(await routeNames(), ["orders-25"]);
    await file.select("0");
    await page.waitForFunction((element) => element.querySelector("[aria-live]").textContent.includes("No declarations match"), {}, panel);
    assert.deepEqual(await routeNames(), []);
    await status.select("unresolved");
    await page.waitForFunction((element) => element.querySelector("li")?.textContent.includes("pool"), {}, panel);
    assert.deepEqual(await routeNames(), ["pool"]);
    assert.match(await panel.evaluate((element) => element.innerText), /Configuration SHA-256/);
    await page.setViewport({ width: 390, height: 844 });
    assert.ok(await panel.evaluate((element) => element.scrollWidth <= element.clientWidth + 1));
    assert.equal(await panel.$('li a[href^="/findings?"]'), null);
    // Two service trees use the same source location. Keep the historical row visible when reviewing this scan.
    const shared = { scanId: gatewayScanId, ruleId: "SHARED", ruleName: "Workspace review", severity: "low",
      message: "Review the service configuration.", modulePath: "src/app.py", filePath: "src/app.py", lineStart: 1, lineEnd: 1 };
    const east = await db.finding.create({ data: { ...shared, repositoryId: "orders-east", isCurrent: false } });
    await db.finding.create({ data: { ...shared, repositoryId: "orders-west" } });
    await file.select("-1");
    await status.select("all");
    await (await panel.$('input[type="search"]')).type("WEST");
    await page.waitForFunction((element) => element.querySelector("[aria-live]").textContent.includes("of 26 declarations"), {}, panel);
    const firstRoute = await panel.waitForSelector('ul[aria-label] > li');
    assert.equal(await firstRoute.$("a"), null);
    await (await firstRoute.$("summary")).click();
    const candidate = await firstRoute.waitForSelector('[aria-label="View findings for orders-east in this scan"]');
    await candidate.focus();
    await page.keyboard.press("Enter");
    const scope = await page.waitForSelector('[aria-label="Review scope"]');
    assert.match(await scope.evaluate((node) => node.innerText), /orders-east/);
    const details = await page.waitForSelector('a[aria-label="Full details for Workspace review"]');
    assert.match(await scope.evaluate((node) => node.innerText), /Partial scan coverage/);
    const detailUrl = new URL(await details.evaluate((node) => node.href));
    assert.equal(detailUrl.pathname, "/findings/" + east.id);
    assert.equal(detailUrl.searchParams.get("scanId"), gatewayScanId);
    assert.equal(detailUrl.searchParams.get("repositoryId"), "orders-east");
    for (const width of [1440, 820, 390, 320]) {
      await page.setViewport({ width, height: 900 });
      assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth));
    }
    await details.click();
    await page.locator('a[aria-label="Back to findings"]').click();
    await page.waitForSelector('a[aria-label="Full details for Workspace review"]');
    await page.locator('select[aria-label="Finding view"]').fill("1");
    await page.waitForFunction(() => globalThis.document.body.innerText.includes("No findings match this view."));
    assert.equal(new URL(page.url()).searchParams.get("repositoryId"), "orders-east");
    await page.locator('::-p-aria(Clear filters[role="button"])').click();
    await page.waitForSelector('a[aria-label="Full details for Workspace review"]');
    await page.locator('::-p-aria(Show all repositories[role="button"])').click();
    await page.waitForFunction(() => globalThis.document.querySelectorAll('a[aria-label="Full details for Workspace review"]').length === 2);
    assert.equal(new URL(page.url()).searchParams.get("scanId"), gatewayScanId);
    assert.equal(new URL(page.url()).searchParams.has("repositoryId"), false);
    await page.locator('button[aria-label="View findings for orders-east in this scan"]').click();
    await page.waitForFunction((project) => new URL(globalThis.location.href).searchParams.get("projectId") === project, {}, projectId);
    assert.equal(new URL(page.url()).searchParams.get("scanId"), gatewayScanId);
    assert.equal(new URL(page.url()).searchParams.get("repositoryId"), "orders-east");
    await page.locator('select[aria-label="Finding view"]').fill("1");
    await page.waitForFunction(() => globalThis.document.body.innerText.includes("No findings match this view."));
    await page.locator('::-p-aria(Clear filters[role="button"])').click();
    await page.waitForSelector('a[aria-label="Full details for Workspace review"]');
    assert.equal(new URL(page.url()).searchParams.get("projectId"), projectId);
    await page.locator('::-p-aria(Show all repositories[role="button"])').click();
    await page.locator('::-p-aria(Leave scan view[role="button"])').click();
    await page.waitForFunction(() => !new URL(globalThis.location.href).searchParams.has("scanId")
      && !globalThis.document.querySelector('[aria-label="Review scope"]'));
    log("Verified gateway pagination, candidate navigation, historical findings, scoped presets and four viewport widths in Chromium.");
  } finally {
    await browser.close();
  }
} });
