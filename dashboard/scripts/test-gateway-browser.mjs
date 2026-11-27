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
    log("Gateway project summary, scan evidence and unresolved reason passed in Chromium.");
  } finally {
    await browser.close();
  }
} });
