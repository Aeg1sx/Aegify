import assert from "node:assert/strict";
import { join } from "node:path";
import process from "node:process";

export async function checkRepositoryCoverage(page, db, origin, cookies, projectId) {
  const ids = [
    "catalog", "checkout", "delivery", "export", "gateway", "inventory", "notifications",
    "orders", "payments", "receipts", "tax", "warehouse-fulfillment-and-transit-event-processor",
  ];
  const rows = ids.map((repositoryId, index) => ({
    repositoryId, analyzedFiles: repositoryId === "tax" ? 0 : index + 1,
    discoveryErrors: repositoryId === "warehouse-fulfillment-and-transit-event-processor" ? 3
      : ["delivery", "inventory"].includes(repositoryId) ? 1 : 0,
  }));
  const sorted = [...rows].sort((a, b) => b.discoveryErrors - a.discoveryErrors || a.repositoryId.localeCompare(b.repositoryId));
  const legacy = await db.scan.create({ data: { projectId, repository: "ledger/archive", status: "completed" } });
  const scan = await db.scan.create({ data: {
    projectId, repository: "ledger/commerce", branch: "main", status: "partial",
    filesScanned: rows.reduce((sum, row) => sum + row.analyzedFiles, 0),
    repositoryCoverage: { create: rows },
  } });
  try {
    const path = "/api/scans/" + scan.id;
    const get = (url, user) => globalThis.fetch(origin + url, {
      headers: { Cookie: "authjs.session-token=" + cookies[user] },
    });
    const response = await get(path, "alice");
    assert.equal(response.status, 200);
    assert.deepEqual((await response.json()).repositoryCoverage, sorted);
    const inaccessible = await get(path, "outside");
    assert.equal(inaccessible.status, 404);
    assert.ok(!(await inaccessible.text()).includes(ids.at(-1)));
    assert.deepEqual((await (await get("/api/scans/" + legacy.id, "alice")).json()).repositoryCoverage, []);
    const region = 'section[aria-labelledby="repository-coverage"]';
    await page.goto(origin + "/scans/" + legacy.id);
    await page.waitForSelector("#scan-findings");
    assert.equal(await page.$(region), null);
    for (const width of [1280, 390, 320]) {
      await page.setViewport({ width, height: width > 500 ? 960 : 844 });
      await page.goto(origin + "/scans/" + scan.id);
      await page.waitForSelector(region + " tbody th");
      assert.deepEqual(await page.$$eval(region + " thead th", (cells) => cells.map((c) => c.innerText)),
        ["Repository", "Analyzed files", "Discovery errors"]);
      assert.equal(await page.$$eval(region + " tbody tr", (items) => items.length), 10);
      assert.deepEqual(await page.$eval(region + " tbody tr", (tr) => Array.from(tr.cells, (cell) => cell.innerText)),
        [ids.at(-1), "12", "3"]);
      assert.ok(await page.$eval(region, (el) => el.scrollWidth <= el.clientWidth));
      assert.ok(await page.$eval("#workspace", (el) => el.scrollWidth <= el.clientWidth));
      if (width > 320 && process.env.AEGIFY_UI_ARTIFACTS) {
        await page.$eval(region, (el) => el.scrollIntoView({ block: "start" }));
        await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "repository-coverage-" + width + ".png") });
      }
      const next = await page.$(region + " nav button:last-child");
      await next.focus();
      await page.keyboard.press("Enter");
      await page.waitForFunction(() => globalThis.document.activeElement?.id === "repository-coverage"
        && globalThis.document.querySelector('[aria-label="Repository coverage pages"]')?.innerText.includes("Page 2 of 2"));
      const zero = await page.waitForSelector(region + ' a[aria-label="Review findings for tax"]');
      assert.deepEqual(await zero.evaluate((link) => Array.from(link.closest("tr").cells, (cell) => cell.innerText)), ["tax", "0", "0"]);
      await page.click(region + " nav button:first-of-type");
      await page.waitForSelector(region + ' a[aria-label="Review findings for inventory"]');
    }
    await page.click(region + ' a[aria-label="Review findings for inventory"]');
    await page.waitForFunction((scanId) => {
      const url = new globalThis.URL(globalThis.location.href);
      return url.pathname === "/findings" && url.searchParams.get("scanId") === scanId && url.searchParams.get("repositoryId") === "inventory";
    }, {}, scan.id);
  } finally {
    await db.scan.deleteMany({ where: { id: { in: [legacy.id, scan.id] } } });
    assert.equal(await db.scanRepositoryCoverage.count({ where: { scanId: scan.id } }), 0);
    await page.setViewport({ width: 1280, height: 1000 });
  }
}
