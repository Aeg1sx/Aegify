// Browser regression for Firefox restoring disabled controls before React hydrates.
// Uses the locked Puppeteer bundled with docs (npm ci --prefix docs --ignore-scripts).
// Run against a local development preview with authentication disabled:
// HYDRATION_BROWSER=firefox HYDRATION_BROWSER_PATH=/path/to/firefox node scripts/test_llm_scan_hydration.mjs
// HYDRATION_BROWSER=chrome HYDRATION_BROWSER_PATH=/path/to/chrome node scripts/test_llm_scan_hydration.mjs
// HYDRATION_BASE_URL defaults to http://127.0.0.1:3037. No external or mutation requests.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const require = createRequire(new URL("../docs/package.json", import.meta.url));
const { default: puppeteer } = await import(require.resolve("puppeteer"));
const browserName = process.env.HYDRATION_BROWSER || "firefox";
const base = new URL(process.env.HYDRATION_BASE_URL || "http://127.0.0.1:3037");
assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(base.hostname) && base.protocol === "http:");
assert.ok(["firefox", "chrome"].includes(browserName));
assert.ok(process.env.HYDRATION_BROWSER_PATH, "Set HYDRATION_BROWSER_PATH to an installed test browser");
const browser = await puppeteer.launch({
  browser: browserName,
  executablePath: process.env.HYDRATION_BROWSER_PATH,
  headless: true,
  userDataDir: await mkdtemp(join(tmpdir(), "aegify-hydration-")),
  args: browserName === "firefox" ? ["--no-remote"] : ["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run", "--no-default-browser-check"],
});
const scan = (id) => ({ id, repository: `Owned fixture / ${id}`, status: "completed", createdAt: "2026-01-01T00:00:00Z", _count: { findings: 1, graphNodes: 0 } });
const errors = [];
const blockedMutations = [];
let blockScripts = true;
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(15_000);
  page.on("pageerror", error => errors.push(error.message));
  page.on("console", message => {
    if (["warn", "error"].includes(message.type()) && /hydration|hydrated|server rendered|server-rendered|didn't match/i.test(message.text())) errors.push(message.text());
  });
  await page.setRequestInterception(true);
  page.on("request", request => {
    const handle = async () => {
      const url = new URL(request.url());
      if (request.method() !== "GET") {
        blockedMutations.push(url.pathname);
        return request.abort();
      }
      if (["data:", "blob:"].includes(url.protocol)) return request.continue();
      if (url.origin !== base.origin || blockScripts && url.pathname.endsWith(".js")) return request.abort();
      const respond = body => request.respond({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
      if (url.pathname === "/api/projects") return respond({ projects: ["a", "b"].map(id => ({ id, name: id, scanCount: 1 })) });
      if (url.pathname === "/api/llm-jobs") return respond({ jobs: [] });
      if (url.pathname === "/api/scans") {
        const project = url.searchParams.get("projectId") || "all";
        // A stale response must never enable B's selector or replace B's options.
        await delay(project === "a" ? 600 : project === "b" ? 150 : 20);
        if (request.failure()) return; // The component's AbortController canceled it.
        return respond({ scans: [scan(project), { ...scan("pending"), status: "running" }] });
      }
      return request.continue();
    };
    void handle().catch(error => {
      // Firefox discards intercepted requests immediately when fetch is aborted.
      if (request.failure() && /no such request/i.test(error.message)) return;
      errors.push(error.message);
    });
  });

  await page.goto(new URL("/llm-scan", base).href, { waitUntil: "load" });
  assert.equal(await page.$eval("#review-scan", el => el.disabled), true, "SSR must start disabled");
  blockScripts = false;
  for (let round = 0; round < 3; round++) {
    await page.reload({ waitUntil: "networkidle2" });
    await page.waitForFunction(() => document.querySelector("#review-scan")?.disabled === false);
    assert.equal(await page.$eval("#review-scan", el => el.value), "", "Reload resets the scan selection");
    assert.equal(await page.$eval('form button[type="submit"]', el => el.disabled), true);
    assert.equal(await page.$eval('form input[type="checkbox"]', el => el.checked), false, "Provider context remains opt-in after reload");
    assert.equal(await page.$eval("#review-scan", el => el.options.length), 2, "Incomplete scans stay excluded");
    await page.select("#review-scan", "all");
    await page.click('form input[type="checkbox"]');
    assert.equal(await page.$eval('form button[type="submit"]', el => el.disabled), false);
  }

  const requestA = page.waitForRequest(request => new URL(request.url()).searchParams.get("projectId") === "a");
  await page.select("#review-project", "a");
  await requestA;
  await page.select("#review-project", "b");
  assert.equal(await page.$eval("#review-scan", el => el.disabled), true);
  assert.equal(await page.$eval("#review-scan", el => el.options.length), 1, "Previous options disappear while loading");
  await page.waitForFunction(() => document.querySelector('#review-scan option[value="b"]'));
  await delay(700);
  assert.deepEqual(await page.$$eval("#review-scan option", options => options.map(option => option.value)), ["", "b"]);
  await page.select("#review-project", "b");
  assert.equal(await page.$eval("#review-scan", el => el.disabled), false, "Re-selecting the same project must not stick in loading");
  await page.goto(new URL("/api-specs", base).href, { waitUntil: "networkidle2" });
  await page.goBack({ waitUntil: "networkidle2" });
  await page.waitForSelector("#review-scan");

  assert.deepEqual(blockedMutations, [], "The test must not start any AI job or mutate data");
  assert.deepEqual(errors, [], "No hydration warnings or runtime errors");
  console.log(JSON.stringify({ browser: browserName, passed: true, checks: ["SSR", "three reloads", "disabled and checked state restoration", "stale request cancellation", "same project selection", "history navigation", "no AI jobs"] }));
} finally {
  await browser.close();
}
