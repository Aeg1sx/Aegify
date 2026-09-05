// Regression for reusing an uncontrolled file input as a controlled URL input.
// Uses the locked Puppeteer in docs; run against an auth-disabled local preview:
// HYDRATION_BROWSER=firefox HYDRATION_BROWSER_PATH=/path/to/firefox node scripts/test_api_spec_inputs.mjs
// HYDRATION_BROWSER=chrome HYDRATION_BROWSER_PATH=/path/to/chrome node scripts/test_api_spec_inputs.mjs
// HYDRATION_BASE_URL defaults to http://127.0.0.1:3037. All mutations/external requests are blocked.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const require = createRequire(new URL("../docs/package.json", import.meta.url));
const { default: puppeteer } = await import(require.resolve("puppeteer"));
const browserName = process.env.HYDRATION_BROWSER || "firefox";
const base = new URL(process.env.HYDRATION_BASE_URL || "http://127.0.0.1:3037");
assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(base.hostname) && base.protocol === "http:");
assert.ok(["firefox", "chrome"].includes(browserName));
assert.ok(process.env.HYDRATION_BROWSER_PATH, "Set HYDRATION_BROWSER_PATH");
const browser = await puppeteer.launch({
  browser: browserName, executablePath: process.env.HYDRATION_BROWSER_PATH, headless: true,
  userDataDir: await mkdtemp(join(tmpdir(), "aegify-spec-inputs-")),
  args: browserName === "firefox" ? ["--no-remote"] : ["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run", "--no-default-browser-check"],
});
const errors = [];
const mutations = [];
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(15_000);
  page.on("pageerror", error => errors.push(error.message));
  page.on("console", message => {
    if (["warn", "error"].includes(message.type()) && /uncontrolled|controlled input|hydration|hydrated/i.test(message.text())) errors.push(message.text());
  });
  await page.setRequestInterception(true);
  page.on("request", request => {
    const handle = async () => {
      const url = new URL(request.url());
      if (request.method() !== "GET") { mutations.push(url.pathname); return request.abort(); }
      if (["data:", "blob:"].includes(url.protocol)) return request.continue();
      if (url.origin !== base.origin) return request.abort();
      const respond = body => request.respond({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
      if (url.pathname === "/api/scans") return respond({ scans: [{ id: "owned-input-fixture", repository: "Owned UI fixture", branch: "main", createdAt: "2026-01-01T00:00:00Z" }] });
      if (url.pathname === "/api/endpoints/import-openapi") return respond({ repositoryIds: [""], specifications: [], total: 0 });
      if (url.pathname === "/api/llm-jobs") return respond({ jobs: [] });
      return request.continue();
    };
    void handle().catch(error => {
      if (request.failure() && /no such request/i.test(error.message)) return;
      errors.push(error.message);
    });
  });
  const source = '[aria-label="Specification source"] button';
  const previewDisabled = () => page.$$eval("fieldset button", buttons => buttons.find(button => button.textContent.trim() === "Preview contract").disabled);
  await page.goto(new URL("/api-specs", base).href, { waitUntil: "networkidle2" });
  await page.select("#spec-scan", "owned-input-fixture");
  await page.waitForSelector('#spec-repository option[value=""]');
  await page.select("#spec-repository", "");
  const exampleUrl = "https://docs.example.test/openapi.json";
  for (let round = 0; round < 3; round++) {
    assert.equal(await previewDisabled(), true, "An empty file input cannot preview a previous file");
    const fileInput = await page.$("#spec-file");
    await fileInput.evaluate(input => {
      const files = new DataTransfer();
      files.items.add(new File(['{"openapi":"3.1.1","info":{"title":"Owned fixture","version":"1"},"paths":{}}'], "owned-fixture.json", { type: "application/json" }));
      input.files = files.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
    assert.equal(await previewDisabled(), false);
    await page.click(source + ':first-child');
    assert.equal(await page.$eval("#spec-file", input => input.files.length), 1, "Clicking the active source preserves its file");
    await page.click(source + ':last-child');
    await page.waitForSelector("#spec-url");
    assert.equal(await fileInput.evaluate(input => input.isConnected), false, "File and URL inputs must have separate lifetimes");
    await fileInput.dispose();
    assert.equal(await page.$eval("#spec-url", input => input.value), round === 0 ? "" : exampleUrl);
    if (round === 0) {
      await page.type("#spec-url", exampleUrl);
      assert.equal(await previewDisabled(), true, "Retrieval needs explicit authorization");
      await page.click('fieldset input[type="checkbox"]');
    }
    assert.equal(await previewDisabled(), false);
    const urlInput = await page.$("#spec-url");
    await page.click(source + ':first-child');
    await page.waitForSelector("#spec-file");
    assert.equal(await urlInput.evaluate(input => input.isConnected), false);
    await urlInput.dispose();
    assert.equal(await page.$eval("#spec-file", input => input.files.length), 0);
    assert.equal(await previewDisabled(), true, "The unmounted file must also be cleared from React state");
  }
  assert.deepEqual(mutations, [], "Source switching must not fetch a URL or upload a file");
  assert.deepEqual(errors, [], "No controlled/uncontrolled, hydration, or runtime errors");
  console.log(JSON.stringify({ browser: browserName, passed: true, checks: ["file selection", "three file/URL round trips", "distinct input lifetimes", "URL draft preserved", "no stale file", "authorization required", "no network mutations"] }));
} finally {
  if (errors.length) console.error(JSON.stringify({ browser: browserName, errors }));
  await browser.close();
}
