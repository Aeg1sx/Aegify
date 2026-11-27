// Owned production fixture only. Requires the locked docs dependencies and a local
// Puppeteer browser: npm ci --ignore-scripts in docs; provision the browser separately.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { URL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import process from "node:process";
import { log } from "node:console";
import { checkAgentHandoff } from "./agent-handoff-browser-check.mjs";
import { runAccessIntegration } from "./test-project-access.mjs";
import { runLlmWorkerOnce } from "../src/lib/llm-worker.ts";
import { makeSourceSnapshot, runPythonSnapshot } from "../src/lib/scan-worker.ts";
const requireDocs = createRequire(new URL("../../docs/package.json", import.meta.url));
const { default: puppeteer } = await import(requireDocs.resolve("puppeteer"));
const browser = await puppeteer.launch({ executablePath: process.env.AEGIFY_TEST_BROWSER || await puppeteer.executablePath(), headless: true });
let checks = 0;
const errors = [];
async function elementWithText(page, selector, text) {
  // Responsive navigation can mount on the frame after a viewport change.
  const handle = await page.waitForFunction((selector, text) =>
    Array.from(globalThis.document.querySelectorAll(selector)).find((node) =>
      node.checkVisibility() && node.textContent?.includes(text)), { timeout: 15_000 }, selector, text);
  return handle.asElement();
}
async function waitText(page, text) { await page.waitForFunction((value) => globalThis.document.body.innerText.includes(value), { timeout: 15_000 }, text); checks++; }

function printedPages(file) {
  return execFileSync("pdftotext", ["-layout", file, "-"], { encoding: "utf8" }).split("\f").filter((page) => page.trim());
}

async function checkHistoricalReport(page, db, projectId, origin, downloadDirectory) {
  const filePath = "reports/archive.py";
  const metadata = { projectId, repository: "ledger/export-service", branch: "main", status: "completed" };
  const earlier = await db.scan.create({ data: { ...metadata, commitSha: "6c4a27e".padEnd(40, "7"), createdAt: new Date("2026-11-15T10:16:00Z") } });
  const later = await db.scan.create({ data: { ...metadata, commitSha: "30cd18e".padEnd(40, "4"), createdAt: new Date("2026-11-18T11:04:00Z") } });
  const ruleId = "AEG-PATH-003";
  const identity = await db.findingIdentity.create({ data: { projectId, ruleId, filePath, fingerprint: "owned-report-directory",
    lastSeenScanId: later.id, firstSeenAt: earlier.createdAt, lastSeenAt: later.createdAt, occurrenceCount: 2 } });
  const evidence = {
    ruleId, filePath, identityId: identity.id, ruleName: "Directory check uses a character prefix",
    severity: "medium", evidenceState: "candidate", disposition: "advisory", lineStart: 43, lineEnd: 43,
    message: "The archive helper compares the shared text prefix with the export directory before selecting files.",
    codeSnippet: ["def accepts_export(directory, filename):", "    root = os.path.abspath(directory)", "    target = os.path.join(root, filename)", "    return os.path.commonprefix([root, target]) == root"].join("\n"),
    provenance: JSON.stringify({ snippet_start_line: 40 }), remediation: "Resolve the root and the candidate according to the export service’s symlink policy. Compare path components using os.path.commonpath.",
    repositoryId: "ledger/export-service", evidenceId: "archive-directory-selection",
  };
  const old = await db.finding.create({ data: { ...evidence, scanId: earlier.id, isCurrent: false, owner: "Intake" } });
  const current = await db.finding.create({ data: { ...evidence, scanId: later.id, isCurrent: true, baselineState: "unchanged" } });
  const recordPath = "/api/findings/" + old.id + "/report";
  const decide = (status, reason) => page.evaluate(async ({ id, status, reason }) => {
    const path = "/api/findings/" + id;
    const detail = await (await globalThis.fetch(path)).json();
    const response = await globalThis.fetch(path, { method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expectedVersion: detail.workflow.version, owner: "Reporting", status, reason }) });
    return response.status;
  }, { id: current.id, status, reason });
  const reason = "Only the nightly export calls this helper. Reporting reviewed its inputs and scheduled the directory check for replacement.";
  assert.equal(await decide("accepted_risk", reason), 200); checks++;
  await page.goto(origin + "/findings/" + old.id + "/report", { waitUntil: "networkidle0" });
  await waitText(page, reason);
  const fields = (heading) => page.$$eval('section[aria-labelledby="' + heading + '"] dl > div', (entries) =>
    Object.fromEntries(entries.map((entry) => [entry.querySelector("dt").innerText, entry.querySelector("dd").innerText])));
  const decision = await fields("decision-heading");
  const observation = await fields("observation-heading");
  assert.equal(decision["Current status"], "Accepted risk"); assert.equal(decision["Current owner"], "Reporting"); checks++;
  assert.ok(decision["Recorded by"] && decision["Decision recorded"]); checks++;
  assert.equal(observation["Stored status"], "Open"); assert.equal(observation["Stored owner"], "Intake"); checks++;
  assert.equal(observation.Producer, "SAST"); assert.equal(observation.Commit, earlier.commitSha); checks++;
  assert.match(await page.$eval(".report-coverage", (node) => node.innerText), /Coverage inventory unavailable/); checks++;
  assert.equal(await page.$eval(".report-coverage a", (node) => node.getAttribute("href")), "/scans/" + earlier.id); checks++;
  await waitText(page, "Earlier scan observation");
  await waitText(page, old.id);
  const syntax = ".finding-report .code-frame .code-token";
  await page.waitForSelector(syntax);
  await checkRenderedContrast(page, syntax);
  const sourceColor = () => page.$eval(syntax, (node) => globalThis.getComputedStyle(node).color);
  const lightSyntax = await sourceColor();
  const artifactDirectory = process.env.AEGIFY_UI_ARTIFACTS;
  const verifyPDF = artifactDirectory && process.env.AEGIFY_TEST_REPORT_PDF === "1";
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width >= 820 ? 1000 : 844 });
    assert.ok(await page.$eval("#workspace", (node) => node.scrollWidth <= node.clientWidth)); checks++;
    assert.ok(await page.$eval(".finding-report", (node) => node.scrollWidth <= node.clientWidth)); checks++;
    const sections = await page.$$eval(".report-records > section", (items) => items.map((node) => {
      const { x, y } = node.getBoundingClientRect(); return { x, y };
    }));
    assert.ok(width === 1440 ? sections[0].y === sections[1].y : sections[0].y < sections[1].y); checks++;
    if (artifactDirectory && (width === 1440 || width === 390)) {
      await page.screenshot({ path: join(artifactDirectory, width === 1440 ? "decision-report-desktop.png" : "decision-report-mobile.png") });
    }
  }
  await page.setViewport({ width: 1280, height: 1000 });
  await page.focus(".report-location");
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => globalThis.location.hash === "#evidence-heading"); checks++;
  await page.evaluate(() => globalThis.document.getElementById("workspace").scrollTo(0, 0));
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  const badge = ".finding-report [data-slot=badge]";
  await checkRenderedContrast(page, syntax);
  assert.notEqual(await sourceColor(), lightSyntax); checks++;
  await page.$eval(badge, (node) => Promise.all(node.getAnimations().map((animation) => animation.finished)).then(() => undefined));
  await checkRenderedContrast(page);
  const screenColor = await page.$eval(badge, (node) => globalThis.getComputedStyle(node).color);
  if (artifactDirectory) await page.screenshot({ path: join(artifactDirectory, "decision-report-dark.png") });
  await page.emulateMediaType("print");
  assert.notEqual(await page.$eval(badge, (node) => globalThis.getComputedStyle(node).color), screenColor); checks++;
  assert.equal(await page.$eval('nav[aria-label="Report actions"]', (node) => node.checkVisibility()), false); checks++;
  assert.equal(await page.$eval('button[aria-label="Copy code"]', (node) => node.checkVisibility()), false); checks++;
  if (verifyPDF) {
    const path = join(artifactDirectory, "decision-report.pdf");
    await page.pdf({ path, format: "A4", printBackground: true, preferCSSPageSize: true });
    const pages = printedPages(path);
    assert.equal(pages.length, 1); checks++;
    assert.ok(pages[0].includes("Accepted risk") && pages[0].includes("archive-directory-selection") && !pages[0].includes("Download Markdown")); checks++;
    const corner = execFileSync("pdftoppm", ["-f", "1", "-l", "1", "-singlefile", "-scale-to", "100", "-x", "0", "-y", "0", "-W", "1", "-H", "1", path]);
    assert.ok(corner.toString("ascii", 0, 2) === "P6" && corner.subarray(-3).every((channel) => channel >= 250), "Printed paper stays white from the dark theme"); checks++;
  }
  await page.emulateMediaType(null);
  await (await elementWithText(page, "button", "Light mode")).click();
  const version = await page.evaluate(async (path) => {
    const record = await globalThis.fetch(path + "?format=json");
    const etag = record.headers.get("X-Aegify-Markdown-ETag");
    const markdown = await globalThis.fetch(path, { headers: { "If-Match": etag } });
    return { etag, exportedTag: markdown.headers.get("ETag"), status: markdown.status, text: await markdown.text() };
  }, recordPath);
  assert.equal(version.status, 200); assert.equal(version.etag, version.exportedTag); checks++;
  assert.equal(version.etag, '"' + createHash("sha256").update(version.text).digest("hex") + '"'); checks++;
  assert.ok(version.text.includes(reason) && version.text.includes("Stored observation owner: Intake")); checks++;
  const revision = "Reporting assigned the directory change to the next export release.";
  assert.equal(await decide("in_progress", revision), 200); checks++;
  const download = () => elementWithText(page, "button", "Download Markdown").then((button) => button.click());
  const responseForDownload = () => page.waitForResponse((response) => response.url() === origin + recordPath && Boolean(response.request().headers()["if-match"]));
  const [stale] = await Promise.all([responseForDownload(), download()]);
  assert.equal(stale.status(), 412); checks++;
  await waitText(page, "This report changed.");
  await (await elementWithText(page, "button", "Reload report")).click();
  await waitText(page, revision);
  assert.equal((await fields("decision-heading"))["Current status"], "In progress"); checks++;
  await page.browserContext().setDownloadBehavior({ policy: "allow", downloadPath: downloadDirectory });
  const [fresh] = await Promise.all([responseForDownload(), download()]);
  assert.equal(fresh.status(), 200); checks++;
  let saved;
  for (let i = 0; !saved && i < 50; i++) {
    try { saved = await readFile(join(downloadDirectory, "aegify-finding-report.md"), "utf8"); }
    catch (error) { if (error.code !== "ENOENT") throw error; await delay(100); }
  }
  assert.ok(saved?.includes(revision) && !saved.includes(reason)); checks++;
  assert.equal('"' + createHash("sha256").update(saved).digest("hex") + '"', fresh.headers().etag); checks++;
  if (verifyPDF) {
    const columns = Array.from({ length: 64 }, (_, index) => '    "export_column_' + (index + 1) + '",');
    const longLine = '# ' + "column_description_".repeat(13) + "end_of_column_description";
    await db.finding.update({ where: { id: old.id }, data: { codeSnippet: [evidence.codeSnippet, longLine, "EXPORT_COLUMNS = (",
      ...columns, '    "archive_manifest_version",', ")"].join("\n") } });
    await page.reload({ waitUntil: "networkidle0" });
    await waitText(page, "archive_manifest_version");
    await page.emulateMediaType("print");
    const path = join(artifactDirectory, "decision-report-long.pdf");
    await page.pdf({ path, format: "A4", printBackground: true, preferCSSPageSize: true });
    await page.emulateMediaType(null);
    const pages = printedPages(path);
    const continuous = pages.join("").replace(/\s/g, "");
    assert.ok(pages.length > 1 && pages[0].includes("In progress")); checks++;
    assert.ok(continuous.includes("end_of_column_description") && pages.some((page) => page.includes("archive_manifest_version"))); checks++;
    assert.ok(pages.at(-1).includes("archive-directory-selection") && !continuous.includes("DownloadMarkdown")); checks++;
  }
  await page.goto(origin + "/findings/" + current.id, { waitUntil: "networkidle0" });
  const trail = 'ol[aria-label="Triage events"]';
  await page.waitForSelector(trail + " li");
  const history = await fields("finding-history-heading");
  assert.deepEqual([history["Baseline change"], history.Occurrences], ["Unchanged", "2"]); checks++;
  assert.deepEqual(await page.$$eval(".finding-facts time", (times) => times.map((item) => item.dateTime)),
    [earlier.createdAt.toISOString(), later.createdAt.toISOString()]); checks++;
  const events = await page.$$eval(trail + " li", (items) => items.map((item) => item.textContent));
  assert.ok(events[0].includes(revision) && events[1].includes(reason)); checks++;
  for (const width of [1440, 390, 320]) {
    await page.setViewport({ width, height: width === 1440 ? 960 : 844 });
    await page.$eval(".finding-reference", async (section) => {
      const area = globalThis.document.getElementById("workspace");
      globalThis.scrollTo(0, 0);
      area.scrollBy(0, section.getBoundingClientRect().top - area.getBoundingClientRect().top - 12);
      await new Promise((resolve) => globalThis.requestAnimationFrame(() => globalThis.requestAnimationFrame(resolve)));
    });
    const layout = await page.$eval(".finding-reference", (section) => {
      const [a, b] = Array.from(section.children, (child) => child.getBoundingClientRect());
      return { paired: b.left >= a.right && Math.abs(a.top - b.top) < 1, stacked: b.top >= a.bottom,
        fits: section.scrollWidth <= section.clientWidth };
    });
    assert.ok(layout.fits && (width === 1440 ? layout.paired : layout.stacked)); checks++;
    if (artifactDirectory && width !== 320) await page.screenshot({ path: join(artifactDirectory, width === 1440 ? "finding-details-desktop.png" : "finding-details-mobile.png") });
  }
  await page.setViewport({ width: 1440, height: 960 });
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page, ".finding-reference h2, .finding-facts dt, .finding-facts dd, .finding-reference time");
  await (await elementWithText(page, "button", "Light mode")).click();
}

async function checkFindingReview(page, viewer, db, origin) {
  const { id: projectId } = await db.project.create({ data: { name: "Notifications", ownerSlug: "ledger/notifications",
    members: { create: { userId: "bob", role: "viewer" } } } });
  const file = "services/notifications/mail.py";
  const processFile = "services/notifications/preview.py";
  const preview = [
    "import subprocess", "from flask import request", "", "def preview_receipt():",
    "    title = request.args.get('title', '')", "    args = []",
    "    if request.method == 'GET':", "        args.append('/bin/sh')", "        args.append('-c')",
    "    else:", "        args.extend(['/bin/bash', '-lc'])", "    args.append(title)", "    return subprocess.run(args)",
  ].join("\n");
  const content = [
    "import smtplib", "import ssl", "",
    "def open_mail_session(host, port):",
    "    client = smtplib.SMTP(host, port, timeout=10)",
    "    client.starttls()", "    return client", "",
    "def verified_session(host, port):",
    "    client = smtplib.SMTP(host, port, timeout=10)",
    "    client.starttls(context=ssl.create_default_context())", "    return client",
  ].join("\n");
  const commit = "d".repeat(40);
  const snapshot = makeSourceSnapshot({ provider: "github", ownerSlug: "ledger/notifications", commitSha: commit },
    { ref: commit, truncated: false, files: [{ path: file, content }, { path: processFile, content: preview }] });
  const { report } = await runPythonSnapshot(snapshot, new globalThis.AbortController().signal, async () => {});
  const uploaded = await page.evaluate(async ({ projectId, report }) => {
    const response = await globalThis.fetch("/api/upload?projectId=" + encodeURIComponent(projectId) + "&repository=ledger%2Fnotifications", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(report),
    });
    return { status: response.status, receipt: await response.json() };
  }, { projectId, report });
  assert.equal(uploaded.status, 200, JSON.stringify(uploaded.receipt)); checks++;
  const findings = await db.finding.findMany({ where: { scanId: uploaded.receipt.scanId, ruleId: "AEG-A02-005" } });
  assert.deepEqual(findings.map((finding) => [finding.filePath, finding.lineStart, finding.disposition]), [[file, 6, "advisory"]]); checks++;
  await page.goto(origin + "/findings/" + findings[0].id, { waitUntil: "networkidle0" });
  await waitText(page, "Triage decision");
  await page.waitForSelector('[data-source-line="6"][data-highlighted="true"]');
  const reader = '[aria-label="Finding evidence inspector"]';
  assert.deepEqual(await page.$$eval(reader + ' [role="tab"]', (tabs) => tabs.map((tab) => tab.textContent)), ["source", "remediation"]); checks++;
  const artifactDirectory = process.env.AEGIFY_UI_ARTIFACTS;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width > 820 ? 960 : 844 });
    const shape = await page.evaluate(() => {
      const element = (selector) => globalThis.document.querySelector(selector);
      const box = (selector) => element(selector).getBoundingClientRect();
      const evidence = box(".evidence-reader"), decision = box(".finding-decision");
      return {
        sideBySide: decision.left >= evidence.right && Math.abs(evidence.top - decision.top) < 1,
        stacked: decision.top >= evidence.bottom,
        fits: element("#workspace").scrollWidth <= element("#workspace").clientWidth,
        controls: Array.from(element(".assignment-fields").querySelectorAll("input, select")).every((input) =>
          input.labels.length > 0 && input.labels[0].innerText.trim() && input.getBoundingClientRect().height >= 44),
      };
    });
    assert.ok(width === 1440 ? shape.sideBySide : shape.stacked, "Source and triage layout at " + width); checks++;
    assert.ok(shape.fits && shape.controls, "Labels, touch controls and viewport at " + width); checks++;
    if (artifactDirectory && (width === 1440 || width === 390)) {
      await page.screenshot({ path: join(artifactDirectory, width === 1440 ? "finding-review-desktop.png" : "finding-review-mobile.png") });
    }
  }
  await page.focus('a[href="#triage-heading"]');
  await page.keyboard.press("Enter");
  await page.waitForFunction(() => globalThis.document.activeElement?.id === "triage-heading"); checks++;
  await page.$eval("#triage-heading", (element) => {
    const top = element.getBoundingClientRect().top;
    if (top < 0 || top > globalThis.innerHeight) throw new Error("Triage heading outside mobile viewport");
  }); checks++;
  await page.setViewport({ width: 1440, height: 960 });
  await page.$eval("#workspace", (element) => element.scrollTo(0, 0));
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page, '#workspace .finding-record-tools a, .evidence-tabs button, .finding-decision label, .assignment-fields label, #workspace [data-slot="badge"], nav a[aria-current="page"]');
  if (artifactDirectory) await page.screenshot({ path: join(artifactDirectory, "finding-review-dark.png") });
  await (await elementWithText(page, "button", "Light mode")).click();
  await page.focus(reader + ' [role="tab"][aria-selected="true"]');
  await page.keyboard.press("End");
  await waitText(page, "Pass context=ssl.create_default_context()");
  await page.keyboard.press("Home");
  await page.waitForSelector('[data-source-line="6"][data-highlighted="true"]'); checks++;
  await page.type('[aria-label="Finding owner"]', "Notifications");
  await page.select('[aria-label="Remediation priority"]', "p1");
  await page.type('[aria-label="Finding tags"]', "mail, tls");
  await page.keyboard.press("Enter");
  await waitText(page, "Assignment saved.");
  await page.reload({ waitUntil: "networkidle0" });
  await page.waitForSelector('[aria-label="Finding owner"]');
  assert.equal(await page.$eval('[aria-label="Finding owner"]', (node) => node.value), "Notifications"); checks++;
  assert.equal(await page.$eval('[aria-label="Remediation priority"]', (node) => node.value), "p1"); checks++;
  assert.equal(await page.$eval('[aria-label="Finding tags"]', (node) => node.value), "mail, tls"); checks++;
  const reason = "The notification service uses its relay on every delivery.";
  await page.type('[aria-label="Triage rationale"]', reason);
  await page.select('[aria-label="Triage status"]', "in_progress");
  await (await elementWithText(page, "button", "Save decision")).click();
  await waitText(page, "Decision saved.");
  const concurrentStatus = await page.evaluate(async (id) => {
    const path = "/api/findings/" + id;
    const { workflow } = await (await globalThis.fetch(path)).json();
    const response = await globalThis.fetch(path, { method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ owner: "Mail operations", expectedVersion: workflow.version }) });
    return response.status;
  }, findings[0].id);
  assert.equal(concurrentStatus, 200); checks++;
  await page.type('[aria-label="Finding tags"]', ", queue");
  await (await elementWithText(page, "button", "Save assignment")).click();
  await page.waitForSelector('.finding-assignment [role="alert"]');
  assert.equal(await page.$('.finding-decision [role="alert"]'), null); checks++;
  assert.match(await page.$eval('[aria-label="Finding tags"]', (node) => node.value), /queue/); checks++;
  await (await elementWithText(page, ".finding-assignment button", "Reload latest")).click();
  await page.waitForFunction(() => globalThis.document.querySelector('[aria-label="Finding owner"]').value === "Mail operations"); checks++;
  assert.equal(await page.$eval('[aria-label="Finding tags"]', (node) => node.value), "mail, tls"); checks++;
  await viewer.goto(origin + "/findings/" + findings[0].id, { waitUntil: "networkidle0" });
  await waitText(viewer, reason);
  await waitText(viewer, "Read-only access");
  assert.equal(await viewer.$(".finding-review form, .finding-assignment form, .finding-assignment button"), null); checks++;
  const saved = await viewer.$$eval(".finding-assignment dl > div", (rows) =>
    Object.fromEntries(rows.map((row) => [row.querySelector("dt").textContent, row.querySelector("dd").textContent])));
  assert.deepEqual(saved, { "Owner or team": "Mail operations", Priority: "P1", "Due date": "No due date", Tags: "mail, tls" }); checks++;
  assert.match(await viewer.$eval(".finding-decision", (node) => node.innerText), /In progress/i); checks++;

  const command = await db.finding.findFirstOrThrow({ where: { scanId: uploaded.receipt.scanId, ruleId: "AEG-CMD-001", filePath: processFile } });
  assert.equal(command.lineStart, 13); checks++;
  assert.deepEqual(JSON.parse(command.taintFlow).map((step) => [step.line, step.message.split(": ")[0]]),
    [[5, "source"], [5, "assignment"], [12, "command-argument"], [13, "sink"]]); checks++;
  await page.setViewport({ width: 1440, height: 1000 });
  await page.goto(origin + "/findings/" + command.id, { waitUntil: "networkidle0" });
  const flowTab = await elementWithText(page, reader + ' [role="tab"]', "flow");
  await flowTab.click();
  const steps = '[aria-label="Recorded flow steps"]';
  await page.waitForSelector(steps + " li");
  assert.deepEqual(await page.$$eval(steps + " strong", (labels) => labels.map((item) => item.textContent)),
    ["Source", "Assignment", "Shell command argument", "Sink"]); checks++;
  assert.deepEqual(await page.$$eval(steps + " button", (items) => items.map((item) => item.textContent)),
    ["L12", "L13"]); checks++;
  assert.equal(await page.$$eval(steps + ' [title="Source excerpt unavailable"]', (items) => items.length), 2); checks++;
  assert.deepEqual(await page.$$eval(steps + " .flow-file", (headers) => headers.map((item) => item.textContent)), ["preview.pyservices/notifications/"]); checks++;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width >= 820 ? 1000 : 844 });
    await page.$eval(reader, (node) => node.scrollIntoView({ block: "start" }));
    assert.ok(await page.$eval(steps, (list) => list.scrollWidth <= list.clientWidth && globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
    await checkRenderedContrast(page, steps + " strong, " + steps + " code, " + steps + " button");
    if (artifactDirectory && [1440, 390].includes(width)) {
      await page.screenshot({ path: join(artifactDirectory, width === 1440 ? "process-flow-desktop.png" : "process-flow-mobile.png") });
    }
  }
  const sourceLink = await page.$(steps + ' button[aria-label="Show source line 12 in ' + processFile + '"]');
  await sourceLink.focus();
  await page.keyboard.press("Enter");
  await page.waitForSelector('[data-source-line="12"] button[aria-current="location"]');
  assert.match(await page.$eval('[data-source-line="12"]', (node) => node.innerText), /args\.append\(title\)/); checks++;
  assert.equal(await page.evaluate(() => globalThis.document.activeElement?.textContent), "source"); checks++;

  const calls = '[aria-controls="nearby-calls"]';
  const graphPath = "/api/findings/" + command.id + "/graph";
  await page.evaluate((path) => {
    const real = globalThis.fetch;
    const replies = [new globalThis.Response('{"nodes":[],"edges":[]}', { status: 503 }), new globalThis.Response('{}')];
    globalThis.fetch = (url, options) => {
      if (String(url) !== path) return real(url, options);
      const reply = replies.shift();
      if (!replies.length) globalThis.fetch = real;
      return Promise.resolve(reply);
    };
  }, graphPath);
  for (let attempt = 0; attempt < 2; attempt++) {
    await page.focus(calls); await page.keyboard.press("Enter");
    await waitText(page, "Nearby calls could not be loaded.");
    assert.equal(await page.$eval(calls, (item) => item.textContent), "Retry calls"); checks++;
    assert.equal(await page.$eval("#nearby-calls", (area) => area.hidden), true); checks++;
    assert.ok(await page.$eval(calls, (item) => item === globalThis.document.activeElement), "Failed call graph loads keep retry in keyboard focus"); checks++;
  }
  const reply = page.waitForResponse((res) => res.url() === origin + graphPath && res.status() === 200);
  await page.keyboard.press("Enter");
  const graph = await (await reply).json();
  await page.waitForSelector(calls + '[aria-expanded="true"]');
  if (graph.nodes.length) await page.waitForSelector("#nearby-calls canvas");
  else await waitText(page, "No call graph nodes recorded for this file.");
  assert.equal(await page.$('[aria-labelledby="nearby-calls-heading"] [role="alert"]'), null); checks++;
  await page.focus(calls); await page.keyboard.press("Enter");
  await page.waitForSelector(calls + '[aria-expanded="false"]');
  assert.equal(await page.$eval(calls, (item) => item === globalThis.document.activeElement), true); checks++;
  const metadata = await page.$$eval('[aria-labelledby="scan-details-heading"] dl > div', (rows) =>
    Object.fromEntries(rows.map((row) => [row.querySelector("dt").textContent, row.querySelector("dd").textContent])));
  assert.deepEqual([metadata.Scan, metadata.Rule, metadata.CWE], ["ledger/notifications", command.ruleId, "CWE-78"]); checks++;
  for (const width of [1440, 390, 320]) {
    await page.setViewport({ width, height: width === 1440 ? 960 : 844 });
    const anchor = width === 1440 ? ".finding-support" : ".finding-reference";
    await page.$eval(anchor, (element) => element.scrollIntoView({ block: "start" }));
    assert.ok(await page.$eval(".finding-support", (area) => [area, ...area.querySelectorAll("dl, dd")].every((item) => item.scrollWidth <= item.clientWidth + 1))); checks++;
    if (width === 1440) await checkRenderedContrast(page, ".finding-support h2, .finding-facts dt, .finding-facts dd, .finding-action");
  }
  await checkImportedFlow(page, db, projectId, origin, artifactDirectory);
}

async function checkImportedFlow(page, db, projectId, origin, artifactDirectory) {
  const entry = "services/accounts/profile.py", helper = "services/text/labels.py";
  const physical = (uri, startLine, text) => ({
    artifactLocation: { uri }, region: { startLine, ...(text === undefined ? {} : { snippet: { text } }) },
  });
  const step = (physicalLocation, text) => ({ location: { physicalLocation, message: { text } } });
  const statement = "    for char in display_name:";
  const call = physical(entry, 22, '    session["display_name"] = label');
  const locations = [
    step(physical(entry, 18), "source: request.form"),
    step(physical(helper, 4, "def compact(display_name: str):"), "argument: display_name"),
    step({ ...physical(helper, 6), contextRegion: { startLine: 5, endLine: 7,
      snippet: { text: ['    label = ""', statement, "        label += char"].join("\n") } } }, "iteration: char"),
    step(call, "sink: flask.session"),
  ];
  const report = { version: "2.1.0", runs: [{ tool: { driver: { name: "Owned SARIF fixture",
    rules: [{ id: "PROFILE-LABEL", name: "Profile label enters the session" }] } },
    properties: { analysisStatus: "partial", analysisScope: "files", analyzedFiles: [entry, helper], evaluatedRules: ["PROFILE-LABEL"],
      analysisGaps: [{ code: "source_unreadable", stage: "parser", message: "internal-fixture-diagnostic", affected_count: 1 }] },
    invocations: [{ executionSuccessful: true }],
    results: [{ ruleId: "PROFILE-LABEL", level: "warning", message: { text: "The profile form supplies the session label." },
      locations: [{ physicalLocation: call }], codeFlows: [{ threadFlows: [{ locations }] }] }] }] };
  const receipt = await page.evaluate(async ({ projectId, report }) => {
    const response = await globalThis.fetch("/api/upload?projectId=" + projectId, { method: "POST",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(report) });
    if (!response.ok) throw new Error("Flow import returned " + response.status);
    return response.json();
  }, { projectId, report });
  const finding = await db.finding.findFirstOrThrow({ where: { scanId: receipt.scanId, ruleId: "PROFILE-LABEL" } });
  assert.deepEqual(JSON.parse(finding.taintFlow).map((row) => row.snippet), [undefined, "def compact(display_name: str):", statement, call.region.snippet.text]); checks++;
  await page.goto(origin + "/findings/" + finding.id, { waitUntil: "networkidle0" });
  await (await elementWithText(page, '#finding-evidence [role="tab"]', "flow")).click();
  const steps = '[aria-label="Recorded flow steps"]';
  assert.deepEqual(await page.$$eval(steps + " .flow-file .font-medium", (items) => items.map((item) => item.textContent)), ["profile.py", "labels.py", "profile.py"]); checks++;
  const toggle = await elementWithText(page, steps + " summary", "Loop element");
  await toggle.focus(); await page.keyboard.press("Enter");
  await page.waitForSelector(steps + " details[open] pre");
  assert.equal(await page.$eval(steps + " details[open] pre", (node) => node.textContent), statement); checks++;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width >= 820 ? 960 : 844 });
    await page.$eval("#finding-evidence", (node) => node.scrollIntoView({ block: "start" }));
    assert.ok(await page.$eval(steps, (node) => node.scrollWidth <= node.clientWidth && globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
    assert.ok(await page.$eval(steps + " summary", (node) => node.getBoundingClientRect().height >= 44)); checks++;
    await checkRenderedContrast(page, steps + " .flow-directory, " + steps + " .flow-line, " + steps + " .flow-description code");
    if (artifactDirectory && [1440, 390].includes(width)) await page.screenshot({ path: join(artifactDirectory, width === 1440 ? "flow-excerpt-desktop.png" : "flow-excerpt-mobile.png") });
  }
  await page.setViewport({ width: 1440, height: 960 });
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page, steps + " .flow-directory, " + steps + " .flow-line, " + steps + " .flow-excerpt code");
  await page.$eval("#finding-evidence", (node) => node.scrollIntoView({ block: "start" }));
  if (artifactDirectory) await page.screenshot({ path: join(artifactDirectory, "flow-excerpt-dark.png") });
  await (await elementWithText(page, "button", "Light mode")).click();
  await toggle.focus(); await page.keyboard.press("Space");
  await page.waitForFunction(() => !globalThis.document.querySelector(".flow-disclosure[open]")); checks++;
  await page.goto(origin + "/findings/" + finding.id + "/report", { waitUntil: "networkidle0" });
  await waitText(page, "Selected files · 2 files analyzed · 1 rule evaluated · 1 recorded gap");
  assert.equal(await page.$eval(".report-coverage strong", (node) => node.innerText), "Partial"); checks++;
  assert.deepEqual(await page.$$eval(".report-trace-file", (nodes) => nodes.map((node) => node.textContent)), [entry, helper, entry]); checks++;
  assert.deepEqual(await page.$$eval(".report-trace-row pre", (nodes) => nodes.map((node) => node.textContent)),
    ["def compact(display_name: str):", statement, call.region.snippet.text]); checks++;
  const exported = await page.evaluate(async (id) => {
    const url = "/api/findings/" + id + "/report";
    const record = await (await globalThis.fetch(url + "?format=json")).json();
    return { record, markdown: await (await globalThis.fetch(url)).text() };
  }, finding.id);
  assert.deepEqual(exported.record.scan.coverage, { scope: "files", files: 2, rules: 1, gaps: 1 }); checks++;
  assert.ok(exported.markdown.includes(statement) && !JSON.stringify(exported).includes("internal-fixture-diagnostic")); checks++;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width >= 820 ? 960 : 844 });
    assert.ok(await page.$$eval(".report-trace, .report-coverage", (nodes) => nodes.every((node) => node.scrollWidth <= node.clientWidth)
      && globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
    if (width === 1440 && artifactDirectory) {
      await page.$eval("#workspace", (node) => node.scrollTo(0, 0));
      await page.screenshot({ path: join(artifactDirectory, "report-coverage-desktop.png") });
    }
    await page.$eval("#report-flow-heading", (node) => node.scrollIntoView({ block: "start" }));
    if (artifactDirectory && (width === 1440 || width === 390)) await page.screenshot({ path: join(artifactDirectory, width === 1440 ? "report-flow-desktop.png" : "report-flow-mobile.png") });
  }
  await page.setViewport({ width: 1440, height: 960 });
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page, ".report-coverage h2, .report-coverage p span, .report-trace-file, .report-trace-line, .report-trace-row code");
  if (artifactDirectory) await page.screenshot({ path: join(artifactDirectory, "report-flow-dark.png") });
  if (artifactDirectory && process.env.AEGIFY_TEST_REPORT_PDF === "1") {
    const path = join(artifactDirectory, "report-flow.pdf");
    await page.pdf({ path, format: "A4", printBackground: true, preferCSSPageSize: true });
    const text = printedPages(path).join(" ");
    assert.ok(text.includes("1 recorded gap") && text.includes(statement.trim()) && text.includes(helper)); checks++;
  }
  await (await elementWithText(page, "button", "Light mode")).click();
}

async function checkWorkspaceSettings(page, db, origin) {
  await page.setViewport({ width: 1440, height: 960 });
  await page.goto(origin + "/settings", { waitUntil: "networkidle0" });
  const tabs = '[role="tablist"][aria-label="Settings sections"]';
  const model = '[id="llm.model"]';
  await page.waitForSelector(model);
  const initialModel = await page.$eval(model, (node) => node.value);
  assert.ok(initialModel); checks++;
  const savedText = () => page.$eval(".settings-saved dl", (node) => node.innerText);
  assert.ok((await savedText()).includes(initialModel)); checks++;
  assert.deepEqual(await page.$$eval(tabs + " button", (items) => items.map((item) => item.textContent)), ["AI review", "Slack", "Jira", "Security"]); checks++;
  const testRequests = [];
  const watchTests = (request) => { if (request.url().startsWith(origin + "/api/settings/test-")) testRequests.push(request.url()); };
  page.on("request", watchTests);
  const directory = process.env.AEGIFY_UI_ARTIFACTS;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width >= 820 ? 960 : 844 });
    const geometry = await page.evaluate(() => {
      const form = globalThis.document.querySelector('[aria-labelledby="settings-form-heading"]').getBoundingClientRect();
      const saved = globalThis.document.querySelector(".settings-saved").getBoundingClientRect();
      const main = globalThis.document.querySelector("#workspace");
      return { alongside: saved.left >= form.right, below: saved.top >= form.bottom,
        fits: main.scrollWidth <= main.clientWidth, controls: [...globalThis.document.querySelectorAll(".settings-sections button, .settings-field select, .settings-field input:not([type=checkbox]), .settings-field button")].every((item) => item.getBoundingClientRect().height >= 44) };
    });
    assert.ok(geometry.fits && geometry.controls && (width >= 1120 ? geometry.alongside : geometry.below), "Settings layout and controls at " + width); checks++;
    await checkRenderedContrast(page, ".settings-sections button, .settings-field > label, .settings-hint, .settings-saved dt");
    if (directory && [1440, 390].includes(width)) await page.screenshot({ path: join(directory, width === 1440 ? "workspace-settings-desktop.png" : "workspace-settings-mobile.png") });
  }
  await page.focus(".settings-jump"); await page.keyboard.press("Enter");
  await page.waitForFunction(() => globalThis.document.activeElement.id === "saved-heading"); checks++;
  await page.setViewport({ width: 1440, height: 960 });
  await page.$eval("#workspace", (node) => node.scrollTo(0, 0));
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page, ".settings-field label, .settings-url dd, .settings-sections button");
  if (directory) await page.screenshot({ path: join(directory, "workspace-settings-dark.png") });
  await (await elementWithText(page, "button", "Light mode")).click();
  await page.select("#provider-preset", "openai");
  assert.equal(await page.$eval("#provider-preset", (node) => node.value), ""); checks++;
  assert.equal(await page.$eval(model, (node) => node.value), initialModel); checks++;
  assert.equal(await page.$eval(".settings-url dd", (node) => node.textContent), "https://api.openai.com/v1/responses"); checks++;
  assert.ok(!(await savedText()).includes("OpenAI Responses")); checks++;
  assert.equal(await page.$eval(".settings-saved button", (node) => node.disabled), true); checks++;
  await page.focus("#section-llm"); await page.keyboard.press("ArrowRight");
  await page.waitForSelector('#section-slack[aria-selected="true"]');
  await page.type('[id="slack.channel"]', "-owned");
  const savedResponse = page.waitForResponse((response) => response.url() === origin + "/api/settings" && response.request().method() === "PATCH");
  await (await elementWithText(page, ".settings-save button", "Save changes")).click();
  assert.equal((await savedResponse).status(), 200); checks++;
  await page.waitForFunction(() => !globalThis.document.querySelector(".settings-saved button").disabled);
  assert.ok((await savedText()).includes("-owned")); checks++;
  assert.equal((await db.setting.findUniqueOrThrow({ where: { key: "llm.provider" } })).value, "anthropic"); checks++;
  await page.focus("#section-slack"); await page.keyboard.press("Home");
  await page.waitForSelector('#section-llm[aria-selected="true"]');
  assert.equal(await page.$eval('[id="llm.provider"]', (node) => node.value), "openai-responses"); checks++;
  await (await elementWithText(page, ".settings-save button", "Discard")).click();
  assert.equal(await page.$eval('[id="llm.provider"]', (node) => node.value), "anthropic"); checks++;
  await page.focus("#section-llm"); await page.keyboard.press("End");
  await page.waitForSelector('#section-security[aria-selected="true"]');
  assert.ok(await page.$(".settings-readiness")); checks++;
  assert.equal(await page.$(".settings-save"), null); checks++;
  page.off("request", watchTests);
  assert.deepEqual(testRequests, []); checks++;
}

async function checkProjectDirectory(page, viewer, db, origin) {
  const directory = process.env.AEGIFY_UI_ARTIFACTS;
  const examples = [
    ["Payout ledger", "settlements", "Settlement batches and bank reconciliation.", "completed", "#286653"],
    ["Customer portal", "customer-portal", "Account and invoice management.", "partial", "#497399"],
    ["Merchant onboarding", "merchant-api", "Merchant registration and identity checks.", "running", "#8e6729"],
    ["Audit exports", "report-export", "Monthly evidence exports for finance.", "", "#777675"],
  ];
  const projects = [];
  for (const [name, slug, description, status, color] of examples) {
    const project = await db.project.create({ data: { name, ownerSlug: "ledger/" + slug, description, color,
      updatedAt: new Date(Date.now() - projects.length * 1000),
      ...(projects.length === 0 ? { members: { create: { userId: "bob", role: "viewer" } } } : {}) } });
    let lastScan;
    if (status) {
      const records = (count) => Array.from({ length: count }, (_, index) => ({
        ruleId: "CF-CONFIG-EXAMPLE", ruleName: "Check a deployment setting", severity: "low", filePath: "wrangler.jsonc",
        lineStart: index + 1, lineEnd: index + 1, message: "Review the deployment setting at this line.",
      }));
      await db.scan.create({ data: { projectId: project.id, repository: project.ownerSlug, status: "completed",
        createdAt: new Date("2026-11-14T09:00:00Z"), findings: { create: records(5) } } });
      lastScan = await db.scan.create({ data: { projectId: project.id, repository: project.ownerSlug, status,
        createdAt: new Date("2026-11-20T11:00:00Z"), findings: { create: records(2 - projects.length) } } });
    }
    projects.push({ project, lastScan });
  }
  const first = projects[0].project;
  const href = 'a[href="/projects/' + first.id + '"]';
  const archive = 'button[aria-label="Archive Payout ledger"]';
  const search = 'input[type="search"]';
  const list = 'ul[aria-label="Project records"]';
  const tab = (text) => elementWithText(page, '[aria-label="Project list"] button', text);
  await page.goto(origin + "/projects?q=ledger%2F", { waitUntil: "networkidle0" });
  await page.waitForSelector(href);
  assert.equal((await page.$$(list + " li")).length, 4); checks++;
  assert.equal(await page.$eval(href, (node) => node.closest("li").querySelectorAll("dd")[1].innerText), "2"); checks++;
  assert.equal(await page.$eval('a[href="/projects/' + projects[2].project.id + '"]', (node) => node.closest("li").querySelectorAll("dd")[1].innerText), "Pending"); checks++;
  const firstScan = list + ' a[href="/scans/' + projects[0].lastScan.id + '"]';
  assert.equal(await page.$eval(firstScan, (node) => node.querySelector("time").dateTime), "2026-11-20T11:00:00.000Z"); checks++;
  assert.equal(await page.$('main a button, main button a'), null); checks++;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width < 820 ? 844 : 1000 });
    assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
    assert.ok(await page.$eval(archive, (node) => node.checkVisibility() && node.getBoundingClientRect().height >= 44)); checks++;
    if (directory && [1440, 390].includes(width)) await page.screenshot({ path: join(directory, width === 1440 ? "projects-desktop.png" : "projects-mobile.png") });
  }
  await page.setViewport({ width: 1440, height: 1000 });
  await checkRenderedContrast(page);
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page);
  if (directory) await page.screenshot({ path: join(directory, "projects-dark.png") });
  await (await elementWithText(page, "button", "Light mode")).click();
  await page.focus(href); await page.keyboard.press("Enter");
  await page.waitForFunction((path) => globalThis.location.pathname === path, {}, "/projects/" + first.id);
  await page.goBack({ waitUntil: "networkidle0" });
  await page.waitForSelector(archive);
  assert.equal(await page.$eval(search, (node) => node.value), "ledger/"); checks++;
  await page.$eval(search, (field) => { field.focus(); field.select(); }); await page.keyboard.press("Backspace"); await page.type(search, "merchant");
  await page.waitForFunction((selector) => globalThis.document.querySelectorAll(selector + " li").length === 1, { timeout: 5000 }, list).catch(async (error) => {
    const state = await page.evaluate(() => ({ search: globalThis.document.querySelector('input[type="search"]').value,
      address: globalThis.location.search, matches: [...globalThis.document.querySelectorAll('ul[aria-label="Project records"] li > div a')].map((link) => link.innerText) }));
    throw new Error("Typed project search did not settle: " + JSON.stringify(state), { cause: error });
  });
  assert.ok((await page.$eval(list, (node) => node.innerText)).includes("Merchant onboarding")); checks++;
  await page.$eval(search, (field) => { field.focus(); field.select(); }); await page.keyboard.press("Backspace"); await page.type(search, "ledger/");
  await page.waitForSelector(archive);

  await page.focus(archive); await page.keyboard.press("Enter");
  await waitText(page, "Payout ledger archived.");
  assert.equal((await db.project.findUniqueOrThrow({ where: { id: first.id } })).archived, true); checks++;
  await (await tab("Archived")).click();
  const restore = 'button[aria-label="Restore Payout ledger"]';
  await page.waitForSelector(restore); await page.focus(restore); await page.keyboard.press("Enter");
  await waitText(page, "Payout ledger restored.");
  assert.equal((await db.project.findUniqueOrThrow({ where: { id: first.id } })).archived, false); checks++;
  await (await tab("Active")).click(); await page.waitForSelector(href);

  await page.evaluate(() => {
    const base = globalThis.fetch;
    globalThis.fetch = (value, init) => {
      if (String(value) === "/api/projects?archived=true") {
        globalThis.fetch = base;
        return Promise.resolve(new globalThis.Response("unavailable", { status: 503 }));
      }
      return base(value, init);
    };
  });
  await (await tab("Archived")).click(); await waitText(page, "The project list could not be loaded.");
  await (await elementWithText(page, "main button", "Retry")).click(); await waitText(page, "No projects match your search.");
  await (await tab("Active")).click(); await page.waitForSelector(href);

  await page.evaluate(() => {
    const base = globalThis.fetch;
    globalThis.fetch = async (value, init) => {
      if (String(value) !== "/api/projects?archived=true") return base(value, init);
      globalThis.fetch = base;
      const response = await base(value, { ...init, signal: undefined });
      await new Promise((done) => { globalThis.releaseArchivedProjects = done; });
      return response;
    };
  });
  await (await tab("Archived")).click();
  await page.waitForFunction(() => typeof globalThis.releaseArchivedProjects === "function");
  await (await tab("Active")).click(); await page.waitForSelector(href);
  await page.evaluate(() => globalThis.releaseArchivedProjects());
  assert.equal(await page.$eval('[aria-label="Project list"] button:first-child', (node) => node.getAttribute("aria-pressed")), "true"); checks++;
  assert.equal((await page.$$(list + " li")).length, 4); checks++;

  await (await elementWithText(page, "main button", "New project")).click();
  assert.equal(await page.evaluate(() => globalThis.document.activeElement.name), "name"); checks++;
  await page.type('input[name="name"]', "Settlement reconciliation");
  await page.evaluate(() => {
    const base = globalThis.fetch;
    globalThis.fetch = (value, init) => {
      if (init?.method === "POST" && value === "/api/projects") {
        globalThis.fetch = base;
        return Promise.resolve(globalThis.Response.json({ error: "The project service is unavailable." }, { status: 503 }));
      }
      return base(value, init);
    };
  });
  await page.click('#create-project button[type="submit"]');
  await waitText(page, "The project service is unavailable.");
  assert.equal(await page.evaluate(() => globalThis.document.activeElement.getAttribute("role")), "alert"); checks++;
  assert.equal(await page.$eval('input[name="name"]', (node) => node.value), "Settlement reconciliation"); checks++;
  await page.click('#create-project button[type="submit"]');
  await waitText(page, "Settlement reconciliation created.");
  await page.waitForSelector(list);
  assert.equal(await db.project.count({ where: { name: "Settlement reconciliation" } }), 1); checks++;
  assert.equal(await page.$eval(search, (node) => node.value), ""); checks++;

  await viewer.goto(origin + "/projects?q=ledger%2F", { waitUntil: "networkidle0" }); await viewer.waitForSelector(href);
  assert.equal((await viewer.$$(list + " li")).length, 1); checks++;
  assert.equal(await viewer.$(archive), null); checks++;
  assert.ok(!(await viewer.$eval("main", (node) => node.innerText)).includes("New project")); checks++;
}

async function checkProjectRecord(page, viewer, db, origin, downloadDirectory) {
  const artifacts = process.env.AEGIFY_UI_ARTIFACTS;
  const project = await db.project.create({ data: {
    name: "Settlement ledger", description: "Daily settlement batches, ledger postings and bank reconciliation.",
    ownerSlug: "payments/settlement-ledger", provider: "github", providerRepoId: "42",
    repositoryUrl: "https://github.com/payments/settlement-ledger", defaultBranch: "main",
    members: { create: { userId: "bob", role: "viewer" } },
  } });
  await db.auditEvent.createMany({ data: Array.from({ length: 36 }, (_, i) => ({
    id: `browser-audit-${String(i).padStart(2, "0")}`, projectId: project.id, actorId: "ledger-auditor",
    targetId: `approval-${i}`, action: "review.recorded", createdAt: new Date("2026-01-02T00:00:00Z"),
  })) });
  const route = "/projects/" + project.id, api = "/api" + route;
  const start = Date.parse("2026-11-21T14:32:00Z");
  const branches = ["release/settlement-cutoff", "main", "chore/bank-imports", "fix/ledger-rounding", "", "main"];
  const statuses = ["running", "completed", "partial", "completed", "failed", "completed"];
  const ids = [];
  const finding = (severity, current, ix) => ({
    ruleId: "SETTLEMENT-" + ix, ruleName: "Settlement configuration " + ix, severity, filePath: "ledger/settings.py",
    lineStart: ix, lineEnd: ix, isCurrent: current, message: "Review the ledger configuration at this line.",
  });
  for (let i = 0; i < 22; i++) {
    const status = statuses[i % statuses.length], branch = branches[i % branches.length];
    const saved = await db.scan.create({ data: {
      projectId: project.id, repository: project.ownerSlug, branch, status,
      commitSha: createHash("sha256").update(branch + i).digest("hex").slice(0, 40),
      createdAt: new Date(start - Math.floor((i + 1) / 2) * 44_400_000),
      filesScanned: ["partial", "completed"].includes(status) ? 73 + i : 0,
      duration: ["partial", "completed"].includes(status) ? 8 + i * 0.6 : 0,
      workspaceSnapshot: "owned snapshot metadata",
      ...(i === 1 ? { findings: { create: [finding("high", true, 1), finding("high", true, 2), finding("medium", true, 3), finding("low", false, 4)] } } :
        i === 2 ? { findings: { create: [finding("low", true, 5)] } } : {}),
    } });
    ids.push(saved.id);
  }
  const history = 'ol[aria-label="Project scan history"]', rows = history + " li";
  const button = (name) => elementWithText(page, "main button", name);
  const details = async (path) => page.evaluate(async (url) => (await globalThis.fetch(url)).json(), path);
  await page.setViewport({ width: 1440, height: 1000 });
  await page.goto(origin + route, { waitUntil: "networkidle0" });
  await page.waitForSelector(rows);
  const legacy = await details(api), first = await details(api + "?scanPage=1&scanLimit=10"), last = await details(api + "?scanLimit=10&scanPage=999");
  assert.equal(legacy.scans.length, 22); checks++;
  assert.ok(Object.hasOwn(legacy.scans[0], "workspaceSnapshot") && !Object.hasOwn(first.scans[0], "workspaceSnapshot")); checks++;
  assert.deepEqual(first.scans.map((s) => s.id), legacy.scans.slice(0, 10).map((s) => s.id)); checks++;
  assert.deepEqual(last.scanPage, { page: 3, pages: 3, limit: 10 }); checks++;
  assert.deepEqual(last.scans.map((s) => s.id), legacy.scans.slice(20).map((s) => s.id)); checks++;
  assert.deepEqual(first.severities, { critical: 0, high: 2, medium: 1, low: 1 }); checks++;
  assert.equal((await page.$$(rows)).length, 10); checks++;
  assert.equal(await page.$('main a button, main button a, #project-settings form'), null); checks++;
  const rowFor = (i) => history + ' a[href="/scans/' + ids[i] + '"]';
  assert.ok((await page.$eval(rowFor(0), (node) => node.innerText)).includes("Awaiting results")); checks++;
  assert.ok(!(await page.$eval(rowFor(0), (node) => node.innerText)).includes("0 files")); checks++;
  assert.ok((await page.$eval(rowFor(4), (node) => node.innerText)).includes("Branch not recorded")); checks++;
  assert.ok((await page.$eval(rowFor(4), (node) => node.innerText)).includes("No results recorded")); checks++;
  assert.ok((await page.$eval(rowFor(1), (node) => node.innerText)).includes("4 findings")); checks++;
  const severity = '[aria-labelledby="project-findings"] a[href*="severity=high"]';
  const highLink = await page.$eval(severity, (node) => node.href);
  assert.equal(new URL(highLink).searchParams.get("projectId"), project.id); checks++;
  const contrast = ".project-facts dt, .project-facts dd, .project-section-heading h2, .project-scan-time time, .project-scan-row .text-muted-foreground";
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width < 820 ? 844 : 1000 });
    assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
    assert.ok(await page.$eval(severity, (node) => node.getBoundingClientRect().height >= 44)); checks++;
    const position = await page.evaluate(() => {
      const history = globalThis.document.querySelector(".project-history").getBoundingClientRect();
      const summary = globalThis.document.querySelector(".project-findings").getBoundingClientRect();
      return history.right <= summary.left || summary.bottom <= history.top + 1;
    });
    assert.ok(position); checks++;
    if (artifacts && [1440, 390].includes(width)) await page.screenshot({ path: join(artifacts, width === 1440 ? "project-record-desktop.png" : "project-record-mobile.png") });
  }
  await page.setViewport({ width: 1440, height: 1000 }); await checkRenderedContrast(page, contrast);
  await (await elementWithText(page, "button", "Dark mode")).click();
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page, contrast);
  await page.evaluate(() => Promise.allSettled(globalThis.document.getAnimations().map((animation) => animation.finished)));
  if (artifacts) await page.screenshot({ path: join(artifacts, "project-record-dark.png") });
  await (await elementWithText(page, "button", "Light mode")).click();

  await page.focus(severity); await page.keyboard.press("Enter");
  await page.waitForFunction((id) => globalThis.location.pathname === "/findings" && globalThis.location.search.includes(id), {}, project.id);
  await waitText(page, "Settlement configuration");
  assert.equal((await details("/api/findings" + new URL(page.url()).search)).total, 2); checks++;
  await page.goBack({ waitUntil: "networkidle0" }); await page.waitForSelector(rows);
  await page.click('nav[aria-label="Scan history pages"] [rel="next"]'); await waitText(page, "11–20 of 22");
  assert.equal(await page.$(rowFor(0)), null); checks++;
  await page.click('nav[aria-label="Scan history pages"] [rel="next"]'); await waitText(page, "21–22 of 22");
  assert.equal((await page.$$(rows)).length, 2); checks++;
  await page.goBack({ waitUntil: "networkidle0" }); await waitText(page, "11–20 of 22");
  await page.evaluate((api) => {
    const base = globalThis.fetch;
    globalThis.fetch = (value, options) => {
      if (String(value) === api + "?scanLimit=10&scanPage=1") {
        globalThis.fetch = base;
        return Promise.resolve(new globalThis.Response(null, { status: 503 }));
      }
      return base(value, options);
    };
  }, api);
  await page.click('nav [rel="prev"]'); await waitText(page, "The project could not be loaded.");
  await (await button("Retry")).click(); await waitText(page, "1–10 of 22");
  await page.evaluate((api) => {
    const base = globalThis.fetch;
    globalThis.fetch = (value, init) => {
      if (String(value) === api + "/tokens" && !init?.method?.match(/POST|DELETE/)) {
        globalThis.fetch = base;
        return Promise.resolve(new globalThis.Response(null, { status: 503 }));
      }
      return base(value, init);
    };
  }, api);
  await (await button("Project settings")).click(); await waitText(page, "Project access and credentials could not be loaded.");
  assert.equal(await page.$('#project-settings form'), null); checks++;
  await (await button("Retry settings")).click(); await waitText(page, "CI upload tokens");
  await page.setViewport({ width: 320, height: 844 });
  assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
  assert.ok(await page.$$eval("#project-settings :is(button, input, select)", (nodes) => nodes.filter((node) => node.checkVisibility()).every((node) => node.getBoundingClientRect().height >= 44))); checks++;
  const auditRows = 'ol[aria-label="Audit events"] li';
  const firstEvents = await page.$$eval(auditRows, (nodes) => nodes.map((node) => node.innerText));
  assert.equal(firstEvents.length, 15); checks++;
  const older = await button("Older events");
  await older.focus(); await page.keyboard.press("Enter");
  const auditPage = (label) => page.waitForFunction((label) =>
    globalThis.document.querySelector('nav[aria-label="Audit history pages"] [role=status]')?.textContent === label, {}, label);
  await auditPage("Page 2");
  const secondEvents = await page.$$eval(auditRows, (nodes) => nodes.map((node) => node.innerText));
  assert.equal(secondEvents.length, 15);
  assert.ok(secondEvents.every((text) => !firstEvents.includes(text)));
  assert.ok(secondEvents.some((text) => text.includes("ledger-auditor"))); checks++;
  assert.equal(await page.$eval('#project-settings a[href$="format=jsonl"]', (node) => node.textContent.trim()), "Download JSONL"); checks++;
  await page.browserContext().setDownloadBehavior({ policy: "allow", downloadPath: downloadDirectory });
  await page.click('#project-settings a[href$="format=jsonl"]');
  let saved;
  for (let i = 0; !saved && i < 50; i++) {
    try { saved = await readFile(join(downloadDirectory, "aegify-project-audit.jsonl"), "utf8"); }
    catch (error) { if (error.code !== "ENOENT") throw error; await delay(100); }
  }
  const recorded = await db.auditEvent.findMany({ where: { projectId: project.id }, orderBy: [{ createdAt: "desc" }, { id: "desc" }] });
  assert.deepEqual(saved?.trimEnd().split("\n").map((line) => JSON.parse(line).id), recorded.map((event) => event.id)); checks++;
  await (await button("Newer events")).click(); await auditPage("Page 1");
  assert.deepEqual(await page.$$eval(auditRows, (nodes) => nodes.map((node) => node.innerText)), firstEvents); checks++;
  await page.setViewport({ width: 1440, height: 1000 });
  const tokenForm = 'section[aria-labelledby="project-tokens-heading"] form';
  await page.type(tokenForm + " input", "Reconciliation CI");
  await (await button("Project settings")).click(); await (await button("Project settings")).click();
  assert.equal(await page.$eval(tokenForm + " input", (node) => node.value), "Reconciliation CI"); checks++;
  await page.click(tokenForm + ' button[type="submit"]'); await waitText(page, "Copy this token now.");
  assert.equal(await page.$eval('input[aria-label="New CI upload token"]', (node) => Boolean(node.value)), true); checks++;
  await (await button("Dismiss")).click();
  assert.equal(await page.$('input[aria-label="New CI upload token"]'), null); checks++;
  await waitText(page, "Reconciliation CI");
  await (await button("Disconnect repository")).click();
  assert.equal(await page.evaluate(() => globalThis.document.activeElement.textContent), "Cancel"); checks++;
  await (await button("Cancel")).click();
  await page.waitForFunction(() => globalThis.document.activeElement?.id === "project-disconnect");
  await (await button("Disconnect repository")).click(); await (await button("Confirm disconnect")).click();
  await waitText(page, "Repository disconnected.");
  assert.equal((await details(api)).repositoryUrl, ""); checks++;

  // Only the directory response is simulated. The project edits below use the real API.
  await page.evaluate(() => {
    const base = globalThis.fetch;
    let listing = 0;
    globalThis.fetch = (path, init) => {
      if (String(path) === "/api/repos?provider=github&start=6")
        return Promise.resolve(globalThis.Response.json({
          repos: [{ id: "gh-501", provider: "github", fullName: "payments/ledger-core", url: "https://github.com/payments/ledger-core", isPrivate: true, defaultBranch: "release" }],
          providers: { github: true, gitlab: false }, next: {}, warnings: [],
        }));
      if (String(path) !== "/api/repos") return base(path, init);
      listing++;
      return Promise.resolve(listing === 1 ? new globalThis.Response(null, { status: 503 }) : globalThis.Response.json({
        repos: [{ id: "gh-1", provider: "github", fullName: "payments/storefront", url: "https://github.com/payments/storefront", isPrivate: true, defaultBranch: "main" }],
        providers: { github: true, gitlab: false }, next: { github: 6 }, warnings: [],
      }));
    };
  });
  await (await button("Connect repository")).click(); await waitText(page, "Your repositories could not be loaded.");
  await (await elementWithText(page, '[role="dialog"] button', "Retry listing")).click();
  await page.waitForSelector('[role="dialog"] input[type="search"]');
  const nextGitHub = () => elementWithText(page, '[role="dialog"] button', "Next GitHub repositories");
  await (await nextGitHub()).click();
  await page.waitForSelector('button[aria-label="Connect payments/ledger-core"]');
  await (await elementWithText(page, '[role="dialog"] button', "Previous repositories")).click();
  await page.waitForSelector('button[aria-label="Connect payments/storefront"]');
  await (await nextGitHub()).click();
  await page.waitForSelector('button[aria-label="Connect payments/ledger-core"]');
  await page.type('[role="dialog"] input[type="search"]', "ledger");
  const choose = 'button[aria-label="Connect payments/ledger-core"]';
  await page.waitForSelector(choose);
  await db.project.update({ where: { id: project.id }, data: { description: "Daily settlement batches and general ledger reconciliation." } });
  await page.click(choose); await waitText(page, "Project settings changed.");
  assert.equal(await page.$eval('[role="dialog"] input', (node) => node.value), "ledger"); checks++;
  assert.equal((await details(api)).provider, ""); checks++;
  await (await elementWithText(page, '[role="dialog"] button', "Reload project")).click();
  await waitText(page, "Daily settlement batches and general ledger reconciliation.");
  await (await button("Connect repository")).click();
  await page.waitForSelector('button[aria-label="Connect payments/storefront"]');
  await (await nextGitHub()).click();
  await page.waitForSelector(choose);
  await page.click(choose);
  await waitText(page, "Repository connected.");
  assert.equal((await details(api)).ownerSlug, "payments/ledger-core"); checks++;

  await (await button("Archive project")).click(); await (await button("Confirm archive")).click(); await waitText(page, "Archived project");
  assert.ok(!(await page.$eval("main", (node) => node.innerText)).includes("Start source scan")); checks++;
  await waitText(page, "Restore the project to issue a new upload token.");
  assert.equal(await page.$(tokenForm), null); checks++;
  assert.ok(await page.$('ul[aria-label="Project CI tokens"] button')); checks++;
  page.once("dialog", (dialog) => { void dialog.accept(); });
  await (await button("Revoke")).click(); await waitText(page, "CI token revoked.");
  assert.ok((await db.projectServiceToken.findFirstOrThrow({ where: { projectId: project.id } })).revokedAt); checks++;
  const archivedEdit = await page.evaluate(async (api) => (await globalThis.fetch(api, { method:"PATCH", headers:{"Content-Type":"application/json"}, body:JSON.stringify({defaultBranch:"trunk"})})).status, api);
  assert.equal(archivedEdit, 409); checks++;
  const viewerReads = [];
  const remember = (request) => { if (request.url().startsWith(origin + api + "/")) viewerReads.push(new URL(request.url()).pathname); };
  viewer.on("request", remember);
  try {
    await viewer.goto(origin + route, { waitUntil: "networkidle0" }); await viewer.waitForSelector(rows);
    const text = await viewer.$eval("main", (node) => node.innerText);
    assert.ok(text.includes("Archived project") && text.includes("Viewer")); checks++;
    assert.ok(!["Restore project", "Project settings", "Connect repository", "Start source scan"].some((label) => text.includes(label))); checks++;
    assert.ok(!viewerReads.some((path) => /\/(members|tokens|audit)$/.test(path))); checks++;
    await (await button("Restore project")).click(); await waitText(page, "Project restored.");
    await page.waitForSelector(tokenForm);
    assert.equal(await page.$('input[aria-label="New CI upload token"]'), null); checks++;
    await viewer.reload({ waitUntil:"networkidle0" }); await viewer.waitForSelector(rows);
    assert.ok(!(await viewer.$eval("main", (node) => node.innerText)).includes("Start source scan")); checks++;
    await db.projectMember.delete({ where: { projectId_userId: { projectId: project.id, userId: "bob" } } });
    await viewer.click('nav [rel="next"]'); await waitText(viewer, "This project is unavailable to your account.");
    assert.equal(await viewer.$(rows), null); checks++;
  } finally { viewer.off("request", remember); }
  await db.account.create({ data: { type: "oauth", provider: "github", providerAccountId: "owned-project-record", userId: "root", access_token: "unused-owned-fixture" } });
  await (await button("Start source scan")).click();
  await page.waitForFunction(() => globalThis.location.pathname.startsWith("/scans/"));
  const queued = await db.scanJob.findFirstOrThrow({ where: { projectId: project.id } });
  assert.equal(new URL(page.url()).pathname, "/scans/" + queued.scanId); checks++;
  assert.equal(queued.requestedRef, "release"); checks++;
}

async function checkRecoveryActivity(page, db, projectId, origin) {
  const commit = "728c135".padEnd(40, "5"), repo = "ledger/settlements";
  const now = Date.now();
  const scan = await db.scan.create({ data: { projectId, repository: repo, branch: "main", commitSha: commit,
    status: "pending", progressPhaseName: "retrying", progressMessage: "The previous attempt stopped.", filesScanned: 0 } });
  const job = await db.scanJob.create({ data: { projectId, scanId: scan.id, requestedBy: "alice", provider: "github",
    ownerSlug: repo, requestedRef: "main", commitSha: commit, status: "queued", attempts: 1, errorCode: "fetch_failed",
    nextAttemptAt: new Date(now + 60_000), heartbeatAt: new Date(now - 18_000) } });
  const events = Array.from({ length: 118 }, (_, i) => ({ jobId: job.id, code: "progress",
    message: "Read source record " + String(i + 1).padStart(3, "0"), createdAt: new Date(now - 121_000 + i * 1000) }));
  events.push({ jobId: job.id, code: "source_pinned", message: "Repository commit pinned", createdAt: new Date(now - 3000) },
    { jobId: job.id, code: "retrying", message: "A retry was scheduled for the pinned commit", createdAt: new Date(now - 1000) });
  await db.scanJobEvent.createMany({ data: events });
  const peer = await db.scanWorker.create({ data: { id: "other-source-" + scan.id, version: "fixture" } });
  await page.setViewport({ width: 1440, height: 1000 });
  await page.goto(origin + "/scans/" + scan.id, { waitUntil: "networkidle0" });
  const panel = '[aria-label="Source scan job"]';
  await waitText(page, "Retry scheduled");
  const linked = await page.evaluate(async (id) => {
    const base = "/api/scans/" + id + "/job?";
    const previous = await (await globalThis.fetch(base + "after=0")).json();
    const recent = await (await globalThis.fetch(base + "order=recent")).json();
    const older = await (await globalThis.fetch(base + "order=recent&before=" + recent.nextBefore)).json();
    return { first: previous.events[0].message, oldCount: previous.events.length, recentCount: recent.events.length,
      latest: recent.events[0].message, earlier: older.events.every((e) => e.id < recent.nextBefore),
      invalid: (await globalThis.fetch(base + "order=recent&before=-1")).status,
      exposedLease: Object.hasOwn(recent.job, "leaseToken"), observation: recent.observation.phase };
  }, scan.id);
  assert.deepEqual(linked, { first: "Read source record 001", oldCount: 100, recentCount: 20,
    latest: "A retry was scheduled for the pinned commit", earlier: true, invalid: 400, exposedLease: false, observation: "retry_scheduled" }); checks++;
  await page.click(panel + " summary");
  assert.equal(await page.$eval(panel + " ol li:first-child", (node) => node.innerText.includes("A retry was scheduled")), true); checks++;
  const older = await elementWithText(page, panel + " button", "Earlier activity");
  await older.focus(); await page.keyboard.press("Enter"); await waitText(page, "Read source record 081");
  assert.ok(!(await page.$eval(panel + " ol", (node) => node.innerText)).includes("A retry was scheduled")); checks++;
  await (await elementWithText(page, panel + " button", "Latest activity")).click(); await waitText(page, "A retry was scheduled for the pinned commit");
  await page.click(panel + " summary");
  const expired = new Date(now - 40_000);
  await db.scanJob.update({ where: { id: job.id }, data: { status: "running", leaseExpiresAt: expired, heartbeatAt: new Date(+expired - 120_000) } });
  await waitText(page, "Waiting for recovery");
  assert.ok(!(await page.$eval("main", (node) => node.innerText)).includes("Analysis in progress")); checks++;
  assert.equal(await page.$('aside[aria-label="Scan breakdown"]'), null); checks++;
  assert.equal(await page.$('input[type="search"]'), null); checks++;
  await waitText(page, "Findings will appear here when the scan publishes its results.");
  assert.ok(!(await page.$eval(panel, (node) => node.innerText)).includes("No recent scan worker heartbeat")); checks++;
  assert.equal(await page.$eval(panel + " time", (node) => node.dateTime), expired.toISOString()); checks++;
  const artifacts = process.env.AEGIFY_UI_ARTIFACTS;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width < 820 ? 844 : 1000 });
    await page.evaluate(() => { globalThis.scrollTo(0, 0); globalThis.document.querySelector("main").scrollTop = 0; });
    assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
    assert.ok(await (await elementWithText(page, panel + " button", "Cancel scan")).evaluate((node) => node.getBoundingClientRect().height >= 44)); checks++;
    if (artifacts && [1440, 390].includes(width)) await page.screenshot({ path: join(artifacts, width === 1440 ? "worker-recovery-desktop.png" : "worker-recovery-mobile.png") });
  }
  await db.scanJob.update({ where: { id: job.id }, data: { attempts: 2, leaseExpiresAt: new Date(Date.now() + 120_000), heartbeatAt: new Date() } });
  await waitText(page, "Retry in progress");
  await db.scanJob.update({ where: { id: job.id }, data: { status: "failed", completedAt: new Date(), errorCode: "scanner_failed" } });
  await waitText(page, "Retry same commit");
  await db.scanWorker.delete({ where: { id: peer.id } });
  const imported = await db.scan.create({ data: { projectId, repository: "ledger/import", status: "running", progressMessage: "Importing evidence" } });
  await page.goto(origin + "/scans/" + imported.id, { waitUntil: "networkidle0" });
  await waitText(page, "Importing evidence");
  assert.equal(await page.$(panel), null); checks++;

  const review = await db.llmJob.create({ data: { projectId, scanId: scan.id, requestedBy: "alice", mode: "deep", status: "running",
    attempts: 1, leaseExpiresAt: expired, totalFindings: 12, totalBatches: 2, deadlineAt: new Date(Date.now() + 900_000) } });
  await page.goto(origin + "/llm-scan", { waitUntil: "networkidle0" });
  await waitText(page, "The next worker will check saved batches and provider calls.");
  await page.click('button[aria-label="Open navigation"]');
  const runningProgress = await page.waitForSelector('[data-review-state="running"] progress', { visible: true });
  assert.deepEqual(await runningProgress.evaluate((bar) => [bar.value, bar.max]), [0, 12]); checks++;
  await page.keyboard.press("Escape");
  assert.equal((await page.$$("#review-run [role=status]")).length, 1); checks++;
  assert.equal(await page.$eval("#review-run time", (node) => node.dateTime), expired.toISOString()); checks++;
  await db.llmJob.update({ where: { id: review.id }, data: { status: "partial", reviewedCount: 6, errorCode: "provider_outcome_unknown", errorMessage: "The provider outcome is unknown.", completedAt: new Date() } });
  await waitText(page, "The provider outcome is unknown.");
  assert.ok(!(await page.$eval("#review-run", (node) => node.innerText)).includes("Waiting for recovery")); checks++;
}

async function checkSpecificationReview(page, db, projectId, origin, directory) {
  const scan = await db.scan.create({ data: { projectId, repository: "ledger/services", branch: "main", status: "completed" } });
  const newerRepository = "owned/pagination-" + scan.id;
  await db.scan.createMany({ data: Array.from({ length: 100 }, () => ({
    projectId, repository: newerRepository, branch: "main", status: "completed", createdAt: new Date(scan.createdAt.getTime() + 1000),
  })) });
  const repo = "billing", other = "catalog";
  const endpoint = (repositoryId, path, filePath, lineStart, authRequired) => ({
    scanId: scan.id, repositoryId, path, method: "GET", filePath, lineStart, lineEnd: lineStart + 7,
    authRequired, framework: "FastAPI", handlerFunction: filePath.split("/").at(-1).split(".")[0],
  });
  await db.endpoint.createMany({ data: [
    endpoint(repo, "/invoices/{id}", "billing/invoices.py", 42, false),
    endpoint(repo, "/customers", "billing/customers.py", 18, true),
    endpoint(repo, "/v1/events", "billing/events_v1.py", 14, true),
    endpoint(repo, "/v2/events", "billing/events_v2.py", 26, false),
    endpoint(repo, "/health", "billing/health.py", 9, false),
    endpoint(other, "/catalog", "catalog/products.py", 10, true),
  ] });
  const ok = { "200": { description: "OK" } };
  const contract = { openapi: "3.1.0", info: { title: "Billing API", version: "2.4" }, components: {
    securitySchemes: { billingOAuth: { type: "oauth2" }, workspaceKey: { type: "apiKey", in: "header", name: "Workspace-Key" } },
  }, paths: {
    "/invoices/{id}": { get: { operationId: "readInvoice", summary: "Retrieve an invoice by its identifier", tags: ["invoices"],
      security: [{ billingOAuth: ["invoices:read"] }], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: { ...ok, "404": { description: "Invoice missing" } } } },
    "/customers": { get: { operationId: "listCustomers", security: [{ billingOAuth: ["customers:read"], workspaceKey: [] }, {}], responses: ok } },
    "/events": { get: { servers: [{ url: "/v1" }, { url: "/v2" }], responses: ok } },
    "/statements": { get: { security: [], responses: ok } },
  } };
  const catalog = { openapi: "3.1.0", info: { title: "Catalog API", version: "1" }, paths: { "/catalog": { get: { responses: ok } } } };
  const file = join(directory, "billing.openapi.json");
  await writeFile(file, JSON.stringify(contract));
  await page.setViewport({ width: 1440, height: 1020 });
  await page.goto(origin + "/api-specs?scanId=" + scan.id, { waitUntil: "networkidle0" });
  await page.waitForFunction((id) => globalThis.document.querySelector("#spec-scan").value === id && globalThis.document.querySelector("#spec-repository option[value=billing]"), {}, scan.id);
  assert.equal(await page.evaluate(async (id) => (await (await globalThis.fetch("/api/scans?limit=100")).json()).scans.some((item) => item.id === id), scan.id), false); checks++;
  await db.scan.deleteMany({ where: { projectId, repository: newerRepository } });
  const catalogId = await page.evaluate(async ({ scanId, catalog, other }) => {
    const params = new globalThis.URLSearchParams({ scanId, repositoryId: other, preview: "true" });
    const init = { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(catalog) };
    const preview = await globalThis.fetch("/api/endpoints/import-openapi?" + params, init);
    const { contract } = await preview.json();
    params.delete("preview"); params.set("expectedHash", contract.digest);
    return (await (await globalThis.fetch("/api/endpoints/import-openapi?" + params, init)).json()).id;
  }, { scanId: scan.id, catalog, other });
  assert.ok(catalogId); checks++;
  await page.select("#spec-repository", repo);
  await waitText(page, "No specifications saved in this scope.");
  await (await page.$("#spec-file")).uploadFile(file);
  await (await elementWithText(page, "button", "Preview specification")).click();
  await waitText(page, "Billing API");
  const detail = '[aria-label="Operation detail"]';
  await waitText(page, "No auth signal recorded");
  assert.match(await page.$eval(detail, (node) => node.innerText), /billingOAuth \(invoices:read\)/); checks++;
  assert.match(await page.$eval(detail, (node) => node.innerText), /billing\/invoices\.py:42–49/); checks++;
  assert.equal(await page.$(detail + " table"), null); checks++;
  assert.deepEqual(await page.$$eval("#workspace dl:first-of-type > div", (nodes) => nodes.slice(0, 4).map((node) => node.querySelector("dd")?.textContent)), ["2","1","1","1"]); checks++;
  await (await elementWithText(page, "button", "Save specification")).click();
  await waitText(page, "Saved specification");
  const saved = await db.apiSpecification.findFirstOrThrow({ where: { scanId: scan.id, repositoryId: repo } });
  const scopeStatus = await page.evaluate(async ({ id, scanId, other }) => {
    const base = "/api/endpoints/import-openapi?" + new globalThis.URLSearchParams({ scanId, repositoryId: other });
    const { specifications, total } = await (await globalThis.fetch(base)).json();
    return { total, titles: specifications.map((spec) => spec.title), detail: (await globalThis.fetch(base + "&id=" + id)).status };
  }, { id: saved.id, scanId: scan.id, other });
  assert.deepEqual(scopeStatus, { total: 1, titles: ["Catalog API"], detail: 404 }); checks++;
  await page.browserContext().setDownloadBehavior({ policy: "allow", downloadPath: directory });
  await (await elementWithText(page, "button", "Export review")).click();
  const download = join(directory, "api-contract-" + saved.contentHash.slice(0, 12) + ".json");
  let exported;
  for (let i = 0; i < 70 && !exported; i++) { try { exported = JSON.parse(await readFile(download, "utf8")); } catch { await delay(75); } }
  assert.equal(exported?.scanId, scan.id); assert.equal(exported.repositoryId, repo); assert.equal(exported.specificationId, saved.id); checks += 3;
  const artifacts = process.env.AEGIFY_UI_ARTIFACTS;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width === 390 ? 844 : 1020 });
    await page.waitForFunction((width) => (globalThis.document.querySelector("#contract-operation").getBoundingClientRect().width > 0) === (width < 1280), {}, width);
    assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)); checks++;
    if (width === 1440) {
      await checkRenderedContrast(page);
      if (artifacts) await page.screenshot({ path: join(artifacts, "api-spec-desktop.png") });
      await (await elementWithText(page, "button", "Dark mode")).click();
      await checkRenderedContrast(page);
      if (artifacts) await page.screenshot({ path: join(artifacts, "api-spec-dark.png") });
      await (await elementWithText(page, "button", "Light mode")).click();
      const customer = await elementWithText(page, '[aria-label="Route list"] button', "/customers");
      await customer.focus(); await page.keyboard.press("Enter");
    } else {
      await page.focus("#contract-operation");
      assert.equal(await page.evaluate(() => globalThis.document.activeElement.id), "contract-operation"); checks++;
      await page.select("#contract-operation", "#/paths/~1customers/get");
    }
    await waitText(page, "Authentication optional"); await waitText(page, "Auth signal recorded");
    assert.match(await page.$eval(detail, (node) => node.innerText), /workspaceKey/); checks++;
    if (width < 1280) {
      await page.select("#contract-operation", "#/paths/~1invoices~1{id}/get");
      await waitText(page, "No auth signal recorded");
      if (width === 390 && artifacts) {
        await page.$eval('[aria-label="Contract operations"]', (node) => node.scrollIntoView({ block: "start" }));
        await page.screenshot({ path: join(artifacts, "api-spec-mobile.png") });
      }
    }
  }
  await page.select('[aria-label="Filter contract associations"]', "ambiguous");
  await waitText(page, "2 possible handlers");
  assert.equal(await page.$$eval(detail + " a", (links) => links.length), 2); checks++;
  await page.select('[aria-label="Filter contract associations"]', "spec_only");
  await waitText(page, "No matching handler");
  await page.click('input[type="search"]'); await page.type('input[type="search"]', "unlisted-operation");
  await waitText(page, "No operations match these filters.");
  await page.setViewport({ width: 1440, height: 1020 });
  await (await elementWithText(page, "button", "Change specification")).click();
  await (await page.$("#spec-file")).uploadFile(file);
  // Hold a real response after decoding. A late result must not replace a newer saved review.
  await page.evaluate(() => {
    const baseFetch = globalThis.window.fetch;
    globalThis.window.fetch = async (...args) => {
      const response = await baseFetch(...args);
      if (String(args[0]).includes("preview=true") && args[1]?.method === "POST") {
        globalThis.window.fetch = baseFetch;
        const payload = await response.json();
        response.json = () => new Promise((resolve) => { globalThis.window.releaseContractPreview = () => resolve(payload); });
      }
      return response;
    };
  });
  await (await elementWithText(page, "button", "Preview specification")).click();
  await page.waitForFunction(() => typeof globalThis.window.releaseContractPreview === "function");
  await page.evaluate(() => {
    const baseFetch = globalThis.window.fetch;
    globalThis.window.fetch = (...args) => {
      if (String(args[0]).includes("import-openapi?") && !args[1]?.method) {
        globalThis.window.fetch = baseFetch;
        return Promise.resolve(new globalThis.Response(null, { status: 503 }));
      }
      return baseFetch(...args);
    };
  });
  await page.select("#spec-repository", other);
  await waitText(page, "Couldn’t load specifications for this scope.");
  await (await elementWithText(page, "#spec-documents button", "Retry")).click();
  await waitText(page, "Catalog API");
  await (await elementWithText(page, "#spec-documents button", "Catalog API")).click();
  await waitText(page, "catalog/products.py:10–17");
  await page.evaluate(async () => { globalThis.window.releaseContractPreview(); await new Promise((done) => globalThis.requestAnimationFrame(() => globalThis.requestAnimationFrame(done))); });
  assert.equal(await page.$eval('h2[tabindex="-1"]', (node) => node.innerText), "Catalog API"); checks++;
  assert.ok(!(await page.$eval("#workspace", (node) => node.innerText)).includes("Save specification")); checks++;
  await (await elementWithText(page, "button", "Change specification")).click();
  await (await elementWithText(page, "button", "HTTPS URL")).click();
  await page.type("#spec-url", "https://example.test/api.json");
  assert.ok(await (await elementWithText(page, "button", "Preview specification")).evaluate((node) => node.disabled)); checks++;
  await page.click('#spec-documents input[type="checkbox"]');
  assert.equal(await page.$eval('#spec-documents button[type="submit"]', (node) => node.disabled), false); checks++;
  await page.type("#spec-url", "?version=2");
  assert.equal(await page.$eval('#spec-documents input[type="checkbox"]', (node) => node.checked), false); checks++;
  assert.ok(await page.$eval('#spec-documents button[type="submit"]', (node) => node.disabled)); checks++;
}

async function checkCallGraph(page, db, projectId, origin) {
  const commit = "f".repeat(40);
  const files = [
    { path: "notifications/delivery.py", content: [
      "import smtplib",
      "from notifications.receipts import render_receipt",
      "",
      "def open_mail_session(host, port):",
      "    client = smtplib.SMTP(host, port, timeout=10)",
      "    client.starttls()",
      "    return client",
      "",
      "def send_receipt(host, port):",
      "    message = render_receipt()",
      "    with open_mail_session(host, port) as client:",
      "        client.send_message(message)",
      "    return \"queued\"",
    ].join("\n") },
    { path: "notifications/receipts.py", content: [
      "from email.message import EmailMessage",
      "",
      "def render_receipt():",
      "    message = EmailMessage()",
      "    message.set_content(\"Receipt recorded\")",
      "    return message",
    ].join("\n") },
    { path: "notifications/routes.py", content: [
      "from flask import Flask",
      "from notifications.delivery import send_receipt",
      "",
      "app = Flask(__name__)",
      "",
      "@app.post(\"/receipts\")",
      "def deliver_receipt():",
      "    return send_receipt(\"mail.example.test\", 587)",
    ].join("\n") },
  ];
  const snapshot = makeSourceSnapshot({ provider: "github", ownerSlug: "ledger/receipt-delivery", commitSha: commit }, { ref: commit, truncated: false, files });
  const { report } = await runPythonSnapshot(snapshot, new globalThis.AbortController().signal, async () => {});
  const upload = await page.evaluate(async ({ projectId, report }) => {
    const response = await globalThis.fetch("/api/upload?projectId=" + projectId + "&repository=ledger%2Freceipt-delivery&branch=main",
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(report) });
    return { status: response.status, data: await response.json() };
  }, { projectId, report });
  assert.equal(upload.status, 200); checks++;
  const id = upload.data.scanId;
  const graph = await page.evaluate(async (id) => (await globalThis.fetch("/api/graph/" + id + "?mode=full")).json(), id);
  assert.equal(graph.repository, "ledger/receipt-delivery"); checks++;
  assert.equal(graph.edges.length, 3); checks++;
  const sourceNode = graph.nodes.find((node) => node.qualifiedName.includes("::open_mail_session("));
  assert.ok(sourceNode); checks++;
  await db.finding.createMany({ data: Array.from({ length: 105 }, (_, index) => ({
    scanId: id, filePath: sourceNode.filePath, lineStart: 40 + index, lineEnd: 40 + index,
    ruleId: "FIXTURE-REVIEW", ruleName: "Unrelated observation", severity: "low",
    message: "Different line in the same file", codeSnippet: "unrelated_observation",
  })) });
  const excerpt = await page.evaluate(async ({ id, node }) => {
    const response = await globalThis.fetch("/api/graph/" + id + "?sourceNode=" + encodeURIComponent(node));
    return { status: response.status, data: await response.json() };
  }, { id, node: sourceNode.id });
  assert.equal(excerpt.status, 200); checks++;
  assert.equal(excerpt.data.finding.lineStart, 6); checks++;
  assert.ok(excerpt.data.finding.codeSnippet.includes("starttls")); checks++;
  const artifacts = process.env.AEGIFY_UI_ARTIFACTS;
  const h2 = "#graph-symbol-name";
  const chosen = (name) => page.waitForFunction((name) => globalThis.document.querySelector("#graph-symbol-name")?.textContent === name, {}, name);
  await page.setViewport({ width: 1440, height: 960 });
  await page.goto(origin + "/scans/" + id, { waitUntil: "networkidle0" });
  await page.click('a[href="/graph/' + id + '"]');
  await page.waitForSelector(h2);
  await page.type('input[aria-label="Filter source structure"]', "send_receipt");
  await (await elementWithText(page, "#graph-file-index li button", "send_receipt")).click();
  await chosen("send_receipt");
  assert.ok((await page.$eval('[aria-label="Called by"]', (el) => el.innerText)).includes("deliver_receipt")); checks++;
  assert.ok((await page.$eval('[aria-label="Calls"]', (el) => el.innerText)).includes("render_receipt")); checks++;
  await page.click('[aria-label="Clear file filter"]');
  assert.equal(await page.$eval('input[aria-label="Filter source structure"]', (el) => el.value), ""); checks++;
  await (await elementWithText(page, '[aria-label="Calls"] button', "open_mail_session")).click();
  await chosen("open_mail_session");
  await page.waitForSelector('section[aria-label="Related finding"] figure');
  const entryPath = await page.$$eval('[aria-label="Recorded entry path"] li', (nodes) => nodes.map((node) => node.innerText.trim()));
  assert.deepEqual(entryPath, ["deliver_receipt", "send_receipt", "open_mail_session"]); checks++;
  assert.ok(await page.$eval('section[aria-label="Related finding"] figure', (el) => el.innerText.includes("starttls"))); checks++;
  assert.equal(await page.evaluate(() => globalThis.document.activeElement?.id), "graph-symbol-name"); checks++;
  for (const width of [1440, 820, 390, 320]) {
    await page.setViewport({ width, height: width < 768 ? 844 : 960 });
    await page.$eval("#workspace", (node) => node.scrollTo(0, 0));
    const shape = await page.evaluate(() => {
      const el = (selector) => globalThis.document.querySelector(selector);
      return { fits: el("#workspace").scrollWidth <= el("#workspace").clientWidth, files: el("#graph-file-index").checkVisibility(),
        zoom: Boolean(el('[aria-label="Network zoom"]')), readable: el("#graph-symbol-name").getBoundingClientRect().bottom < globalThis.innerHeight };
    });
    assert.ok(shape.fits && shape.readable && !shape.zoom && shape.files === (width >= 1024)); checks++;
    await checkRenderedContrast(page, '.graph-view-buttons button, .graph-heading dt, .graph-reader h3, .graph-path button, #graph-symbol-name');
    if (artifacts && [1440, 390].includes(width)) await page.screenshot({ path: join(artifacts, "call-graph-" + (width === 390 ? "mobile" : "desktop") + ".png") });
  }
  await page.click(".graph-file-toggle");
  await page.type('[aria-label="Filter source structure"]', "render_receipt");
  const result = await elementWithText(page, "#graph-file-index li button", "render_receipt");
  await result.focus(); await page.keyboard.press("Enter");
  await chosen("render_receipt");
  assert.equal(await page.$eval(".graph-file-toggle", (el) => el.getAttribute("aria-expanded")), "false"); checks++;
  assert.equal(await page.evaluate(() => globalThis.document.activeElement?.id), "graph-symbol-name"); checks++;
  await waitText(page, "No recorded finding excerpt overlaps this symbol.");
  await page.setViewport({ width: 1440, height: 960 });
  await page.waitForFunction(() => [...globalThis.document.querySelectorAll("button")].some((el) =>
    /^(Light|Dark) mode$/.test(el.textContent.trim()) && el.checkVisibility()));
  if (!(await page.evaluate(() => globalThis.document.documentElement.classList.contains("dark")))) {
    await (await elementWithText(page, "button", "Dark mode")).click();
  }
  await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
  await checkRenderedContrast(page, '.graph-view-buttons button, .graph-heading dt, .graph-reader h3, .graph-path button, #graph-symbol-name');
  if (artifacts) await page.screenshot({ path: join(artifacts, "call-graph-dark.png") });
  await (await elementWithText(page, "button", "Light mode")).click();
  await (await elementWithText(page, ".graph-view-buttons button", "Network")).click();
  await page.waitForSelector(".graph-canvas canvas");
  await page.click('[aria-label="Fit graph"]');
  await page.waitForFunction(() => {
    const drawing = globalThis.document.querySelector(".graph-canvas canvas");
    if (!drawing?.width || !drawing.height) return false;
    const colors = new Set([...globalThis.document.querySelectorAll(".graph-legend i[style]")].map((key) => {
      const [r, g, b] = key.style.backgroundColor.match(/\d+/g).map(Number);
      return (r << 16) | (g << 8) | b;
    }));
    if (colors.size !== 4) return false;
    const pixels = drawing.getContext("2d").getImageData(0, 0, drawing.width, drawing.height).data;
    for (let i = 0; i < pixels.length && colors.size; i += 4) {
      if (pixels[i + 3] === 255) colors.delete((pixels[i] << 16) | (pixels[i + 1] << 8) | pixels[i + 2]);
    }
    return colors.size === 0;
  }); checks++;
  for (const width of [1440, 390, 320]) {
    await page.setViewport({ width, height: width < 768 ? 844 : 960 });
    await page.waitForFunction(() => {
      const box = globalThis.document.querySelector(".graph-canvas").getBoundingClientRect();
      const canvas = globalThis.document.querySelector(".graph-canvas canvas").getBoundingClientRect();
      return Math.abs(box.width - canvas.width) <= 3 && Math.abs(box.height - canvas.height) <= 3;
    });
    assert.ok(await page.$eval("#workspace", (el) => el.scrollWidth <= el.clientWidth)); checks++;
    assert.ok(await page.$$eval(".graph-zoom button", (buttons) => buttons.every((el) => el.getBoundingClientRect().height >= 44 && el.getAttribute("aria-label")))); checks++;
    if (artifacts && width === 1440) await page.screenshot({ path: join(artifacts, "call-network-desktop.png") });
  }
  await page.click('[aria-label="Zoom in"]'); await page.click('[aria-label="Zoom out"]'); await page.click('[aria-label="Fit graph"]');
  await page.type('[aria-label="Search network symbols"]', "unmatched-fixture-symbol");
  await waitText(page, "No symbols match these filters.");
  await page.$eval('[aria-label="Search network symbols"]', (el) => el.select()); await page.keyboard.press("Backspace");
  await page.waitForSelector(".graph-canvas canvas");
  await page.select('[aria-label="Filter network node types"]', "entry_point");
  await waitText(page, "2 of " + graph.nodes.length + " symbols");
  await (await elementWithText(page, ".graph-network-index li button", "deliver_receipt")).click();
  await (await elementWithText(page, "button", "Open in source structure")).click();
  await chosen("deliver_receipt"); checks++;
  const empty = await db.scan.create({ data: { projectId, repository: "ledger/symbols", branch: "main", status: "completed",
    graphNodes: { create: { qualifiedName: "standalone", filePath: "utils.py", lineStart: 1, lineEnd: 2 } } } });
  await page.goto(origin + "/graph/" + empty.id);
  await waitText(page, "No symbols in this summary");
  await page.select('[aria-label="Graph scope"]', "full");
  await chosen("standalone"); checks++;
}

async function checkScanImport(page, db, projectId, reportPath, simulateMissingReceipt) {
  const picker = 'input[type="file"]';
  const result = '[aria-label="Import result"]';
  const destination = await page.$eval("#import-project", (select) => select.selectedOptions[0].text);
  const tabList = '[role="tablist"][aria-label="Scan source"]';
  const panel = '[role="tabpanel"]:not([hidden])';
  await (await elementWithText(page, tabList + ' [role="tab"]', "Repository")).focus();
  await page.keyboard.press("ArrowRight");
  await waitText(page, "View example manifest");
  assert.match(await page.$eval(panel + " code", (el) => el.textContent), /aegify scan-workspace workspace\.yml[\s\S]*--prepare-to[\s\S]*results\.sarif/); checks++;
  await page.keyboard.press("ArrowLeft");
  await page.waitForFunction(() => globalThis.document.querySelector('[role="tab"][aria-selected="true"]')?.textContent === "Repository");
  assert.match(await page.$eval(panel + " code", (el) => el.textContent), /aegify scan \.\/src/); checks++;
  await (await elementWithText(page, tabList + ' [role="tab"]', "Workspace")).click();
  const writes = [];
  const countWrite = (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname === "/api/upload") writes.push(request.url());
  };
  page.on("request", countWrite);
  try {
    await page.$eval('[aria-labelledby="report-title"] div', (zone) => {
      const files = new globalThis.DataTransfer();
      files.items.add(new globalThis.File(["invalid JSON"], "invalid.sarif", { type: "application/json" }));
      zone.dispatchEvent(new globalThis.DragEvent("drop", { bubbles: true, dataTransfer: files }));
    });
    await waitText(page, "The file contains invalid JSON.");
    assert.match(await page.$eval(result + ' [role="alert"]', (node) => node.innerText), /invalid\.sarif/); checks++;
    assert.equal(writes.length, 0); checks++;
    await page.select("#import-project", "");
    assert.equal(await page.$(result), null); checks++;
    await page.select("#import-project", projectId);

    simulateMissingReceipt();
    await (await page.$(picker)).uploadFile(reportPath);
    await waitText(page, "Import status unknown");
    assert.equal(await page.$eval(result + " a", (link) => link.getAttribute("href")), "/scans"); checks++;
    assert.equal(await page.$(result + " dl"), null); checks++;

    const waitForUpload = () => page.waitForResponse((res) => res.request().method() === "POST" && new URL(res.url()).pathname === "/api/upload");
    const source = JSON.parse(await readFile(reportPath, "utf8"));
    const legacy = globalThis.structuredClone(source);
    delete legacy.runs[0].properties.gatewayInventory;
    const legacyPath = join(dirname(reportPath), "legacy.sarif");
    await writeFile(legacyPath, JSON.stringify(legacy));
    const legacyResponse = waitForUpload();
    await (await page.$(picker)).uploadFile(legacyPath);
    const legacyReceipt = await (await legacyResponse).json();
    await waitText(page, "Report imported");
    assert.equal(await page.$(result + ' [aria-label="Gateway routes"]'), null); checks++;
    await db.scan.delete({ where: { id: legacyReceipt.scanId } });

    source.runs[0].properties.gatewayInventory.input_status = "partial";
    source.runs[0].properties.gatewayInventory.omitted_routes = 1;
    const receiptResponse = waitForUpload();
    const filename = "billing-pipeline.sarif";
    const report = join(dirname(reportPath), filename);
    await writeFile(report, JSON.stringify(source));
    await (await page.$(picker)).uploadFile(report);
    const response = await receiptResponse;
    assert.equal(response.status(), 200); checks++;
    const receipt = await response.json();
    await waitText(page, "Partial gateway input");
    assert.match(await page.$eval(result, (node) => node.innerText), /billing-pipeline\.sarif/); checks++;
    const fields = await page.$$eval(result + " dt", (labels) => Object.fromEntries(labels.map((label) => [label.textContent, label.nextElementSibling.textContent])));
    assert.deepEqual(fields, { Project: destination, "Scan status": "Partial coverage", Findings: "0" }); checks++;
    assert.deepEqual(await db.scan.findUnique({ where: { id: receipt.scanId }, select: { projectId: true, status: true } }), { projectId, status: "partial" }); checks++;
    assert.equal(writes.length, 3); checks++;
    const routes = result + ' [aria-label="Gateway routes"]';
    assert.deepEqual(await page.$$eval(routes + " li", (items) => items.map((el) => el.innerText.trim().split(/\s+/))), [["1", "Resolved"], ["26", "Ambiguous"], ["1", "Unresolved"]]); checks++;
    const routesLink = await page.$(routes + " a");
    assert.equal(await routesLink.evaluate((el) => el.getAttribute("href")), "/scans/" + receipt.scanId + "#gateway-inventory"); checks++;
    const contrast = '#workspace dt, #workspace dd, #workspace summary, #workspace [role="tab"], #workspace [aria-label="Gateway routes"] li span, #import-project, #workspace label[for="import-project"], #workspace [aria-label="Import result"] a';
    for (const width of [1440, 820, 390, 320]) {
      await page.setViewport({ width, height: width >= 820 ? 1000 : 844 });
      await page.waitForFunction(() => globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth);
      assert.ok(await page.$eval(result, (node) => node.getBoundingClientRect().right <= globalThis.innerWidth)); checks++;
      await checkRenderedContrast(page, contrast);
      if (process.env.AEGIFY_UI_ARTIFACTS && [1440, 390].includes(width)) {
        await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, width === 1440 ? "import-desktop.png" : "import-mobile.png") });
      }
    }
    await page.setViewport({ width: 1440, height: 1000 });
    await (await elementWithText(page, "aside.app-sidebar button", "Dark mode")).click();
    await checkRenderedContrast(page, contrast);
    if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "import-dark.png") });
    await (await elementWithText(page, "aside.app-sidebar button", "Light mode")).click();
    const link = await elementWithText(page, result + " a", "Open scan");
    assert.equal(await link.evaluate((node) => node.getAttribute("href")), "/scans/" + receipt.scanId); checks++;
    await routesLink.focus();
    await page.keyboard.press("Enter");
    await page.waitForFunction((id) => globalThis.location.pathname === "/scans/" + id && globalThis.location.hash === "#gateway-inventory", {}, receipt.scanId); checks++;
    await page.waitForFunction(() => globalThis.document.activeElement?.id === "gateway-inventory"
      && globalThis.document.activeElement.getBoundingClientRect().top < globalThis.innerHeight / 2); checks++;
    await waitText(page, "Partial");
    await db.scan.delete({ where: { id: receipt.scanId } });
  } finally {
    page.off("request", countWrite);
  }
}

async function checkRenderedContrast(page, selector = '#workspace [data-slot="badge"], #workspace dt, nav a[aria-current="page"]') {
  // A theme switch also transitions inherited text and ancestor surfaces.
  await page.evaluate(async () => {
    await new Promise((resolve) => globalThis.requestAnimationFrame(resolve));
    const transitions = globalThis.document.getAnimations().filter((animation) => Number.isFinite(animation.effect?.getComputedTiming().endTime));
    await Promise.allSettled(transitions.map((animation) => animation.finished));
  });
  const samples = await page.evaluate((selector) => {
    const context = globalThis.document.createElement("canvas").getContext("2d", { willReadFrequently: true });
    function luminance() {
      const rgb = Array.from(context.getImageData(0, 0, 1, 1).data).slice(0, 3).map((byte) => {
        const channel = byte / 255;
        return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
    }
    return Array.from(globalThis.document.querySelectorAll(selector)).filter((node) => node.checkVisibility()).map((element) => {
      const layers = [];
      for (let node = element; node; node = node.parentElement) layers.unshift(globalThis.getComputedStyle(node).backgroundColor);
      for (const color of ["white", ...layers]) { context.fillStyle = color; context.fillRect(0, 0, 1, 1); }
      const background = luminance();
      context.fillStyle = globalThis.getComputedStyle(element).color;
      context.fillRect(0, 0, 1, 1);
      const foreground = luminance();
      return { label: element.textContent, ratio: (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05) };
    });
  }, selector);
  assert.ok(samples.length >= 6, "Expected rendered navigation, labels and severity");
  for (const sample of samples) assert.ok(sample.ratio >= 4.5, sample.label + " contrast " + sample.ratio.toFixed(2));
  checks++;
}
try {
  await runAccessIntegration({ verifyBrowser: async ({ origin, cookies, projectId, reportPath, queuedScanId, reviewScanId, sourceScanId, db, environment }) => {
    const previous = process.env.ENCRYPTION_SECRET;
    process.env.ENCRYPTION_SECRET = environment.ENCRYPTION_SECRET;
    const context = await browser.createBrowserContext();
    try {
      const page = await context.newPage();
      let failConfigOnce = true;
      let failEndpointsOnce = false;
      let failReviewHistoryOnce = false;
      let failCatalogOnce = false;
      let failRuleSyncOnce = false;
      let failRuleSaveOnce = false;
      let missingImportReceipt = false;
      let localAuthFixture = false;
      async function configurePage(surface) {
        surface.on("pageerror", (error) => errors.push(error.message));
        await surface.setRequestInterception(true);
        surface.on("request", (request) => {
          if (missingImportReceipt && request.method() === "POST" && request.url().startsWith(origin + "/api/upload?")) {
            missingImportReceipt = false;
            void request.respond({ status: 200, contentType: "application/json", body: "{}" });
          } else if (failReviewHistoryOnce && request.url() === origin + "/api/llm-jobs?limit=10") {
            failReviewHistoryOnce = false;
            void request.respond({ status: 503, body: "" });
          } else if (failRuleSaveOnce && request.method() === "PATCH" && request.url() === origin + "/api/rules/AEG-A08-004") {
            failRuleSaveOnce = false;
            void request.respond({ status: 503, body: "" });
          } else if (failCatalogOnce && request.url() === origin + "/api/rules?view=catalog") {
            failCatalogOnce = false;
            void request.respond({ status: 503, body: "" });
          } else if (failRuleSyncOnce && request.url() === origin + "/api/rules/sync") {
            failRuleSyncOnce = false;
            void request.respond({ status: 503, body: "" });
          } else if (failEndpointsOnce && request.url().startsWith(origin + "/api/endpoints?")) {
            failEndpointsOnce = false;
            void request.respond({ status: 503, body: "" });
          } else if (failConfigOnce && request.url() === origin + "/api/auth/config") {
            failConfigOnce = false;
            void request.respond({ status: 503, body: "" });
          } else if (localAuthFixture && request.url() === origin + "/api/auth/config") {
            void request.respond({ status: 200, contentType: "application/json", body: JSON.stringify({ methods: [], local: true, email: true, policyConfigured: true, development: false }) });
          } else if (request.url().startsWith(origin + "/") || request.url().startsWith("data:")) void request.continue();
          else void request.abort();
        });
      }
      await configurePage(page);
      await page.setViewport({ width: 1280, height: 1000 });
      await page.goto(origin + "/auth/signin");
      await waitText(page, "Couldn’t load sign-in methods.");
      await (await elementWithText(page, "button", "Retry")).click();
      await waitText(page, "Continue with GitHub");
      assert.equal(await page.$('input[name="identifier"]'), null); checks++;
      assert.deepEqual(await page.$$eval("#workspace button", (buttons) => buttons.map((button) => button.textContent)), ["Continue with GitHub"]); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "signin-desktop.png") });
      localAuthFixture = true;
      await page.goto(origin + "/auth/activate#token=owned-browser-fixture");
      await page.waitForSelector("#username:enabled");
      await page.type("#username", "sample-user");
      assert.ok(await page.$eval("#username", (input) => input.checkValidity())); checks++;
      assert.equal(new URL(page.url()).hash, ""); checks++;
      await page.click('[aria-label="Show password"]');
      assert.equal(await page.$eval("#password", (input) => input.type), "text"); checks++;
      localAuthFixture = false;

      await context.setCookie({ name: "authjs.session-token", value: cookies.alice, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
      await page.goto(origin, { waitUntil: "networkidle0" });
      await waitText(page, "No unresolved critical or high findings.");
      const coverageLink = await page.waitForSelector('[aria-label="Incomplete scan coverage"] a');
      const coverageId = await coverageLink.evaluate((link) => link.pathname.split("/").pop());
      const gapScan = await db.scan.findUniqueOrThrow({ where: { id: coverageId } });
      assert.ok(["partial", "failed"].includes(gapScan.status)); checks++;

      // A separate scan in the disposable browser database exercises non-empty queues.
      const examples = [
        { ruleId: "AEG-A02-001", ruleName: "Hardcoded cryptographic key", severity: "critical", filePath: "billing/receipts/signing.py", lineStart: 38, evidenceState: "candidate", owner: "Payments", codeSnippet: 'RECEIPT_FORMAT = "v1"\nSIGNING_KEY = "demo-fixture-only"\nDEFAULT_LOCALE = "en"', provenance: JSON.stringify({ snippet_start_line: 37 }), message: "The signing configuration contains a literal key. Check how the receipt service loads this value in production." },
        { ruleId: "AEG-SEC-001", ruleName: "Hardcoded password", severity: "high", filePath: "service/config/database.ts", lineStart: 67, evidenceState: "candidate", owner: "Platform", message: "Database configuration includes a literal password." },
        { ruleId: "AEG-API-015", ruleName: "Sensitive data in URL query parameters", severity: "medium", filePath: "clients/reporting.ts", lineStart: 112, evidenceState: "reachable", owner: "Reporting", message: "The reporting client includes an account identifier in its query string.",
          taintFlow: JSON.stringify([{ file: "clients/reporting.ts", line: 112, message: "Account identifier added to the reporting URL." }]) },
      ];
      const displayScan = await db.scan.create({ data: {
        projectId, repository: "ledger/billing-service", branch: "main", commitSha: "7fc82a6b321026ef52a37d31df2df673bda871b1", status: "completed", filesScanned: 84, duration: 12.4,
        findings: { create: examples.map((entry) => ({ ...entry, lineEnd: entry.lineStart })) },
      } });
      await page.reload({ waitUntil: "networkidle0" });
      await waitText(page, examples[0].ruleName); await waitText(page, examples[1].ruleName);
      const countsInScan = async (id) => page.$eval('.overview-scans a[href="/scans/' + id + '"]', (link) => {
        const cells = link.closest("tr").cells;
        return [cells[2].textContent, cells[3].textContent];
      });
      assert.deepEqual(await countsInScan(queuedScanId), ["—No result recorded", "—No result recorded"]); checks++;
      assert.deepEqual(await countsInScan(displayScan.id), ["84", "3"]); checks++;
      const totals = await page.evaluate(async () => {
        const stats = await (await globalThis.fetch("/api/stats")).json();
        return {
          active: ["open", "triaged", "confirmed", "in_progress"].reduce((sum, status) => sum + (stats.statuses[status] || 0), 0),
          overdue: stats.overdue, regressed: stats.regressions,
        };
      });
      for (const [queue, expected] of Object.entries(totals)) {
        const link = await page.$(`#workspace a[href="/findings?queue=${queue}"]`);
        assert.equal(Number((await link.evaluate((element) => element.textContent)).replaceAll(",", "")), expected);
        const count = await page.evaluate(async (value) => (await (await globalThis.fetch("/api/findings?queue=" + value)).json()).total, queue);
        assert.equal(count, expected); checks++;
      }
      const lead = await db.finding.findFirstOrThrow({ where: { scanId: displayScan.id, ruleId: examples[0].ruleId } });
      const expandedRecord = '[aria-label="Priority findings"] article[data-expanded="true"]';
      const leadLink = expandedRecord + " h3 a";
      for (const width of [320, 390, 820, 1440]) {
        await page.setViewport({ width, height: width < 768 ? 844 : 1000 });
        assert.equal(await page.$eval(leadLink, (link) => link.getAttribute("href")), "/findings/" + lead.id); checks++;
        assert.ok(await page.$eval(expandedRecord, (el) => el.getBoundingClientRect().bottom <= globalThis.innerHeight)); checks++;
        assert.equal(await page.$eval(expandedRecord + " .priority-path code", (node) => node.textContent), examples[0].filePath); checks++;
        assert.ok(await page.$eval("#workspace", (el) => el.scrollWidth <= el.clientWidth)); checks++;
        if (width === 390 && process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "overview-lead-mobile.png") });
      }
      for (const width of [390, 1440]) {
        await page.setViewport({ width, height: width === 390 ? 844 : 1000 });
        for (const index of [1, 0]) {
          const record = examples[index];
          const toggle = await page.$('button[aria-label^="Show context for ' + record.ruleName + ',"]');
          await toggle.focus();
          await page.keyboard.press("Enter");
          const state = await toggle.evaluate((button) => {
            const details = globalThis.document.getElementById(button.getAttribute("aria-controls"));
            return {
              focused: button === globalThis.document.activeElement,
              expanded: button.getAttribute("aria-expanded"), visible: details.checkVisibility(),
              path: details.querySelector("code").textContent, line: details.querySelector(".priority-path span").ariaLabel,
              facts: [...details.querySelectorAll("dd")].map((value) => value.textContent),
            };
          });
          assert.deepEqual(state, { focused: true, expanded: "true", visible: true, path: record.filePath, line: "Line " + record.lineStart, facts: ["Static candidate", record.owner] }); checks++;
          assert.equal((await page.$$(expandedRecord)).length, 1); checks++;
        }
      }
      await page.focus(expandedRecord + " a.priority-location");
      await page.keyboard.press("Enter");
      const evidenceInView = () => globalThis.document.activeElement?.id === "finding-evidence"
        && globalThis.document.activeElement.getBoundingClientRect().top >= 0
        && globalThis.document.activeElement.getBoundingClientRect().top < globalThis.innerHeight;
      await page.waitForFunction(evidenceInView);
      assert.equal(new URL(page.url()).hash, "#finding-evidence"); checks++;
      await page.reload({ waitUntil: "networkidle0" });
      await page.waitForFunction(evidenceInView);
      assert.equal(await page.$eval('#finding-evidence [role="tab"][aria-selected="true"]', (tab) => tab.textContent), "source"); checks++;
      await page.goBack({ waitUntil: "networkidle0" });
      await page.waitForSelector(leadLink);
      await page.focus(leadLink);
      await page.keyboard.press("Enter");
      await page.waitForFunction((id) => globalThis.location.pathname === "/findings/" + id, {}, lead.id); checks++;
      await page.goBack({ waitUntil: "networkidle0" });
      await waitText(page, examples[0].ruleName);
      await checkRenderedContrast(page);
      const priorityContrast = ".priority-location code, .priority-location span, .priority-facts dd, .priority-record-heading button, .overview-totals dt, .overview-scans tbody tr, nav a";
      await checkRenderedContrast(page, priorityContrast);
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "overview-desktop.png") });
      await (await elementWithText(page, "aside.app-sidebar button", "Dark mode")).click();
      await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
      await checkRenderedContrast(page, priorityContrast);
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "overview-desktop-dark.png") });
      await (await elementWithText(page, "aside.app-sidebar button", "Light mode")).click();
      await page.goto(origin + "/scans/" + displayScan.id, { waitUntil: "networkidle0" });
      const records = 'ul[aria-label="Findings in this scan"] > li';
      await page.waitForSelector(records);
      assert.equal((await page.$$(records)).length, 3); checks++;
      assert.deepEqual(await page.$$eval(records, (nodes) => nodes.map((node) => node.querySelector("h3").textContent)), examples.map((item) => item.ruleName)); checks++;
      assert.ok(await page.$$eval(records, (nodes) => nodes[0].textContent.includes("Static candidate") && nodes[2].textContent.includes("Static path"))); checks++;
      assert.equal(await page.$eval("h1", (node) => node.textContent), "ledger/billing-service"); checks++;
      await page.setViewport({ width: 1440, height: 900 });
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "scan-desktop.png") });
      const criticalLevel = await elementWithText(page, 'aside[aria-label="Scan breakdown"] button', "critical");
      await criticalLevel.click();
      await waitText(page, "1 of 3 records");
      assert.ok(page.url().endsWith("/scans/" + displayScan.id)); checks++;
      assert.ok((await page.$eval(records, (node) => node.textContent)).includes(examples[0].filePath)); checks++;
      await (await elementWithText(page, "button", "Clear filters")).click();
      await (await elementWithText(page, 'aside[aria-label="Scan breakdown"] button', examples[1].ruleName)).click();
      await waitText(page, "1 of 3 records");
      assert.ok((await page.$eval(records, (node) => node.textContent)).includes(examples[1].filePath)); checks++;
      await (await elementWithText(page, "button", "Clear filters")).click();
      await page.setViewport({ width: 390, height: 844 });
      await page.evaluate(() => globalThis.document.getElementById("workspace").scrollTo(0, 0));
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "scan-mobile.png") });
      for (const width of [390, 320]) {
        await page.setViewport({ width, height: 844 });
        assert.ok(await page.$eval("#workspace", (node) => node.scrollWidth <= node.clientWidth)); checks++;
      }
      await page.type('input[type="search"]', "unmatched-display-path");
      await waitText(page, "No findings match these filters.");
      assert.equal((await page.$$(records)).length, 0); checks++;
      await (await elementWithText(page, "button", "Clear filters")).click();
      await page.select('select', "medium");
      await waitText(page, "1 of 3 records");
      await page.click(records + " a");
      await page.waitForFunction(() => globalThis.location.pathname.startsWith("/findings/")); checks++;
      await waitText(page, examples[2].ruleName);
      await page.goto(origin + "/scans/owned-missing-scan", { waitUntil: "domcontentloaded" });
      await waitText(page, "This scan could not be found or is outside your workspace."); checks++;
      await page.setViewport({ width: 1280, height: 1000 });
      await page.goto(origin, { waitUntil: "networkidle0" });
      await page.click('#workspace a[href="/findings?queue=priority"]');
      await page.waitForSelector('button[aria-label="Clear review queue filter"]');
      assert.ok(page.url().includes("queue=priority")); checks++;
      await waitText(page, examples[0].ruleName);
      const results = '[aria-label="Finding results"]';
      await page.waitForSelector(results + " tbody .finding-summary button");
      await page.setViewport({ width: 1440, height: 900 });
      await (await elementWithText(page, ".finding-summary button", examples[0].ruleName)).click();
      await waitText(page, "demo-fixture-only");
      const caption = await page.$eval("#finding-inspector figcaption", (element) => element.innerText);
      assert.ok(caption.includes(examples[0].filePath + ":38") && !caption.includes("38–38")); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "findings-desktop.png") });
      await page.click('[aria-label="Close inspector"]');
      await (await elementWithText(page, ".finding-summary button", examples[1].ruleName)).click();
      await waitText(page, "No source snippet in this artifact.");
      assert.equal(await page.$('#finding-inspector [aria-label="Copy code"]'), null); checks++;
      await page.click('[aria-label="Close inspector"]');
      for (const width of [850, 390, 320]) {
        await page.setViewport({ width, height: 844 });
        await page.waitForFunction(() => globalThis.getComputedStyle(globalThis.document.querySelector(".finding-narrow")).display !== "none");
        const geometry = await page.evaluate(() => {
          const main = globalThis.document.querySelector("main");
          const viewport = globalThis.document.querySelector(".finding-scroll");
          const row = viewport.querySelector("tbody tr");
          return {
            fits: main.scrollWidth <= main.clientWidth && viewport.scrollWidth <= viewport.clientWidth,
            text: row.innerText,
            touchWidth: row.querySelector("label").getBoundingClientRect().width,
          };
        });
        assert.ok(geometry.fits && geometry.touchWidth >= 44, "Finding list must fit at " + width); checks++;
        assert.match(geometry.text, /Static candidate/); checks++;
      }
      await page.setViewport({ width: 390, height: 844 });
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "findings-mobile.png") });
      const titleButton = await elementWithText(page, ".finding-summary button", examples[0].ruleName);
      await titleButton.click();
      await page.waitForFunction(() => globalThis.document.activeElement?.id === "finding-inspector"); checks++;
      await page.focus('#finding-inspector [role="tab"][aria-selected=true]');
      await page.keyboard.press("ArrowRight");
      await page.waitForFunction(() => globalThis.document.activeElement?.textContent === "remediation"); checks++;
      await waitText(page, "View rule " + examples[0].ruleId);
      await page.keyboard.press("Escape");
      await page.waitForFunction((title) => globalThis.document.activeElement?.textContent === title, {}, examples[0].ruleName); checks++;
      await page.click('button[aria-controls="finding-filters"]');
      await page.select('select[aria-label="All severities"]', "critical");
      await page.waitForFunction(() => globalThis.document.querySelectorAll(".finding-summary").length === 1);
      await page.click('button[aria-controls="finding-filters"]');
      assert.equal(await page.$eval('#finding-filters', (element) => element.hidden), true); checks++;
      assert.equal(await page.$eval('button[aria-controls="finding-filters"]', (button) => button.textContent), "Filters1"); checks++;
      await page.select('select[aria-label="Finding view"]', "0");
      await waitText(page, examples[2].ruleName);
      await (await elementWithText(page, ".finding-summary button", examples[2].ruleName)).click();
      await page.focus('#finding-inspector [role="tab"][aria-selected=true]');
      await page.keyboard.press("ArrowRight");
      await waitText(page, "Account identifier added to the reporting URL.");
      await page.keyboard.press("Escape");
      await page.setViewport({ width: 1280, height: 1000 });
      const sharedStorage = "11111111-1111-4111-8111-111111111111";
      const manifest = [
        'name = "receipts"', 'main = "src/index.ts"', 'compatibility_date = "2026-11-01"',
        'workers_dev = false', '', '[env.production]', 'preview_urls = true',
        '', '[env.production.vars]', 'SIGNING_KEY = "owned-browser-configuration-canary"',
        '', '[[env.development.d1_databases]]', 'binding = "LOCAL_RECEIPTS"', 'database_name = "local-receipts"',
        'database_id = "22222222-2222-4222-8222-222222222222"', `preview_database_id = "${sharedStorage}"`, 'remote = true',
        '', '[[env.production.d1_databases]]', 'binding = "ARCHIVE"', 'database_name = "archived-receipts"',
        `database_id = "${sharedStorage}"`,
        '', '[[previews.d1_databases]]', 'binding = "BRANCH_RECEIPTS"', 'database_name = "branch-receipts"',
        `database_id = "${sharedStorage}"`, 'preview_database_id = "33333333-3333-4333-8333-333333333333"', 'remote = false',
      ].join("\n");
      const commit = "b".repeat(40);
      const snapshot = makeSourceSnapshot({ provider: "github", ownerSlug: "ledger/receipt-worker", commitSha: commit }, {
        ref: commit, truncated: false, files: [{ path: "workers/receipts/wrangler.toml", content: manifest }],
      });
      const { report } = await runPythonSnapshot(snapshot, new globalThis.AbortController().signal, async () => {});
      assert.ok(!JSON.stringify(report).includes("owned-browser-configuration-canary")); checks++;
      const uploaded = await page.evaluate(async ({ report, projectId }) => {
        const response = await globalThis.fetch("/api/upload?projectId=" + encodeURIComponent(projectId) + "&repository=ledger%2Freceipt-worker&branch=configuration-review", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(report),
        });
        return { status: response.status, receipt: await response.json() };
      }, { report, projectId });
      assert.equal(uploaded.status, 200, JSON.stringify(uploaded.receipt)); checks++;
      assert.equal(uploaded.receipt.findingsCount, 4); checks++;
      const binding = await db.finding.findFirstOrThrow({ where: { scanId: uploaded.receipt.scanId, ruleId: "AEG-CF-001" } });
      await page.goto(origin + "/findings?search=wrangler", { waitUntil: "networkidle0" });
      await (await elementWithText(page, ".finding-summary button", binding.ruleName)).click();
      await waitText(page, "env.production.vars.SIGNING_KEY = [withheld]");
      assert.deepEqual(await page.$$eval('#finding-inspector [role="tab"]', (buttons) => buttons.map((b) => b.textContent)), ["Settings", "remediation"]); checks++;
      assert.match(await page.$eval('#finding-inspector [role="tabpanel"]', (node) => node.innerText), /Line 10/); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "configuration-desktop.png") });
      await page.click('[aria-label="Close inspector"]');
      await page.setViewport({ width: 390, height: 844 });
      await (await elementWithText(page, ".finding-summary button", binding.ruleName)).click();
      await page.waitForFunction(() => globalThis.document.activeElement?.id === "finding-inspector");
      assert.ok(await page.$eval(".finding-results", (node) => !node.getClientRects().length)); checks++;
      await page.waitForFunction(() => globalThis.document.querySelector('[aria-label="Parsed settings"]')?.getBoundingClientRect().bottom <= globalThis.innerHeight);
      assert.ok(await page.$eval("#finding-inspector", (node) => node.scrollWidth <= node.clientWidth)); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "configuration-mobile.png") });
      await page.focus('#finding-inspector [role="tab"][aria-selected=true]');
      await page.keyboard.press("End");
      await waitText(page, "move it to an encrypted secret"); checks++;
      await (await elementWithText(page, "button", "Back to list")).click();
      await page.waitForFunction((title) => globalThis.document.activeElement?.textContent === title, {}, binding.ruleName); checks++;
      await page.click(`a[aria-label="Full details for ${binding.ruleName}"]`);
      await waitText(page, "env.production.vars.SIGNING_KEY = [withheld]");
      assert.ok(await page.$eval('[aria-label="Parsed settings"]', (node) => node.getBoundingClientRect().bottom <= globalThis.innerHeight)); checks++;
      const detailText = await page.$eval("#workspace", (node) => node.innerText);
      assert.ok(detailText.indexOf("Finding evidence") < detailText.indexOf("Save decision")); checks++;
      assert.ok(await page.$("#nearby-calls-heading") === null && !detailText.includes("owned-browser-configuration-canary")); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "configuration-detail-mobile.png") });
      await page.select('select[aria-label="Triage status"]', "false_positive");
      assert.equal(await page.$eval('textarea[aria-label="Triage rationale"]', (input) => input.validity.valueMissing), true); checks++;
      const readDecision = () => page.evaluate(async (id) => {
        const response = await globalThis.fetch("/api/findings/" + id);
        return (await response.json()).workflow;
      }, binding.id);
      assert.equal((await readDecision()).status, "open"); checks++;
      await (await elementWithText(page, 'button[type="submit"]', "Save decision")).click();
      assert.equal(await page.evaluate(() => globalThis.document.activeElement?.getAttribute("aria-label")), "Triage rationale"); checks++;
      await page.type('textarea[aria-label="Triage rationale"]', "Owned test binding with a synthetic value.");
      await (await elementWithText(page, 'button[type="submit"]', "Save decision")).click();
      await waitText(page, "Decision saved.");
      const decision = await readDecision();
      assert.equal(decision.status, "false_positive"); checks++;
      assert.equal(decision.reason, "Owned test binding with a synthetic value."); checks++;
      await page.click('a[aria-label="Back to findings"]');
      await page.waitForFunction(() => globalThis.document.querySelector('input[aria-label="Search findings"]')?.value === "wrangler"); checks++;
      await page.goto(origin + "/findings/" + binding.id + "/report", { waitUntil: "networkidle0" });
      await waitText(page, "Configuration settings");
      assert.equal(await page.$eval('ul[aria-label="Parsed settings"] li', (node) => node.innerText), binding.codeSnippet); checks++;
      const exported = await page.evaluate(async (id) => (await globalThis.fetch("/api/findings/" + id + "/report")).text(), binding.id);
      assert.ok(exported.includes("## Configuration settings") && !exported.includes("## Recorded flow")); checks++;
      assert.ok(exported.includes("Owned test binding with a synthetic value.") && exported.includes("This scan observation")); checks++;
      await checkHistoricalReport(page, db, projectId, origin, dirname(reportPath));
      await page.setViewport({ width: 1280, height: 1000 });
      const shared = await db.finding.findFirstOrThrow({ where: { scanId: uploaded.receipt.scanId, ruleId: "AEG-CF-003" } });
      assert.ok(!JSON.stringify(report).includes(sharedStorage)); checks++;
      const manifestLines = manifest.split("\n");
      const sourceLine = (text) => manifestLines.indexOf(text) + 1;
      const remoteLine = sourceLine("remote = true");
      const selectorLine = sourceLine(`preview_database_id = "${sharedStorage}"`);
      const peerLine = sourceLine(`database_id = "${sharedStorage}"`);
      assert.equal(shared.lineStart, remoteLine); checks++;
      await page.goto(origin + "/findings/" + shared.id, { waitUntil: "networkidle0" });
      for (const width of [1440, 390, 320]) {
        await page.setViewport({ width, height: width < 768 ? 844 : 1000 });
        await waitText(page, "Matching deployment");
        const panel = await page.$('[aria-label="Parsed settings"]');
        const value = await panel.evaluate((node) => node.innerText);
        for (const text of ["Local development", "env.development", "env.production", "D1 database",
          "remote = true · line " + remoteLine, "preview_database_id · line " + selectorLine, "[0].database_id · line " + peerLine]) {
          assert.ok(value.includes(text), text); checks++;
        }
        assert.ok(!value.includes(sharedStorage)); checks++;
        const overflow = await page.$eval("#workspace", (el) => el.scrollWidth <= el.clientWidth ? null : {
          width: el.scrollWidth, elements: [...el.querySelectorAll("*")].filter((item) => item.getBoundingClientRect().right > el.getBoundingClientRect().right).map((item) => item.tagName + "." + item.className).slice(0, 8) } );
        assert.equal(overflow, null, "Setting detail overflow at " + width + ": " + JSON.stringify(overflow)); checks++;
        if (width !== 320 && process.env.AEGIFY_UI_ARTIFACTS) {
          await panel.evaluate((node) => node.scrollIntoView({ block: "nearest" }));
          await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, width === 390 ? "storage-mobile.png" : "storage-desktop.png") });
        }
      }
      await page.goto(origin + "/findings/" + shared.id + "/report");
      await waitText(page, "Matching deployment"); checks++;
      const markdown = await page.evaluate(async (id) => (await globalThis.fetch("/api/findings/" + id + "/report")).text(), shared.id);
      assert.ok(markdown.includes(shared.codeSnippet) && !markdown.includes(sharedStorage)); checks++;
      const preview = await db.finding.findFirstOrThrow({ where: { scanId: uploaded.receipt.scanId, ruleId: "AEG-CF-004" } });
      const previewLine = manifestLines.lastIndexOf(`database_id = "${sharedStorage}"`) + 1;
      assert.equal(preview.lineStart, previewLine); checks++;
      await page.goto(origin + "/findings/" + preview.id, { waitUntil: "networkidle0" });
      for (const width of [1440, 820, 390, 320]) {
        await page.setViewport({ width, height: width < 768 ? 844 : 960 });
        await waitText(page, "inherits the top-level previews block.");
        const rows = await page.$$eval('[aria-label="Parsed settings"] dl > div', (items) => items.map((row) => row.innerText));
        assert.deepEqual(rows.map((value) => value.split("\n").filter(Boolean)), [
          ["Worker Preview", "default.previews", "d1_databases[0].database_id", "Line " + previewLine],
          ["Worker deployment", "env.production", "d1_databases[0].database_id", "Line " + peerLine],
        ]); checks++;
        assert.ok(await page.$eval("#workspace", (node) => node.scrollWidth <= node.clientWidth)); checks++;
        assert.ok(!(await page.$eval("#workspace", (node) => node.innerText)).includes(sharedStorage)); checks++;
        await checkRenderedContrast(page, '[aria-label="Parsed settings"] dt, [aria-label="Parsed settings"] dd > code, [aria-label="Parsed settings"] p');
        if (process.env.AEGIFY_UI_ARTIFACTS && [1440, 390].includes(width)) {
          const settings = await page.$('[aria-label="Parsed settings"]');
          await settings.evaluate((node) => node.scrollIntoView({ block: "nearest" }));
          await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "worker-preview-" + (width === 390 ? "mobile" : "desktop") + ".png") });
        }
        if (width === 1440) {
          await (await elementWithText(page, "button", "Dark mode")).click();
          await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
          await checkRenderedContrast(page, '[aria-label="Parsed settings"] dt, [aria-label="Parsed settings"] dd > code');
          if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "worker-preview-dark.png") });
          await (await elementWithText(page, "button", "Light mode")).click();
        }
      }
      await page.goto(origin + "/findings/" + preview.id + "/report");
      await waitText(page, "Worker deployment"); checks++;
      const exportedPreview = await page.evaluate(async (id) => (await globalThis.fetch("/api/findings/" + id + "/report")).text(), preview.id);
      assert.ok(exportedPreview.includes(preview.codeSnippet) && !exportedPreview.includes(sharedStorage)); checks++;
      for (const [saved, label] of [
        [{ isFalsePositive: false, confidence: 0.92, reasoning: "Owned legacy observation" }, "Needs human review"],
        [{ isFalsePositive: true, confidence: 0.55, reasoning: "Owned legacy observation" }, "Likely false positive"],
        [{ isFalsePositive: true, confidence: 12, reasoning: {}, mode: {}, reviewedAt: "invalid" }, "Likely false positive"],
        [{ isFalsePositive: false, verdict: "needs_review", confidence: 0.2, reasoning: "Missing deployment record" }, "Needs human review"],
      ]) {
        await db.finding.update({ where: { id: shared.id }, data: { llmAnalysis: JSON.stringify(saved) } });
        await page.goto(origin + "/findings/" + shared.id, { waitUntil: "networkidle0" });
        await waitText(page, label);
        const review = await page.$eval('section[aria-labelledby="model-review-heading"]', (el) => el.innerText);
        if (typeof saved.reasoning === "string") assert.ok(review.includes(saved.reasoning));
        else assert.ok(!review.includes("model estimate") && !review.includes("Invalid Date"));
        assert.ok(!review.includes("True Positive")); checks++;
        await page.select('select[aria-label="Review language"]', "ko");
        assert.equal(await page.$eval('select[aria-label="Review language"]', (el) => el.value), "ko"); checks++;
        assert.ok(await page.$eval("#workspace", (el) => el.scrollWidth <= el.clientWidth)); checks++;
      }
      await page.setViewport({ width: 1280, height: 1000 });
      const reviewed = await db.finding.create({ data: {
        scanId: displayScan.id, ruleId: "AEG-HOST-001", ruleName: "Partial URL host comparison",
        severity: "medium", filePath: "policy/origin.py", lineStart: 2, lineEnd: 2,
        message: "Review the hostname comparison used by the allowlist.",
        codeSnippet: 'def accepts(host):\n    return host.startswith("portal.example.test")',
        llmAnalysis: JSON.stringify({ verdict: "likely_true_positive", confidence: 0.82,
          analysis: "The prefix check accepts hostnames outside the configured service.",
          evidenceFor: ["The service compares a hostname prefix."],
          remediation: "Use an exact hostname comparison.",
          fixedCode: 'def accepts(host):\n    return host == "portal.example.test"' }),
      } });
      await page.goto(origin + "/findings/" + reviewed.id, { waitUntil: "networkidle0" });
      const compare = 'section[aria-label="Suggested code change"]';
      await waitText(page, "1 added, 1 removed");
      for (const width of [1440, 390, 320]) {
        await page.setViewport({ width, height: 900 });
        await page.$eval(compare, (el) => el.scrollIntoView({ block: "center" }));
        assert.ok(await page.$eval("#workspace", (el) => el.scrollWidth <= el.clientWidth)); checks++;
        const button = await elementWithText(page, compare + " button", "Original");
        await button.focus(); await page.keyboard.press("Enter");
        assert.match(await page.$eval(compare + " figure", (el) => el.innerText), /startswith/); checks++;
        await (await elementWithText(page, compare + " button", "Proposed")).click();
        assert.match(await page.$eval(compare + " figure", (el) => el.innerText), /host ==/); checks++;
        await (await elementWithText(page, compare + " button", "Changes")).click();
        assert.equal(await page.$$eval(compare + " tbody tr", (rows) => rows.length), 3); checks++;
        if (process.env.AEGIFY_UI_ARTIFACTS && width !== 320) {
          await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "code-comparison-" + width + ".png") });
        }
      }
      await db.finding.delete({ where: { id: reviewed.id } });
      await page.setViewport({ width: 1280, height: 1000 });
      await checkAgentHandoff(page, db, origin, displayScan.id);
      await page.setViewport({ width: 1280, height: 1000 });
      const stageRun = await db.agentRun.create({ data: {
        scanId: displayScan.id, status: "completed", currentRole: "steward", mode: "deep",
        artifactDigest: "b".repeat(64),
        stages: { create: [
          { sequence: 0, role: "surface", agentCode: "haetae", agentName: "Haetae", status: "completed",
            summary: "One receipt endpoint has a recorded route and authentication check.",
            facts: JSON.stringify({ endpoints: 1, endpointsWithoutDetectedAuth: 0, gatewayExposed: 0, runtimeObserved: 0,
              threatScenarios: [{ surface: "GET /receipts/{receiptId}", auth: "required" }] }) },
          { sequence: 1, role: "static", agentCode: "maenun", agentName: "Maenun", status: "completed",
            summary: "The receipt handler calls the signing service. The scan includes two source locations.",
            evidenceIds: JSON.stringify(["receipt-source-38"]), promptDigest: "a".repeat(64),
            reachability: JSON.stringify([{ findingId: "AEG-A02-001", endpoint: "/receipts/{receiptId}",
              method: "GET", entryPoint: "get_receipt", sink: "sign_receipt", staticComplete: true,
              runtimeObserved: false, impactProven: false, unresolvedLinks: [], evidenceIds: ["receipt-source-38"],
              hops: [{ function: "build_receipt", filePath: "billing/receipts/service.py", line: 24, snippet: "" },
                { function: "get_signing_key", filePath: "billing/receipts/signing.py", line: 38, snippet: 'return config["receipt_key"]' }] }]) },
          { sequence: 2, role: "dynamic", agentCode: "salgwaengi", agentName: "Salgwaengi", status: "completed" },
          { sequence: 3, role: "cve", agentCode: "geobukseon", agentName: "Geobukseon", status: "completed" },
          { sequence: 4, role: "synthesis", agentCode: "jangseung", agentName: "Jangseung", status: "completed",
            summary: "Review the signing configuration used by the receipt service." },
          { sequence: 5, role: "steward", agentCode: "hanul", agentName: "Hanul", status: "completed" },
        ] },
        events: { create: { type: "analysis_finished", actor: "scanner", message: "Receipt analysis completed." } },
      } });
      await page.goto(origin + "/agents/" + stageRun.id);
      const activePanel = '[role="tabpanel"][data-state="active"]';
      await page.waitForSelector(activePanel + " h2");
      assert.equal(await page.$eval(activePanel + " h2", (heading) => heading.textContent), "Final assessment"); checks++;
      await page.focus('[role="tab"][aria-selected="true"]');
      await page.keyboard.press("Home");
      await page.waitForFunction(() => globalThis.document.activeElement?.textContent.includes("Environment & threats")
        && globalThis.document.activeElement?.getAttribute("aria-selected") === "true");
      await page.keyboard.press("ArrowDown");
      await page.waitForSelector('[aria-label="Recorded code path"]');
      assert.equal(await page.$$eval('[aria-label="Recorded code path"] li', (steps) => steps.length), 4); checks++;
      assert.equal(await page.$eval('[role="tab"][aria-selected="true"]', (tab) => globalThis.document.activeElement === tab), true); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "agent-analysis-desktop.png") });
      await (await elementWithText(page, "summary", "Stage evidence")).click();
      await waitText(page, "receipt-source-38");
      await (await elementWithText(page, "summary", "Run history")).click();
      await waitText(page, "Receipt analysis completed.");
      await page.setViewport({ width: 390, height: 844 });
      await page.select('#workspace select', "surface");
      await waitText(page, "GET /receipts/{receiptId}");
      assert.equal(await page.$eval('#workspace select', (select) => select.labels[0].textContent.trim().startsWith("Stage")), true); checks++;
      await page.select('#workspace select', "static");
      await page.waitForSelector('[aria-label="Recorded code path"]');
      assert.ok(await page.evaluate(() => {
        const main = globalThis.document.querySelector("main");
        return main.scrollWidth <= main.clientWidth && globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth;
      }), "The recorded path must fit a mobile viewport"); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "agent-analysis-mobile.png") });
      await page.setViewport({ width: 1280, height: 1000 });
      // Drafts stay attached to their own evidence record while the reviewer edits.
      const documents = ["billing", "receipts", "ledger", "archive"];
      const draftRun = await db.agentRun.create({ data: {
        scanId: displayScan.id, status: "awaiting_approval", currentRole: "dynamic",
        stages: { create: { sequence: 0, role: "dynamic", agentCode: "salgwaengi", agentName: "Salgwaengi",
          status: "waiting_approval", dynamicPlans: JSON.stringify(documents.map((id) => ({
            id, requestTemplate: id, targetScope: "owned fixture",
          }))) } },
        approvals: { create: documents.map((id, index) => ({
          resourceId: id, scopeDigest: "test-scope-" + id, status: index < 2 ? "pending" : "approved",
        })) },
      } });
      await page.goto(origin + "/agents/" + draftRun.id);
      await page.waitForSelector('textarea[id^="note-"]');
      for (const kind of ["note", "evidence"]) {
        const selector = `textarea[id^="${kind}-"]`;
        const fields = await page.$$(selector);
        assert.equal(fields.length, 2);
        await fields[0].type("first document");
        await fields[1].type("second document");
        assert.deepEqual(await page.$$eval(selector, (inputs) => inputs.map((el) => el.value)), ["first document", "second document"]); checks++;
        assert.ok(await page.$$eval(selector, (inputs) => inputs.every((el) => el.labels.length === 1))); checks++;
      }
      const partialReceipt = await page.evaluate(async (projectId) => {
        const query = new globalThis.URLSearchParams({ projectId, repository: "ledger/settlement-worker", branch: "release" });
        const response = await globalThis.fetch("/api/upload?" + query, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ version: "2.1.0", runs: [{
            tool: { driver: { name: "Aegify" } }, results: [],
            invocations: [{ executionSuccessful: true, properties: { filesScanned: 47, durationSeconds: 8.2 } }],
            properties: { analysisStatus: "completed", taintAnalysis: {
              truncated: true, contexts_analyzed: 200, warnings: ["global taint hit the 200-context bound"],
            } },
          }] }),
        });
        if (!response.ok) throw new Error("Partial scan import returned " + response.status);
        return response.json();
      }, projectId);
      assert.equal(partialReceipt.status, "partial"); checks++;
      const partialRun = await db.scan.findUniqueOrThrow({ where: { id: partialReceipt.scanId } });
      const activeRun = await db.scan.create({ data: {
        projectId, repository: "ledger/customer-portal", branch: "main", status: "running", scanType: "repo-ai-candidate",
        progressMessage: "Reviewing source files", progressPercent: 42, progressEta: 65,
      } });
      await page.setViewport({ width: 1440, height: 900 });
      await page.goto(origin + "/scans");
      await waitText(page, "ledger/billing-service");
      const ledger = 'section[aria-label="Scan history"]';
      const row = await (await page.$(ledger + ' table a[href="/scans/' + displayScan.id + '"]')).evaluateHandle((link) => link.closest("tr"));
      assert.equal(await row.$eval("th", (cell) => cell.scope), "row"); checks++;
      assert.deepEqual(await row.$$eval('[aria-label="Severity counts"] li', (items) => items.map((item) => item.textContent)), ["critical 1", "high 1", "medium 1"]); checks++;
      assert.equal(await page.$eval(ledger + " table progress", (element) => element.value), 42); checks++;
      assert.match(await page.$eval(ledger + " table progress", (progress) => progress.closest("tr").innerText), /Awaiting results/); checks++;
      assert.match(await page.$eval(ledger + " table", (element) => element.innerText), /Incomplete coverage/); checks++;
      assert.equal(await page.$eval(ledger + ' ul[aria-label="Recorded runs"]', (list) => list.checkVisibility()), false); checks++;
      const paged = await page.evaluate(async () => {
        const response = await globalThis.fetch("/api/scans?page=invalid&limit=9999");
        return response.json();
      });
      assert.equal(paged.page, 1); assert.equal(paged.limit, 100); checks++;
      assert.deepEqual(paged.scans.find((scan) => scan.id === displayScan.id).severities, {critical: 1, high: 1, medium: 1}); checks++;
      assert.deepEqual(paged.scans.find((scan) => scan.id === activeRun.id).severities, {}); checks++;
      await page.evaluate(() => globalThis.document.getElementById("workspace").scrollTo(0, 0));
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "history-desktop.png") });
      for (const width of [820, 390, 320]) {
        await page.setViewport({ width, height: 844 });
        assert.ok(await page.$eval("#workspace", (node) => node.scrollWidth <= node.clientWidth)); checks++;
        assert.equal(await page.$eval(ledger + " table", (table) => table.checkVisibility()), false); checks++;
        assert.ok(await page.$eval(ledger + ' ul[aria-label="Recorded runs"]', (list) => list.checkVisibility())); checks++;
        if (width === 390 && process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "history-mobile.png") });
      }
      const partialLink = await page.$(ledger + ' ul[aria-label="Recorded runs"] a[href="/scans/' + partialRun.id + '"]');
      assert.ok(await partialLink.evaluate((link) => link.getBoundingClientRect().height >= 44)); checks++;
      await partialLink.focus(); await page.keyboard.press("Enter");
      await page.waitForFunction((id) => globalThis.location.pathname === "/scans/" + id, {}, partialRun.id); checks++;
      await waitText(page, "Data flow reached its limit of 200 call contexts.");
      const warning = await page.waitForSelector('[role="status"] h2');
      assert.equal(await warning.evaluate((el) => el.textContent), "Partial analysis"); checks++;
      for (const width of [390, 1440]) {
        await page.setViewport({ width, height: 900 });
        assert.ok(await warning.evaluate((el) => {
          const region = el.closest('[role="status"]');
          return region.scrollWidth <= region.clientWidth && region.innerText.includes("Earlier findings stay open");
        })); checks++;
        if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, width === 390 ? "partial-scan-mobile.png" : "partial-scan-desktop.png") });
      }
      await page.goto(origin + "/scans");
      await page.setViewport({ width: 1280, height: 1000 });
      const refresh = await page.waitForSelector("select");
      await refresh.select("30000");
      assert.equal(await page.evaluate(() => globalThis.localStorage.getItem("scans_refresh_interval")), "30000"); checks++;
      await refresh.select("0");
      const routePath = "/v1/billing/receipts/{receipt_id}";
      const routeSource = { filePath: "src/routes/receipts.py", lineStart: 24, lineEnd: 31, framework: "Flask" };
      const receiptRoute = await db.endpoint.create({ data: {
        ...routeSource, scanId: displayScan.id, method: "GET", path: routePath, handlerFunction: "read_receipt",
        authRequired: true, calledByFrontend: true, frontendCallCount: 2, exposedViaGateway: true,
      } });
      await db.endpoint.createMany({ data: [
        { ...routeSource, scanId: displayScan.id, method: "POST", path: "/v1/billing/receipts", handlerFunction: "create_receipt", lineStart: 44, lineEnd: 52 },
        { ...routeSource, scanId: partialRun.id, method: "GET", path: routePath, handlerFunction: "receipt_status", runtimeObserved: true, runtimeObservationCount: 3 },
        { ...routeSource, scanId: displayScan.id, method: "GET", path: "/assets/billing.css", handlerFunction: "static_asset" },
      ] });
      failEndpointsOnce = true;
      await page.setViewport({ width: 1440, height: 900 });
      await page.goto(origin + "/endpoints");
      await waitText(page, "Couldn’t load endpoint records.");
      assert.doesNotMatch(await page.$eval("#workspace", (node) => node.innerText), /No API routes recorded/); checks++;
      await (await elementWithText(page, "button", "Retry")).click();
      await waitText(page, routePath);
      const endpointRows = 'ul[aria-label="Endpoint records"] > li';
      const searchEndpoints = 'section[aria-label="Endpoint inventory"] input[type="search"]';
      await page.type(searchEndpoints, "unmatched-owned-route-name", { delay: 0 });
      assert.equal(await page.$eval(searchEndpoints, (node) => node.value), "unmatched-owned-route-name"); checks++;
      assert.equal(new URL(page.url()).searchParams.get("q"), "unmatched-owned-route-name"); checks++;
      await waitText(page, "No endpoints match these filters");
      await (await elementWithText(page, "button", "Clear search")).click();
      assert.equal(await page.$eval(searchEndpoints, (node) => node.value), ""); checks++;
      assert.equal(new URL(page.url()).searchParams.has("q"), false); checks++;
      // Create a separate history entry so editing with replaceState preserves Back/Forward.
      await page.evaluate(() => globalThis.history.pushState(null, "", globalThis.location.href));
      await page.type(searchEndpoints, "billing/receipts", { delay: 0 });
      assert.equal(await page.$eval(searchEndpoints, (node) => node.value), "billing/receipts"); checks++;
      await page.goBack();
      await page.waitForFunction((selector) => globalThis.document.querySelector(selector)?.value === ""
        && !new globalThis.URL(globalThis.location.href).searchParams.has("q"), {}, searchEndpoints);
      await page.goForward();
      await page.waitForFunction((selector) => globalThis.document.querySelector(selector)?.value === "billing/receipts"
        && new globalThis.URL(globalThis.location.href).searchParams.get("q") === "billing/receipts", {}, searchEndpoints);
      await waitText(page, "3 routes");
      assert.equal((await page.$$(endpointRows)).length, 3); checks++;
      assert.equal(new URL(page.url()).searchParams.get("q"), "billing/receipts"); checks++;
      await waitText(page, "2 with linked evidence");
      assert.match(await page.$eval(endpointRows + ' a[href="/endpoints/' + receiptRoute.id + '"]', (node) => node.textContent), /Frontend \(2\) · Gateway/); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "endpoints-desktop.png") });
      await (await elementWithText(page, "button", "By file")).click();
      await waitText(page, "2 source groups");
      await (await elementWithText(page, "button", "Expand all")).click();
      assert.equal((await page.$$(endpointRows)).length, 3); checks++;
      await (await elementWithText(page, "button", "Collapse all")).click();
      assert.equal((await page.$$(endpointRows)).length, 0); checks++;
      await (await elementWithText(page, 'ul[aria-label="Source groups"] button', "ledger/billing-service")).click();
      assert.equal((await page.$$(endpointRows)).length, 2); checks++;
      await (await elementWithText(page, "button", "Routes")).click();
      await (await elementWithText(page, "button", "Filters")).click();
      const evidenceLabel = await elementWithText(page, "#endpoint-filters label", "Linked evidence");
      await (await evidenceLabel.$("select")).select("gateway");
      await waitText(page, "1 with linked evidence");
      assert.equal((await page.$$(endpointRows)).length, 1); checks++;
      const httpMethod = await elementWithText(page, "#endpoint-filters label", "HTTP method");
      await (await httpMethod.$("select")).select("POST");
      await waitText(page, "No endpoints match these filters");
      await (await elementWithText(page, "button", "Clear filters")).click();
      await waitText(page, routePath);
      await page.click('#endpoint-filters input[type="checkbox"]');
      await page.type(searchEndpoints, "/assets/billing.css");
      await waitText(page, "static_asset");
      assert.equal((await page.$$(endpointRows)).length, 1); checks++;
      await (await elementWithText(page, "button", "Clear filters")).click();
      await waitText(page, routePath);
      await (await elementWithText(page, 'button[aria-controls="endpoint-filters"]', "Filters")).click();
      await page.type(searchEndpoints, "billing/receipts");
      await waitText(page, "3 routes");
      for (const width of [820, 390, 320]) {
        await page.setViewport({ width, height: 844 });
        assert.ok(await page.$eval("#workspace", (node) => node.scrollWidth <= node.clientWidth)); checks++;
        assert.ok(await page.$eval(endpointRows + " a", (node) => node.getBoundingClientRect().height >= 44)); checks++;
        if (width === 390 && process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "endpoints-mobile.png") });
      }
      await (await page.$(endpointRows + ' a[href="/endpoints/' + receiptRoute.id + '"]')).focus();
      await page.keyboard.press("Enter");
      await page.waitForFunction((id) => globalThis.location.pathname === "/endpoints/" + id, {}, receiptRoute.id);
      await page.waitForFunction((path) => globalThis.document.querySelector("h1")?.textContent === path, {}, routePath); checks++;
      await page.goBack();
      await waitText(page, "3 routes");
      assert.equal(await page.$eval(searchEndpoints, (node) => node.value), "billing/receipts"); checks++;
      await page.setViewport({ width: 1280, height: 1000 });
      await db.scan.deleteMany({ where: { id: { in: [partialRun.id, activeRun.id] } } });
      await page.goto(origin + "/rules");
      await waitText(page, "Workspace administrator access is required");
      assert.equal(await page.$('a[href="/rules/new"]'), null); checks++;
      // A separate browser session keeps background member requests from refreshing the administrator cookie.
      const adminContext = await browser.createBrowserContext();
      try {
        const page = await adminContext.newPage();
        await configurePage(page);
        await adminContext.setCookie({ name: "authjs.session-token", value: cookies.root, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
        const catalog = [
          { id: "AEG-DESER-001", name: "Python pickle deserialization", cweId: 502, languages: "python", severity: "critical", findingCount: 12 },
          { id: "AEG-EDGE-001", name: "Worker route exposes a preview deployment", languages: "wrangler", severity: "medium", findingCount: 8 },
          { id: "AEG-API-018", name: "Missing authorization on an API operation", cweId: 862, languages: "python, typescript", severity: "high", findingCount: 6 },
          { id: "AEG-XML-001", name: "XML parser enables external entities", cweId: 611, languages: "python", severity: "high", findingCount: 3 },
          { id: "AEG-A08-004", name: "YAML loader configuration", cweId: 502, languages: "python", severity: "high", findingCount: 2, enabled: false },
        ];
        const yamlRule = catalog.find((row) => row.id === "AEG-A08-004");
        Object.assign(yamlRule, {
          findingCount: 12, description: "Reviews the loader, registered constructors and the source of the YAML document.",
          sourceFile: "a08-data-integrity/data_integrity.yml", owaspCategory: "A08:2021 Software and Data Integrity Failures",
          yamlContent: ["rules:", "  - id: AEG-A08-004", "    name: YAML loader configuration", "    severity: high",
            "    languages: [python]", "    cwe_id: 502", "    semantic:", "      kind: python_yaml_loader",
            "    message: Review the YAML loader policy and input provenance."].join("\n"),
        });
        await db.rule.createMany({ data: catalog });
        const ruleScan = await db.scan.create({ data: {
          projectId, repository: "ledger/catalog-sample", status: "completed",
          findings: { create: Array.from({ length: 12 }, (_, index) => ({
            ruleId: yamlRule.id, ruleName: yamlRule.name, severity: "high", confidence: 0,
            filePath: "services/imports/reader_" + String(index).padStart(2, "0") + ".py", lineStart: 8, lineEnd: 8, message: "Review input.",
          })) },
        } });
        failCatalogOnce = true;
        await page.goto(origin + "/rules");
        await waitText(page, "Couldn’t load the rule catalog");
        await (await elementWithText(page, "button", "Retry")).click();
        await waitText(page, "Python pickle deserialization");
        const ruleRows = 'ul[aria-label="Detection rules"] li';
        const summaries = await page.evaluate(async () => (await (await globalThis.fetch("/api/rules?view=catalog")).json()).rules);
        assert.ok(summaries.every((row) => !("yamlContent" in row) && !("description" in row))); checks++;
        assert.ok(await page.evaluate(async () => (await (await globalThis.fetch("/api/rules")).json()).rules.some((row) => "yamlContent" in row))); checks++;
        failRuleSyncOnce = true;
        await (await elementWithText(page, "button", "Sync rules")).click();
        await waitText(page, "Rule sync failed");
        await page.goto(origin + "/rules");
        await waitText(page, "Python pickle deserialization");
        await page.setViewport({ width: 1440, height: 900 });
        if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "rules-desktop.png") });
        for (const width of [820, 390, 320]) {
          await page.setViewport({ width, height: 844 });
          assert.ok(await page.$eval("#workspace", (node) => node.scrollWidth <= node.clientWidth)); checks++;
          assert.ok(await page.$$eval(ruleRows + " a", (links) => links.every((el) => el.getBoundingClientRect().height >= 44))); checks++;
          const first = await page.$(ruleRows);
          assert.ok(await first.evaluate((row) => {
            const a = row.querySelector("a[aria-label]").getBoundingClientRect();
            const b = row.querySelector('[data-slot="badge"]').getBoundingClientRect();
            return a.left >= b.right || a.top >= b.bottom || a.bottom <= b.top;
          })); checks++;
          if (width === 390 && process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "rules-mobile.png") });
        }
        await page.type("#rule-query", "CWE-502", { delay: 0 });
        assert.equal(await page.$eval("#rule-query", el => el.value), "CWE-502"); checks++;
        await page.select("#rule-severity", "high");
        await waitText(page, "1 of " + summaries.length + " rules");
        assert.equal((await page.$$(ruleRows)).length, 1); checks++;
        assert.match(await page.$eval(ruleRows, (row) => row.innerText), /Disabled/); checks++;
        await (await page.$(ruleRows + ' a[href^="/rules/AEG-A08-004?"]')).focus();
        await page.keyboard.press("Enter");
        await page.waitForFunction(() => globalThis.location.pathname === "/rules/AEG-A08-004");
        await waitText(page, "12 distinct paths");
        await waitText(page, "0% average confidence");
        const ruleStats = await page.evaluate(async () => (await (await globalThis.fetch("/api/rules/AEG-A08-004")).json()).stats);
        assert.deepEqual([ruleStats.filePathCount, ruleStats.topFiles.length, ruleStats.totalFindings], [12, 10, 12]); checks++;
        const stateSwitch = 'button[role="switch"][aria-label="Enable rule"]';
        assert.equal(await page.$eval(stateSwitch, (node) => node.getAttribute("aria-checked")), "false"); checks++;
        await page.click(stateSwitch); await waitText(page, "Rule enabled.");
        assert.equal(await page.$eval(stateSwitch, (node) => node.getAttribute("aria-checked")), "true"); checks++;
        await page.setViewport({ width: 1440, height: 900 });
        await page.evaluate(() => globalThis.document.getElementById("workspace").scrollTo(0, 0));
        if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "rule-detail-desktop.png") });
        for (const width of [390, 320]) {
          await page.setViewport({ width, height: 844 });
          assert.ok(await page.$eval("#workspace", (node) => node.scrollWidth <= node.clientWidth)); checks++;
          if (width === 390 && process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "rule-detail-mobile.png") });
        }
        await (await elementWithText(page, "button", "Edit YAML")).click();
        const ruleEditor = await page.waitForSelector('textarea[aria-label="Rule YAML editor"]');
        await ruleEditor.focus();
        await ruleEditor.evaluate((editor) => editor.setSelectionRange(editor.value.length, editor.value.length));
        await ruleEditor.type("\n# local edit");
        await page.waitForFunction(() => [...globalThis.document.querySelectorAll("button")].some((btn) => btn.textContent === "Save definition" && !btn.disabled));
        failRuleSaveOnce = true;
        await (await elementWithText(page, "button", "Save definition")).click();
        await waitText(page, "Your draft is still open.");
        assert.ok(await ruleEditor.evaluate((editor) => editor.value.includes("# local edit"))); checks++;
        await (await elementWithText(page, "button", "Save definition")).click();
        await waitText(page, "Definition saved.");
        const savedRule = await db.rule.findUniqueOrThrow({ where: { id: yamlRule.id } });
        assert.ok(savedRule.yamlContent.includes("# local edit")); checks++;
        const catalogBack = await page.$('article header a[href^="/rules?"]');
        const backUrl = new URL(await catalogBack.evaluate((link) => link.href));
        assert.equal(backUrl.searchParams.get("q"), "CWE-502"); checks++;
        assert.equal(backUrl.searchParams.get("severity"), "high"); checks++;
        await page.goBack();
        await waitText(page, "YAML loader configuration");
        assert.equal(await page.$eval("#rule-query", (input) => input.value), "CWE-502"); checks++;
        assert.equal(await page.$eval("#rule-severity", (select) => select.value), "high"); checks++;
        const findingsLink = await page.$(ruleRows + ' a[aria-label="12 findings for AEG-A08-004"]');
        assert.equal(await findingsLink.evaluate((link) => link.getAttribute("href")), "/findings?ruleId=AEG-A08-004"); checks++;
        await page.type("#rule-query", "-missing");
        await waitText(page, "No rules match these filters.");
        await (await elementWithText(page, "button", "Clear filters")).click();
        await waitText(page, "Python pickle deserialization");
        await db.scan.delete({ where: { id: ruleScan.id } });
        await db.rule.createMany({ data: Array.from({ length: 51 }, (_, index) => ({
          id: "PAGE-" + index, name: "Catalog pagination sample " + index, severity: "low",
        })) });
        await page.goto(origin + "/rules?q=pagination");
        await waitText(page, "Page 1 of 2");
        assert.equal((await page.$$(ruleRows)).length, 50); checks++;
        await (await elementWithText(page, 'nav[aria-label="Rule pages"] button', "Next")).click();
        await waitText(page, "Page 2 of 2");
        assert.equal((await page.$$(ruleRows)).length, 1); checks++;
        assert.equal(await page.evaluate(() => globalThis.document.activeElement.getAttribute("role")), "status"); checks++;
      } finally {
        await adminContext.close();
      }
      await page.setViewport({ width: 1280, height: 1000 });
      await page.goto(origin + "/upload");
      await page.waitForSelector("select:enabled");
      const chooseFile = await page.waitForSelector('input[type="file"]');
      assert.ok(await chooseFile.evaluate((input) => input.disabled)); checks++;
      await page.select("select", projectId);
      const enabledFile = await page.waitForSelector('input[type="file"]:enabled'); checks++;
      await page.bringToFront();
      await enabledFile.focus();
      const [picker] = await Promise.all([page.waitForFileChooser(), (async () => {
        await page.waitForFunction(() => globalThis.document.hasFocus() && globalThis.document.activeElement?.matches('input[type="file"]:enabled'));
        await page.keyboard.press("Enter");
      })()]);
      await picker.cancel(); checks++;
      await checkScanImport(page, db, projectId, reportPath, () => { missingImportReceipt = true; });
      await page.setViewport({ width: 390, height: 844 });
      await page.goto(origin);
      await waitText(page, "High-risk review queue");
      assert.ok(await page.evaluate(() => {
        const main = globalThis.document.querySelector("main");
        return main.scrollWidth <= main.clientWidth && globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth;
      }), "Overview must reflow within the mobile workspace"); checks++;
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "overview-mobile.png") });
      const menu = 'button[aria-label="Open navigation"]';
      await page.click(menu);
      const dialog = '[role="dialog"][data-state="open"]';
      await page.waitForSelector(dialog);
      await page.$eval(dialog, async (element) => Promise.allSettled(element.getAnimations().map((animation) => animation.finished)));
      assert.ok(await page.$(dialog + ' button[aria-label="Sign out"]')); checks++;
      await (await elementWithText(page, dialog + " button", "Dark mode")).click();
      assert.ok(await page.evaluate(() => globalThis.document.documentElement.classList.contains("dark"))); checks++;
      await page.keyboard.press("Escape");
      await page.waitForFunction(() => globalThis.document.activeElement?.getAttribute("aria-label") === "Open navigation"); checks++;
      await checkRenderedContrast(page);
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "overview-dark.png") });
      await page.click(menu);
      await page.waitForSelector(dialog);
      await page.$eval(dialog, async (element) => Promise.allSettled(element.getAnimations().map((animation) => animation.finished)));
      await (await elementWithText(page, dialog + " button", "Light mode")).click();
      failReviewHistoryOnce = true;
      await page.click(dialog + ' a[href="/llm-scan"]');
      await page.waitForSelector("fieldset button[aria-pressed=true]");
      assert.equal(await page.$(dialog), null); checks++;
      await waitText(page, "Could not refresh recent runs.");
      await (await elementWithText(page, '[aria-label="Review runs"] button', "Retry")).click();
      await page.waitForSelector('[data-review-job] button');
      assert.equal(await page.$('[aria-label="Review runs"] [role="alert"]'), null); checks++;
      await page.setViewport({ width: 1280, height: 1000 });
      await checkRecoveryActivity(page, db, projectId, origin);
      await checkSpecificationReview(page, db, projectId, origin, dirname(reportPath));
      await page.setViewport({ width: 1280, height: 1000 });
      await page.goto(origin + "/llm-scan", { waitUntil: "networkidle0" });
      await waitText(page, "No AI worker is online");
      for (const [key, value] of Object.entries({ "llm.enabled": "true", "llm.provider": "anthropic", "llm.model": "owned-browser-model", "llm.anthropic_api_key": "owned-nonworking-placeholder" })) await db.setting.upsert({ where: { key }, create: { key, value }, update: { value } });
      const accessFinding = await db.finding.findFirstOrThrow({ where: { scanId: reviewScanId } });
      const accessFile = "src/catalog/read.ts";
      const accessRule = "CATALOG-01";
      const identity = await db.findingIdentity.create({ data: { projectId, fingerprint: "owned-review-catalog", filePath: accessFile, ruleId: accessRule, status: "in_progress" } });
      await db.finding.update({ where: { id: accessFinding.id }, data: {
        identityId: identity.id, ruleId: accessRule, ruleName: "Catalog access check", severity: "high", status: "open",
        filePath: accessFile, lineStart: 42, lineEnd: 42, provenance: JSON.stringify({ snippet_start_line: 40 }),
        codeSnippet: ["export async function readCatalog(account: Account) {", "  const catalog = await loadCatalog();", "  await requireCatalogAccess(account, catalog);", "  return catalog.entries;", "}"].join("\n"),
      } });
      const cacheFinding = await db.finding.create({ data: {
        scanId: reviewScanId, ruleId: "CATALOG-02", ruleName: "Response cache policy", severity: "low",
        filePath: "src/catalog/response.ts", lineStart: 18, lineEnd: 18, message: "Check the response cache policy.",
        codeSnippet: "const headers = new Headers();\nheaders.set('Cache-Control', 'private, no-store');",
      } });
      const accessReason = "The handler calls requireCatalogAccess before returning entries. The review needs the helper implementation to assess who can read the catalog.";
      await page.select("#review-project", projectId);
      await page.waitForSelector(`#review-scan option[value="${reviewScanId}"]`);
      await page.select("#review-scan", reviewScanId);
      await page.waitForSelector('[aria-label="New review"] button[type="submit"]:enabled');
      await page.$eval('[aria-label="New review"] button[type="submit"]', (el) => Promise.allSettled(el.getAnimations().map((animation) => animation.finished)));
      for (const width of [1440, 390, 320]) {
        await page.setViewport({ width, height: width === 1440 ? 960 : 844 });
        await page.$eval("#workspace", (node) => node.scrollTo(0, 0));
        assert.ok(await page.$eval('[aria-label="New review"]', (node) => node.scrollWidth <= node.clientWidth)); checks++;
        const methodRows = await page.$$eval('[aria-label="New review"] fieldset button', (buttons) => new Set(buttons.map((button) => Math.round(button.getBoundingClientRect().top))).size);
        assert.equal(methodRows, 1); checks++;
        assert.ok(await page.evaluate((wide) => {
          const setup = globalThis.document.querySelector('[aria-label="New review"]').getBoundingClientRect();
          const history = globalThis.document.querySelector('[aria-label="Review runs"]').getBoundingClientRect();
          return wide ? history.left >= setup.right && Math.abs(setup.top - history.top) < 1 : history.top >= setup.bottom;
        }, width === 1440)); checks++;
        if (width === 390) {
          assert.ok(await page.$eval('[aria-label="New review"] button[type="submit"]', (node) => node.getBoundingClientRect().bottom <= globalThis.innerHeight), "The start action must fit the mobile setup viewport"); checks++;
        }
        if (process.env.AEGIFY_UI_ARTIFACTS && width !== 320) {
          await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, width === 1440 ? "review-setup-desktop.png" : "review-setup-mobile.png") });
        }
        if (width === 390) {
          await page.focus('.review-history-jump');
          await page.keyboard.press("Enter");
          await page.waitForFunction(() => globalThis.document.activeElement?.id === "recent-review-runs");
          assert.ok(await page.$eval("#recent-review-runs", (title) => title.getBoundingClientRect().bottom <= globalThis.innerHeight)); checks++;
        }
      }
      await page.setViewport({ width: 1280, height: 1000 });
      const options = '[aria-label="New review"] details';
      await page.click(options + " summary");
      await page.click(options + ' input[type="checkbox"]');
      await waitText(page, "API context on");
      await page.click(options + ' input[type="checkbox"]');
      await page.click(options + " summary");
      await (await elementWithText(page, "button", "Start Quick Review")).click();
      await waitText(page, "Cancel review");
      const queuedIndicator = await page.waitForSelector('.app-sidebar [data-review-state="pending"]', { visible: true });
      assert.ok(await queuedIndicator.evaluate((link) => link.innerText.includes("Review queued") && !link.querySelector("progress"))); checks++;
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
        const reviews = findings.map(({ id }) => id === cacheFinding.id
          ? { findingId: id, verdict: "likely_false_positive", confidence: 0.8, reasoning: "The response explicitly disables caching.", remediation: "", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: ["The Cache-Control header includes no-store."], evidenceGaps: [] }
          : { findingId: id, verdict: "needs_review", confidence: 0.3, reasoning: accessReason, remediation: "Inspect the membership and role checks in requireCatalogAccess.", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["The stored excerpt contains the caller only."] });
        return { status: 200, text: JSON.stringify({ id: "owned-browser-response", model: "owned-browser-model", stop_reason: "end_turn", usage: { input_tokens: 120, output_tokens: 80, cache_read_input_tokens: 0 }, content: [{ type: "text", text: JSON.stringify(reviews) }] }) };
      } });
      await page.waitForSelector('#review-run a[href="#review-results"]');
      await page.focus('#review-run a[href="#review-results"]'); await page.keyboard.press("Enter");
      await page.waitForFunction(() => globalThis.document.activeElement?.id === "review-results"); checks++;
      await (await elementWithText(page, "#review-run summary", "Budget and timing")).click();
      await (await elementWithText(page, "#review-run summary", "Provider calls")).click();
      await waitText(page, "Batch 1 · completed");
      await (await elementWithText(page, "summary", "Usage and receipt")).click();
      await waitText(page, "input_tokens"); await waitText(page, "Unknown — check provider billing");
      assert.equal((await db.llmJob.findUniqueOrThrow({ where: { id: queued.id } })).reviewedCount, 2); checks++;
      await waitText(page, accessReason);
      const inspect = '[aria-label="Saved review detail"]';
      const savedHistory = '[aria-label="Saved AI review history"]';
      assert.equal(await page.$eval(inspect, (node) => node.innerText.includes("model estimate")), false); checks++;
      assert.equal(await page.$eval(inspect + ' tr[data-highlighted]', (node) => node.getAttribute("data-source-line")), "42"); checks++;
      await waitText(page, "Tracked finding status");
      await (await elementWithText(page, '[aria-label="Saved review list"] button', "Response cache policy")).focus();
      await page.keyboard.press("Enter");
      await waitText(page, "80% model estimate");
      await waitText(page, "Relative line numbers");
      assert.equal(await page.$(inspect + " [data-source-line]"), null); checks++;
      await (await elementWithText(page, '[aria-label="Saved review list"] button', "Catalog access check")).click();
      await waitText(page, accessReason);
      const firstHistory = await db.llmReview.findFirstOrThrow({ where: { jobId: queued.id, findingId: accessFinding.id } });
      await (await elementWithText(page, "button", "Start Quick Review")).click();
      let later;
      for (let i = 0; i < 100; i++) { later = await db.llmJob.findFirst({ where: { scanId: reviewScanId, status: "pending" } }); if (later) break; await delay(50); }
      assert.ok(later); assert.notEqual(later.id, queued.id);
      await runLlmWorkerOnce(db, "owned-second-browser-worker", environment, new globalThis.AbortController().signal, { transport: async (request) => {
        const findings = JSON.parse(JSON.parse(request.body).messages[0].content).findings;
        const reviews = findings.map(({ id }) => ({ findingId: id, verdict: "needs_review", confidence: 0.4, reasoning: "Owned second review with different advice.", remediation: "Inspect the newer source context.", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["No runtime observation."] }));
        return { status: 200, text: JSON.stringify({ id: "owned-second-response", model: "owned-browser-model", stop_reason: "end_turn", content: [{ type: "text", text: JSON.stringify(reviews) }] }) };
      } });
      await waitText(page, "Owned second review with different advice.");
      await page.click(`[data-review-job="${queued.id}"] button`);
      await waitText(page, accessReason);
      await waitText(page, "The finding currently displays a different suggestion.");
      await (await elementWithText(page, '#review-results button', "Back to recent runs")).click();
      assert.equal(await page.evaluate(() => globalThis.document.activeElement.id), "run-row-" + queued.id); checks++;
      assert.equal(await page.evaluate(() => globalThis.document.body.innerText.includes("Owned second review with different advice.")), false); checks++;
      const download = await page.$('[aria-label="Saved review detail"] a[download]'); assert.ok(download);
      const downloaded = await page.evaluate(async (path) => { const response = await globalThis.fetch(path); return response.json(); }, await download.evaluate((node) => node.href));
      assert.equal(downloaded.record.id, firstHistory.id); assert.equal(downloaded.payloadDigest, firstHistory.payloadDigest); checks += 2;
      await db.finding.update({ where: { id: firstHistory.findingId }, data: { aiReviewStatus: "accepted" } });
      await page.click('button[aria-label="Refresh results"]');
      await page.waitForFunction((selector) => Array.from(globalThis.document.querySelectorAll(selector + " dt")).some((node) =>
        node.textContent === "Suggestion on this observation" && node.nextElementSibling?.textContent === "accepted"), {}, inspect); checks++;
      assert.deepEqual(downloaded.current.triage, { scope: "identity", status: "in_progress" }); assert.equal(downloaded.current.status, "open"); checks += 2;
      for (const width of [1440, 820, 390, 320]) {
        await page.setViewport({ width, height: width >= 820 ? 960 : 844 });
        await page.$eval(savedHistory, (node) => node.scrollIntoView({ block: "start" }));
        for (const selector of ["#workspace", savedHistory, inspect]) {
          assert.ok(await page.$eval(selector, (node) => node.scrollWidth <= node.clientWidth + 1)); checks++;
        }
        const oneLine = await page.$eval(inspect + ' tr[data-source-line="42"] td', (cell) => {
          const range = globalThis.document.createRange(); range.selectNodeContents(cell);
          return range.getClientRects().length === 1 && cell.textContent.trim() === "42";
        });
        assert.ok(oneLine, "The highlighted source line number must fit on one line"); checks++;
        const mobile = await page.$eval(savedHistory + " select", (node) => node.checkVisibility());
        if (width < 800) assert.equal(mobile, true); else if (width >= 1440) assert.equal(mobile, false); checks++;
        if (mobile) {
          const select = savedHistory + " select";
          const ids = await page.$$eval(select + " option", (options) => options.map((option) => option.value));
          await page.select(select, ids[1]); await waitText(page, "80% model estimate");
          await page.select(select, firstHistory.id); await waitText(page, accessReason);
          assert.equal(await page.$eval(inspect, (node) => node.innerText.includes("model estimate")), false); checks++;
        }
        if (process.env.AEGIFY_UI_ARTIFACTS && [1440, 390].includes(width)) {
          await page.$eval(savedHistory, (node) => node.scrollIntoView({ block: "start" }));
          await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, width === 1440 ? "saved-review-desktop.png" : "saved-review-mobile.png") });
        }
      }
      await page.setViewport({ width: 1440, height: 960 });
      await page.waitForFunction(() => Array.from(globalThis.document.querySelectorAll("aside.app-sidebar button")).some((node) => node.textContent.includes("Dark mode") && node.checkVisibility()));
      await (await elementWithText(page, "aside.app-sidebar button", "Dark mode")).click();
      await page.waitForFunction(() => globalThis.document.documentElement.classList.contains("dark"));
      await page.$eval(savedHistory, (node) => node.scrollIntoView({ block: "start" }));
      await checkRenderedContrast(page);
      if (process.env.AEGIFY_UI_ARTIFACTS) await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "saved-review-dark.png") });
      await (await elementWithText(page, "button", "Light mode")).click();
      // Select and review a retained source fixture through the visible dashboard flow.
      await page.setViewport({ width: 1280, height: 1000 });
      await (await elementWithText(page, "button", "Source Investigation")).click();
      await page.select("#review-scan", sourceScanId);
      await page.waitForSelector('[aria-label="Select findings for source review"] input[type="checkbox"]');
      assert.equal(await (await elementWithText(page, "button", "Start Source Investigation")).evaluate((node) => node.disabled), true); checks++;
      await page.click('[aria-label="Select findings for source review"] input[type="checkbox"]');
      await waitText(page, "Choose findings to investigate · 1/25");
      await Promise.all([
        page.waitForResponse((response) => response.url().includes(`/api/findings?scanId=${sourceScanId}`) && response.status() === 200),
        (await page.$('[aria-label="Select findings for source review"] button')).click(),
      ]);
      await page.waitForSelector('[aria-label="Select findings for source review"] input[type="checkbox"]');
      assert.equal(await page.$eval('[aria-label="Select findings for source review"] input[type="checkbox"]', (node) => node.checked), true); checks++;
      await (await elementWithText(page, "button", "Start Source Investigation")).click();
      let sourceJob;
      for (let i = 0; i < 100; i++) { sourceJob = await db.llmJob.findFirst({ where: { scanId: sourceScanId, status: "pending" } }); if (sourceJob) break; await delay(50); }
      assert.ok(sourceJob); assert.equal(sourceJob.mode, "source"); checks++;
      await runLlmWorkerOnce(db, "owned-browser-source-worker", environment, new globalThis.AbortController().signal, { transport: async (request) => {
        const input = JSON.parse(JSON.parse(request.body).messages[0].content);
        const value = input.source_progress.round === 1
          ? { kind: "tools", requests: [{ name: "source_read", arguments: { file_id: input.findings[0].finding_source.file_id, line_start: 1, line_end: 2 } }] }
          : { kind: "review", reviews: input.findings.map(({ id }) => ({ findingId: id, verdict: "needs_review", confidence: 0.3, reasoning: "Owned browser source investigation.", remediation: "Inspect caller constraints.", adjustedSeverity: null, evidenceFor: [], evidenceAgainst: [], evidenceGaps: ["Static evidence only."], citationIds: [input.source_progress.tool_results[0].evidence.citation.citation_id] })) };
        return { status: 200, text: JSON.stringify({ id: "owned-source-browser", model: "owned-browser-model", stop_reason: "end_turn", usage: { input_tokens: 100, output_tokens: 50 }, content: [{ type: "text", text: JSON.stringify(value) }] }) };
      } });
      await waitText(page, "Owned browser source investigation.");
      await (await elementWithText(page, "#review-run summary", "Provider calls")).click();
      await waitText(page, "Batch 1 · Turn 1 · Source tools · completed");
      await waitText(page, "Batch 1 · Turn 2 · Review · completed");
      await waitText(page, "Source evidence & tool activity");
      await waitText(page, "The review excluded 1 Python file because it could not verify signing-key redaction."); checks++;
      await (await elementWithText(page, '[aria-label="Source references"] summary', "main.py:1–2")).click();
      await waitText(page, "OWNED_SOURCE_HTTP_EVIDENCE");
      const sourceDownload = await page.$('[aria-label="Saved review detail"] a[download]');
      const downloadedSource = await page.evaluate(async (path) => (await globalThis.fetch(path)).json(), await sourceDownload.evaluate((node) => node.href));
      assert.equal(downloadedSource.record.sourceEvidence.tools_used.length, 1); assert.equal(downloadedSource.record.sourceEvidence.trace.model_calls, 2); checks += 2;
      await page.screenshot({ path: "/private/tmp/aegify-source-review-desktop.png", fullPage: true });
      await page.setViewport({ width: 390, height: 844 });
      assert.ok(await page.evaluate(() => globalThis.document.documentElement.scrollWidth <= globalThis.window.innerWidth), "Source evidence must fit mobile width"); checks++;
      assert.ok(await page.$eval('[aria-label="Saved review detail"] span.break-all', (node) => node.getBoundingClientRect().right <= node.parentElement.getBoundingClientRect().right + 1), "The immutable commit must wrap inside its evidence panel"); checks++;
      await page.setViewport({ width: 390, height: 2500 });
      await (await page.$('[aria-label="Saved AI review history"]')).screenshot({ path: "/private/tmp/aegify-source-review-mobile-evidence.png" });
      await page.setViewport({ width: 390, height: 844 });
      await db.projectMember.upsert({ where: { projectId_userId: { projectId, userId: "bob" } }, create: { projectId, userId: "bob", role: "viewer" }, update: { role: "viewer" } });
      await context.setCookie({ name: "authjs.session-token", value: cookies.bob, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
      await page.goto(origin + "/llm-scan", { waitUntil: "networkidle0" });
      await page.select("#review-project", projectId); await page.waitForSelector(`#review-scan option[value="${reviewScanId}"]`); await page.select("#review-scan", reviewScanId);
      await waitText(page, "maintainer access are required");
      assert.equal(await (await elementWithText(page, "button", "Start Quick Review")).evaluate((node) => node.disabled), true); checks++;
      await page.click(`[data-review-job="${queued.id}"] button`);
      await waitText(page, accessReason);
      await db.projectMember.delete({ where: { projectId_userId: { projectId, userId: "bob" } } });
      await page.click('button[aria-label="Refresh results"]');
      await page.waitForSelector('[aria-label="Saved AI review history"] [role="alert"]');
      assert.equal(await page.evaluate((reason) => globalThis.document.body.innerText.includes(reason), accessReason), false); checks++;
      const projectAdmin = await browser.createBrowserContext();
      try {
        const adminPage = await projectAdmin.newPage();
        await configurePage(adminPage);
        await projectAdmin.setCookie({ name: "authjs.session-token", value: cookies.root, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" });
        await checkProjectDirectory(adminPage, page, db, origin);
        await checkProjectRecord(adminPage, page, db, origin, dirname(reportPath));
        await checkFindingReview(adminPage, page, db, origin);
        await checkCallGraph(adminPage, db, projectId, origin);
        await checkWorkspaceSettings(adminPage, db, origin);
      } finally { await projectAdmin.close(); }
      assert.deepEqual(errors, [], "No client runtime errors"); checks++;
    } finally {
      if (previous === undefined) delete process.env.ENCRYPTION_SECRET; else process.env.ENCRYPTION_SECRET = previous;
      await context.close();
    }
  } });
  log(`Dashboard browser checks passed (${checks}). Verified finding evidence, concurrent assignments, read-only decisions, project access, worker recovery, saved reviews and responsive layouts with owned fixtures.`);
} finally { await browser.close(); }
