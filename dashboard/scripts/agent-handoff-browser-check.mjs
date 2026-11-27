import assert from "node:assert/strict";
import { join } from "node:path";
import process from "node:process";

export async function checkAgentHandoff(page, db, origin, scanId) {
  const cited = "billing/src/review/receipts.py:105";
  const opaque = "snapshot-" + "a".repeat(64);
  const unresolved = "The deployed gateway policy was unavailable at scan time.";
  const traces = ["receipt-totals", "receipt-signature"].map((findingId) => ({
    findingId, method: "GET", endpoint: "/receipts/{id}", entryPoint: "get_receipt",
    sink: findingId, hops: [], evidenceIds: [cited], unresolvedLinks: [],
    staticComplete: true, runtimeObserved: false, impactProven: false,
  }));
  const run = await db.agentRun.create({ data: {
    scanId, status: "completed", stages: { create: [
      { sequence: 0, role: "surface", agentCode: "haetae", agentName: "Haetae", status: "completed",
        evidenceIds: JSON.stringify(["receipt-route"]), facts: JSON.stringify({ threatScenarios: [{ surface: "GET /receipts/{id}",
          trustBoundary: "external-to-application", auth: "not_detected" }] }) },
      { sequence: 1, role: "static", agentCode: "maenun", agentName: "Maenun", status: "partial",
        evidenceIds: JSON.stringify([cited]), reachability: JSON.stringify(traces),
        facts: JSON.stringify({ reviewHandoff: { version: 1,
          inputs: [{ role: "surface", status: "completed", evidenceIds: ["receipt-route"], omittedEvidence: 0 }], gaps: [] } }) },
      { sequence: 2, role: "synthesis", agentCode: "jangseung", agentName: "Jangseung", status: "completed",
        summary: "Review the source evidence and outstanding deployment checks for receipt signing.",
        facts: JSON.stringify({ findings: [{ findingId: "receipt-signature", ruleId: "Receipt signing", severity: "medium",
          likelihood: "statically_reachable", attackSurface: "GET /receipts/{id}", remediation: "Check the deployment configuration.",
          preconditions: ["The deployment configuration is still unverified."] }],
          reviewHandoff: { version: 1, inputs: [{ role: "static", status: "partial", evidenceIds: [cited, opaque], omittedEvidence: 3 }],
            gaps: [unresolved] } }) },
    ] },
  } });
  const panel = '[role="tabpanel"][data-state="active"]';
  const handoff = panel + ' section[aria-label="Review handoff"]';
  const focusText = (text) => page.waitForFunction((text) => globalThis.document.activeElement?.textContent === text, {}, text);
  const clickButton = async (selector, text) => {
    const handle = await page.waitForFunction((selector, text) => Array.from(globalThis.document.querySelectorAll(selector))
      .find((node) => node.checkVisibility() && node.textContent.trim() === text), {}, selector, text);
    await handle.asElement().focus();
    await page.keyboard.press("Enter");
    await handle.dispose();
  };

  for (const width of [1280, 390, 320]) {
    await page.setViewport({ width, height: width > 500 ? 960 : 844 });
    await page.goto(origin + "/agents/" + run.id);
    await page.waitForSelector(handoff + " h3");
    assert.match(await page.$eval(handoff, (el) => el.innerText), /Static analysis[\s\S]*Partial/);
    assert.match(await page.$eval(handoff, (el) => el.innerText), /3 additional references omitted/);
    assert.ok((await page.$eval(handoff, (el) => el.innerText)).includes(unresolved));
    assert.ok((await page.$eval(panel, (el) => el.innerText)).includes("The deployment configuration is still unverified."));
    await page.click(handoff + " summary");
    assert.deepEqual(await page.$$eval(handoff + " details button", (items) => items.map((el) => el.innerText)), [cited]);
    assert.ok((await page.$eval(handoff + " details", (el) => el.innerText)).includes(opaque));
    assert.ok(await page.$eval("#workspace", (el) => el.scrollWidth <= el.clientWidth), "Handoff references fit at " + width);
    if (process.env.AEGIFY_UI_ARTIFACTS && width > 320) {
      await page.screenshot({ path: join(process.env.AEGIFY_UI_ARTIFACTS, "agent-handoff-" + width + ".png") });
    }
    await clickButton(handoff + " button", cited);
    await focusText(cited);
    assert.ok(await page.evaluate(() => globalThis.document.activeElement.closest("details").open));
    assert.equal(await page.$eval(panel + " h2", (el) => el.innerText), "Static analysis");
    await clickButton(handoff + " button", "Environment & threats");
    await focusText("Environment & threats");
    assert.ok((await page.$eval(panel, (el) => el.innerText)).includes("Trust boundary · external-to-application"));
    assert.equal(await page.$(handoff), null);
    if (width > 500) await clickButton('[role="tab"]', "Final assessment, completed");
    else await page.select("#workspace select", "synthesis");
    await clickButton(panel + " button", "Review code path");
    await page.waitForFunction(() => globalThis.document.activeElement?.id === "code-path-receipt-signature");
    assert.equal(await page.$eval(panel + " h2", (el) => el.innerText), "Static analysis");
  }
  const historic = await db.agentRun.create({ data: { scanId, status: "completed",
    stages: { create: { sequence: 0, role: "synthesis", agentCode: "jangseung", agentName: "Jangseung",
      status: "completed", facts: JSON.stringify({ findings: [{ findingId: "old", ruleId: "Archived rule",
        severity: "low", likelihood: "unresolved" }] }) } } } });
  await page.goto(origin + "/agents/" + historic.id);
  await page.waitForSelector(panel + " h2");
  assert.ok((await page.$eval(panel, (el) => el.innerText)).includes("Archived rule"));
  assert.equal(await page.$(handoff), null);
  assert.equal(await page.$(panel + " button"), null);
}
