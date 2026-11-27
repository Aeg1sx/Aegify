// Compare the offline Wrangler config reader and local binding builder with Aegify SARIF.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const [modulePath, scannerPath, outputPath] = process.argv.slice(2);
if (!modulePath || !scannerPath || !outputPath) {
  throw new Error("Usage: node compare.mjs WRANGLER_PACKAGE_DIRECTORY AEGIFY_EXECUTABLE REPORT_JSON");
}
const version = "4.166.0";
const wranglerPath = resolve(modulePath);
const pkg = JSON.parse(readFileSync(join(wranglerPath, "package.json")));
assert.equal(pkg.version, version);
const require = createRequire(import.meta.url);
const wrangler = require(wranglerPath);
const scratch = mkdtempSync(join(tmpdir(), "aegify-config-compare-"));
const inputs = join(scratch, "fixtures");
const findingsReport = join(scratch, "aegify.sarif");
const fixtureHash = createHash("sha256");
const targets = [
  ["kv_namespaces", "id", "preview_id", "1".repeat(32), "2".repeat(32)],
  ["d1_databases", "database_id", "preview_database_id", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"],
  ["r2_buckets", "bucket_name", "preview_bucket_name", "owned-receipts", "owned-archive"],
];
let compared = 0;
const cases = [];
try {
  mkdirSync(inputs);
  for (const [collection, field, preview, shared, other] of targets) {
    const scenarios = ["primary-shared", "preview-shared", "preview-isolated", "peer-preview-only",
      "local-binding", "remote-unspecified", "explicit-peer-account", "sibling-scope", "peer-binding-omitted"];
    if (collection === "r2_buckets") scenarios.push("same-jurisdiction", "separate-jurisdictions");
    for (const scenario of scenarios) {
      const caseName = collection + "-" + scenario;
      const local = { binding: "LOCAL_STORE", [field]: shared, remote: true };
      const peer = { binding: "DEPLOY_STORE", [field]: shared };
      if (collection === "d1_databases") {
        local.database_name = "receipts-local";
        peer.database_name = "receipts-deploy";
      }
      if (scenario === "preview-shared") Object.assign(local, { [field]: other, [preview]: shared });
      if (scenario === "preview-isolated") local[preview] = other;
      if (scenario === "peer-preview-only") Object.assign(peer, { [field]: other, [preview]: shared });
      if (scenario === "local-binding") local.remote = false;
      if (scenario === "remote-unspecified") delete local.remote;
      if (scenario.endsWith("jurisdiction") || scenario.endsWith("jurisdictions")) {
        local.jurisdiction = "eu";
        peer.jurisdiction = scenario === "same-jurisdiction" ? "eu" : "fedramp";
      }
      const sibling = ["sibling-scope", "explicit-peer-account", "peer-binding-omitted"].includes(scenario);
      const config = { name: "owned-worker", compatibility_date: "2026-11-01", account_id: "a".repeat(32),
        env: { studio: { [collection]: [local] } } };
      const peerScope = sibling ? "archive" : undefined;
      if (sibling) config.env.archive = scenario === "peer-binding-omitted" ? {} : { [collection]: [peer] };
      else config[collection] = [peer];
      if (scenario === "explicit-peer-account") config.env.archive.account_id = "b".repeat(32);
      const directory = join(inputs, caseName);
      mkdirSync(directory);
      const manifest = join(directory, "wrangler.json");
      const source = JSON.stringify(config, null, 2) + "\n";
      writeFileSync(manifest, source);
      fixtureHash.update(caseName + "\0" + source + "\0");
      const read = (env) => wrangler.unstable_readConfig({ config: manifest, ...(env && { env }) }, { hideWarnings: true });
      const devConfig = read("studio");
      const deployment = read(peerScope);
      const dev = wrangler.unstable_convertConfigBindingsToStartWorkerBindings({ [collection]: devConfig[collection] }).LOCAL_STORE;
      assert.ok(dev && typeof dev[field] === "string");
      const match = dev.remote === true && deployment.account_id === devConfig.account_id &&
        deployment[collection].some((entry) => entry[field] === dev[field] && entry.jurisdiction === dev.jurisdiction);
      assert.equal(match, ["primary-shared", "preview-shared", "sibling-scope", "same-jurisdiction"].includes(scenario), caseName);
      compared += 2;
      const flagLine = source.split("\n").findIndex((row) => row.includes('"remote": true')) + 1;
      cases.push({ case: caseName, expected: match, line: match ? flagLine : null });
    }
  }
  const scanner = resolve(scannerPath);
  execFileSync(scanner, ["scan", inputs, "--no-llm", "--output", "sarif", "--output-file", findingsReport], {
    cwd: scratch, stdio: "pipe", timeout: 90_000,
  });
  const raw = readFileSync(findingsReport, "utf8");
  const [run] = JSON.parse(raw).runs;
  assert.equal(run.invocations[0].executionSuccessful, true);
  assert.equal(run.invocations[0].properties.filesScanned, cases.length);
  const byCase = new Map();
  for (const result of run.results) {
    assert.equal(result.ruleId, "AEG-CF-003");
    assert.equal(result.kind, "review");
    const physical = result.locations[0].physicalLocation;
    const name = basename(dirname(decodeURIComponent(physical.artifactLocation.uri)));
    assert.ok(!byCase.has(name));
    byCase.set(name, physical.region.startLine);
  }
  for (const marker of targets.flatMap((row) => row.slice(3))) assert.ok(!raw.includes(marker), "Resource value in SARIF");
  for (const entry of cases) assert.equal(byCase.get(entry.case) ?? null, entry.line, entry.case);
  assert.equal(byCase.size, cases.filter((entry) => entry.expected).length);
  const sha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
  const report = {
    wrangler: version, wranglerCliSha256: sha256(join(wranglerPath, "wrangler-dist", "cli.js")),
    comparisonScriptSha256: sha256(new URL(import.meta.url)), fixtureSha256: fixtureHash.digest("hex"),
    scannerVersion: run.tool.driver.version, scopesRead: compared, cases: cases.length,
    expectedFindings: byCase.size, expectedClean: cases.length - byCase.size, lineAgreement: cases.length,
    results: cases,
  };
  writeFileSync(resolve(outputPath), JSON.stringify(report, null, 2) + "\n");
  console.log(`${cases.length} configurations agreed with Wrangler, including ${byCase.size} advisory locations.`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
