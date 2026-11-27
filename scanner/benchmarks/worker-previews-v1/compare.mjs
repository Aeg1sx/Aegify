import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { runInNewContext } from "node:vm";

const [packageDir, executable, output, mode] = process.argv.slice(2);
assert.ok(packageDir && executable && output && (!mode || mode === "--baseline"),
  "Usage: node compare.mjs WRANGLER_DIR AEGIFY_CLI REPORT [--baseline]");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const pkg = resolve(packageDir);
const version = JSON.parse(readFileSync(join(pkg, "package.json"))).version;
assert.equal(version, "4.166.0");
const bundle = readFileSync(join(pkg, "wrangler-dist/cli.js"), "utf8");
const bundleHash = sha(bundle);
assert.equal(bundleHash, "0d064b8bde1073900f1337aec71c76732007fe1408a2654dda99f9ffe51bd873");
const readConfig = createRequire(import.meta.url)(pkg).unstable_readConfig;
// These pure functions build Worker Preview request metadata but are not public exports.
// The allowlisted distribution is the only source of executable text.
function declaration(name) {
  const start = bundle.indexOf("\nfunction " + name + "(");
  assert.ok(start > 0);
  const end = bundle.indexOf("\n}", start);
  assert.ok(end > start);
  return bundle.slice(start, end + 2);
}
const requestBindings = runInNewContext(declaration("extractBindings") + declaration("extractConfigBindings")
  + "\nextractConfigBindings", Object.create(null));
const kinds = [
  { group: "kv_namespaces", field: "id", wire: "namespace_id", local: "preview_id", type: "kv_namespace", ids: ["a".repeat(32), "b".repeat(32)] },
  { group: "d1_databases", field: "database_id", wire: "database_id", local: "preview_database_id", type: "d1",
    ids: ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"] },
  { group: "r2_buckets", field: "bucket_name", wire: "bucket_name", local: "preview_bucket_name", type: "r2_bucket", ids: ["owned-branch-store", "owned-other-store"] },
  { group: "queues.producers", field: "queue", wire: "queue_name", type: "queue", ids: ["owned-branch-queue", "owned-other-queue"] },
];
const token = "owned-branch-config-marker";
const scratch = mkdtempSync(join(tmpdir(), "aegify-worker-previews-"));
const fixtures = join(scratch, "fixtures");
const fixtureHash = createHash("sha256");
const expected = new Map();
let environmentsRead = 0;

function addCase(name, config, kind) {
  const directory = join(fixtures, name);
  mkdirSync(directory);
  const ext = expected.size % 2 === 0 ? "jsonc" : "json";
  const file = join(directory, "wrangler." + ext);
  const source = (ext === "jsonc" ? "// Branch review settings\n" : "") + JSON.stringify(config, null, 2) + "\n";
  writeFileSync(file, source);
  fixtureHash.update(name + "\0" + source + "\0");
  const lines = source.split("\n");
  const fieldLine = (alias) => {
    const index = lines.findIndex((line) => line.includes('"binding": "' + alias + '"'));
    assert.ok(index > 0);
    const delta = lines.slice(index + 1).findIndex((line) => line.includes('"' + kind.field + '":'));
    assert.ok(delta >= 0);
    return index + delta + 2;
  };
  const rows = new Set();
  for (const env of [undefined, ...Object.keys(config.env || {})]) {
    const cfg = readConfig({ config: file, ...(env && { env }) }, { hideWarnings: true });
    environmentsRead++;
    const branch = requestBindings(cfg);
    const worker = env ? "env." + env : "default";
    const declared = env && Object.hasOwn(config.env[env], "previews") ? worker : "default";
    const deployments = kind.group === "queues.producers" ? cfg.queues.producers : cfg[kind.group];
    for (const [alias, ref] of Object.entries(branch)) {
      if (ref.type === "plain_text" && alias === "SIGNING_KEY" && ref.text === token) {
        const line = lines.findIndex((row) => row.includes('"SIGNING_KEY":')) + 1;
        rows.add(["AEG-CF-001", line, declared + ".previews.vars.SIGNING_KEY = [withheld]"].join("|"));
      }
      if (ref.type !== kind.type || typeof ref[kind.wire] !== "string") continue;
      const list = kind.group === "queues.producers" ? cfg.previews?.queues?.producers : cfg.previews?.[kind.group];
      const index = list.findIndex((entry) => entry.binding === alias);
      assert.ok(index >= 0);
      const peerIndex = deployments.findIndex((entry) => entry[kind.field] === ref[kind.wire]
        && (entry.jurisdiction ?? "default") === (ref.jurisdiction ?? "default"));
      if (peerIndex === -1) continue;
      const line = fieldLine(alias);
      const peerLine = fieldLine(deployments[peerIndex].binding);
      const path = (scope, i, n) => scope + "." + kind.group + "[" + i + "]." + kind.field + " (line " + n + ")";
      rows.add(["AEG-CF-004", line, path(declared + ".previews", index, line) + " matches " + path(worker, peerIndex, peerLine)].join("|"));
    }
  }
  expected.set(name, [...rows].sort());
}

try {
  mkdirSync(fixtures);
  for (const kind of kinds) {
    const targets = (alias, number, options = {}) => {
      const binding = { binding: alias, [kind.field]: kind.ids[number], ...(kind.type === "d1" && { database_name: "owned-database" }), ...options };
      return kind.group === "queues.producers" ? { queues: { producers: [binding] } } : { [kind.group]: [binding] };
    };
    const branch = targets("BRANCH", 0);
    const deploy = targets("WORKER", 0);
    const base = { name: "owned-worker", compatibility_date: "2026-11-01" };
    const add = (name, config) => addCase(kind.group + "-" + name, { ...base, ...config }, kind);
    add("shared", { ...deploy, previews: branch });
    add("isolated", { ...targets("WORKER", 1), previews: branch });
    add("absent", deploy);
    add("named-preview", { env: { branch: { ...deploy, previews: branch } } });
    add("inherited-preview", { account_id: "c".repeat(32), previews: branch, env: { branch: { account_id: "d".repeat(32), ...deploy } } });
    add("empty-override", { previews: branch, env: { branch: { ...deploy, previews: {} } } });
    add("sibling-only", { env: { one: { previews: branch }, two: deploy } });
    add("unbound-named-worker", { ...deploy, env: { branch: { previews: branch } } });
    if (kind.local) {
      add("dev-selector-only", { ...deploy, previews: targets("BRANCH", 1, { [kind.local]: kind.ids[0], remote: true }) });
      add("dedicated-dev-selector", { ...deploy, previews: targets("BRANCH", 0, { [kind.local]: kind.ids[1], remote: false }) });
    }
    if (kind.type === "r2_bucket") {
      add("jurisdiction-different", { ...deploy, previews: targets("BRANCH", 0, { jurisdiction: "eu" }) });
      add("jurisdiction-equal", { ...targets("WORKER", 0, { jurisdiction: "eu" }), previews: targets("BRANCH", 0, { jurisdiction: "eu" }) });
    }
    if (kind.type === "queue") {
      add("consumer-only", { ...deploy, previews: { queues: { consumers: [{ queue: kind.ids[0] }] } } });
      add("preview-vars", { previews: { vars: { SIGNING_KEY: token, PUBLIC_API_KEY: token } }, env: { branch: {} } });
    }
  }
  const sarif = join(scratch, "result.sarif");
  execFileSync(resolve(executable), ["scan", fixtures, "--no-llm", "--output", "sarif", "--output-file", sarif],
    { cwd: scratch, stdio: "pipe", timeout: 120000 });
  const raw = readFileSync(sarif, "utf8");
  const [run] = JSON.parse(raw).runs;
  assert.equal(run.invocations[0].executionSuccessful, true);
  assert.equal(run.invocations[0].properties.filesScanned, expected.size);
  for (const literal of [token, ...kinds.flatMap((kind) => kind.ids)]) assert.ok(!raw.includes(literal), "Raw target in report");
  const observed = new Map();
  for (const record of run.results) {
    assert.equal(record.kind, "review");
    const { region, artifactLocation } = record.locations[0].physicalLocation;
    const name = basename(dirname(decodeURIComponent(artifactLocation.uri)));
    assert.ok(expected.has(name));
    const rows = observed.get(name) ?? [];
    for (const text of region.snippet.text.split(" · ")) rows.push([record.ruleId, region.startLine, text].join("|"));
    observed.set(name, rows);
  }
  const results = [...expected].map(([name, rows]) => ({ name, expected: rows, observed: (observed.get(name) ?? []).sort() }));
  const agrees = (row) => JSON.stringify(row.expected) === JSON.stringify(row.observed);
  const report = { wrangler: version, bundleSha256: bundleHash, scriptSha256: sha(readFileSync(new URL(import.meta.url))),
    fixtureSha256: fixtureHash.digest("hex"), cases: results.length, environmentsRead,
    expectedAdvisories: results.reduce((n, row) => n + row.expected.length, 0),
    observedAdvisories: results.reduce((n, row) => n + row.observed.length, 0),
    exactAgreement: results.filter(agrees).length, results };
  writeFileSync(resolve(output), JSON.stringify(report, null, 2) + "\n");
  console.log(report.exactAgreement + "/" + report.cases + " cases agreed with the pinned Wrangler configuration and request builder.");
  if (mode !== "--baseline") assert.deepEqual(results.filter((row) => !agrees(row)), []);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
