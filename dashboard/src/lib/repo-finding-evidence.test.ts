import assert from "node:assert/strict";
import test from "node:test";

import {
  bindRepoFindingsToSource,
  canReconcileRepoFindingAbsence,
} from "./repo-finding-evidence.ts";

const source = [
  "export function handler(req: Request) {",
  "  const target = new URL(req.url).searchParams.get('url');",
  "  return fetch(target!);",
  "}",
].join("\n");

function modelFinding(overrides: Record<string, unknown> = {}) {
  return {
    ruleId: "REPO-SSRF",
    ruleName: "Server-side request forgery",
    severity: "high",
    confidence: 1.7,
    filePath: "src/handler.ts",
    lineStart: 3,
    lineEnd: 99,
    codeSnippet: "return fetch(target!);",
    message: "User input controls the request URL.",
    cweId: 918,
    remediation: "Allowlist the destination origin.",
    ...overrides,
  };
}

test("binds a model candidate to exact immutable source evidence", () => {
  const result = bindRepoFindingsToSource(
    JSON.stringify([modelFinding()]),
    [{ path: "src/handler.ts", content: source }],
  );

  assert.equal(result.rejected.length, 0);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].lineStart, 3);
  assert.equal(result.findings[0].lineEnd, 3);
  assert.equal(result.findings[0].confidence, 1);
  assert.match(result.findings[0].sourceDigest, /^sha256:[a-f0-9]{64}$/);
  assert.match(result.findings[0].snippetDigest, /^sha256:[a-f0-9]{64}$/);
  assert.match(result.findings[0].evidenceId, /^ai:[a-f0-9]{32}$/);
});

test("rejects hallucinated files, snippets, locations, and rule identities", () => {
  const result = bindRepoFindingsToSource(
    JSON.stringify([
      modelFinding({ filePath: "src/missing.ts" }),
      modelFinding({ codeSnippet: "return exec(target!);" }),
      modelFinding({ lineStart: 20 }),
      modelFinding({ ruleId: "../../RULE" }),
    ]),
    [{ path: "src/handler.ts", content: source }],
  );

  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.rejected.map((item) => item.reason), [
    "filePath is not in the fetched source batch",
    "codeSnippet is not present in the fetched source file",
    "lineStart does not identify the exact source snippet",
    "ruleId must match REPO-[A-Z0-9-]",
  ]);
});

test("matches and persists a redacted secret marker instead of the credential", () => {
  const secretSource = 'const token = "sk-ant-abcdefghijklmnopqrstuvwxyz";';
  const result = bindRepoFindingsToSource(
    JSON.stringify([modelFinding({
      ruleId: "REPO-HARDCODED-SECRET",
      filePath: "src/config.ts",
      lineStart: 1,
      codeSnippet: 'const token = "[REDACTED_API_KEY]";',
    })]),
    [{ path: "src/config.ts", content: secretSource }],
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].codeSnippet.includes("sk-ant-"), false);
  assert.equal(result.findings[0].codeSnippet.includes("[REDACTED]"), true);
});

test("fails closed on malformed model output", () => {
  const result = bindRepoFindingsToSource("not-json", [
    { path: "src/handler.ts", content: source },
  ]);
  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.rejected, [
    { index: -1, reason: "model output was not a JSON array" },
  ]);
});

test("reconciles absence only for a complete default-branch scan", () => {
  assert.equal(canReconcileRepoFindingAbsence("main", "main", false), true);
  assert.equal(canReconcileRepoFindingAbsence("main", "main", true), false);
  assert.equal(canReconcileRepoFindingAbsence("feature/test", "main", false), false);
});
