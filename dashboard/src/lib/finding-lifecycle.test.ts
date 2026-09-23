import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

import {
  classifyFindingBaseline,
  findingMessageDigest,
  legacyFindingFingerprint,
  sourceFindingFingerprint,
  relativeIdentityPath,
  stableFindingFingerprint,
} from "./finding-lifecycle.ts";

test("retains the exact legacy producer algorithm only for migration", () => {
  assert.equal(
    legacyFindingFingerprint({
      ruleId: "AEG-001",
      filePath: "src/a.py",
      message: "unsafe call",
      partialFingerprints: { "aegifyFingerprint/v1": "producer-stable-id" },
    }),
    "sarif:aegifyFingerprint/v1:producer-stable-id",
  );
});

test("retains historical message normalization for migration", () => {
  const first = legacyFindingFingerprint({
    ruleId: "AEG-001",
    filePath: "./src\\api.py",
    message: "unsafe call at line 41",
  });
  const second = legacyFindingFingerprint({
    ruleId: "aeg-001",
    filePath: "src/api.py",
    message: "unsafe call at line 99",
  });
  assert.equal(first, second);
});

test("v2 producer hints are qualified by rule, repository and path", () => {
  const base = { ruleId: "AEG-ONE", filePath: "src/a.py", repositoryId: "service-a", message: "review",
    partialFingerprints: { primaryLocationLineHash: "same-producer-line" } };
  const fingerprint = stableFindingFingerprint(base);
  assert.match(fingerprint, /^sarif-finding\/v2:[a-f0-9]{64}$/);
  for (const changed of [{ ruleId: "AEG-TWO" }, { repositoryId: "service-b" }, { filePath: "src/b.py" }]) {
    assert.notEqual(stableFindingFingerprint({ ...base, ...changed }), fingerprint);
  }
  assert.equal(stableFindingFingerprint({ ...base, message: "updated review text" }), fingerprint);
});

test("source identities survive checkout movement and preserve case and numeric evidence", () => {
  const base = { ruleId: "AEG-ONE", repositoryId: "service", modulePath: "src/app.py", filePath: "/old/src/app.py",
    codeSnippet: "review(value, 1)", message: "review", partialFingerprints: { "aegifyFingerprint/v2": "untrusted-hint" } };
  const fingerprint = stableFindingFingerprint(base);
  assert.equal(stableFindingFingerprint({ ...base, filePath: "/new/src/app.py", message: "new line" }), fingerprint);
  for (const changed of [{ ruleId: "aeg-one" }, { repositoryId: "other" }, { codeSnippet: "review(value, 2)" }]) {
    assert.notEqual(stableFindingFingerprint({ ...base, ...changed }), fingerprint);
  }
  assert.notEqual(sourceFindingFingerprint({ ...base, codeSnippet: 'review("a b")' }),
    sourceFindingFingerprint({ ...base, codeSnippet: 'review("a  b")' }));
  assert.notEqual(sourceFindingFingerprint({ ...base, modulePath: "", filePath: "file:///host/a.py" }),
    sourceFindingFingerprint({ ...base, modulePath: "", filePath: "file://host/a.py" }));
  for (const path of ["../a.py", "/root/a.py", "C:\\work\\a.py", "a/../../b.py"]) assert.equal(relativeIdentityPath(path), "");
});

test("Python and TypeScript share frozen Unicode and path identity vectors", () => {
  const vectors = JSON.parse(readFileSync(new URL("./fixtures/finding-identities-v2.json", import.meta.url), "utf8"));
  for (const vector of vectors) assert.equal(sourceFindingFingerprint(vector.input), `aegify-finding/v2:${vector.sha256}`);
});

test("classifies new, unchanged, updated, and regressed findings", () => {
  const current = {
    severity: "high",
    evidenceState: "reachable",
    message: "tainted input reaches sink",
  };
  assert.equal(classifyFindingBaseline(undefined, current), "new");

  const existing = {
    status: "confirmed",
    absentAt: null,
    lastSeverity: "high",
    lastEvidenceState: "reachable",
    lastMessageDigest: findingMessageDigest(current.message),
  };
  assert.equal(classifyFindingBaseline(existing, current), "unchanged");
  assert.equal(
    classifyFindingBaseline({ ...existing, lastSeverity: "medium" }, current),
    "updated",
  );
  assert.equal(
    classifyFindingBaseline({ ...existing, absentAt: new Date() }, current),
    "regressed",
  );
  assert.equal(
    classifyFindingBaseline({ ...existing, status: "fixed" }, current),
    "regressed",
  );
});
