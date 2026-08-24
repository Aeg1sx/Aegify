import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyFindingBaseline,
  findingMessageDigest,
  stableFindingFingerprint,
} from "./finding-lifecycle.ts";

test("uses producer fingerprints before deriving a local fingerprint", () => {
  assert.equal(
    stableFindingFingerprint({
      ruleId: "AEG-001",
      filePath: "src/a.py",
      message: "unsafe call",
      partialFingerprints: { "aegifyFingerprint/v1": "producer-stable-id" },
    }),
    "sarif:aegifyFingerprint/v1:producer-stable-id",
  );
});

test("derived fingerprints survive line and path separator changes", () => {
  const first = stableFindingFingerprint({
    ruleId: "AEG-001",
    filePath: "./src\\api.py",
    message: "unsafe call at line 41",
  });
  const second = stableFindingFingerprint({
    ruleId: "aeg-001",
    filePath: "src/api.py",
    message: "unsafe call at line 99",
  });
  assert.equal(first, second);
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
