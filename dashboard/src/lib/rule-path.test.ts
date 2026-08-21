import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { assertAegifyRuleId, resolveWithinDirectory } from "./rule-path.ts";

test("accepts Aegify rule IDs and rejects path-like IDs", () => {
  assert.doesNotThrow(() => assertAegifyRuleId("AEG-SSRF-ADV-001"));
  assert.throws(() => assertAegifyRuleId("../AEG-001"));
  assert.throws(() => assertAegifyRuleId("CG-001"));
});

test("keeps rule paths under the configured root", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aegify-rule-path-"));
  assert.equal(
    resolveWithinDirectory(root, "ssrf/aeg-ssrf-001.yml"),
    path.join(root, "ssrf", "aeg-ssrf-001.yml"),
  );
  assert.throws(() => resolveWithinDirectory(root, "../outside.yml"));
  assert.throws(() => resolveWithinDirectory(root, path.join(root, "absolute.yml")));
});

test("rejects an existing symbolic-link path component", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aegify-rule-link-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "aegify-rule-outside-"));
  fs.symlinkSync(outside, path.join(root, "linked"));

  assert.throws(() => resolveWithinDirectory(root, "linked/rule.yml"), /symbolic links/);
});
