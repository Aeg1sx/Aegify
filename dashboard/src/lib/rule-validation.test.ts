import assert from "node:assert/strict";
import test from "node:test";

import { validateRuleYaml } from "./rule-validation.ts";

test("accepts a structured Aegify rule", () => {
  const result = validateRuleYaml(`rules:
  - id: AEG-CUSTOM-001
    name: Custom sink
    severity: high
    confidence: 0.8
    languages: [python]
    patterns:
      - callee: execute
    message: Unsafe call
`);
  assert.equal(result.valid, true);
  assert.equal(result.ruleCount, 1);
});

test("reports syntax and semantic rule errors", () => {
  assert.equal(validateRuleYaml("rules: [").valid, false);
  const semantic = validateRuleYaml(`id: custom
name: ""
severity: urgent
languages: python
`);
  assert.equal(semantic.valid, false);
  assert.ok(semantic.diagnostics.filter((item) => item.level === "error").length >= 4);
});

test("prevents an existing rule definition from changing identity", () => {
  const result = validateRuleYaml(`
id: AEG-OTHER-001
name: Other
severity: high
languages: [python]
patterns: [danger]
`, "AEG-EXPECTED-001");

  assert.equal(result.valid, false);
  assert.match(result.diagnostics[0].message, /must remain AEG-EXPECTED-001/);
});
