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

test("rejects malformed detector containers and non-finite confidence", () => {
  const base = "id: AEG-TEST-001\nname: Test rule\nseverity: high\nlanguages: [python]\n";
  for (const extra of ["patterns: text", "patterns: []", "patterns: [text]", "taint: text", "confidence: .nan", "confidence: '0.9'", "cwe_id: -1"]) {
    assert.equal(validateRuleYaml(base + extra).valid, false, extra);
  }
  assert.equal(validateRuleYaml("rules: wrong").valid, false);
  assert.equal(validateRuleYaml(base.replace("[python]", "[]")).valid, false);
});

test("quoted duplicate IDs navigate to the duplicate definition, not its description", () => {
  const result = validateRuleYaml('rules:\n  - id: "AEG-TEST-001"\n    name: First\n    severity: high\n    languages: [python]\n  - id: "AEG-TEST-001"\n    name: Second\n    severity: high\n    languages: [python]\n');
  assert.equal(result.diagnostics.find((d) => d.message.includes("Duplicate"))?.line, 6);
});

test("rejects aliases and malformed YAML with a navigable syntax diagnostic", () => {
  assert.equal(validateRuleYaml("rules: &rules [*rules]").valid, false);
  const result = validateRuleYaml("rules: [\n");
  assert.equal(result.valid, false);
  assert.ok(result.diagnostics[0].line);
});

test("rejects ignored or malformed taint selectors instead of validating a broad fallback", () => {
  const base = "id: AEG-TEST-001\nname: Test rule\nseverity: high\nlanguages: [python]\n";
  for (const taint of [
    "{}", "{sources: [{type: http_param}], sinks: [{type: sql_query}]}",
    "{source_types: http_param}", "{sink_types: [false]}", "{sink_types: [' ']}",
    "{source_types: []}", "{sink_pattern: ''}", "{sink_pattern: false}",
    "{sink_types: [sql_query], propagation: [{through: assignment}]}",
    "{sink_types: [sql_query], ignore_sanitizers: 'false'}",
    `{sink_pattern: '${"x".repeat(4097)}'}`,
  ]) {
    assert.equal(validateRuleYaml(base + `taint: ${taint}\n`).valid, false, taint.slice(0, 120));
  }
});

test("accepts implemented taint selectors without substituting JavaScript regex semantics", () => {
  const result = validateRuleYaml(`id: AEG-TEST-001
name: Review modeled SQL flow
severity: high
languages: [python]
taint:
  source_types: [http_param, http_body]
  sink_types: [sql_query]
  sink_pattern: '(?i:execute|query)'
  ignore_sanitizers: false
message: Review this static flow
`);
  assert.equal(result.valid, true);
});
