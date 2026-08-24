import { load } from "js-yaml";

export interface RuleDiagnostic {
  level: "error" | "warning";
  message: string;
  line?: number;
  ruleId?: string;
}

export interface RuleValidationResult {
  valid: boolean;
  ruleCount: number;
  diagnostics: RuleDiagnostic[];
}

const RULE_ID = /^AEG-[A-Z0-9][A-Z0-9_-]{2,80}$/;
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const MAX_RULE_BYTES = 1_000_000;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function approximateLine(source: string, key: string): number | undefined {
  const index = source.split("\n").findIndex((line) => line.includes(key));
  return index >= 0 ? index + 1 : undefined;
}

export function validateRuleYaml(
  source: string,
  expectedRuleId?: string,
): RuleValidationResult {
  const diagnostics: RuleDiagnostic[] = [];
  if (Buffer.byteLength(source, "utf8") > MAX_RULE_BYTES) {
    return {
      valid: false,
      ruleCount: 0,
      diagnostics: [{ level: "error", message: "Rule YAML exceeds the 1 MB limit." }],
    };
  }
  if (!source.trim()) {
    return {
      valid: false,
      ruleCount: 0,
      diagnostics: [{ level: "error", message: "Rule YAML is empty." }],
    };
  }

  let parsed: unknown;
  try {
    parsed = load(source, { json: false });
  } catch (error) {
    const mark = asRecord(error)?.mark as { line?: number } | undefined;
    return {
      valid: false,
      ruleCount: 0,
      diagnostics: [{
        level: "error",
        message: error instanceof Error ? error.message.split("\n")[0] : "Invalid YAML syntax.",
        line: typeof mark?.line === "number" ? mark.line + 1 : undefined,
      }],
    };
  }

  const root = asRecord(parsed);
  if (!root) {
    return { valid: false, ruleCount: 0, diagnostics: [{ level: "error", message: "The YAML root must be an object." }] };
  }
  const rawRules = Array.isArray(root.rules) ? root.rules : [root];
  if (rawRules.length === 0) {
    return { valid: false, ruleCount: 0, diagnostics: [{ level: "error", message: "At least one rule is required." }] };
  }
  if (expectedRuleId && rawRules.length !== 1) {
    diagnostics.push({
      level: "error",
      message: "An existing rule editor accepts exactly one rule definition.",
      ruleId: expectedRuleId,
    });
  }

  const ids = new Set<string>();
  for (const [index, rawRule] of rawRules.entries()) {
    const rule = asRecord(rawRule);
    if (!rule) {
      diagnostics.push({ level: "error", message: `Rule ${index + 1} must be an object.` });
      continue;
    }
    const id = typeof rule.id === "string" ? rule.id : "";
    const line = id ? approximateLine(source, `id: ${id}`) : undefined;
    if (!RULE_ID.test(id)) {
      diagnostics.push({ level: "error", message: "Rule ID must use the AEG-UPPERCASE-ID format.", line, ruleId: id || undefined });
    } else if (ids.has(id)) {
      diagnostics.push({ level: "error", message: `Duplicate rule ID: ${id}.`, line, ruleId: id });
    }
    if (expectedRuleId && id && id !== expectedRuleId) {
      diagnostics.push({
        level: "error",
        message: `Rule ID must remain ${expectedRuleId}.`,
        line,
        ruleId: id,
      });
    }
    ids.add(id);
    if (typeof rule.name !== "string" || !rule.name.trim()) {
      diagnostics.push({ level: "error", message: "Rule name is required.", line, ruleId: id || undefined });
    }
    if (!SEVERITIES.has(String(rule.severity))) {
      diagnostics.push({ level: "error", message: "Severity must be critical, high, medium, or low.", line, ruleId: id || undefined });
    }
    if (!Array.isArray(rule.languages) || rule.languages.some((item) => typeof item !== "string")) {
      diagnostics.push({ level: "error", message: "Languages must be a YAML list of language names.", line, ruleId: id || undefined });
    }
    if (typeof rule.message !== "string" || !rule.message.trim()) {
      diagnostics.push({ level: "warning", message: "Add a finding message for actionable output.", line, ruleId: id || undefined });
    }
    if (!rule.patterns && !rule.taint && !rule.pattern && !rule.dependencies && !rule.dependency_patterns) {
      diagnostics.push({ level: "warning", message: "No pattern, taint, or dependency detector is declared.", line, ruleId: id || undefined });
    }
    if (typeof rule.confidence === "number" && (rule.confidence < 0 || rule.confidence > 1)) {
      diagnostics.push({ level: "error", message: "Confidence must be between 0 and 1.", line, ruleId: id || undefined });
    }
  }

  return {
    valid: !diagnostics.some((diagnostic) => diagnostic.level === "error"),
    ruleCount: rawRules.length,
    diagnostics,
  };
}
