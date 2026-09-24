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
const TAINT_FIELDS = new Set(["source_types", "sink_types", "source_pattern", "sink_pattern", "ignore_sanitizers"]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function taintShapeErrors(value: unknown): string[] {
  const taint = asRecord(value);
  if (!taint) return ["Taint must be a source/sink configuration object."];
  const errors: string[] = [];
  if (Object.keys(taint).some((key) => !TAINT_FIELDS.has(key))) {
    errors.push("Unsupported taint field. Use source_types/sink_types or source_pattern/sink_pattern; propagation comes from scanner models.");
  }
  let selector = false;
  for (const key of ["source_types", "sink_types"]) {
    if (!Object.hasOwn(taint, key)) continue;
    const types = taint[key];
    if (!Array.isArray(types) || types.length > 100 || types.some((item) => typeof item !== "string" || !item.trim() || [...item].length > 256)) {
      errors.push(`${key} must be a list of at most 100 nonempty type names, each at most 256 characters.`);
    } else {
      selector ||= types.length > 0;
    }
  }
  for (const key of ["source_pattern", "sink_pattern"]) {
    if (!Object.hasOwn(taint, key)) continue;
    const pattern = taint[key];
    if (typeof pattern !== "string" || !pattern || [...pattern].length > 4096) {
      errors.push(`${key} must be a nonempty pattern of at most 4096 characters.`);
    } else {
      // Python regex syntax is checked by the scanner, never by JS RegExp.
      selector = true;
    }
  }
  if (Object.hasOwn(taint, "ignore_sanitizers") && typeof taint.ignore_sanitizers !== "boolean") {
    errors.push("ignore_sanitizers must be a YAML boolean.");
  }
  if (!selector) errors.push("Taint needs at least one source or sink selector.");
  return errors;
}

function ruleLine(source: string, id: string, occurrence = 0): number | undefined {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`^\\s*(?:-\\s*)?["']?id["']?\\s*:\\s*["']?${escaped}["']?\\s*(?:#.*)?$`);
  const matches = source.split("\n").map((line, index) => pattern.test(line) ? index : -1).filter((index) => index >= 0);
  const index = matches[occurrence] ?? -1;
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
    parsed = load(source, { json: false, maxDepth: 40, maxAliases: 0 });
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
  if (Object.hasOwn(root, "rules") && !Array.isArray(root.rules)) {
    return { valid: false, ruleCount: 0, diagnostics: [{ level: "error", message: "rules must be a list of rule objects." }] };
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
  const occurrences = new Map<string, number>();
  for (const [index, rawRule] of rawRules.entries()) {
    const rule = asRecord(rawRule);
    if (!rule) {
      diagnostics.push({ level: "error", message: `Rule ${index + 1} must be an object.` });
      continue;
    }
    const id = typeof rule.id === "string" ? rule.id : "";
    const occurrence = occurrences.get(id) || 0;
    const line = id ? ruleLine(source, id, occurrence) : undefined;
    occurrences.set(id, occurrence + 1);
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
    if (!Array.isArray(rule.languages) || rule.languages.length === 0 || rule.languages.some((item) => typeof item !== "string" || !item.trim())) {
      diagnostics.push({ level: "error", message: "Languages must be a non-empty YAML list of language names.", line, ruleId: id || undefined });
    }
    if (typeof rule.message !== "string" || !rule.message.trim()) {
      diagnostics.push({ level: "warning", message: "Add a finding message for actionable output.", line, ruleId: id || undefined });
    }
    if (!rule.patterns && !rule.taint && !rule.pattern && !rule.dependencies && !rule.dependency_patterns) {
      diagnostics.push({ level: "warning", message: "No pattern, taint, or dependency detector is declared.", line, ruleId: id || undefined });
    }
    if (rule.confidence !== undefined && (typeof rule.confidence !== "number" || !Number.isFinite(rule.confidence) || rule.confidence < 0 || rule.confidence > 1)) {
      diagnostics.push({ level: "error", message: "Confidence must be a finite number between 0 and 1.", line, ruleId: id || undefined });
    }
    if (rule.patterns !== undefined) {
      if (!Array.isArray(rule.patterns) || rule.patterns.length === 0 || rule.patterns.some((pattern) => !asRecord(pattern))) {
        diagnostics.push({ level: "error", message: "Patterns must be a non-empty list of detector objects.", line, ruleId: id || undefined });
      } else {
        for (const [patternIndex, rawPattern] of rule.patterns.entries()) {
          const pattern = asRecord(rawPattern)!;
          for (const field of ["callee", "pattern", "args_match", "context_match"]) {
            if (pattern[field] !== undefined && (typeof pattern[field] !== "string" || !String(pattern[field]).trim())) {
              diagnostics.push({ level: "error", message: `Pattern ${patternIndex + 1}: ${field} must be a non-empty string.`, line, ruleId: id || undefined });
            }
          }
        }
      }
    }
    if (Object.hasOwn(rule, "taint")) {
      diagnostics.push(...taintShapeErrors(rule.taint).map((message): RuleDiagnostic => ({
        level: "error", message, line, ruleId: id || undefined,
      })));
    }
    if (rule.cwe_id !== undefined && rule.cwe_id !== null && (typeof rule.cwe_id !== "number" || !Number.isSafeInteger(rule.cwe_id) || rule.cwe_id <= 0)) {
      diagnostics.push({ level: "error", message: "CWE ID must be a positive integer or null.", line, ruleId: id || undefined });
    }
  }

  return {
    valid: !diagnostics.some((diagnostic) => diagnostic.level === "error"),
    ruleCount: rawRules.length,
    diagnostics,
  };
}
