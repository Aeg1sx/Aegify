import { isWranglerManifest } from "./configuration-evidence.ts";

/** Presentation only: never upgrades evidence or guesses a context offset. */
export function parseRecord(value: unknown): Record<string, unknown> {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch { return {}; }
}

export function sourceLine(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : null;
}

export function isConfigurationEvidence(provenance: unknown): boolean {
  const recorded = parseRecord(provenance);
  return recorded.analysis_kind === "configuration" && recorded.fidelity === "parsed-settings";
}

export function lineRange(start: number, end = start): string {
  return start === end ? String(start) : start + "–" + end;
}

export function codePreview(code: string) {
  const clipped = code.slice(0, 100_000);
  const truncated = clipped.length < code.length;
  const text = clipped.replace(/\r\n/g, "\n");
  const lines = text ? text.split("\n") : [];
  if (truncated && text.endsWith("\n")) lines.pop();
  return { text, lines, truncated };
}

export function snippetStart(finding: { provenance?: string; codeSnippet: string; lineStart: number; lineEnd: number }): number | null {
  const provenance = parseRecord(finding.provenance);
  if ("snippet_start_line" in provenance) return sourceLine(provenance.snippet_start_line);
  const count = finding.codeSnippet.replace(/\r\n/g, "\n").split("\n").length;
  return count <= finding.lineEnd - finding.lineStart + 1 ? sourceLine(finding.lineStart) : null;
}

export interface EvidenceStep { file: string; line: number; message: string; snippet?: string }
const flowLabels = new Map([
  ["source", "Source"], ["assignment", "Assignment"], ["argument", "Call argument"],
  ["return", "Return value"], ["iteration", "Loop element"], ["sink", "Sink"], ["keyed-store", "Stored value"],
  ["field-store", "Field write"], ["field-load", "Field read"], ["buffer-write", "Buffer write"],
  ["response-body", "Response body"], ["command-argument", "Shell command argument"],
]);

export function describeFlowMessage(message: string): { label: string; value: string } {
  const separator = message.indexOf(": ");
  const kind = separator < 0 ? "" : message.slice(0, separator);
  const label = flowLabels.get(kind);
  if (!label) return { label: "", value: message };
  const value = message.slice(separator + 2);
  return { label, value: kind === "command-argument" && value === "shell command argument" ? "" : value };
}

export function parseEvidenceSteps(value: unknown): { steps: EvidenceStep[]; warning: string | null } {
  if (!value) return { steps: [], warning: null };
  try {
    const parsed: unknown = typeof value === "string" ? JSON.parse(value) : value;
    if (!Array.isArray(parsed)) throw new Error("Expected a list");
    const steps: EvidenceStep[] = [];
    for (const step of parsed.slice(0, 200)) {
      const item = parseRecord(step);
      const line = sourceLine(item.line);
      if (typeof item.file !== "string" || line === null || typeof item.message !== "string") continue;
      const snippet = item.snippet;
      const located = item.file !== "" && !isWranglerManifest(item.file) && typeof snippet === "string"
        && snippet.length <= 4096 && snippet.trim().length > 0 && !/[\r\n]/.test(snippet);
      steps.push({ file: item.file, line, message: item.message, ...(located ? { snippet } : {}) });
    }
    return { steps, warning: steps.length !== parsed.length ? "Some flow steps are invalid or exceed the 200-step display limit. Inspect the original artifact." : null };
  } catch { return { steps: [], warning: "Flow evidence could not be parsed. The original artifact has not been modified." }; }
}

export const EVIDENCE_LABELS: Record<string, string> = {
  candidate: "Static candidate", reachable: "Static path", observed: "Runtime observed", impact_proven: "Impact evidence",
};

export function codeLanguage(language?: string): string {
  const aliases: Record<string, string> = { py: "python", js: "javascript", ts: "typescript", rb: "ruby", rs: "rust", kt: "kotlin", cs: "csharp", yml: "yaml", sh: "bash", h: "c", md: "markdown" };
  const key = language?.toLowerCase() || "text";
  return aliases[key] || key;
}
