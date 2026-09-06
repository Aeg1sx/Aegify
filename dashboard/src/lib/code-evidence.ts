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

export function snippetStart(finding: { provenance?: string; codeSnippet: string; lineStart: number; lineEnd: number }): number | null {
  const provenance = parseRecord(finding.provenance);
  if ("snippet_start_line" in provenance) return sourceLine(provenance.snippet_start_line);
  const count = finding.codeSnippet.replace(/\r\n/g, "\n").split("\n").length;
  return count <= finding.lineEnd - finding.lineStart + 1 ? sourceLine(finding.lineStart) : null;
}

export interface EvidenceStep { file: string; line: number; message: string; snippet?: string }
export function parseEvidenceSteps(value: unknown): { steps: EvidenceStep[]; warning: string | null } {
  if (!value) return { steps: [], warning: null };
  try {
    const parsed: unknown = typeof value === "string" ? JSON.parse(value) : value;
    if (!Array.isArray(parsed)) throw new Error("Expected a list");
    const steps = parsed.slice(0, 200).filter((step): step is EvidenceStep => {
      const item = parseRecord(step);
      return typeof item.file === "string" && sourceLine(item.line) !== null && typeof item.message === "string";
    });
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
