import { EVIDENCE_LABELS, parseEvidenceSteps, snippetStart } from "./code-evidence.ts";

export interface ReportFinding {
  id: string; ruleId: string; ruleName: string; severity: string; status: string;
  evidenceState: string; disposition: string; message: string; filePath: string;
  lineStart: number; lineEnd: number; codeSnippet: string; provenance?: string;
  taintFlow?: string | null; remediation?: string | null; owner?: string;
  scan: { repository: string; branch: string; commitSha: string };
}
export function markdownText(value: string): string {
  return value.replace(/[\\`*_{}\[\]()#+.!|~-]/g, "\\$&").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/[\r\n]+/g, " ");
}
export function fencedCode(code: string, language = "text"): string {
  const runs = code.match(/`+/g) || [];
  const fence = "`".repeat(Math.max(3, ...runs.map((run) => run.length + 1)));
  return `${fence}${/^[a-z0-9+-]+$/i.test(language) ? language : "text"}\n${code}\n${fence}`;
}
export function buildFindingReport(finding: ReportFinding): string {
  const text = markdownText;
  const flow = parseEvidenceSteps(finding.taintFlow);
  const start = snippetStart(finding);
  return [
    `# ${text(finding.ruleName)}`, "",
    `- Finding: ${text(finding.id)}`,
    `- Rule: ${text(finding.ruleId)}`,
    `- Severity: ${text(finding.severity)} · Status: ${text(finding.status)}`,
    `- Evidence: ${text(EVIDENCE_LABELS[finding.evidenceState] || "Unclassified")} · Gate: ${text(finding.disposition)}`,
    `- Repository: ${text(finding.scan.repository)} · Branch: ${text(finding.scan.branch)} · Commit: ${text(finding.scan.commitSha || "not supplied")}`,
    `- Owner: ${text(finding.owner || "Unassigned")}`,
    "", "## Summary", "", text(finding.message),
    "", "## Source evidence", "", `${text(finding.filePath)} · reported lines ${finding.lineStart}–${finding.lineEnd}`,
    "", start === null ? "Snippet source offset is unavailable; lines are relative. No location has been inferred." : `Snippet begins at source line ${start}.`,
    "", finding.codeSnippet ? fencedCode(finding.codeSnippet, finding.filePath.split(".").pop()) : "No source snippet supplied.",
    "", "## Recorded flow", "", "Static flow does not establish runtime exploitability.", "",
    ...flow.steps.map((step, index) => `${index + 1}. ${text(step.file)}:${step.line} — ${text(step.message)}`),
    ...(flow.warning ? [text(flow.warning)] : []),
    ...(!flow.steps.length ? ["No structured flow supplied."] : []),
    "", "## Remediation guidance", "", finding.remediation ? fencedCode(finding.remediation, "markdown") : "No remediation supplied.",
    "", "## Evidence limits", "", "This report preserves the recorded scanner classification. AI suggestions, static reachability, runtime observation, and impact evidence are separate claims. Guidance is not an applied or verified patch.", "",
  ].join("\n");
}
