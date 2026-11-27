import { parseConfigurationSettings, unavailableSettings } from "./configuration-evidence.ts";
import { EVIDENCE_LABELS, isConfigurationEvidence, parseEvidenceSteps, snippetStart, type EvidenceStep } from "./code-evidence.ts";
import type { ScanCoverage } from "./sarif-evidence.ts";

export interface ReportDecision {
  scope: "identity" | "observation"; status: string; owner: string; reason: string; actor: string;
  recordedAt: string | null; expiresAt: string | null; needsReview: boolean;
}

export interface ReportFinding {
  id: string; ruleId: string; ruleName: string; severity: string; status: string;
  evidenceState: string; disposition: string; message: string; filePath: string;
  lineStart: number; lineEnd: number; codeSnippet: string; provenance?: string;
  taintFlow?: string | null; flowWarning?: string | null; remediation?: string | null; owner?: string;
  source?: string; scanId?: string; repositoryId?: string; evidenceId?: string; isCurrent?: boolean;
  scan: { repository: string; branch: string; commitSha: string; createdAt?: string; status?: string; coverage?: ScanCoverage | null };
  decision?: ReportDecision | null;
}
export function markdownText(value: string): string {
  return value.replace(/[\\`*_{}\[\]()#+.!|~-]/g, "\\$&").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/[\r\n]+/g, " ");
}
export function fencedCode(code: string, language = "text"): string {
  const runs = code.match(/`+/g) || [];
  const fence = "`".repeat(runs.reduce((length, run) => Math.max(length, run.length + 1), 3));
  return `${fence}${/^[a-z0-9+-]+$/i.test(language) ? language : "text"}\n${code}\n${fence}`;
}
export function reportStatus(status: string): string {
  const words = status.replaceAll("_", " ");
  return words ? words[0].toUpperCase() + words.slice(1) : "Unavailable";
}

export function reportScope(decision: ReportDecision): string {
  return decision.scope === "identity" ? "Tracked issue on the default branch" : "This scan observation";
}

export function coverageSummary(coverage?: ScanCoverage | null): string {
  const parts: string[] = [];
  if (coverage) {
    if (coverage.scope !== "unknown") parts.push({ repository: "Repository", workspace: "Workspace", files: "Selected files" }[coverage.scope]);
    const { files, rules, gaps } = coverage;
    if (files !== null) parts.push(`${files} ${files === 1 ? "file" : "files"} analyzed`);
    if (rules !== null) parts.push(`${rules} ${rules === 1 ? "rule" : "rules"} evaluated`);
    if (gaps !== null) parts.push(`${gaps} recorded ${gaps === 1 ? "gap" : "gaps"}`);
  }
  return parts.join(" · ") || "Coverage inventory unavailable";
}

export function reportFlow(finding: ReportFinding) {
  const flow = parseEvidenceSteps(finding.taintFlow);
  return { steps: flow.steps, warning: flow.warning ?? finding.flowWarning };
}

function markdownFlowStep(step: EvidenceStep, index: number): string {
  const marker = `${index + 1}. `;
  const label = marker + markdownText(step.file) + ":" + step.line + " — " + markdownText(step.message);
  if (!step.snippet) return label;
  const indent = " ".repeat(marker.length);
  const block = fencedCode(step.snippet).split("\n").map((line) => indent + line);
  return [label, "", ...block, ""].join("\n");
}

export function buildFindingReport(finding: ReportFinding): string {
  const text = markdownText;
  const flow = reportFlow(finding);
  const start = snippetStart(finding);
  const configuration = isConfigurationEvidence(finding.provenance);
  const settings = configuration ? parseConfigurationSettings(finding.codeSnippet) : null;
  const decision = finding.decision;
  return [
    `# ${text(finding.ruleName)}`, "",
    `- Finding: ${text(finding.id)}`,
    `- Rule: ${text(finding.ruleId)}`,
    `- Severity: ${text(finding.severity)}`,
    `- Evidence: ${text(EVIDENCE_LABELS[finding.evidenceState] || "Unclassified")} · Gate: ${text(finding.disposition)}`,
    `- Repository: ${text(finding.scan.repository)} · Branch: ${text(finding.scan.branch)} · Commit: ${text(finding.scan.commitSha || "not supplied")}`,
    ...(finding.source ? [`- Producer: ${text(finding.source)}`] : []),
    ...(decision?.scope === "identity" && finding.isCurrent === false ? ["- Observation: Earlier scan"] : []),
    ...(finding.scanId ? [`- Scan: ${text(finding.scanId)}`] : []),
    ...(finding.scan.createdAt ? [`- Scan recorded: ${text(finding.scan.createdAt)}`] : []),
    `- Scan coverage: ${text(reportStatus(finding.scan.status || ""))} · ${coverageSummary(finding.scan.coverage)}`,
    ...(finding.repositoryId ? [`- Repository ID: ${text(finding.repositoryId)}`] : []),
    ...(finding.evidenceId ? [`- Evidence ID: ${text(finding.evidenceId)}`] : []),
    `- Stored observation status: ${text(reportStatus(finding.status))}`,
    `- Stored observation owner: ${text(finding.owner || "Unassigned")}`,
    "", "## Triage decision", "",
    ...(decision ? [
      `- Scope: ${reportScope(decision)}`,
      `- Current status: ${text(reportStatus(decision.status))}`,
      `- Current owner: ${text(decision.owner || "Unassigned")}`,
      ...(decision.actor ? [`- Recorded by: ${text(decision.actor)}`] : []),
      ...(decision.recordedAt ? [`- Decision recorded: ${text(decision.recordedAt)}`] : []),
      ...(decision.expiresAt ? [`- Expires: ${text(decision.expiresAt)}`] : []),
      ...(decision.needsReview ? ["", "Historical assignments need review."] : []),
      "", ...(decision.reason ? ["Rationale", "", fencedCode(decision.reason)] : ["No rationale recorded."]),
    ] : ["The current triage decision is unavailable."]),
    "", "## Summary", "", text(finding.message),
    "", configuration ? "## Configuration settings" : "## Source evidence", "", `${text(finding.filePath)} · reported lines ${finding.lineStart}–${finding.lineEnd}`,
    "", ...(configuration ? [settings ? fencedCode(settings.map((setting) => setting.text).join("\n")) : unavailableSettings] : [
      start === null ? "Snippet source offset is unavailable; lines are relative. No location has been inferred." : `Snippet begins at source line ${start}.`,
      "", finding.codeSnippet ? fencedCode(finding.codeSnippet, finding.filePath.split(".").pop()) : "No source snippet supplied.",
      "", "## Recorded flow", "", "Static flow does not establish runtime exploitability.", "",
      ...flow.steps.map(markdownFlowStep),
      ...(flow.warning ? [text(flow.warning)] : []),
      ...(!flow.steps.length ? ["No structured flow supplied."] : []),
    ]),
    "", "## Remediation guidance", "", finding.remediation ? fencedCode(finding.remediation, "markdown") : "No remediation supplied.",
    "", "## Evidence limits", "", "This report preserves the recorded scanner classification. AI suggestions, static reachability, runtime observation, and impact evidence are separate claims. Guidance is not an applied or verified patch.", "",
  ].join("\n");
}
