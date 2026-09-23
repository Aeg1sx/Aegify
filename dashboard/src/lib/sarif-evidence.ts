export interface EvidenceProvenancePayload {
  contract_version?: number;
  producer?: string;
  producer_version?: string;
  analysis_kind?: string;
  fidelity?: string;
  repository_id?: string;
  module_path?: string;
  workspace_snapshot?: string;
  rule_digest?: string;
  evidence_id?: string;
}

interface RunProperties {
  workspaceSnapshot?: unknown;
  analysisStatus?: unknown;
  analysisGaps?: unknown;
  analysisScope?: unknown;
  evaluatedRules?: unknown;
  analyzedFiles?: unknown;
}

export interface ScanHealth {
  status: "completed" | "partial" | "failed";
  scope: "repository" | "workspace" | "files" | "unknown";
  gaps: Array<{ code: string; stage: string; message: string; affected_count: number }>;
  evaluatedRules: string[];
  analyzedFiles: string[];
}

export function scanHealthForRun(
  runProperties?: RunProperties,
  invocation?: { executionSuccessful?: unknown; properties?: RunProperties },
): ScanHealth {
  const declared = runProperties?.analysisStatus ?? invocation?.properties?.analysisStatus;
  const rawGaps = runProperties?.analysisGaps ?? invocation?.properties?.analysisGaps;
  const scope = runProperties?.analysisScope;
  const gaps: ScanHealth["gaps"] = [];
  if (Array.isArray(rawGaps)) {
    for (const raw of rawGaps.slice(0, 100)) {
      const item = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
      gaps.push({
        code: typeof item.code === "string" ? item.code.slice(0, 100) : "invalid_diagnostic",
        stage: typeof item.stage === "string" ? item.stage.slice(0, 100) : "import",
        message: typeof item.message === "string" ? item.message.slice(0, 1000) : "Malformed scan diagnostic",
        affected_count: typeof item.affected_count === "number" && Number.isSafeInteger(item.affected_count) && item.affected_count >= 0 ? item.affected_count : 1,
      });
    }
  } else if (rawGaps !== undefined) {
    gaps.push({ code: "invalid_diagnostics", stage: "import", message: "Malformed scan diagnostics", affected_count: 1 });
  }
  const rules = runProperties?.evaluatedRules;
  const evaluatedRules = Array.isArray(rules) && rules.length <= 10_000 && rules.every((rule) => typeof rule === "string" && /^[A-Z][A-Z0-9-]{1,127}$/.test(rule))
    ? [...new Set(rules as string[])].sort() : [];
  const files = runProperties?.analyzedFiles;
  const analyzedFiles = Array.isArray(files) && files.length <= 100_000 && files.every((file) => typeof file === "string" && file.length > 0 && file.length <= 4096 && !/[\x00-\x1f]/.test(file))
    ? [...new Set(files as string[])].sort() : [];
  // A contradictory successful declaration cannot override a failed invocation.
  // Legacy successful reports remain viewable, but lack a reconciliable scope.
  const status = declared === "failed" ? "failed"
    : declared === "partial" ? "partial"
    : invocation?.executionSuccessful !== true ? "failed"
    : declared !== undefined && declared !== "completed" ? "failed"
    : gaps.length > 0 ? "partial" : "completed";
  return {
    status,
    scope: scope === "repository" || scope === "workspace" || scope === "files" ? scope : "unknown",
    gaps, evaluatedRules, analyzedFiles,
  };
}

export function canReconcileScanAbsence(health: ScanHealth, branch: string, defaultBranch: string): boolean {
  return health.status === "completed" && health.gaps.length === 0
    && (health.scope === "repository" || health.scope === "workspace")
    && health.evaluatedRules.length > 0 && health.analyzedFiles.length > 0
    && branch.length > 0 && branch === defaultBranch;
}

interface FindingProperties {
  provenance?: unknown;
  evidenceState?: unknown;
  disposition?: unknown;
  blocksCi?: unknown;
}

export type EvidenceState = "candidate" | "reachable" | "observed" | "impact_proven";
export type FindingDisposition = "blocking" | "advisory";

const EVIDENCE_STATES = new Set<EvidenceState>([
  "candidate",
  "reachable",
  "observed",
  "impact_proven",
]);
const FINDING_DISPOSITIONS = new Set<FindingDisposition>(["blocking", "advisory"]);

function stringField(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function provenancePayload(value: unknown): EvidenceProvenancePayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as EvidenceProvenancePayload;
}

export function workspaceSnapshotForRun(
  runProperties?: RunProperties,
  invocationProperties?: RunProperties,
): string {
  return (
    stringField(runProperties?.workspaceSnapshot) ||
    stringField(invocationProperties?.workspaceSnapshot)
  );
}

export function normalizeFindingEvidence(
  properties: FindingProperties | undefined,
): {
  evidenceId: string;
  repositoryId: string;
  modulePath: string;
  provenance: string;
} {
  const provenance = provenancePayload(properties?.provenance);
  return {
    evidenceId: stringField(provenance.evidence_id),
    repositoryId: stringField(provenance.repository_id),
    modulePath: stringField(provenance.module_path),
    provenance: JSON.stringify(provenance),
  };
}

export function normalizeFindingClassification(
  properties: FindingProperties | undefined,
): {
  evidenceState: EvidenceState;
  disposition: FindingDisposition;
} {
  const evidenceState = stringField(properties?.evidenceState) as EvidenceState;
  const disposition = stringField(properties?.disposition) as FindingDisposition;
  return {
    evidenceState: EVIDENCE_STATES.has(evidenceState) ? evidenceState : "candidate",
    disposition: FINDING_DISPOSITIONS.has(disposition) ? disposition : "advisory",
  };
}

interface SnippetRegion { startLine?: number; endLine?: number; snippet?: { text?: string } }
export function normalizeSourceSnippet(location?: { region?: SnippetRegion; contextRegion?: SnippetRegion }): {
  codeSnippet: string; snippetStartLine: number | null;
} {
  const region = location?.region;
  const context = location?.contextRegion;
  const positiveLine = (line: unknown): line is number => typeof line === "number" && Number.isSafeInteger(line) && line > 0;
  if (typeof context?.snippet?.text === "string" && positiveLine(context.startLine)
      && positiveLine(region?.startLine) && context.startLine <= region.startLine) {
    const lines = context.snippet.text.replace(/\r\n/g, "\n").split("\n");
    const last = context.startLine + lines.length - 1;
    const end = region.endLine ?? region.startLine;
    if (positiveLine(end) && end >= region.startLine && last >= end && (context.endLine === undefined || context.endLine === last)) {
      return { codeSnippet: context.snippet.text, snippetStartLine: context.startLine };
    }
  }
  const text = typeof region?.snippet?.text === "string" ? region.snippet.text : "";
  const count = text.replace(/\r\n/g, "\n").split("\n").length;
  // Legacy Aegify reports sometimes put context in region.snippet without its offset.
  const end = region?.endLine ?? region?.startLine;
  const known = positiveLine(region?.startLine) && positiveLine(end) && count <= end - region.startLine + 1;
  return { codeSnippet: text, snippetStartLine: known ? region!.startLine! : null };
}
