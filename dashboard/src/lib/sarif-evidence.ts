import { relativeIdentityPath } from "./finding-lifecycle.ts";

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
  sourceIdentityVersion?: unknown;
  analyzedSources?: unknown;
  repositoryCoverage?: unknown;
  taintAnalysis?: unknown;
}

interface ScanInvocation {
  executionSuccessful?: unknown;
  properties?: RunProperties;
}

export interface ScanHealth {
  status: "completed" | "partial" | "failed";
  scope: "repository" | "workspace" | "files" | "unknown";
  gaps: Array<{ code: string; stage: string; message: string; affected_count: number }>;
  evaluatedRules: string[];
  analyzedFiles: string[];
  sourceIdentityVersion?: 1;
  analyzedSources?: Array<{ repositoryId: string; modulePath: string; filePath: string }>;
  repositoryCoverage?: Array<{ repositoryId: string; analyzedFiles: number; discoveryErrors: number }>;
  producerDiagnostics?: { overflow: number | null; recorded: boolean };
}

export interface ScanCoverage {
  scope: ScanHealth["scope"];
  files: number | null;
  rules: number | null;
  gaps: number | null;
}

const diagnosticLimit = 100;
// Bound import memory for distinct diagnostic bodies and persistence work per scan.
const diagnosticKeyLimit = 1_024;
const workspaceRepositoryLimit = 4_096;
const maxInt = 2_147_483_647;

type Gap = ScanHealth["gaps"][number];

function normalizedGap(raw: unknown): Gap {
  const item = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
  return {
    code: typeof item.code === "string" ? item.code.slice(0, 100) : "invalid_diagnostic",
    stage: typeof item.stage === "string" ? item.stage.slice(0, 100) : "import",
    message: typeof item.message === "string" ? item.message.slice(0, 1000) : "Malformed scan diagnostic",
    affected_count: typeof item.affected_count === "number" && Number.isSafeInteger(item.affected_count) && item.affected_count >= 0 ? item.affected_count : 1,
  };
}

/** When distinct keys exceed the budget, single reports and identical/prefix mirrors still have an exact count. */
function oversizedDiagnosticCount(lists: unknown[][]): number | null {
  const largest = lists.reduce((longest, list) => list.length > longest.length ? list : longest);
  for (const list of lists) {
    if (list === largest) continue;
    for (let index = 0; index < list.length; index++) {
      if (JSON.stringify(normalizedGap(list[index])) !== JSON.stringify(normalizedGap(largest[index]))) return null;
    }
  }
  return largest.length;
}

/** Take the maximum multiplicity of each diagnostic across the run and its mirrored invocations. */
function producerGaps(reports: (RunProperties | undefined)[]) {
  const gaps: Gap[] = [];
  const lists: unknown[][] = [];
  for (const report of reports) {
    const raw = report?.analysisGaps;
    if (raw !== undefined) lists.push(Array.isArray(raw) ? raw : [
      { code: "invalid_diagnostics", stage: "import", message: "Malformed scan diagnostics", affected_count: 1 },
    ]);
  }
  const nonempty = lists.filter((entries) => entries.length > 0);
  if (nonempty.length <= 1) {
    const entries = nonempty[0] ?? [];
    const displayed = entries.slice(0, diagnosticLimit).map(normalizedGap);
    return { gaps: displayed, overflow: entries.length - displayed.length, recorded: lists.length > 0 };
  }
  const multiplicity = new Map<string, { report: number; local: number; maximum: number }>();
  let count = 0;
  for (const [report, entries] of lists.entries()) {
    for (const entry of entries) {
      const gap = normalizedGap(entry);
      const key = JSON.stringify(gap);
      let seen = multiplicity.get(key);
      if (!seen) {
        if (multiplicity.size >= diagnosticKeyLimit) {
          // Unproven overlap is an unknown count in the audit receipt. The displayed gaps still mark the scan partial.
          const total = oversizedDiagnosticCount(lists);
          return { gaps, overflow: total === null ? null : total - gaps.length, recorded: true };
        }
        seen = { report, local: 0, maximum: 0 };
        multiplicity.set(key, seen);
      }
      if (seen.report !== report) {
        seen.report = report;
        seen.local = 0;
      }
      if (++seen.local <= seen.maximum) continue;
      seen.maximum = seen.local;
      count++;
      if (gaps.length < diagnosticLimit) gaps.push(gap);
    }
  }
  return { gaps, overflow: count - gaps.length, recorded: lists.length > 0 };
}

/** Prefer a diagnostic backed by independent scan metadata when it falls outside the display limit. */
function summaryGap(reports: (RunProperties | undefined)[], gaps: Gap[], code: string, stage: string): Gap | undefined {
  const displayed = gaps.find((gap) => gap.code === code && gap.stage === stage);
  if (displayed || gaps.length < diagnosticLimit) return displayed;
  for (const report of reports) {
    const entries = report?.analysisGaps;
    if (!Array.isArray(entries)) continue;
    const entry = entries.find((item) => item?.code === code && item.stage === stage);
    if (!entry) continue;
    const gap = normalizedGap(entry);
    const index = gaps.slice(0, diagnosticLimit).findLastIndex((item) =>
      !(item.code === "taint_limit" && item.stage === "taint") &&
      !(item.code === "source_discovery_error" && item.stage === "discovery"));
    gaps[index < 0 ? diagnosticLimit - 1 : index] = gap;
    return gap;
  }
  return undefined;
}

function validCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= maxInt;
}

function verifiedRepositoryCoverage(raw: unknown, scope: unknown, files: unknown, normalizedFiles: string[],
  sources: ScanHealth["analyzedSources"]): ScanHealth["repositoryCoverage"] {
  if (scope !== "workspace" || !Array.isArray(files) || files.length !== normalizedFiles.length ||
      !sources || !raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const coverage = raw as Record<string, unknown>;
  if (coverage.version !== 1 || !Array.isArray(coverage.repositories) || !coverage.repositories.length ||
      coverage.repositories.length > workspaceRepositoryLimit) return undefined;

  const sourceCounts = new Map<string, number>();
  for (const source of sources) sourceCounts.set(source.repositoryId, (sourceCounts.get(source.repositoryId) ?? 0) + 1);
  const seen = new Set<string>();
  const rows: NonNullable<ScanHealth["repositoryCoverage"]> = [];
  for (const row of coverage.repositories) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return undefined;
    const { repositoryId, analyzedFiles, discoveryErrors } = row;
    if (typeof repositoryId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(repositoryId) ||
        seen.has(repositoryId) || !validCount(analyzedFiles) || !validCount(discoveryErrors) ||
        analyzedFiles !== (sourceCounts.get(repositoryId) ?? 0)) return undefined;
    seen.add(repositoryId);
    sourceCounts.delete(repositoryId);
    rows.push({ repositoryId, analyzedFiles, discoveryErrors });
  }
  return sourceCounts.size ? undefined : rows;
}

function recordedTaintLimit(summary: Record<string, unknown>, reached: unknown[]): string {
  const warnings = Array.isArray(summary.warnings) ? summary.warnings.slice(0, diagnosticLimit) : [];
  const contexts = summary.context_limit ?? summary.contexts_analyzed;
  const passes = summary.iterations;
  const messages: string[] = [];
  if (typeof contexts === "number" && Number.isSafeInteger(contexts) && contexts > 0 &&
      ((reached.includes("contexts") && summary.context_limit === contexts) ||
       warnings.includes(`global taint hit the ${contexts}-context bound`))) {
    messages.push(`Data flow reached its limit of ${contexts.toLocaleString("en-US")} call ${contexts === 1 ? "context" : "contexts"}. Additional call contexts could not be analyzed.`);
  }
  if (typeof passes === "number" && Number.isSafeInteger(passes) && passes > 0 &&
      ((reached.includes("iterations") && summary.iteration_limit === passes) ||
       warnings.includes(`global taint fixed point hit the ${passes}-iteration bound`))) {
    messages.push(`Data flow stopped after ${passes.toLocaleString("en-US")} ${passes === 1 ? "pass" : "passes"} while results were still changing.`);
  }
  return messages.join(" ") || "Data flow reached an analysis limit.";
}

/** Keep artifact counts for exports without copying paths or diagnostic text. */
export function scanCoverageForRun(health: ScanHealth, run?: RunProperties,
  invocation?: RunProperties | ScanInvocation | ScanInvocation[]): ScanCoverage {
  function inventory(raw: unknown, normalized: string[]): number | null {
    return normalized.length || (Array.isArray(raw) && raw.length === 0 ? 0 : null);
  }
  let receipt = health.producerDiagnostics;
  if (!receipt) {
    const properties = Array.isArray(invocation) ? invocation.map((item) => item?.properties)
      : invocation && ("executionSuccessful" in invocation || "properties" in invocation)
        ? [invocation.properties] : [invocation as RunProperties | undefined];
    receipt = producerGaps([run, ...properties]);
  }
  return {
    scope: health.scope,
    files: inventory(run?.analyzedFiles, health.analyzedFiles),
    rules: inventory(run?.evaluatedRules, health.evaluatedRules),
    gaps: receipt.overflow !== null && (health.gaps.length || receipt.recorded) ? health.gaps.length + receipt.overflow : null,
  };
}

export function scanHealthForRun(
  runProperties?: RunProperties,
  invocation?: ScanInvocation | ScanInvocation[],
): ScanHealth {
  const invocations = Array.isArray(invocation) ? invocation : invocation ? [invocation] : [];
  const reports = [runProperties, ...invocations.map((item) => item?.properties)];
  const declarations = reports.map((report) => report?.analysisStatus);
  const scope = runProperties?.analysisScope;
  const { gaps, recorded, overflow } = producerGaps(reports);
  for (const report of reports) {
    const taint = report?.taintAnalysis;
    if (!taint || typeof taint !== "object") continue;
    const summary = taint as Record<string, unknown>;
    const reached = Array.isArray(summary.limits_reached) ? summary.limits_reached : [];
    if (summary.truncated === true || reached.includes("contexts") || reached.includes("iterations")) {
      const gap = summaryGap(reports, gaps, "taint_limit", "taint");
      if (!gap) gaps.push({ code: "taint_limit", stage: "taint", message: recordedTaintLimit(summary, reached), affected_count: 1 });
      else if (gap.message === "Taint analysis reached its configured bound") gap.message = recordedTaintLimit(summary, reached);
    }
  }
  const rules = runProperties?.evaluatedRules;
  const evaluatedRules = Array.isArray(rules) && rules.length <= 10_000 && rules.every((rule) => typeof rule === "string" && /^[A-Z][A-Z0-9-]{1,127}$/.test(rule))
    ? [...new Set(rules as string[])].sort() : [];
  const files = runProperties?.analyzedFiles;
  const analyzedFiles = Array.isArray(files) && files.length <= 100_000 && files.every((file) => typeof file === "string" && file.length > 0 && file.length <= 4096 && !/[\x00-\x1f]/.test(file))
    ? [...new Set(files as string[])].sort() : [];
  const rawSources = runProperties?.analyzedSources;
  const analyzedPaths = new Set(analyzedFiles);
  const identityVersion = runProperties?.sourceIdentityVersion;
  let analyzedSources: ScanHealth["analyzedSources"];
  if (identityVersion !== undefined || rawSources !== undefined) {
    const valid = identityVersion === 1 && Array.isArray(rawSources) && rawSources.length <= 100_000
      && rawSources.every((source) => source && typeof source === "object"
        && typeof source.repositoryId === "string" && source.repositoryId.length <= 128 && source.repositoryId.trim() === source.repositoryId && !/[\x00-\x1f]/.test(source.repositoryId)
        && typeof source.modulePath === "string" && source.modulePath.length <= 4096
        && relativeIdentityPath(source.modulePath) === source.modulePath
        && source.modulePath.length > 0
        && typeof source.filePath === "string" && analyzedPaths.has(source.filePath));
    if (valid) {
      analyzedSources = rawSources as NonNullable<ScanHealth["analyzedSources"]>;
      const physical = new Set(analyzedSources.map((source) => source.filePath));
      const logical = new Set(analyzedSources.map((source) => JSON.stringify([source.repositoryId, source.modulePath])));
      if (physical.size !== analyzedFiles.length || physical.size !== analyzedSources.length || logical.size !== analyzedSources.length) analyzedSources = undefined;
    }
    if (!analyzedSources) gaps.push({ code: "invalid_source_identity_scope", stage: "import",
      message: "Logical source identities do not match the analyzed file inventory", affected_count: 1 });
  }
  let repositoryCoverage: ScanHealth["repositoryCoverage"];
  if (runProperties?.repositoryCoverage !== undefined) {
    repositoryCoverage = verifiedRepositoryCoverage(runProperties.repositoryCoverage, scope, files, analyzedFiles, analyzedSources);
    if (!repositoryCoverage) {
      gaps.push({ code: "invalid_repository_coverage", stage: "import",
        message: "Workspace repository counts do not match the qualified source inventory", affected_count: 1 });
    } else {
      const discoveryErrors = repositoryCoverage.reduce((sum, row) => sum + row.discoveryErrors, 0);
      if (discoveryErrors && !summaryGap(reports, gaps, "source_discovery_error", "discovery")) {
        gaps.push({ code: "source_discovery_error", stage: "discovery",
          message: "Source discovery was incomplete in one or more repositories", affected_count: discoveryErrors });
      }
    }
  }
  // The producer marks partial scans executionSuccessful=false. Preserve that distinction
  // while requiring every invocation to agree before treating the full run as completed.
  const failedDeclaration = declarations.some((status) => status !== undefined && status !== "completed" && status !== "partial");
  const unsuccessful = invocations.length ? invocations.some((item) => item?.executionSuccessful !== true &&
    (item?.properties?.analysisStatus ?? runProperties?.analysisStatus) !== "partial") : runProperties?.analysisStatus !== "partial";
  const status = failedDeclaration || unsuccessful ? "failed"
    : declarations.includes("partial") || gaps.length ? "partial" : "completed";
  const health: ScanHealth = {
    status,
    scope: scope === "repository" || scope === "workspace" || scope === "files" ? scope : "unknown",
    gaps, evaluatedRules, analyzedFiles,
    producerDiagnostics: { overflow, recorded },
    ...(analyzedSources ? { sourceIdentityVersion: 1 as const, analyzedSources } : {}),
    ...(repositoryCoverage ? { repositoryCoverage } : {}),
  };
  return health;
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

/** Keep the reported line of an explicitly located flow excerpt. */
export function flowLineExcerpt(location?: { region?: SnippetRegion; contextRegion?: SnippetRegion }): string | undefined {
  const line = location?.region?.startLine;
  if (!line) return;
  const { codeSnippet, snippetStartLine } = normalizeSourceSnippet(location);
  if (snippetStartLine === null || !codeSnippet) return;
  const excerpt = codeSnippet.replace(/\r\n/g, "\n").split("\n")[line - snippetStartLine];
  if (excerpt?.trim() && excerpt.length <= 4096) return excerpt;
}
