import { createHash } from "node:crypto";

import { SECURITY_AGENTS, type AgentRole } from "./agent-catalog.ts";
export { SECURITY_AGENTS } from "./agent-catalog.ts";
export type { AgentIdentity, AgentRole } from "./agent-catalog.ts";

export interface AgentFindingInput {
  id: string;
  ruleId: string;
  severity: string;
  evidenceState: string;
  filePath: string;
  lineStart: number;
  message: string;
  remediation: string | null;
  evidenceId: string;
  callChain: string | null;
}

export interface AgentEndpointInput {
  path: string;
  method: string;
  handlerFunction: string;
  filePath: string;
  framework: string;
  authRequired: boolean;
  calledByFrontend: boolean;
  exposedViaGateway: boolean;
  runtimeObserved: boolean;
}

export interface AgentScanInput {
  id: string;
  repository: string;
  workspaceSnapshot: string;
  findings: AgentFindingInput[];
  endpoints: AgentEndpointInput[];
}

export interface CveInput {
  cveId: string;
  package?: string;
  installedVersion?: string;
  dependencyPresent?: boolean;
  versionAffected?: boolean;
  componentReachable?: boolean;
  runtimeVerified?: boolean;
  evidenceIds?: string[];
}

export interface ReachabilityView {
  findingId: string;
  endpoint: string;
  method: string;
  entryPoint: string;
  sink: string;
  hops: Array<{ function: string; filePath: string; line: number; snippet: string }>;
  evidenceIds: string[];
  staticComplete: boolean;
  runtimeObserved: boolean;
  impactProven: boolean;
  unresolvedLinks: string[];
}

export interface DynamicPlanView {
  id: string;
  findingId: string;
  targetScope: "owned_fixture_only";
  targetOrigin: "http://127.0.0.1";
  harness: "http" | "container";
  requestTemplate: string;
  payloadTemplate: "{{SAFE_CANARY}}";
  expectedSignal: string;
  negativeControl: string;
  cleanup: string[];
  requiresApproval: true;
  destructive: false;
}

export interface AgentStageBlueprint {
  sequence: number;
  role: AgentRole;
  agentCode: string;
  agentName: string;
  status: "completed" | "partial" | "waiting_approval";
  summary: string;
  facts: Record<string, unknown>;
  evidenceIds: string[];
  reachability: ReachabilityView[];
  dynamicPlans: DynamicPlanView[];
  cveAssessments: Array<Record<string, unknown>>;
  improvementProposals: Array<Record<string, unknown>>;
  promptDigest: string;
}

export interface AgentBlueprint {
  status: "completed" | "awaiting_approval";
  stages: AgentStageBlueprint[];
  artifactDigest: string;
}

const PROMPT_VERSION = "2026-09-05.1";

export function buildAgentBlueprint(
  scan: AgentScanInput,
  mode: "lite" | "deep",
  cves: CveInput[] = [],
): AgentBlueprint {
  const traces = scan.findings.map((finding) => buildReachability(finding, scan.endpoints));
  const surfaceEvidence = scan.endpoints.map((endpoint) => endpointEvidenceId(endpoint));
  const publicEndpoints = scan.endpoints.filter((endpoint) => !endpoint.authRequired);
  const completePaths = traces.filter((trace) => trace.staticComplete);
  const observedPaths = traces.filter((trace) => trace.runtimeObserved);
  const dynamicPlans = completePaths
    .filter((trace) => !trace.runtimeObserved)
    .map((trace) => dynamicPlan(trace));
  const cveAssessments = cves.map(assessCve);
  const proposals: Array<Record<string, unknown>> = [];
  const unresolved = traces.filter((trace) => !trace.staticComplete).length;
  if (unresolved > 0) {
    proposals.push(improvementProposal(
      "reachability",
      "Expand endpoint-to-sink framework corpus",
      `${unresolved} paths have an explicit missing link`,
      "complete-path recall without precision regression",
    ));
  }
  if (dynamicPlans.length > 0) {
    proposals.push(improvementProposal(
      "dynamic-validation",
      "Grow owned-fixture validation coverage",
      `${dynamicPlans.length} complete static paths lack runtime evidence`,
      "runtime-correlated path coverage",
    ));
  }

  const stages: AgentStageBlueprint[] = [
    stage("surface", 0, "completed", {
      summary: `Mapped ${scan.endpoints.length} endpoints and ${publicEndpoints.length} without detected auth evidence.`,
      facts: {
        endpoints: scan.endpoints.length,
        endpointsWithoutDetectedAuth: publicEndpoints.length,
        frontendLinked: scan.endpoints.filter((item) => item.calledByFrontend).length,
        gatewayExposed: scan.endpoints.filter((item) => item.exposedViaGateway).length,
        runtimeObserved: scan.endpoints.filter((item) => item.runtimeObserved).length,
        frameworks: counts(scan.endpoints.map((item) => item.framework || "unknown")),
        threatScenarios: publicEndpoints.slice(0, 100).map((item) => ({
          surface: `${item.method} ${item.path}`,
          trustBoundary: "external-to-application",
          auth: "not_detected",
          runtimeObserved: item.runtimeObserved,
        })),
      },
      evidenceIds: surfaceEvidence,
    }),
    stage("static", 1, scan.findings.length > 0 && completePaths.length === 0 ? "partial" : "completed", {
      summary: `Reviewed ${scan.findings.length} findings; ${completePaths.length} have endpoint-to-sink paths.`,
      facts: {
        mode,
        findings: scan.findings.length,
        severity: counts(scan.findings.map((item) => item.severity)),
        evidenceState: counts(scan.findings.map((item) => item.evidenceState)),
        completeStaticPaths: completePaths.length,
        runtimeCorrelatedPaths: observedPaths.length,
      },
      evidenceIds: unique(traces.flatMap((trace) => trace.evidenceIds)),
      reachability: traces,
    }),
    stage("dynamic", 2, dynamicPlans.length > 0 ? "waiting_approval" : "completed", {
      summary: dynamicPlans.length > 0
        ? `Prepared ${dynamicPlans.length} bounded plans; no plan was executed without approval.`
        : "No unobserved complete static path requires a new dynamic plan.",
      facts: {
        observedPaths: observedPaths.length,
        approvalRequiredPlans: dynamicPlans.length,
        executionPolicy: "owned loopback fixture, non-destructive, negative control required",
      },
      evidenceIds: unique(observedPaths.flatMap((trace) => trace.evidenceIds)),
      dynamicPlans,
    }),
    stage("cve", 3, "completed", {
      summary: `Assessed ${cveAssessments.length} supplied CVE candidates.`,
      facts: { candidates: cveAssessments.length },
      evidenceIds: unique(cves.flatMap((item) => item.evidenceIds || [])),
      cveAssessments,
    }),
    stage("synthesis", 4, "completed", {
      summary: `Reconciled ${scan.findings.length} findings without upgrading unproven claims.`,
      facts: {
        findings: scan.findings.map((finding) => {
          const trace = traces.find((item) => item.findingId === finding.id)!;
          return {
            findingId: finding.id,
            ruleId: finding.ruleId,
            severity: finding.severity,
            likelihood: trace.impactProven
              ? "demonstrated_in_fixture"
              : trace.runtimeObserved
                ? "observed_surface"
                : trace.staticComplete
                  ? "statically_reachable"
                  : "unresolved",
            attackSurface: `${trace.method} ${trace.endpoint}`.trim(),
            preconditions: trace.unresolvedLinks,
            remediation: finding.remediation || "Rule-specific remediation review required",
            evidenceIds: trace.evidenceIds,
          };
        }),
      },
      evidenceIds: unique(traces.flatMap((trace) => trace.evidenceIds)),
    }),
    stage("steward", 5, "completed", {
      summary: `Proposed ${proposals.length} evaluation-gated improvements; none were auto-applied.`,
      facts: { unresolvedPaths: unresolved, unobservedCompletePaths: dynamicPlans.length, autoApply: false },
      evidenceIds: [],
      improvementProposals: proposals,
    }),
  ];
  const status = dynamicPlans.length > 0 ? "awaiting_approval" : "completed";
  const artifactDigest = digest(JSON.stringify({ scanId: scan.id, mode, status, stages }));
  return { status, stages, artifactDigest };
}

export function validateCveInputs(value: unknown): CveInput[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 100) {
    throw new Error("cves must be an array with at most 100 entries");
  }
  return value.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("each CVE entry must be an object");
    }
    const item = raw as Record<string, unknown>;
    const cveId = String(item.cveId || "").toUpperCase();
    if (!/^CVE-(?:19|20)\d{2}-\d{4,}$/.test(cveId)) {
      throw new Error(`invalid CVE identifier: ${cveId}`);
    }
    const optionalBoolean = (key: string): boolean | undefined => {
      if (!(key in item)) return undefined;
      if (typeof item[key] !== "boolean") throw new Error(`${key} must be boolean`);
      return item[key];
    };
    const evidenceIds = Array.isArray(item.evidenceIds)
      ? item.evidenceIds.slice(0, 100).map((entry) => String(entry).slice(0, 200))
      : [];
    return {
      cveId,
      package: String(item.package || "").slice(0, 300),
      installedVersion: String(item.installedVersion || "").slice(0, 100),
      dependencyPresent: optionalBoolean("dependencyPresent"),
      versionAffected: optionalBoolean("versionAffected"),
      componentReachable: optionalBoolean("componentReachable"),
      runtimeVerified: optionalBoolean("runtimeVerified"),
      evidenceIds,
    };
  });
}

function buildReachability(
  finding: AgentFindingInput,
  endpoints: AgentEndpointInput[],
): ReachabilityView {
  const hops = parseCallChain(finding.callChain);
  const endpoint = endpoints.find((item) =>
    item.filePath === finding.filePath || hops.some((hop) => hop.filePath === item.filePath));
  const staticComplete = !!endpoint && hops.length > 0;
  const unresolvedLinks: string[] = [];
  if (!endpoint) unresolvedLinks.push("No endpoint-to-finding correlation was produced");
  if (hops.length === 0) unresolvedLinks.push("No entry-to-sink call chain was produced");
  if (!endpoint?.runtimeObserved) unresolvedLinks.push("No runtime observation is linked to this path");
  const evidenceIds = [finding.evidenceId || `finding:${finding.id}`];
  if (endpoint) evidenceIds.push(endpointEvidenceId(endpoint));
  return {
    findingId: finding.id,
    endpoint: endpoint?.path || "",
    method: endpoint?.method || "",
    entryPoint: hops[0]?.function || "",
    sink: `${finding.filePath}:${finding.lineStart}`,
    hops,
    evidenceIds: unique(evidenceIds),
    staticComplete,
    runtimeObserved: !!endpoint?.runtimeObserved,
    impactProven: finding.evidenceState === "impact_proven" && !!endpoint?.runtimeObserved,
    unresolvedLinks,
  };
}

function parseCallChain(value: string | null): ReachabilityView["hops"] {
  if (!value || value.length > 1_000_000) return [];
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(0, 200).map((raw) => {
      if (typeof raw === "string") {
        return { function: raw.slice(0, 500), filePath: "", line: 0, snippet: "" };
      }
      const item = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
      return {
        function: String(item.function || item.qualifiedName || "unknown").slice(0, 500),
        filePath: String(item.filePath || item.file_path || "").slice(0, 2_000),
        line: Math.max(0, Number(item.line || 0) || 0),
        snippet: String(item.snippet || item.codeSnippet || item.code_snippet || "").slice(0, 4_000),
      };
    });
  } catch {
    return [];
  }
}

function dynamicPlan(trace: ReachabilityView): DynamicPlanView {
  const material = `${trace.findingId}:${trace.method}:${trace.endpoint}`;
  return {
    id: `plan-${createHash("sha256").update(material).digest("hex").slice(0, 20)}`,
    findingId: trace.findingId,
    targetScope: "owned_fixture_only",
    targetOrigin: "http://127.0.0.1",
    harness: trace.endpoint ? "http" : "container",
    requestTemplate: `${trace.method || "GET"} ${trace.endpoint || "/{{FIXTURE_PATH}}"}`,
    payloadTemplate: "{{SAFE_CANARY}}",
    expectedSignal: `A bounded canary reaches ${trace.sink} and is recorded by the fixture`,
    negativeControl: "The same request without {{SAFE_CANARY}} does not produce the signal",
    cleanup: ["Stop the ephemeral fixture", "Verify temporary artifacts and containers are removed"],
    requiresApproval: true,
    destructive: false,
  };
}

function assessCve(item: CveInput): Record<string, unknown> {
  const missingEvidence: string[] = [];
  if (item.dependencyPresent === undefined) missingEvidence.push("component presence");
  if (item.versionAffected === undefined) missingEvidence.push("affected version evaluation");
  if (item.componentReachable === undefined) missingEvidence.push("component reachability");
  let applicability = "needs_evidence";
  let rationale = "The supplied CVE cannot be classified without the missing evidence.";
  if (item.dependencyPresent === false || item.versionAffected === false) {
    applicability = "not_affected";
    rationale = "The supplied inventory or version evidence excludes this environment.";
  } else if (item.runtimeVerified) {
    applicability = "exploitable_in_fixture";
    rationale = "An approved owned-fixture validation was supplied as runtime evidence.";
  } else if (item.componentReachable && item.versionAffected) {
    applicability = "reachable";
    rationale = "The affected version and component path are present; exploitability is unproven.";
  } else if (item.dependencyPresent && item.versionAffected) {
    applicability = "version_exposed";
    rationale = "The affected version is present; application reachability is unresolved.";
  }
  return {
    cveId: item.cveId,
    package: item.package || "",
    installedVersion: item.installedVersion || "",
    applicability,
    rationale,
    evidenceIds: item.evidenceIds || [],
    missingEvidence,
  };
}

function improvementProposal(
  category: string,
  title: string,
  hypothesis: string,
  targetMetric: string,
): Record<string, unknown> {
  return {
    id: `proposal-${digest(`${category}:${hypothesis}`).slice(7, 27)}`,
    category,
    title,
    hypothesis,
    targetMetric,
    minimumSamples: 30,
    requiredGates: [
      "owned benchmark passes",
      "precision does not regress",
      "security policy review",
      "human approval",
    ],
    status: "proposed",
    autoApply: false,
  };
}

function stage(
  role: AgentRole,
  sequence: number,
  status: AgentStageBlueprint["status"],
  values: Partial<AgentStageBlueprint> & Pick<AgentStageBlueprint, "summary" | "facts" | "evidenceIds">,
): AgentStageBlueprint {
  const identity = SECURITY_AGENTS.find((item) => item.role === role)!;
  return {
    sequence,
    role,
    agentCode: identity.code,
    agentName: identity.name,
    status,
    summary: values.summary,
    facts: values.facts,
    evidenceIds: values.evidenceIds,
    reachability: values.reachability || [],
    dynamicPlans: values.dynamicPlans || [],
    cveAssessments: values.cveAssessments || [],
    improvementProposals: values.improvementProposals || [],
    promptDigest: digest(`${PROMPT_VERSION}:${role}:${identity.mission}:${identity.tools.join(",")}`),
  };
}

function endpointEvidenceId(endpoint: AgentEndpointInput): string {
  return `surface:${digest(`${endpoint.method}:${endpoint.path}:${endpoint.filePath}`).slice(7, 27)}`;
}

function counts(values: string[]): Record<string, number> {
  return values.reduce<Record<string, number>>((result, value) => {
    result[value] = (result[value] || 0) + 1;
    return result;
  }, {});
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
