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
