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
}

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
