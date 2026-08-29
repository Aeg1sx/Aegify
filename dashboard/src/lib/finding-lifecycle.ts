import { createHash } from "node:crypto";

export type FindingBaselineState = "new" | "unchanged" | "updated" | "regressed";

export interface FingerprintInput {
  ruleId: string;
  filePath: string;
  message: string;
  codeSnippet?: string;
  partialFingerprints?: Record<string, string>;
}

export interface ExistingFindingIdentity {
  status: string;
  absentAt: Date | string | null;
  lastSeverity: string;
  lastEvidenceState: string;
  lastMessageDigest: string;
}

export interface CurrentFindingVersion {
  severity: string;
  evidenceState: string;
  message: string;
}

const PREFERRED_SARIF_FINGERPRINTS = [
  "aegifyFingerprint/v1",
  "primaryLocationLineHash",
  "primaryLocationStartColumnFingerprint",
];

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizePath(value: string): string {
  return value
    .replaceAll("\\", "/")
    .replace(/^file:\/\//, "")
    .replace(/^\.\//, "")
    .replace(/\/+/g, "/");
}

function normalizeEvidenceText(value: string): string {
  return value
    .replace(/\b\d+\b/g, "#")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

export function findingMessageDigest(message: string): string {
  return `sha256:${sha256(normalizeEvidenceText(message))}`;
}

export function stableFindingFingerprint(input: FingerprintInput): string {
  for (const name of PREFERRED_SARIF_FINGERPRINTS) {
    const supplied = input.partialFingerprints?.[name]?.trim();
    if (supplied) return `sarif:${name}:${supplied}`;
  }

  const stableEvidence = normalizeEvidenceText(input.codeSnippet || input.message);
  const material = [
    "aegify-finding/v1",
    input.ruleId.trim().toLowerCase(),
    normalizePath(input.filePath),
    stableEvidence,
  ].join("\n");
  return `sha256:${sha256(material)}`;
}

export function classifyFindingBaseline(
  existing: ExistingFindingIdentity | undefined,
  current: CurrentFindingVersion,
): FindingBaselineState {
  if (!existing) return "new";
  if (existing.absentAt || existing.status === "fixed") return "regressed";

  const unchanged =
    existing.lastSeverity === current.severity &&
    existing.lastEvidenceState === current.evidenceState &&
    existing.lastMessageDigest === findingMessageDigest(current.message);
  return unchanged ? "unchanged" : "updated";
}
