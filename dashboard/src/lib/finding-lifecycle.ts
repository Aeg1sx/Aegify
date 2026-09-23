import { createHash } from "node:crypto";

export type FindingBaselineState = "new" | "unchanged" | "updated" | "regressed";

export interface FingerprintInput {
  ruleId: string;
  filePath: string;
  message: string;
  codeSnippet?: string;
  partialFingerprints?: Record<string, string>;
  repositoryId?: string;
  modulePath?: string;
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

/** Exact historical algorithm, used only for guarded legacy-identity lookup. */
export function legacyFindingFingerprint(input: FingerprintInput): string {
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

function trimIdentityText(value: string): string {
  return value.replace(/^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g, "");
}

export function normalizeIdentityPath(value: string): string {
  const path = value.replaceAll("\\", "/");
  const scheme = path.match(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/)(.*)$/);
  const prefix = scheme ? scheme[1] + (scheme[2].startsWith("/") ? "/" : "")
    : path.startsWith("//") ? "//" : path.startsWith("/") ? "/" : "";
  const body = scheme?.[2] ?? path;
  return prefix + body.split("/").filter((part) => part && part !== ".").join("/");
}

export function relativeIdentityPath(value: string): string {
  const path = normalizeIdentityPath(value);
  return !path || path.startsWith("/") || path.split("/")[0].includes(":")
    || path.split("/").includes("..") || /[\x00-\x1f]/.test(path) ? "" : path;
}

/** Mirrors Python json.dumps(ensure_ascii=True, separators=(",", ":")). */
function identityDigest(material: string[]): string {
  const encoded = JSON.stringify(material).replace(/[\u007f-\uffff]/g,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
  return sha256(encoded);
}

export function findingIdentityScope(input: FingerprintInput): { repositoryId: string; modulePath: string } {
  return {
    repositoryId: trimIdentityText(input.repositoryId || ""),
    modulePath: relativeIdentityPath(input.modulePath || "") || relativeIdentityPath(input.filePath),
  };
}

export function sourceFindingFingerprint(input: FingerprintInput): string {
  const path = relativeIdentityPath(input.modulePath || "") || normalizeIdentityPath(input.filePath);
  return `aegify-finding/v2:${identityDigest([
    "aegify-finding/v2", trimIdentityText(input.ruleId), trimIdentityText(input.repositoryId || ""), path,
    trimIdentityText((input.codeSnippet || input.message).replace(/\r\n?/g, "\n")),
  ])}`;
}

export function stableFindingFingerprint(input: FingerprintInput): string {
  // Recompute Aegify's identity from retained source evidence. Producer strings
  // cannot override a repository/rule/path namespace or force a merge.
  if (input.partialFingerprints?.["aegifyFingerprint/v2"]
      || (input.partialFingerprints?.["aegifyFingerprint/v1"] && relativeIdentityPath(input.modulePath || ""))) {
    return sourceFindingFingerprint(input);
  }
  const path = relativeIdentityPath(input.modulePath || "") || normalizeIdentityPath(input.filePath);
  for (const name of PREFERRED_SARIF_FINGERPRINTS) {
    const supplied = input.partialFingerprints?.[name]?.trim();
    if (supplied) return `sarif-finding/v2:${identityDigest([
      "sarif-finding/v2", trimIdentityText(input.ruleId), trimIdentityText(input.repositoryId || ""),
      path, name, supplied,
    ])}`;
  }
  return sourceFindingFingerprint(input);
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
