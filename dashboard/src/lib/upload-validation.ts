export type UploadKind = "sarif" | "openapi";

interface UploadMetadata {
  name: string;
  size: number;
  type: string;
}

const POLICIES: Record<
  UploadKind,
  { extensions: Set<string>; mediaTypes: Set<string>; maxBytes: number; label: string }
> = {
  sarif: {
    extensions: new Set([".sarif", ".json"]),
    mediaTypes: new Set(["", "application/json", "application/sarif+json"]),
    maxBytes: 100 * 1024 * 1024,
    label: "SARIF",
  },
  openapi: {
    extensions: new Set([".json"]),
    mediaTypes: new Set(["", "application/json"]),
    maxBytes: 10 * 1024 * 1024,
    label: "OpenAPI",
  },
};

export function uploadValidationError(
  file: UploadMetadata,
  kind: UploadKind,
): string | null {
  const policy = POLICIES[kind];
  const normalizedName = file.name.trim().toLowerCase();
  const extension = [...policy.extensions].find((item) => normalizedName.endsWith(item));

  if (!extension || !policy.mediaTypes.has(file.type.toLowerCase())) {
    return `${policy.label} upload has an unsupported file type`;
  }
  if (file.size > policy.maxBytes) {
    return `${policy.label} upload exceeds the ${policy.maxBytes / (1024 * 1024)} MB limit`;
  }
  return null;
}
