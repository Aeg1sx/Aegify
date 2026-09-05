export type EvidenceKind = "frontend" | "gateway" | "runtime";
export interface EndpointEvidence {
  key: string;
  kind: EvidenceKind;
  id?: string;
  label: string;
  method: string;
  location: string;
  matchKind?: string;
  confidence?: number;
  details: Record<string, string | number | boolean | string[]>;
}
export interface Parsed<T> { items: T[]; warnings: string[]; total: number }

/** Missing handler bounds must not turn into a whole-file match. */
export function handlerRange(start: unknown, end: unknown): { start: number; end: number } | null {
  return typeof start === "number" && typeof end === "number" && Number.isSafeInteger(start) && Number.isSafeInteger(end) && start > 0 && end >= start ? { start, end } : null;
}

function arrayArtifact(raw: string, label: string): Parsed<unknown> {
  if (!raw) return { items: [], warnings: [], total: 0 };
  if (raw.length > 2_000_000) return { items: [], warnings: [`${label}: artifact exceeds the preview size limit.`], total: 0 };
  try {
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value)) throw new Error("Not an array");
    return { items: value.slice(0, 200), warnings: value.length > 200 ? [`${label}: showing the first 200 of ${value.length} records.`] : [], total: value.length };
  } catch { return { items: [], warnings: [`${label}: malformed JSON array; evidence could not be read.`], total: 0 }; }
}
function record(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
const STRING_FIELDS: Record<EvidenceKind, string[]> = {
  frontend: ["id", "path", "method", "filePath", "client", "repositoryId", "matchKind"],
  gateway: ["id", "uri", "file_path", "repository_id", "matchKind"],
  runtime: ["id", "kind", "method", "path", "traceId", "spanId", "repositoryId", "matchKind"],
};

/** Preview/export only known metadata. Headers, bodies, and arbitrary extra fields are excluded. */
export function parseEndpointEvidence(raw: string, kind: EvidenceKind): Parsed<EndpointEvidence> {
  const parsed = arrayArtifact(raw, kind);
  let invalid = false;
  const items = parsed.items.flatMap((value, index): EndpointEvidence[] => {
    if (!record(value)) { invalid = true; return []; }
    const details: EndpointEvidence["details"] = {};
    for (const key of STRING_FIELDS[kind]) {
      if (value[key] === undefined || value[key] === null) continue;
      if (typeof value[key] !== "string" || (value[key] as string).length > 4096) { invalid = true; continue; }
      // Do not carry query-string or fragment values into the evidence preview/export.
      details[key] = ["path", "uri"].includes(key) ? (value[key] as string).split(/[?#]/)[0] : value[key] as string;
    }
    const numeric = kind === "runtime" ? ["statusCode", "durationMs", "linkConfidence"] : ["line", "confidence", "linkConfidence"];
    for (const key of numeric) {
      const n = value[key];
      if (n === undefined || n === null) continue;
      const valid = typeof n === "number" && Number.isFinite(n) && n >= 0 &&
        (!key.toLowerCase().includes("confidence") || n <= 1) &&
        (key !== "line" || (Number.isSafeInteger(n) && n > 0)) &&
        (key !== "statusCode" || (Number.isInteger(n) && n >= 100 && n <= 599));
      if (valid) details[key] = n as number; else invalid = true;
    }
    for (const key of kind === "runtime" ? ["passed"] : kind === "frontend" ? ["dynamic"] : []) {
      if (typeof value[key] === "boolean") details[key] = value[key];
      else if (value[key] !== undefined && value[key] !== null) invalid = true;
    }
    if (kind === "gateway") for (const key of ["path_patterns", "methods", "filters"]) {
      if (value[key] === undefined) continue;
      const values = value[key];
      if (!Array.isArray(values)) { invalid = true; continue; }
      const strings = values.filter((item): item is string => typeof item === "string" && item.length <= 4096).slice(0, 50);
      if (strings.length !== values.length) invalid = true;
      details[key] = key === "path_patterns" ? strings.map((item) => item.split(/[?#]/)[0]) : strings;
    }
    const id = typeof details.id === "string" ? details.id : undefined;
    const path = details.path || (Array.isArray(details.path_patterns) ? details.path_patterns.join(", ") : "") || details.uri;
    const file = details.filePath || details.file_path;
    if (!id && !path && !file && !details.traceId) { invalid = true; return []; }
    return [{ key: `${kind}-${index}`, kind, id, label: String(path || details.client || details.kind || "Recorded link"), method: String(details.method || (Array.isArray(details.methods) ? details.methods.join(", ") : "") || "—"), location: file ? `${file}${details.line ? ":" + details.line : ""}` : details.traceId ? "Trace " + details.traceId : "Source location not included", matchKind: typeof details.matchKind === "string" ? details.matchKind : undefined, confidence: typeof details.linkConfidence === "number" ? details.linkConfidence : undefined, details }];
  });
  return { ...parsed, items, warnings: [...parsed.warnings, ...(invalid ? [`${kind}: malformed records or fields were omitted; inspect the original artifact for completeness.`] : [])] };
}

export function parseEndpointContract(parameters: string, middleware: string) {
  const params = arrayArtifact(parameters, "Parameters");
  const chain = arrayArtifact(middleware, "Middleware");
  const fields = params.items.flatMap((item) => record(item) && typeof item.name === "string" && item.name.length <= 4096 && typeof item.location === "string" && item.location.length <= 4096 ? [{ name: item.name, location: item.location, type: typeof item.paramType === "string" && item.paramType.length <= 4096 ? item.paramType : "Not specified" }] : []);
  const handlers = chain.items.filter((item): item is string => typeof item === "string" && item.length <= 4096);
  return { parameters: fields, middleware: handlers, warnings: [...params.warnings, ...chain.warnings, ...(fields.length !== params.items.length || handlers.length !== chain.items.length ? ["Contract: malformed entries were omitted."] : [])] };
}
