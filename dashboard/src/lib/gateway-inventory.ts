/** Passive declaration evidence admitted from the scanner's v1 SARIF extension. */
export const gatewaySummarySelect = {
  inputStatus: true, fileCount: true, resolved: true, ambiguous: true, unresolved: true,
  omittedFiles: true, omittedRoutes: true,
} as const;

export interface GatewaySummary {
  inputStatus: string;
  fileCount: number;
  resolved: number;
  ambiguous: number;
  unresolved: number;
  omittedFiles: number;
  omittedRoutes: number;
}

const schemas = [
  "spring.cloud.gateway.routes", "spring.cloud.gateway.mvc.routes",
  "spring.cloud.gateway.server.webflux.routes", "spring.cloud.gateway.server.webmvc.routes",
  "kong.1.1", "kong.3.0",
] as const;

const reasonStatus = {
  manifest_service_name: "resolved",
  multiple_manifest_owners: "ambiguous",
  conflicting_service_ref: "ambiguous",
  ambiguous_service_ref: "ambiguous",
  conflicting_service_destination: "ambiguous",
  no_manifest_owner: "unresolved",
  dynamic_or_unsupported_destination: "unresolved",
  kong_upstream_pool: "unresolved",
  unresolved_service_ref: "unresolved",
} as const;

const diagnostics = [
  "unreadable_or_size_limit", "unsupported_kong_format", "invalid_or_unsupported_configuration",
  "no_supported_gateway_declarations",
] as const;

export interface GatewayRouteReview {
  schema: string;
  document: number;
  line: number;
  name: string | null;
  status: "resolved" | "unresolved" | "ambiguous";
  reason: keyof typeof reasonStatus;
  owners: string[];
}
export interface GatewayFileReview {
  repositoryId: string;
  path: string;
  sha256: string | null;
  diagnostics: string[];
  routes: GatewayRouteReview[];
}
export interface GatewayReview extends GatewaySummary {
  digest: string;
  files: GatewayFileReview[];
}

export class GatewayInventoryError extends Error {
  constructor() { super("Invalid or unsupported gateway inventory."); }
}

function requireValue(condition: unknown): asserts condition {
  if (!condition) throw new GatewayInventoryError();
}
function record(value: unknown): Record<string, unknown> {
  requireValue(value && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}
function array(value: unknown, limit: number): unknown[] {
  requireValue(Array.isArray(value) && value.length <= limit);
  return value;
}
function count(value: unknown, minimum = 0): number {
  requireValue(typeof value === "number" && Number.isInteger(value) && value >= minimum && value <= 2_147_483_647);
  return value;
}
function validRepo(value: unknown): value is string {
  return typeof value === "string" && value.length <= 2048 && value.split("/").every(
    (part) => /^[A-Za-z0-9._-]+$/.test(part) && part !== "." && part !== "..",
  );
}
function digest(value: unknown): string {
  requireValue(typeof value === "string" && /^[0-9a-f]{64}$/.test(value));
  return value;
}

function route(value: unknown): GatewayRouteReview {
  const row = record(value);
  const schema = schemas.find((option) => row.schema_path === option);
  requireValue(schema && typeof row.reason === "string" && Object.hasOwn(reasonStatus, row.reason));
  const reason = row.reason as keyof typeof reasonStatus;
  const status = reasonStatus[reason];
  requireValue(row.status === status);
  const name = row.route_name;
  requireValue(name === null || (typeof name === "string" && /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(name)));
  const owners = array(row.repository_ids, 4096);
  requireValue(owners.every(validRepo) && new Set(owners).size === owners.length);
  requireValue(reason === "manifest_service_name" ? owners.length === 1
    : reason === "multiple_manifest_owners" ? owners.length >= 2 : owners.length === 0);
  return { schema, name, document: count(row.document, 1), line: count(row.line, 1), status, reason, owners };
}

export function parseGatewayInventory(value: unknown): GatewayReview | null {
  if (value === undefined) return null;
  const input = record(value);
  requireValue(input.version === 1 && (input.input_status === "processed" || input.input_status === "partial"));
  const summary: GatewaySummary = {
    inputStatus: input.input_status, fileCount: 0, resolved: 0, ambiguous: 0, unresolved: 0,
    omittedFiles: count(input.omitted_files), omittedRoutes: count(input.omitted_routes),
  };
  const reportedDigest = digest(input.digest);
  const seenFiles = new Set<string>();
  let routeCount = 0;
  let ownerReferences = 0;
  const files = array(input.files, 128).map((value): GatewayFileReview => {
    const file = record(value);
    requireValue(file.repository_id === "" || validRepo(file.repository_id));
    const path = file.path;
    requireValue(typeof path === "string" && path.length > 0 && path.length <= 4096
      && !/[\\\x00-\x1f\x7f]/.test(path) && !/^[A-Za-z]:/.test(path)
      && !path.split("/").some((part) => !part || [".", "..", ".git"].includes(part)));
    const key = JSON.stringify([file.repository_id, path]);
    requireValue(!seenFiles.has(key));
    seenFiles.add(key);
    const issues = array(file.diagnostics, 4096).map((issue) => {
      const known = diagnostics.find((item) => item === issue);
      requireValue(known);
      return known;
    });
    const rows = array(file.routes, 4096 - routeCount);
    routeCount += rows.length;
    requireValue(file.sha256 !== null || (rows.length === 0 && issues.includes("unreadable_or_size_limit")));
    const routes = rows.map((value) => {
      const review = route(value);
      ownerReferences += review.owners.length;
      requireValue(ownerReferences <= 65_536);
      summary[review.status]++;
      return review;
    });
    return { repositoryId: file.repository_id, path, sha256: file.sha256 === null ? null : digest(file.sha256),
      diagnostics: [...new Set(issues)], routes };
  });
  summary.fileCount = files.length;
  if (summary.omittedFiles || summary.omittedRoutes || files.some((file) => file.diagnostics.length))
    requireValue(summary.inputStatus === "partial");
  return { ...summary, digest: reportedDigest, files };
}

export function gatewayStorage(review: GatewayReview) {
  const { files, digest, ...summary } = review;
  const details = JSON.stringify({ digest, files });
  requireValue(new TextEncoder().encode(details).length <= 8 * 1024 * 1024);
  return { summary, data: { ...summary, details } };
}

export function storedGatewayReview(row: (GatewaySummary & { details: string }) | null): GatewayReview | null {
  if (!row) return null;
  const { digest, files } = JSON.parse(row.details) as Pick<GatewayReview, "digest" | "files">;
  const { inputStatus, fileCount, resolved, ambiguous, unresolved, omittedFiles, omittedRoutes } = row;
  return { inputStatus, fileCount, resolved, ambiguous, unresolved, omittedFiles, omittedRoutes, digest, files };
}
