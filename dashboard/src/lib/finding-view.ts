import type { Prisma } from "@prisma/client";

export const ACTIVE_STATUSES = ["open", "triaged", "confirmed", "in_progress"];
export const QUEUE_LABELS = { active: "Unresolved", priority: "High-risk queue", regressed: "Reopened", overdue: "Past due" } as const;
export function queueConditions(queue: string | null, now = new Date()): Prisma.FindingWhereInput {
  if (!queue || !Object.hasOwn(QUEUE_LABELS, queue)) return {};
  return {
    isCurrent: true,
    status: { in: ACTIVE_STATUSES },
    ...(queue === "priority" && { severity: { in: ["critical", "high"] } }),
    ...(queue === "regressed" && { baselineState: "regressed" }),
    ...(queue === "overdue" && { dueAt: { lt: now } }),
  };
}
export const FILTER_KEYS = ["search", "severity", "status", "ruleId", "language", "projectId", "scanId", "repositoryId", "source", "disposition", "evidenceState", "baselineState", "queue", "history", "sort", "page"] as const;
export type FindingFilters = Record<typeof FILTER_KEYS[number], string>;
export function findingFilters(params = new URLSearchParams()): FindingFilters {
  const result = Object.fromEntries(FILTER_KEYS.map((key) => [
    key, key === "scanId" || key === "repositoryId" ? params.get(key) || "" : (params.get(key) || "").slice(0, 500),
  ])) as FindingFilters;
  result.page = String(boundedInteger(result.page, 1, 100_000));
  result.sort = ["newest", "oldest", "file", "rule"].includes(result.sort) ? result.sort : "newest";
  result.history = result.history === "true" ? "true" : "";
  if (!Object.hasOwn(QUEUE_LABELS, result.queue)) result.queue = "";
  return result;
}
export function boundedInteger(value: string | null, fallback: number, maximum: number): number {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? Math.min(number, maximum) : fallback;
}
export function filterQuery(filters: FindingFilters): string {
  return new URLSearchParams(Object.entries(filters).filter(([, value]) => value !== "")).toString();
}

export function invalidFindingScope(params: URLSearchParams): boolean {
  return ["scanId", "repositoryId"].some((key) => {
    const values = params.getAll(key);
    return values.length > 1 || (values.length === 1 && (!values[0].trim() || /[\x00-\x1f\x7f]/.test(values[0])));
  });
}

export function scanFindingsHref(scanId: string, repositoryId?: string): string {
  const params = new URLSearchParams({ scanId });
  if (repositoryId) params.set("repositoryId", repositoryId);
  return "/findings?" + params.toString();
}
