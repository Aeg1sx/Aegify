export const FILTER_KEYS = ["search", "severity", "status", "ruleId", "language", "projectId", "source", "disposition", "evidenceState", "baselineState", "history", "sort", "page"] as const;
export type FindingFilters = Record<typeof FILTER_KEYS[number], string>;
export function findingFilters(params = new URLSearchParams()): FindingFilters {
  const result = Object.fromEntries(FILTER_KEYS.map((key) => [key, (params.get(key) || "").slice(0, 500)])) as FindingFilters;
  result.page = String(boundedInteger(result.page, 1, 100_000));
  result.sort = ["newest", "oldest", "file", "rule"].includes(result.sort) ? result.sort : "newest";
  result.history = result.history === "true" ? "true" : "";
  return result;
}
export function boundedInteger(value: string | null, fallback: number, maximum: number): number {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? Math.min(number, maximum) : fallback;
}
export function filterQuery(filters: FindingFilters): string {
  return new URLSearchParams(Object.entries(filters).filter(([, value]) => value !== "")).toString();
}
