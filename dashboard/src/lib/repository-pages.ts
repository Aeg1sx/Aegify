import { readBoundedProviderBody } from "./repo-fetcher.ts";

export type RepositoryProvider = "github" | "gitlab";
const pagesPerRequest = 5;

// Only page numbers from the picker reach the provider's fixed endpoint.
export function repositoryWindow(params: URLSearchParams): { provider?: RepositoryProvider; start: number } | null {
  if (!params.has("provider") && !params.has("start")) return { start: 1 };
  const provider = params.get("provider");
  const raw = params.get("start") ?? "";
  if (params.getAll("provider").length !== 1 || params.getAll("start").length !== 1
    || (provider !== "github" && provider !== "gitlab") || !/^[1-9]\d{0,8}$/.test(raw)) return null;
  const start = Number(raw);
  return (start - 1) % pagesPerRequest === 0 ? { provider, start } : null;
}

function isLastPage(records: unknown[], headers: Headers) {
  if (headers.has("x-next-page")) return !headers.get("x-next-page");
  const link = headers.get("link");
  if (link && /;\s*rel="next"/i.test(link)) return false;
  if (link && /;\s*rel="(?:first|prev|last)"/i.test(link)) return true;
  return records.length < 100;
}

/** Retain complete pages when a provider stops responding. */
export async function repositoryPages<T>(
  address: (page: number) => string,
  headers: Record<string, string>,
  signal: AbortSignal,
  start = 1,
): Promise<{ items: T[]; state: "complete" | "limited" | "interrupted"; next?: number }> {
  const items: T[] = [];
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(12_000)]);
  for (let page = start; page < start + pagesPerRequest; page++) {
    try {
      const response = await fetch(address(page), {
        headers, signal: deadline, cache: "no-store", redirect: "error",
      });
      if (!response.ok) {
        await response.body?.cancel();
        return { items, state: "interrupted" };
      }
      const records = JSON.parse(await readBoundedProviderBody(response, 4 * 1024 * 1024, deadline));
      if (!Array.isArray(records) || records.length > 100) return { items, state: "interrupted" };
      items.push(...records);
      if (isLastPage(records, response.headers)) return { items, state: "complete" };
    } catch (error) {
      if (signal.aborted) throw error;
      return { items, state: "interrupted" };
    }
  }
  return { items, state: "limited", next: start + pagesPerRequest };
}
