/** Keep successfully retrieved pages if a provider stops responding. */
export async function repositoryPages<T>(
  address: (page: number) => string,
  headers: Record<string, string>,
  signal: AbortSignal,
): Promise<{ items: T[]; state: "complete" | "limited" | "interrupted" }> {
  const items: T[] = [];
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(12_000)]);
  for (let page = 1; page <= 5; page++) {
    try {
      const response = await fetch(address(page), {
        headers,
        signal: deadline,
        cache: "no-store",
        redirect: "error",
      });
      if (!response.ok) {
        await response.body?.cancel();
        return { items, state: "interrupted" };
      }
      const records = await response.json();
      if (!Array.isArray(records)) return { items, state: "interrupted" };
      items.push(...records.slice(0, 100));
      if (records.length < 100) return { items, state: "complete" };
    } catch (error) {
      if (signal.aborted) throw error;
      return { items, state: "interrupted" };
    }
  }
  return { items, state: "limited" };
}
