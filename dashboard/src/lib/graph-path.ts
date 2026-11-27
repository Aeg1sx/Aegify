export interface PathNode { id: string; nodeType: string }
export interface PathEdge { sourceNodeId: string; targetNodeId: string }

export function graphSymbolName(name: string): string {
  if (name.startsWith("<module:") && name.endsWith(">")) {
    return name.slice(8, -1).split(/[\\/]/).pop() || name;
  }
  const separator = name.indexOf("::");
  if (name.startsWith("file:") && separator >= 0) {
    const symbol = name.slice(separator + 2);
    return symbol.replace(/\((?:\?(?:,\?)*)?\)$/, "") || name;
  }
  return name;
}
/** One shortest recorded call path, not a proof of data flow or runtime reachability. */
export function entryPath(nodes: PathNode[], edges: PathEdge[], target: string): string[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  if (!byId.has(target)) return [];
  const incoming = new Map<string, string[]>();
  for (const edge of edges) {
    if (!byId.has(edge.sourceNodeId) || !byId.has(edge.targetNodeId)) continue;
    const sources = incoming.get(edge.targetNodeId) || [];
    sources.push(edge.sourceNodeId); incoming.set(edge.targetNodeId, sources);
  }
  const next = new Map<string, string | null>([[target, null]]);
  const queue = [target];
  for (let i = 0; i < queue.length && i < 3000; i++) {
    const id = queue[i];
    if (byId.get(id)?.nodeType === "entry_point") {
      const path: string[] = [];
      for (let current: string | null = id; current; current = next.get(current) ?? null) path.push(current);
      return path;
    }
    for (const source of incoming.get(id) || []) {
      if (!next.has(source)) { next.set(source, id); queue.push(source); }
    }
  }
  return [];
}
