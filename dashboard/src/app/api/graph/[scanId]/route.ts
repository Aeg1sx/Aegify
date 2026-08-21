import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const CHUNK_SIZE = 500; // SQLite IN clause limit safe zone

async function findEdgesForNodes(scanId: string, nodeIds: string[]) {
  // Query edges in chunks to avoid SQLite variable limit
  const allEdges: Array<{
    id: string;
    sourceNodeId: string;
    targetNodeId: string;
    callSiteLine: number;
  }> = [];

  for (let i = 0; i < nodeIds.length; i += CHUNK_SIZE) {
    const chunk = nodeIds.slice(i, i + CHUNK_SIZE);
    const [sourceEdges, targetEdges] = await Promise.all([
      prisma.callGraphEdge.findMany({
        where: { scanId, sourceNodeId: { in: chunk } },
        select: {
          id: true,
          sourceNodeId: true,
          targetNodeId: true,
          callSiteLine: true,
        },
      }),
      prisma.callGraphEdge.findMany({
        where: { scanId, targetNodeId: { in: chunk } },
        select: {
          id: true,
          sourceNodeId: true,
          targetNodeId: true,
          callSiteLine: true,
        },
      }),
    ]);
    allEdges.push(...sourceEdges, ...targetEdges);
  }

  // Deduplicate
  const seen = new Set<string>();
  return allEdges.filter((e) => {
    if (seen.has(e.id)) return false;
    seen.add(e.id);
    return true;
  });
}

async function findNodesByIds(ids: string[]) {
  const allNodes: Array<{
    id: string;
    qualifiedName: string;
    filePath: string;
    lineStart: number;
    lineEnd: number;
    nodeType: string;
    hasFinding: boolean;
    findingSeverity: string | null;
  }> = [];

  for (let i = 0; i < ids.length; i += CHUNK_SIZE) {
    const chunk = ids.slice(i, i + CHUNK_SIZE);
    const nodes = await prisma.callGraphNode.findMany({
      where: { id: { in: chunk } },
      select: {
        id: true,
        qualifiedName: true,
        filePath: true,
        lineStart: true,
        lineEnd: true,
        nodeType: true,
        hasFinding: true,
        findingSeverity: true,
      },
    });
    allNodes.push(...nodes);
  }

  return allNodes;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const { scanId } = await params;
  const url = new URL(request.url);
  const mode = url.searchParams.get("mode") || "summary";
  const maxNodes = parseInt(url.searchParams.get("maxNodes") || "3000", 10);

  const scan = await prisma.scan.findUnique({ where: { id: scanId } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Get total counts for the HUD
  const [totalNodeCount, totalEdgeCount] = await Promise.all([
    prisma.callGraphNode.count({ where: { scanId } }),
    prisma.callGraphEdge.count({ where: { scanId } }),
  ]);

  if (mode === "full") {
    const [nodes, edges] = await Promise.all([
      prisma.callGraphNode.findMany({
        where: { scanId },
        select: {
          id: true,
          qualifiedName: true,
          filePath: true,
          lineStart: true,
          lineEnd: true,
          nodeType: true,
          hasFinding: true,
          findingSeverity: true,
        },
      }),
      prisma.callGraphEdge.findMany({
        where: { scanId },
        select: {
          id: true,
          sourceNodeId: true,
          targetNodeId: true,
          callSiteLine: true,
        },
      }),
    ]);

    return NextResponse.json({
      scanId,
      mode: "full",
      nodeCount: nodes.length,
      edgeCount: edges.length,
      totalNodes: totalNodeCount,
      totalEdges: totalEdgeCount,
      nodes,
      edges,
    });
  }

  // Summary mode: important nodes + 1-hop neighbors (capped)
  // Step 1: Get important nodes (entry points, sinks, finding nodes)
  const importantNodes = await prisma.callGraphNode.findMany({
    where: {
      scanId,
      OR: [
        { nodeType: "entry_point" },
        { nodeType: "sink" },
        { hasFinding: true },
      ],
    },
    select: {
      id: true,
      qualifiedName: true,
      filePath: true,
      lineStart: true,
      lineEnd: true,
      nodeType: true,
      hasFinding: true,
      findingSeverity: true,
    },
  });

  // Cap important nodes if there are too many
  const cappedImportant = importantNodes.length > maxNodes
    ? importantNodes.slice(0, maxNodes)
    : importantNodes;

  const importantIds = new Set(cappedImportant.map((n) => n.id));
  const importantIdsArray = [...importantIds];

  // Step 2: Get edges connected to important nodes (chunked for SQLite)
  const connectedEdges = await findEdgesForNodes(scanId, importantIdsArray);

  // Step 3: Collect neighbor IDs
  const neighborIds = new Set<string>();
  for (const edge of connectedEdges) {
    if (!importantIds.has(edge.sourceNodeId)) {
      neighborIds.add(edge.sourceNodeId);
    }
    if (!importantIds.has(edge.targetNodeId)) {
      neighborIds.add(edge.targetNodeId);
    }
  }

  // Step 4: Fetch neighbor nodes (cap total)
  const remainingBudget = Math.max(0, maxNodes - cappedImportant.length);
  const neighborIdsArray = [...neighborIds].slice(0, remainingBudget);
  const neighborNodes = neighborIdsArray.length > 0
    ? await findNodesByIds(neighborIdsArray)
    : [];

  const allNodes = [...cappedImportant, ...neighborNodes];
  const allNodeIds = new Set(allNodes.map((n) => n.id));

  // Only include edges where both endpoints are in our node set
  const filteredEdges = connectedEdges.filter(
    (e) => allNodeIds.has(e.sourceNodeId) && allNodeIds.has(e.targetNodeId)
  );

  return NextResponse.json({
    scanId,
    mode: "summary",
    nodeCount: allNodes.length,
    edgeCount: filteredEdges.length,
    totalNodes: totalNodeCount,
    totalEdges: totalEdgeCount,
    nodes: allNodes,
    edges: filteredEdges,
  });
}
