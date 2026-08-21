import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const MAX_NODES = 150;
const MAX_HOPS = 2;

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const finding = await prisma.finding.findUnique({
    where: { id },
    select: { scanId: true, filePath: true, lineStart: true, lineEnd: true },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  // Step 1: Find seed nodes that overlap the finding's location (DB-level query)
  let seedNodes = await prisma.callGraphNode.findMany({
    where: {
      scanId: finding.scanId,
      filePath: finding.filePath,
      lineStart: { gt: 0, lte: finding.lineEnd },
      lineEnd: { gte: finding.lineStart },
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

  if (seedNodes.length === 0) {
    // Fallback: non-module nodes in same file
    seedNodes = await prisma.callGraphNode.findMany({
      where: {
        scanId: finding.scanId,
        filePath: finding.filePath,
        nodeType: { not: "module" },
      },
      select: {
        id: true, qualifiedName: true, filePath: true,
        lineStart: true, lineEnd: true, nodeType: true,
        hasFinding: true, findingSeverity: true,
      },
    });
  }

  if (seedNodes.length === 0) {
    // Last resort: module node for the file
    seedNodes = await prisma.callGraphNode.findMany({
      where: {
        scanId: finding.scanId,
        filePath: finding.filePath,
      },
      select: {
        id: true, qualifiedName: true, filePath: true,
        lineStart: true, lineEnd: true, nodeType: true,
        hasFinding: true, findingSeverity: true,
      },
    });
  }

  if (seedNodes.length === 0) {
    return NextResponse.json({ nodes: [], edges: [] });
  }

  const findingNodeIds = new Set(seedNodes.map((n) => n.id));

  // Step 2: BFS expanding outward, querying edges per hop, with a node cap
  const collectedNodeIds = new Set(seedNodes.map((n) => n.id));
  let frontier = [...collectedNodeIds];
  let capped = false;

  for (let hop = 0; hop < MAX_HOPS && !capped; hop++) {
    if (frontier.length === 0) break;

    // Query edges connected to frontier nodes (both directions)
    const [outEdges, inEdges] = await Promise.all([
      prisma.callGraphEdge.findMany({
        where: { sourceNodeId: { in: frontier }, scanId: finding.scanId },
        select: { sourceNodeId: true, targetNodeId: true },
      }),
      prisma.callGraphEdge.findMany({
        where: { targetNodeId: { in: frontier }, scanId: finding.scanId },
        select: { sourceNodeId: true, targetNodeId: true },
      }),
    ]);

    const nextFrontier: string[] = [];

    for (const e of outEdges) {
      if (!collectedNodeIds.has(e.targetNodeId)) {
        collectedNodeIds.add(e.targetNodeId);
        nextFrontier.push(e.targetNodeId);
        if (collectedNodeIds.size >= MAX_NODES) { capped = true; break; }
      }
    }

    if (!capped) {
      for (const e of inEdges) {
        if (!collectedNodeIds.has(e.sourceNodeId)) {
          collectedNodeIds.add(e.sourceNodeId);
          nextFrontier.push(e.sourceNodeId);
          if (collectedNodeIds.size >= MAX_NODES) { capped = true; break; }
        }
      }
    }

    frontier = nextFrontier;
  }

  // Step 3: Fetch full node data and edges for the collected set
  const nodeIds = [...collectedNodeIds];

  const [nodes, edges] = await Promise.all([
    prisma.callGraphNode.findMany({
      where: { id: { in: nodeIds } },
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
      where: {
        scanId: finding.scanId,
        sourceNodeId: { in: nodeIds },
        targetNodeId: { in: nodeIds },
      },
      select: {
        id: true,
        sourceNodeId: true,
        targetNodeId: true,
        callSiteLine: true,
      },
    }),
  ]);

  return NextResponse.json({
    nodes: nodes.map((n) => ({
      ...n,
      isFindingNode: findingNodeIds.has(n.id),
    })),
    edges,
    capped,
  });
}
