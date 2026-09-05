import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { handlerRange } from "@/lib/endpoint-evidence";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const endpoint = await prisma.endpoint.findUnique({
    where: { id },
    include: {
      scan: {
        select: {
          id: true,
          repository: true,
          branch: true,
          commitSha: true,
          createdAt: true,
        },
      },
    },
  });

  if (!endpoint) {
    return NextResponse.json({ error: "Endpoint not found" }, { status: 404 });
  }

  // An overlapping source range is a location association, not proof of an attack path.
  const range = handlerRange(endpoint.lineStart, endpoint.lineEnd);
  const where = range ? {
      scanId: endpoint.scanId,
      filePath: endpoint.filePath,
      repositoryId: endpoint.repositoryId,
      lineStart: { gte: 1, lte: range.end },
      lineEnd: { gte: range.start },
  } : null;
  const siblingWhere = { scanId: endpoint.scanId, repositoryId: endpoint.repositoryId, filePath: endpoint.filePath, id: { not: endpoint.id } };
  const [relatedFindings, relatedFindingCount, siblings, siblingCount] = await Promise.all([
    where ? prisma.finding.findMany({ where, orderBy: [{ lineStart: "asc" }, { id: "asc" }], take: 100 }) : [],
    where ? prisma.finding.count({ where }) : 0,
    prisma.endpoint.findMany({ where: siblingWhere, select: { id: true, method: true, path: true, handlerFunction: true, lineStart: true, lineEnd: true, authRequired: true }, orderBy: [{ lineStart: "asc" }, { id: "asc" }], take: 12 }),
    prisma.endpoint.count({ where: siblingWhere }),
  ]);

  return NextResponse.json({ endpoint, relatedFindings, relatedFindingCount, association: range ? "handler_range_overlap" : "unavailable_handler_range", siblings, siblingCount }, { headers: { "Cache-Control": "no-store" } });
}
