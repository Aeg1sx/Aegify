import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

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
          createdAt: true,
        },
      },
    },
  });

  if (!endpoint) {
    return NextResponse.json({ error: "Endpoint not found" }, { status: 404 });
  }

  // Find related findings in the same file
  const relatedFindings = await prisma.finding.findMany({
    where: {
      scanId: endpoint.scanId,
      filePath: endpoint.filePath,
      lineStart: { gte: endpoint.lineStart, lte: endpoint.lineEnd || 99999 },
    },
    orderBy: { severity: "asc" },
  });

  return NextResponse.json({ endpoint, relatedFindings });
}
