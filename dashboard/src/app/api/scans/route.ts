import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get("page") || "1", 10);
  const limit = parseInt(url.searchParams.get("limit") || "20", 10);
  const hasCallGraph = url.searchParams.get("hasCallGraph");
  const projectId = url.searchParams.get("projectId");
  const skip = (page - 1) * limit;

  const where: Record<string, unknown> = {};

  // Filter by project
  if (projectId) {
    where.projectId = projectId;
  }

  // Filter scans that have call graph nodes
  if (hasCallGraph === "true") {
    where.graphNodes = { some: {} };
  }

  const [scans, total] = await Promise.all([
    prisma.scan.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip,
      take: limit,
      include: {
        _count: { select: { findings: true, graphNodes: true } },
      },
      // Include progress fields for running scans
    }),
    prisma.scan.count({ where }),
  ]);

  // Add severity breakdown for each scan
  const enriched = await Promise.all(
    scans.map(async (scan) => {
      const severities = await prisma.finding.groupBy({
        by: ["severity"],
        where: { scanId: scan.id },
        _count: true,
      });
      const severityMap: Record<string, number> = {};
      for (const s of severities) {
        severityMap[s.severity] = s._count;
      }
      return {
        ...scan,
        findingsCount: scan._count.findings,
        severities: severityMap,
        progressPhase: scan.progressPhase,
        progressPhaseName: scan.progressPhaseName,
        progressPercent: scan.progressPercent,
        progressMessage: scan.progressMessage,
        progressEta: scan.progressEta,
      };
    })
  );

  return NextResponse.json({ scans: enriched, total, page, limit });
}
