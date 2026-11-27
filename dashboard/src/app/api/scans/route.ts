import { requireAccess, scanScope } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { boundedInteger } from "@/lib/finding-view";

export async function GET(request: NextRequest) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  const url = new URL(request.url);
  const page = boundedInteger(url.searchParams.get("page"), 1, 100_000);
  const limit = boundedInteger(url.searchParams.get("limit"), 20, 100);
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

  const visible = { AND: [where, scanScope(access)] };
  const { scans, total, counts } = await prisma.$transaction(async (tx) => {
    const scans = await tx.scan.findMany({
      where: visible,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      skip,
      take: limit,
      include: { _count: { select: { findings: true, graphNodes: true } } },
    });
    const total = await tx.scan.count({ where: visible });
    const counts = scans.length
      ? await tx.finding.groupBy({
          by: ["scanId", "severity"],
          where: { scanId: { in: scans.map((scan) => scan.id) } },
          _count: true,
        })
      : [];
    return { scans, total, counts };
  });

  const severitiesByScan = new Map<string, Record<string, number>>();
  for (const { scanId, severity, _count } of counts) {
    const levels = severitiesByScan.get(scanId) ?? (Object.create(null) as Record<string, number>);
    levels[severity] = _count;
    severitiesByScan.set(scanId, levels);
  }
  const enriched = scans.map((scan) => ({
    ...scan,
    findingsCount: scan._count.findings,
    severities: severitiesByScan.get(scan.id) ?? {},
  }));

  return NextResponse.json({ scans: enriched, total, page, limit });
}
