import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const scan = await prisma.scan.findUnique({
    where: { id },
    include: {
      findings: {
        orderBy: [
          { severity: "asc" },
          { lineStart: "asc" },
        ],
      },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  // Severity breakdown
  const severities = await prisma.finding.groupBy({
    by: ["severity"],
    where: { scanId: id },
    _count: true,
  });
  const severityMap: Record<string, number> = {};
  for (const s of severities) {
    severityMap[s.severity] = s._count;
  }

  // Status breakdown
  const statuses = await prisma.finding.groupBy({
    by: ["status"],
    where: { scanId: id },
    _count: true,
  });
  const statusMap: Record<string, number> = {};
  for (const s of statuses) {
    statusMap[s.status] = s._count;
  }

  // Top rules
  const topRules = await prisma.finding.groupBy({
    by: ["ruleId", "ruleName"],
    where: { scanId: id },
    _count: true,
    orderBy: { _count: { ruleId: "desc" } },
    take: 10,
  });

  // Check if call graph exists
  const graphNodeCount = await prisma.callGraphNode.count({
    where: { scanId: id },
  });

  return NextResponse.json({
    id: scan.id,
    repository: scan.repository,
    branch: scan.branch,
    commitSha: scan.commitSha,
    status: scan.status,
    filesScanned: scan.filesScanned,
    duration: scan.duration,
    createdAt: scan.createdAt,
    findings: scan.findings || [],
    severities: severityMap,
    statuses: statusMap,
    topRules: topRules.map((r) => ({
      ruleId: r.ruleId,
      ruleName: r.ruleName,
      count: r._count,
    })),
    hasCallGraph: graphNodeCount > 0,
    callGraphNodeCount: graphNodeCount,
  });
}
