import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  const [totalScans, totalFindings, severities, statuses, recentScans, topRules] =
    await Promise.all([
      prisma.scan.count(),
      prisma.finding.count(),
      prisma.finding.groupBy({
        by: ["severity"],
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["status"],
        _count: true,
      }),
      prisma.scan.findMany({
        orderBy: { createdAt: "desc" },
        take: 10,
        include: { _count: { select: { findings: true } } },
      }),
      prisma.finding.groupBy({
        by: ["ruleId", "ruleName", "severity"],
        _count: true,
        orderBy: { _count: { ruleId: "desc" } },
        take: 15,
      }),
    ]);

  const severityMap: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const s of severities) {
    severityMap[s.severity] = s._count;
  }

  const statusMap: Record<string, number> = {};
  for (const s of statuses) {
    statusMap[s.status] = s._count;
  }

  return NextResponse.json({
    totalScans,
    totalFindings,
    severities: severityMap,
    statuses: statusMap,
    recentScans: recentScans.map((s) => ({
      ...s,
      findingsCount: s._count.findings,
    })),
    topRules: topRules.map((r) => ({
      ruleId: r.ruleId,
      ruleName: r.ruleName,
      severity: r.severity,
      count: r._count,
    })),
  });
}
