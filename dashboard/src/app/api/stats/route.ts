import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  const [totalScans, totalFindings, severities, statuses, recentScans, topRules, evidence, priorityQueue, regressions, overdue] =
    await Promise.all([
      prisma.scan.count(),
      prisma.finding.count({ where: { isCurrent: true } }),
      prisma.finding.groupBy({
        by: ["severity"],
        where: { isCurrent: true },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["status"],
        where: { isCurrent: true },
        _count: true,
      }),
      prisma.scan.findMany({
        orderBy: { createdAt: "desc" },
        take: 10,
        include: { _count: { select: { findings: true } } },
      }),
      prisma.finding.groupBy({
        by: ["ruleId", "ruleName", "severity"],
        where: { isCurrent: true },
        _count: true,
        orderBy: { _count: { ruleId: "desc" } },
        take: 15,
      }),
      prisma.finding.groupBy({ by: ["evidenceState"], where: { isCurrent: true }, _count: true }),
      prisma.finding.findMany({
        where: { isCurrent: true, severity: { in: ["critical", "high"] }, status: { in: ["open", "triaged", "confirmed", "in_progress"] } },
        orderBy: [{ severity: "asc" }, { createdAt: "desc" }, { id: "asc" }], take: 8,
        select: { id: true, ruleName: true, severity: true, filePath: true, lineStart: true, evidenceState: true, owner: true, baselineState: true },
      }),
      prisma.finding.count({ where: { isCurrent: true, baselineState: "regressed", status: { notIn: ["fixed", "false_positive", "accepted_risk"] } } }),
      prisma.finding.count({ where: { isCurrent: true, dueAt: { lt: new Date() }, status: { notIn: ["fixed", "false_positive", "accepted_risk"] } } }),
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
    evidence: Object.fromEntries(evidence.map((item) => [item.evidenceState, item._count])),
    priorityQueue,
    regressions,
    overdue,
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
