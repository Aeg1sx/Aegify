import { requireAccess, scanScope, findingScope } from "@/lib/access";
import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { queueConditions } from "@/lib/finding-view";

export async function GET(request: Request) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  const [totalScans, totalFindings, severities, statuses, recentScans, topRules, evidence, priorityQueue, regressions, overdue] =
    await Promise.all([
      prisma.scan.count({ where: scanScope(access) }),
      prisma.finding.count({ where: { ...findingScope(access), isCurrent: true } }),
      prisma.finding.groupBy({
        by: ["severity"],
        where: { ...findingScope(access), isCurrent: true },
        _count: true,
      }),
      prisma.finding.groupBy({
        by: ["status"],
        where: { ...findingScope(access), isCurrent: true },
        _count: true,
      }),
      prisma.scan.findMany({
        where: scanScope(access),
        orderBy: { createdAt: "desc" },
        take: 10,
        select: { id: true, repository: true, project: { select: { name: true } }, branch: true, status: true, filesScanned: true,
          duration: true, createdAt: true, _count: { select: { findings: true } } },
      }),
      prisma.finding.groupBy({
        by: ["ruleId", "ruleName", "severity"],
        where: { ...findingScope(access), isCurrent: true },
        _count: true,
        orderBy: { _count: { ruleId: "desc" } },
        take: 15,
      }),
      prisma.finding.groupBy({ by: ["evidenceState"], where: { ...findingScope(access), isCurrent: true }, _count: true }),
      prisma.finding.findMany({
        where: { ...findingScope(access), ...queueConditions("priority") },
        orderBy: [{ severity: "asc" }, { createdAt: "desc" }, { id: "asc" }], take: 8,
        select: { id: true, ruleId: true, ruleName: true, severity: true, filePath: true, lineStart: true, evidenceState: true, owner: true, baselineState: true, scan: { select: { repository: true, branch: true } } },
      }),
      prisma.finding.count({ where: { ...findingScope(access), ...queueConditions("regressed") } }),
      prisma.finding.count({ where: { ...findingScope(access), ...queueConditions("overdue") } }),
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
