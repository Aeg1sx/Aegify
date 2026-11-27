import { requireAccess } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { validateRuleYaml } from "@/lib/rule-validation";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const access = await requireAccess(request, true);
  if (access instanceof Response) return access;
  const { id } = await params;
  const rule = await prisma.rule.findUnique({ where: { id } });

  if (!rule) {
    return NextResponse.json({ error: "Rule not found" }, { status: 404 });
  }

  const where = { ruleId: id, isCurrent: true };
  const [total, severities, statuses, paths] = await prisma.$transaction([
    prisma.finding.aggregate({ where, _count: true, _avg: { confidence: true } }),
    prisma.finding.groupBy({ by: ["severity"], where, _count: { _all: true } }),
    prisma.finding.groupBy({ by: ["status"], where, _count: { _all: true } }),
    prisma.finding.groupBy({
      by: ["filePath"], where, _count: { _all: true },
      orderBy: [{ _count: { filePath: "desc" } }, { filePath: "asc" }],
    }),
  ]);
  return NextResponse.json({
    rule,
    stats: {
      totalFindings: total._count,
      severityBreakdown: Object.fromEntries(severities.map((row) => [row.severity, row._count._all])),
      statusBreakdown: Object.fromEntries(statuses.map((row) => [row.status, row._count._all])),
      avgConfidence: total._avg.confidence ?? 0,
      filePathCount: paths.length,
      topFiles: paths.slice(0, 10).map((row) => ({ path: row.filePath, count: row._count._all })),
    },
  });
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const access = await requireAccess(request, true);
  if (access instanceof Response) return access;
  const { id } = await params;
  const body = await request.json();

  const data: Record<string, unknown> = {};
  if (body.enabled !== undefined) data.enabled = body.enabled;
  if (body.yamlContent !== undefined) {
    if (typeof body.yamlContent !== "string") {
      return NextResponse.json({ error: "yamlContent must be a string" }, { status: 400 });
    }
    const validation = validateRuleYaml(body.yamlContent, id);
    if (!validation.valid) {
      return NextResponse.json({ error: "Rule validation failed", ...validation }, { status: 422 });
    }
    data.yamlContent = body.yamlContent;
  }
  if (body.description !== undefined) data.description = body.description;
  if (body.name !== undefined) data.name = body.name;
  if (body.severity !== undefined) {
    if (!["critical", "high", "medium", "low"].includes(body.severity)) {
      return NextResponse.json({ error: "Invalid severity" }, { status: 400 });
    }
    data.severity = body.severity;
  }
  if (body.cweId !== undefined) data.cweId = body.cweId;
  if (body.owaspCategory !== undefined) data.owaspCategory = body.owaspCategory;
  if (body.languages !== undefined) data.languages = body.languages;

  const rule = await prisma.rule.update({
    where: { id },
    data,
  });

  return NextResponse.json({ rule });
}
