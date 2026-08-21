import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const rule = await prisma.rule.findUnique({ where: { id } });

  if (!rule) {
    return NextResponse.json({ error: "Rule not found" }, { status: 404 });
  }

  // Get finding stats for this rule
  const findings = await prisma.finding.findMany({
    where: { ruleId: id },
    select: {
      severity: true,
      status: true,
      filePath: true,
      confidence: true,
    },
  });

  const severityBreakdown: Record<string, number> = {};
  const statusBreakdown: Record<string, number> = {};
  const fileBreakdown: Record<string, number> = {};
  let totalConfidence = 0;

  for (const f of findings) {
    severityBreakdown[f.severity] = (severityBreakdown[f.severity] || 0) + 1;
    statusBreakdown[f.status] = (statusBreakdown[f.status] || 0) + 1;
    fileBreakdown[f.filePath] = (fileBreakdown[f.filePath] || 0) + 1;
    totalConfidence += f.confidence;
  }

  const topFiles = Object.entries(fileBreakdown)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .map(([path, count]) => ({ path, count }));

  return NextResponse.json({
    rule,
    stats: {
      totalFindings: findings.length,
      severityBreakdown,
      statusBreakdown,
      avgConfidence: findings.length > 0 ? totalConfidence / findings.length : 0,
      topFiles,
    },
  });
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json();

  const data: Record<string, unknown> = {};
  if (body.enabled !== undefined) data.enabled = body.enabled;
  if (body.yamlContent !== undefined) data.yamlContent = body.yamlContent;
  if (body.description !== undefined) data.description = body.description;
  if (body.name !== undefined) data.name = body.name;
  if (body.severity !== undefined) data.severity = body.severity;
  if (body.cweId !== undefined) data.cweId = body.cweId;
  if (body.owaspCategory !== undefined) data.owaspCategory = body.owaspCategory;
  if (body.languages !== undefined) data.languages = body.languages;

  const rule = await prisma.rule.update({
    where: { id },
    data,
  });

  return NextResponse.json({ rule });
}
