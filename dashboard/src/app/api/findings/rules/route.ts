import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { findingScope, requireAccess } from "@/lib/access";

/** Filter labels from readable findings; workspace rule definitions stay admin-only. */
export async function GET(request: NextRequest) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  const rules = await prisma.finding.groupBy({ by: ["ruleId"], where: { ...findingScope(access), isCurrent: true }, _min: { ruleName: true }, _count: true, orderBy: { ruleId: "asc" } });
  return NextResponse.json({ rules: rules.map((rule) => ({ id: rule.ruleId, name: rule._min.ruleName || rule.ruleId, findingCount: rule._count })) }, { headers: { "Cache-Control": "no-store" } });
}
