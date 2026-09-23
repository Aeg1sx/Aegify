import { requireResource } from "@/lib/access";
import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { buildFindingReport } from "@/lib/finding-report";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "finding", id, "viewer");
  if (access instanceof Response) return access;
  const finding = await prisma.finding.findUnique({ where: { id }, include: { scan: true } });
  if (!finding) return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  return new Response(buildFindingReport(finding), { headers: {
    "Content-Type": "text/markdown; charset=utf-8",
    "Content-Disposition": 'attachment; filename="aegify-finding-report.md"',
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  } });
}
