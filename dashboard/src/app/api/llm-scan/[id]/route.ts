import { requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const access = await requireResource(request, "scan", id, "viewer");
  if (access instanceof Response) return access;

  const scan = await prisma.scan.findUnique({
    where: { id },
    include: {
      findings: {
        orderBy: { severity: "asc" },
      },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const severityCounts: Record<string, number> = {};
  for (const f of scan.findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  }

  return NextResponse.json({
    scan: {
      id: scan.id,
      scanType: scan.scanType,
      status: scan.status,
      filesScanned: scan.filesScanned,
      createdAt: scan.createdAt,
    },
    findings: scan.findings,
    summary: {
      total: scan.findings.length,
      bySeverity: severityCounts,
    },
  });
}
