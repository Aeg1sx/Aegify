import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

/**
 * GET /api/scans/:id/progress - Get scan progress for polling
 * Returns progress info for running scans.
 */
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const scan = await prisma.scan.findUnique({
    where: { id },
    select: {
      id: true,
      status: true,
      progressPhase: true,
      progressPhaseName: true,
      progressPercent: true,
      progressMessage: true,
      progressEta: true,
      progressUpdatedAt: true,
      filesScanned: true,
      duration: true,
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  return NextResponse.json(scan);
}

/**
 * PATCH /api/scans/:id/progress - Update scan progress (called by scanner)
 */
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json();

  const scan = await prisma.scan.update({
    where: { id },
    data: {
      progressPhase: body.phase ?? undefined,
      progressPhaseName: body.phaseName ?? undefined,
      progressPercent: body.percent ?? undefined,
      progressMessage: body.message ?? undefined,
      progressEta: body.eta ?? undefined,
      progressUpdatedAt: new Date(),
      ...(body.status && { status: body.status }),
      ...(body.filesScanned !== undefined && { filesScanned: body.filesScanned }),
      ...(body.duration !== undefined && { duration: body.duration }),
    },
  });

  return NextResponse.json({ id: scan.id, status: scan.status });
}
