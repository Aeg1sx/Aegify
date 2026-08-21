import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const project = await prisma.project.findUnique({
    where: { id },
    include: {
      scans: {
        orderBy: { createdAt: "desc" },
        include: {
          _count: { select: { findings: true } },
        },
      },
    },
  });

  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  // Aggregate findings by severity across all project scans
  const scanIds = project.scans.map((s) => s.id);
  const severities = scanIds.length > 0
    ? await prisma.finding.groupBy({
        by: ["severity"],
        where: { scanId: { in: scanIds } },
        _count: true,
      })
    : [];

  const severityMap: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const s of severities) {
    severityMap[s.severity] = s._count;
  }

  return NextResponse.json({
    ...project,
    severities: severityMap,
    totalFindings: Object.values(severityMap).reduce((a, b) => a + b, 0),
  });
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json();

  const project = await prisma.project.update({
    where: { id },
    data: {
      ...(body.name !== undefined && { name: body.name }),
      ...(body.repositoryUrl !== undefined && { repositoryUrl: body.repositoryUrl }),
      ...(body.defaultBranch !== undefined && { defaultBranch: body.defaultBranch }),
      ...(body.description !== undefined && { description: body.description }),
      ...(body.color !== undefined && { color: body.color }),
      ...(body.provider !== undefined && { provider: body.provider }),
      ...(body.providerRepoId !== undefined && { providerRepoId: body.providerRepoId }),
      ...(body.ownerSlug !== undefined && { ownerSlug: body.ownerSlug }),
    },
  });

  return NextResponse.json(project);
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const url = new URL(request.url);
  const permanent = url.searchParams.get("permanent") === "true";

  if (permanent) {
    // Permanent delete (hard delete) - must be explicitly requested
    await prisma.project.delete({ where: { id } });
    return NextResponse.json({ success: true, action: "deleted" });
  }

  // Soft delete: archive the project
  await prisma.project.update({
    where: { id },
    data: { archived: true, archivedAt: new Date() },
  });

  return NextResponse.json({ success: true, action: "archived" });
}
