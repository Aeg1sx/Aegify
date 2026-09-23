import { requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "viewer");
  if (access instanceof Response) return access;
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
        where: { scanId: { in: scanIds }, isCurrent: true },
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
    accessRole: access.workspaceAdmin ? "admin" : (await prisma.projectMember.findUnique({ where: { projectId_userId: { projectId: id, userId: access.userId! } }, select: { role: true } }))?.role || "viewer",
    severities: severityMap,
    totalFindings: Object.values(severityMap).reduce((a, b) => a + b, 0),
  });
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const body = await request.json();

  const project = await prisma.$transaction(async (tx) => {
    const updated = await tx.project.update({
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
    await tx.auditEvent.create({ data: { projectId: id, actorId: access.userId || "development", action: "project.update", targetId: id, details: JSON.stringify({ fields: Object.keys(body).filter((key) => ["name", "repositoryUrl", "defaultBranch", "description", "color", "provider", "providerRepoId", "ownerSlug"].includes(key)) }) } });
    return updated;
  });

  return NextResponse.json(project);
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const url = new URL(request.url);
  const permanent = url.searchParams.get("permanent") === "true";

  if (permanent) {
    // Permanent delete (hard delete) - must be explicitly requested
    await prisma.$transaction(async (tx) => {
      await tx.project.delete({ where: { id } });
      await tx.auditEvent.create({ data: { projectId: id, actorId: access.userId || "development", action: "project.delete", targetId: id } });
    });
    return NextResponse.json({ success: true, action: "deleted" });
  }

  // Soft delete: archive the project
  await prisma.$transaction(async (tx) => {
    await tx.project.update({ where: { id }, data: { archived: true, archivedAt: new Date() } });
    await tx.auditEvent.create({ data: { projectId: id, actorId: access.userId || "development", action: "project.archive", targetId: id } });
  });

  return NextResponse.json({ success: true, action: "archived" });
}
