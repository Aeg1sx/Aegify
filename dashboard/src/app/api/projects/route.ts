import { requireAccess, projectScope } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  const url = new URL(request.url);
  const showArchived = url.searchParams.get("archived") === "true";

  const projects = await prisma.project.findMany({
    where: { AND: [{ archived: showArchived }, projectScope(access)] },
    orderBy: { updatedAt: "desc" },
    include: {
      members: { where: { userId: access.userId || "" }, select: { role: true } },
      _count: { select: { scans: true } },
      scans: {
        include: { _count: { select: { findings: true } } },
        orderBy: { createdAt: "desc" },
        take: 1,
      },
    },
  });

  const result = projects.map((p) => {
    const totalFindings = p.scans.reduce(
      (sum, s) => sum + s._count.findings,
      0
    );
    return {
      id: p.id,
      accessRole: access.workspaceAdmin ? "admin" : p.members[0]?.role || "viewer",
      name: p.name,
      repositoryUrl: p.repositoryUrl,
      defaultBranch: p.defaultBranch,
      description: p.description,
      color: p.color,
      archived: p.archived,
      archivedAt: p.archivedAt,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
      scanCount: p._count.scans,
      findingCount: totalFindings,
      lastScan: p.scans[0] || null,
    };
  });

  return NextResponse.json({ projects: result, canCreate: access.workspaceAdmin });
}

export async function POST(request: NextRequest) {
  const access = await requireAccess(request, true);
  if (access instanceof Response) return access;
  try {
    const body = await request.json();
    const { name, repositoryUrl, defaultBranch, description, color } = body;

    if (!name || typeof name !== "string" || name.trim().length === 0) {
      return NextResponse.json(
        { error: "Project name is required" },
        { status: 400 }
      );
    }

    const project = await prisma.$transaction(async (tx) => {
      const created = await tx.project.create({
      data: {
        name: name.trim(),
        userId: access.userId,
        ...(access.userId ? { members: { create: { userId: access.userId, role: "admin" } } } : {}),
        repositoryUrl: repositoryUrl || "",
        defaultBranch: defaultBranch || "main",
        description: description || "",
        color: color || "#6366f1",
      },
      });
      await tx.auditEvent.create({ data: { projectId: created.id, actorId: access.userId || "development", action: "project.create", targetId: created.id } });
      return created;
    });

    return NextResponse.json(project, { status: 201 });
  } catch (error) {
    console.error("Project creation error:", error);
    return NextResponse.json(
      { error: "Failed to create project" },
      { status: 500 }
    );
  }
}
