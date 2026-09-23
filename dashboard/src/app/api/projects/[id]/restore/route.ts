import { requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;

  const project = await prisma.project.findUnique({ where: { id } });
  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  if (!project.archived) {
    return NextResponse.json({ error: "Project is not archived" }, { status: 400 });
  }

  await prisma.$transaction(async (tx) => {
    await tx.project.update({ where: { id }, data: { archived: false, archivedAt: null } });
    await tx.auditEvent.create({ data: { projectId: id, actorId: access.userId || "development", action: "project.restore", targetId: id } });
  });

  return NextResponse.json({ success: true, action: "restored" });
}
