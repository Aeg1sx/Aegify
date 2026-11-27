import { accessError, projectScope, requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { readAuthBody } from "@/lib/auth-request";
import { writeTransaction } from "@/lib/database-runtime";
import { boundedInteger } from "@/lib/finding-view";
import { AccessDenied, resolvePrincipal } from "@/lib/project-access";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "viewer");
  if (access instanceof Response) return access;
  const query = request.nextUrl.searchParams;
  const limit = query.has("scanLimit") ? boundedInteger(query.get("scanLimit"), 10, 100) : undefined;
  const requestedPage = boundedInteger(query.get("scanPage"), 1, 100_000);
  const result = await prisma.$transaction(async (tx) => {
    const project = await tx.project.findFirst({
      where: { AND: [{ id }, projectScope(access)] },
      include: {
        members: { where: { userId: access.userId || "" }, select: { role: true } },
        _count: { select: { scans: true } },
      },
    });
    if (!project) return null;
    const { members, _count, ...fields } = project;
    const pages = limit ? Math.max(1, Math.ceil(_count.scans / limit)) : 1;
    const page = Math.min(requestedPage, pages);
    const scans = await tx.scan.findMany({
      where: { projectId: id },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      ...(limit && { take: limit, skip: (page - 1) * limit, omit: { workspaceSnapshot: true } }),
      include: { _count: { select: { findings: true } } },
    });
    const groups = await tx.finding.groupBy({
      by: ["severity"],
      where: { scan: { projectId: id }, isCurrent: true },
      _count: true,
    });
    const severities = Object.fromEntries(groups.map((item) => [item.severity, item._count]));
    return {
      ...fields,
      accessRole: access.workspaceAdmin ? "admin" : members[0]?.role || "viewer",
      scans,
      scanCount: _count.scans,
      ...(limit && { scanPage: { page, pages, limit } }),
      severities: { critical: 0, high: 0, medium: 0, low: 0, ...severities },
      totalFindings: groups.reduce((total, item) => total + item._count, 0),
    };
  });
  return result
    ? NextResponse.json(result, { headers: { "Cache-Control": "no-store" } })
    : NextResponse.json({ error: "Project not found" }, { status: 404 });
}

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request);
  if (!body)
    return NextResponse.json(
      { error: "Provide project settings as a JSON object within 8 KiB." },
      { status: 400 },
    );
  const keys = [
    "name",
    "repositoryUrl",
    "defaultBranch",
    "description",
    "color",
    "provider",
    "providerRepoId",
    "ownerSlug",
  ] as const;
  const changes: Partial<Record<(typeof keys)[number], string>> = {};
  for (const key of keys) {
    if (body[key] === undefined) continue;
    if (typeof body[key] !== "string")
      return NextResponse.json({ error: "Project fields must be text." }, { status: 400 });
    changes[key] = body[key];
  }
  if (!Object.keys(changes).length)
    return NextResponse.json({ error: "Provide a project field to update." }, { status: 400 });
  try {
    const project = await writeTransaction(prisma, async (tx) => {
      const principal = await resolvePrincipal(tx, access.userId ?? undefined, process.env);
      const current = await tx.project.findFirst({
        where: { AND: [{ id }, projectScope(principal, "admin")] },
        select: { updatedAt: true, archived: true },
      });
      if (!current) throw new AccessDenied();
      if (
        current.archived &&
        ["repositoryUrl", "defaultBranch", "provider", "providerRepoId", "ownerSlug"].some(
          (key) => key in changes,
        )
      ) {
        throw new AccessDenied(409, "Restore the project before changing its repository.");
      }
      if (
        body.expectedUpdatedAt !== undefined &&
        body.expectedUpdatedAt !== current.updatedAt.toISOString()
      ) {
        throw new AccessDenied(409, "Project settings changed. Reload the project before saving.");
      }
      const updated = await tx.project.update({
        where: { id },
        data: {
          ...changes,
          updatedAt: new Date(Math.max(Date.now(), current.updatedAt.getTime() + 1)),
        },
      });
      await tx.auditEvent.create({
        data: {
          projectId: id,
          actorId: principal.userId || "development",
          action: "project.update",
          targetId: id,
          details: JSON.stringify({ fields: Object.keys(changes) }),
        },
      });
      return updated;
    });
    return NextResponse.json(project);
  } catch (error) {
    return accessError(error);
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const url = new URL(request.url);
  const permanent = url.searchParams.get("permanent") === "true";

  if (permanent) {
    // Permanent delete (hard delete) - must be explicitly requested
    await prisma.$transaction(async (tx) => {
      await tx.project.delete({ where: { id } });
      await tx.auditEvent.create({
        data: {
          projectId: id,
          actorId: access.userId || "development",
          action: "project.delete",
          targetId: id,
        },
      });
    });
    return NextResponse.json({ success: true, action: "deleted" });
  }

  // Soft delete: archive the project
  await prisma.$transaction(async (tx) => {
    await tx.project.update({ where: { id }, data: { archived: true, archivedAt: new Date() } });
    await tx.auditEvent.create({
      data: {
        projectId: id,
        actorId: access.userId || "development",
        action: "project.archive",
        targetId: id,
      },
    });
  });

  return NextResponse.json({ success: true, action: "archived" });
}
