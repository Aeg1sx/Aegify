import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { scanRepoCode } from "@/lib/repo-scanner";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  // Get user session for OAuth token lookup
  const session = await auth();
  const userId = session?.user?.id;

  const project = await prisma.project.findUnique({ where: { id } });
  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  if (!project.provider || !project.ownerSlug) {
    return NextResponse.json(
      { error: "No repository connected to this project" },
      { status: 400 },
    );
  }

  if (!userId) {
    return NextResponse.json(
      { error: "Authentication required to scan repository" },
      { status: 401 },
    );
  }

  const body = await request.json().catch(() => ({}));
  const branch = (body.branch as string) || undefined;

  // Fire-and-forget (same pattern as /api/llm-scan)
  scanRepoCode(project.id, userId, branch).catch((err) =>
    console.error(`Repo scan ${project.id} failed:`, err),
  );

  return NextResponse.json({
    projectId: project.id,
    status: "running",
    branch: branch || project.defaultBranch || "main",
  });
}
