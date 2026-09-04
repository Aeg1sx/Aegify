import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { scanRepoCode } from "@/lib/repo-scanner";

export const maxDuration = 300;

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  // Get user session for OAuth token lookup
  const session = await auth();
  const userId = session?.user?.id;

  if (!userId) {
    return NextResponse.json(
      { error: "Authentication required to scan repository" },
      { status: 401 },
    );
  }

  const project = await prisma.project.findUnique({ where: { id } });
  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  if (project.userId && project.userId !== userId) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  if (!project.provider || !project.ownerSlug) {
    return NextResponse.json(
      { error: "No repository connected to this project" },
      { status: 400 },
    );
  }

  const body = await request.json().catch(() => ({}));
  const branch = typeof body.branch === "string" ? body.branch.trim() : "";
  if (branch && (!/^[A-Za-z0-9._/-]{1,255}$/.test(branch) || branch.includes(".."))) {
    return NextResponse.json({ error: "Invalid branch or ref" }, { status: 400 });
  }

  const active = await prisma.scan.findFirst({
    where: {
      projectId: project.id,
      scanType: "repo-ai-candidate",
      status: "running",
    },
    select: { id: true },
  });
  if (active) {
    return NextResponse.json(
      { error: "A repository AI scan is already running", scanId: active.id },
      { status: 409 },
    );
  }

  try {
    const result = await scanRepoCode(project.id, userId, branch || undefined);
    const completed = await prisma.scan.findUnique({
      where: { id: result.scanId },
      select: { status: true },
    });
    return NextResponse.json({
      projectId: project.id,
      scanId: result.scanId,
      status: completed?.status || "failed",
      branch: branch || project.defaultBranch || "main",
    });
  } catch (error) {
    console.error(`Repo scan ${project.id} failed:`, error);
    return NextResponse.json({ error: "Repository AI scan failed" }, { status: 500 });
  }
}
