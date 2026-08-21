import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const showArchived = url.searchParams.get("archived") === "true";

  const projects = await prisma.project.findMany({
    where: { archived: showArchived },
    orderBy: { updatedAt: "desc" },
    include: {
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

  return NextResponse.json({ projects: result });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name, repositoryUrl, defaultBranch, description, color } = body;

    if (!name || typeof name !== "string" || name.trim().length === 0) {
      return NextResponse.json(
        { error: "Project name is required" },
        { status: 400 }
      );
    }

    const project = await prisma.project.create({
      data: {
        name: name.trim(),
        repositoryUrl: repositoryUrl || "",
        defaultBranch: defaultBranch || "main",
        description: description || "",
        color: color || "#6366f1",
      },
    });

    return NextResponse.json(project, { status: 201 });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to create project" },
      { status: 500 }
    );
  }
}
