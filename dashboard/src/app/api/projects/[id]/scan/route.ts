import { requireResource, accessError } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { enqueueScan } from "@/lib/scan-jobs";
import { readAuthBody } from "@/lib/auth-request";

export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "maintainer");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request, 4096);
  if (!body || (body.branch !== undefined && typeof body.branch !== "string")) return NextResponse.json({ error: "Provide a JSON object within 4 KiB and an optional branch string." }, { status: 400 });
  const project = await prisma.project.findUniqueOrThrow({ where: { id }, select: { defaultBranch: true } });
  try {
    const ref = typeof body.branch === "string" && body.branch.trim() ? body.branch.trim() : project.defaultBranch || "main";
    const job = await enqueueScan(prisma, access, id, ref, process.env);
    return NextResponse.json({ ...job, projectId: id, branch: ref }, { status: 202 });
  } catch (error) { return accessError(error); }
}
