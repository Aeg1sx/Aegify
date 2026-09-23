import { requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const access = await requireResource(request, "llmJob", id, "viewer");
  if (access instanceof Response) return access;

  const job = await prisma.llmJob.findUnique({
    where: { id },
    include: {
      scan: {
        select: { id: true, repository: true, branch: true, status: true },
      },
    },
  });

  if (!job) {
    return NextResponse.json({ error: "Job not found" }, { status: 404 });
  }

  return NextResponse.json(job);
}
