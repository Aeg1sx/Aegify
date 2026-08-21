import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function POST(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const project = await prisma.project.findUnique({ where: { id } });
  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  if (!project.archived) {
    return NextResponse.json({ error: "Project is not archived" }, { status: 400 });
  }

  await prisma.project.update({
    where: { id },
    data: { archived: false, archivedAt: null },
  });

  return NextResponse.json({ success: true, action: "restored" });
}
