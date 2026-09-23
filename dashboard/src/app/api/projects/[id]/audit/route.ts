import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireResource } from "@/lib/access";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const events = await prisma.auditEvent.findMany({ where: { projectId: id }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 100 });
  return NextResponse.json({ events }, { headers: { "Cache-Control": "no-store" } });
}
