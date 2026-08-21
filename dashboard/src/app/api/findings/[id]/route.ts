import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  const finding = await prisma.finding.findUnique({
    where: { id },
    include: { scan: true },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  return NextResponse.json(finding);
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await request.json();

  const validStatuses = [
    "open",
    "triaged",
    "confirmed",
    "in_progress",
    "false_positive",
    "fixed",
  ];
  if (body.status && !validStatuses.includes(body.status)) {
    return NextResponse.json({ error: "Invalid status" }, { status: 400 });
  }

  const finding = await prisma.finding.update({
    where: { id },
    data: {
      ...(body.status && { status: body.status }),
    },
  });

  return NextResponse.json(finding);
}
