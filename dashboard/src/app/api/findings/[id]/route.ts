import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { auth } from "@/lib/auth";

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

  const identity = finding.identityId
    ? await prisma.findingIdentity.findUnique({
        where: { id: finding.identityId },
        include: { triageEvents: { orderBy: { createdAt: "desc" }, take: 50 } },
      })
    : null;

  return NextResponse.json({ ...finding, identity });
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
    "accepted_risk",
  ];
  if (body.status && !validStatuses.includes(body.status)) {
    return NextResponse.json({ error: "Invalid status" }, { status: 400 });
  }

  const current = await prisma.finding.findUnique({ where: { id } });
  if (!current) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  if (!body.status) return NextResponse.json(current);
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";
  if (["false_positive", "accepted_risk"].includes(body.status) && !reason) {
    return NextResponse.json(
      { error: "A reason is required for false-positive or accepted-risk triage" },
      { status: 400 },
    );
  }
  let expiresAt: Date | null = null;
  if (body.expiresAt) {
    expiresAt = new Date(body.expiresAt);
    if (Number.isNaN(expiresAt.getTime())) {
      return NextResponse.json({ error: "Invalid expiry date" }, { status: 400 });
    }
  }

  const session = await auth();
  const actor = session?.user?.email || session?.user?.id || "local-user";
  const finding = await prisma.$transaction(async (tx) => {
    const updated = await tx.finding.update({
      where: { id },
      data: { status: body.status },
    });
    if (current.identityId) {
      await tx.findingIdentity.update({
        where: { id: current.identityId },
        data: {
          status: body.status,
          triageReason: reason,
          triageActor: actor,
          triageExpiresAt: expiresAt,
        },
      });
      await tx.findingTriageEvent.create({
        data: {
          identityId: current.identityId,
          fromStatus: current.status,
          toStatus: body.status,
          reason,
          actor,
          expiresAt,
        },
      });
    }
    return updated;
  });

  return NextResponse.json(finding);
}
