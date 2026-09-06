import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { sameAuthOrigin } from "@/lib/auth-request";

export async function POST(request: NextRequest) {
  if (!sameAuthOrigin(request, process.env)) return NextResponse.json({ error: "Request origin is not allowed." }, { status: 403 });
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  await prisma.user.update({ where: { id: session.user.id }, data: { sessionVersion: { increment: 1 } } });
  return NextResponse.json({ success: true }, { headers: { "Cache-Control": "no-store" } });
}
