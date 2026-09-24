import { NextRequest, NextResponse } from "next/server";
import { accessError, requireResource } from "@/lib/access";
import { prisma } from "@/lib/prisma";
import { listReviewHistory } from "@/lib/ai-review-history";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "llmJob", id, "viewer");
  if (access instanceof Response) return access;
  try {
    return NextResponse.json(await listReviewHistory(prisma, access, id, request.nextUrl.searchParams), { headers: { "Cache-Control": "no-store" } });
  } catch (error) { return accessError(error); }
}
