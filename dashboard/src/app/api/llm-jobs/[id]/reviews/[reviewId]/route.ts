import { NextRequest, NextResponse } from "next/server";
import { accessError, requireResource } from "@/lib/access";
import { prisma } from "@/lib/prisma";
import { readReviewHistory } from "@/lib/ai-review-history";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string; reviewId: string }> }) {
  const { id, reviewId } = await params;
  const access = await requireResource(request, "llmJob", id, "viewer");
  if (access instanceof Response) return access;
  try {
    return NextResponse.json(await readReviewHistory(prisma, access, id, reviewId), { headers: { "Cache-Control": "no-store" } });
  } catch (error) { return accessError(error); }
}
