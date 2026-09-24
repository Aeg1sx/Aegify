import { requireAccess, scanScope } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { queueLlmReview } from "@/lib/llm-job-http";
import { llmJobMetadata } from "@/lib/llm-jobs";

export async function POST(request: NextRequest) { return queueLlmReview(request); }

export async function GET(request: NextRequest) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  const { searchParams } = new URL(request.url);
  const rawLimit = Number(searchParams.get("limit") || 20);
  if (!Number.isInteger(rawLimit) || rawLimit < 1 || rawLimit > 100) return NextResponse.json({ error: "limit must be between 1 and 100" }, { status: 400 });
  const jobs = await prisma.llmJob.findMany({
    where: { scan: scanScope(access), ...(searchParams.get("active") === "true" ? { status: { in: ["pending", "running"] } } : {}), ...(searchParams.get("scanId") ? { scanId: searchParams.get("scanId")! } : {}) },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: rawLimit,
    select: { ...llmJobMetadata, scan: { select: { id: true, repository: true, branch: true } } },
  });
  const workerReady = (await prisma.llmWorker.count({ where: { lastSeenAt: { gt: new Date(Date.now() - 45_000) } } })) > 0;
  return NextResponse.json({ jobs, workerReady }, { headers: { "Cache-Control": "no-store" } });
}
