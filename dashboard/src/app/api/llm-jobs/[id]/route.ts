import { accessError, requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { cancelLlmJob, llmCallMetadata, llmJobMetadata } from "@/lib/llm-jobs";
import { readAuthBody } from "@/lib/auth-request";
import { AccessDenied, authorizeProject } from "@/lib/project-access";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "llmJob", id, "viewer");
  if (access instanceof Response) return access;
  const job = await prisma.llmJob.findUnique({ where: { id }, select: { ...llmJobMetadata,
    scan: { select: { id: true, repository: true, branch: true, status: true } },
    calls: { orderBy: { batchIndex: "asc" }, take: 20, select: llmCallMetadata },
    events: { orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 100, select: { id: true, code: true, message: true, details: true, createdAt: true } },
  } });
  if (!job) return NextResponse.json({ error: "Job not found" }, { status: 404 });
  let canCancel = false;
  try { if (job.projectId) { await authorizeProject(prisma, access, job.projectId, "maintainer"); canCancel = true; } }
  catch (error) { if (!(error instanceof AccessDenied)) throw error; }
  const workerReady = (await prisma.llmWorker.count({ where: { lastSeenAt: { gt: new Date(Date.now() - 45_000) } } })) > 0;
  return NextResponse.json({ ...job, workerReady, permissions: { canCancel } }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "llmJob", id, "maintainer");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request);
  if (body?.action !== "cancel") return NextResponse.json({ error: "Use action: cancel" }, { status: 400 });
  try { await cancelLlmJob(prisma, access, id, process.env); return NextResponse.json({ cancelled: true }, { headers: { "Cache-Control": "no-store" } }); }
  catch (error) { return accessError(error); }
}
