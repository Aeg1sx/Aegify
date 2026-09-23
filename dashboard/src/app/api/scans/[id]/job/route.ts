import { requireResource, accessError } from "@/lib/access";
import { authorizeProject } from "@/lib/project-access";
import { prisma } from "@/lib/prisma";
import { cancelScanJob, enqueueScan, jobMetadata } from "@/lib/scan-jobs";
import { readAuthBody } from "@/lib/auth-request";
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "scan", id, "viewer");
  if (access instanceof Response) return access;
  const job = await prisma.scanJob.findUnique({ where: { scanId: id }, select: jobMetadata });
  if (!job) return NextResponse.json({ job: null });
  const cursor = Number(new URL(request.url).searchParams.get("after") || 0);
  if (!Number.isSafeInteger(cursor) || cursor < 0) return NextResponse.json({ error: "Invalid event cursor." }, { status: 400 });
  let canManage = false;
  try { await authorizeProject(prisma, access, job.projectId, "maintainer"); canManage = true; } catch { /* Viewer still has access to progress. */ }
  const [events, scan, worker] = await Promise.all([
    prisma.scanJobEvent.findMany({ where: { jobId: job.id, id: { gt: cursor } }, orderBy: { id: "asc" }, take: 100, select: { id: true, code: true, message: true, details: true, createdAt: true } }),
    prisma.scan.findUnique({ where: { id }, select: { progressPhaseName: true, progressPercent: true, progressMessage: true } }),
    prisma.scanWorker.findFirst({ where: { lastSeenAt: { gt: new Date(Date.now() - 45_000) } }, select: { id: true } }),
  ]);
  return NextResponse.json({ job, events, scan, canManage, workerAvailable: Boolean(worker) });
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "scan", id, "maintainer");
  if (access instanceof Response) return access;
  const job = await prisma.scanJob.findUnique({ where: { scanId: id }, omit: { sourceCiphertext: true, sourceManifest: true } });
  if (!job) return NextResponse.json({ error: "Scan job not found." }, { status: 404 });
  const body = await readAuthBody(request, 4096);
  if (!body) return NextResponse.json({ error: "Provide a JSON object within 4 KiB." }, { status: 400 });
  try {
    if (body.action === "cancel") {
      await cancelScanJob(prisma, access, job.id, process.env);
      return NextResponse.json({ status: "cancelled" });
    }
    if (body.action === "retry" && ["failed", "cancelled", "partial"].includes(job.status)) {
      const project = await prisma.project.findUnique({ where: { id: job.projectId } });
      if (!project || project.provider !== job.provider || project.ownerSlug !== job.ownerSlug || project.providerRepoId !== job.providerRepoId) return NextResponse.json({ error: "Repository connection changed; start a new scan from the project." }, { status: 409 });
      const retried = await enqueueScan(prisma, access, job.projectId, job.requestedRef, process.env, job.commitSha);
      return NextResponse.json(retried, { status: 202 });
    }
    return NextResponse.json({ error: "Choose cancel for an active job or retry for an incomplete job." }, { status: 400 });
  } catch (error) { return accessError(error); }
}
