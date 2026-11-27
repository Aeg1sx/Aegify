import { WORKER_FRESH_MS } from "@/lib/worker-registry";
import { requireResource, accessError } from "@/lib/access";
import { authorizeProject } from "@/lib/project-access";
import { prisma } from "@/lib/prisma";
import { cancelScanJob, enqueueScan, jobMetadata } from "@/lib/scan-jobs";
import { observeJob } from "@/lib/job-observation";
import { readAuthBody } from "@/lib/auth-request";
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "scan", id, "viewer");
  if (access instanceof Response) return access;
  const record = await prisma.scanJob.findUnique({ where: { scanId: id }, select: { ...jobMetadata, leaseExpiresAt: true } });
  const headers = { "Cache-Control": "no-store" };
  if (!record) return NextResponse.json({ job: null }, { headers });
  const { leaseExpiresAt, ...job } = record;
  const phase = observeJob({ ...job, leaseExpiresAt });
  const query = request.nextUrl.searchParams;
  const recent = query.get("order") === "recent";
  const after = Number(query.get("after") || 0), before = query.has("before") ? Number(query.get("before")) : null;
  if (!Number.isSafeInteger(after) || after < 0 || (recent && query.has("after"))
      || (before !== null && (!recent || !Number.isSafeInteger(before) || before <= 0))) {
    return NextResponse.json({ error: "Invalid event cursor." }, { status: 400, headers });
  }
  let canManage = false;
  try { await authorizeProject(prisma, access, job.projectId, "maintainer"); canManage = true; } catch { /* Viewer still has access to progress. */ }
  const [events, scan, worker] = await Promise.all([
    prisma.scanJobEvent.findMany({ where: { jobId: job.id, id: recent ? (before === null ? undefined : { lt: before }) : { gt: after } },
      orderBy: { id: recent ? "desc" : "asc" }, take: recent ? 21 : 100, select: { id: true, code: true, message: true, details: true, createdAt: true } }),
    prisma.scan.findUnique({ where: { id }, select: { progressPhaseName: true, progressPercent: true, progressMessage: true } }),
    prisma.scanWorker.findFirst({ where: { lastSeenAt: { gt: new Date(Date.now() - WORKER_FRESH_MS) } }, select: { id: true } }),
  ]);
  return NextResponse.json({ job, observation: phase, events: recent ? events.slice(0, 20) : events,
    nextBefore: recent && events.length > 20 ? events[19].id : null, scan, canManage, workerAvailable: Boolean(worker) }, { headers });
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
