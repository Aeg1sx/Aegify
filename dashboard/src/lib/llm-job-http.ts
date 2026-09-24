import { NextResponse } from "next/server";
import { requireResource } from "./access";
import { readAuthBody } from "./auth-request.ts";
import { AccessDenied } from "./project-access.ts";
import { ReviewContractError } from "./ai-review-contract.ts";
import { enqueueLlmJob } from "./llm-jobs.ts";
import { prisma } from "./prisma.ts";
import type { ReviewMode } from "./ai-review-contract.ts";

export async function queueLlmReview(request: Request, legacy = false) {
  const body = await readAuthBody(request);
  if (!body || typeof body.scanId !== "string" || !/^[a-z0-9]{20,40}$/.test(body.scanId) || !["quick", "deep", "source"].includes(String(body.mode)) || (body.includeApiContracts !== undefined && typeof body.includeApiContracts !== "boolean")
    || (body.findingIds !== undefined && (!Array.isArray(body.findingIds) || body.findingIds.some((id) => typeof id !== "string")))) return NextResponse.json({ error: "Provide scanId, mode (quick/deep/source), optional boolean includeApiContracts and optional findingIds for source review." }, { status: 400 });
  const access = await requireResource(request, "scan", body.scanId, "maintainer");
  if (access instanceof Response) return access;
  try {
    const job = await enqueueLlmJob(prisma, access, body.scanId, body.mode as ReviewMode, body.includeApiContracts === true, process.env, body.findingIds as string[] | undefined);
    if (job.alreadyQueued) return NextResponse.json({ error: "A review is already queued or running for this scan", jobId: job.id }, { status: 409 });
    return NextResponse.json(legacy ? { scanId: job.scanId, jobId: job.id, mode: job.mode, status: job.status, findingsCount: job.totalFindings } : job, { status: 202, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof AccessDenied) return NextResponse.json({ error: error.message }, { status: error.status });
    if (error instanceof ReviewContractError) return NextResponse.json({ error: error.message }, { status: 400 });
    if (error && typeof error === "object" && "code" in error && error.code === "P2002") return NextResponse.json({ error: "A review is already queued for this scan" }, { status: 409 });
    return NextResponse.json({ error: "Could not queue the review. Check the AI worker and encryption configuration." }, { status: 500 });
  }
}
