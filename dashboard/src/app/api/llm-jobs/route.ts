import { after, NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { reviewScanFindings } from "@/lib/llm-scanner";
import { failStaleLlmJobs } from "@/lib/llm-job-operations";

export const maxDuration = 300;

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { scanId, mode } = body;

    if (typeof scanId !== "string" || !/^[a-z0-9]{20,40}$/.test(scanId)) {
      return NextResponse.json({ error: "a valid scanId is required" }, { status: 400 });
    }

    if (!mode || !["quick", "deep"].includes(mode)) {
      return NextResponse.json({ error: "mode must be 'quick' or 'deep'" }, { status: 400 });
    }

    // Validate scan exists and count findings
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { _count: { select: { findings: true } } },
    });

    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    if (scan._count.findings === 0) {
      return NextResponse.json({ error: "Scan has no findings to review" }, { status: 400 });
    }

    await failStaleLlmJobs();
    const existing = await prisma.llmJob.findFirst({
      where: { scanId, status: { in: ["pending", "running"] } },
    });

    if (existing) {
      return NextResponse.json(
        { error: "A review is already running for this scan", jobId: existing.id },
        { status: 409 },
      );
    }

    const totalFindings = scan._count.findings;
    const totalBatches = Math.ceil(totalFindings / 50);

    // Create LlmJob row
    const job = await prisma.llmJob.create({
      data: {
        scanId,
        activeKey: scanId,
        mode,
        status: "pending",
        totalFindings,
        totalBatches,
      },
    });

    after(async () => {
      try {
        await reviewScanFindings(scanId, mode, job.id);
      } catch (error) {
        console.error(`LLM job ${job.id} failed:`, error);
      }
    });

    return NextResponse.json(job, { status: 202 });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "P2002") {
      return NextResponse.json(
        { error: "A review is already running for this scan" },
        { status: 409 },
      );
    }
    console.error("LLM job creation error:", error);
    return NextResponse.json(
      { error: "Failed to create job" },
      { status: 500 },
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    await failStaleLlmJobs();
    const { searchParams } = new URL(request.url);
    const active = searchParams.get("active");
    const scanId = searchParams.get("scanId");
    const limit = parseInt(searchParams.get("limit") || "20", 10);

    const where: Record<string, unknown> = {};

    if (active === "true") {
      where.status = { in: ["pending", "running"] };
    }

    if (scanId) {
      where.scanId = scanId;
    }

    const jobs = await prisma.llmJob.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: Math.min(limit, 100),
      include: {
        scan: {
          select: { id: true, repository: true, branch: true },
        },
      },
    });

    return NextResponse.json({ jobs });
  } catch (error) {
    console.error("LLM jobs list error:", error);
    return NextResponse.json(
      { error: "Failed to list jobs" },
      { status: 500 },
    );
  }
}
