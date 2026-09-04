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

    // Validate scan exists and has findings
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

    const job = await prisma.llmJob.create({
      data: {
        scanId,
        activeKey: scanId,
        mode,
        status: "pending",
        totalFindings: scan._count.findings,
        totalBatches: Math.ceil(scan._count.findings / 50),
      },
    });

    after(async () => {
      try {
        await reviewScanFindings(scanId, mode, job.id);
      } catch (error) {
        console.error(`LLM job ${job.id} failed:`, error);
      }
    });

    return NextResponse.json({
      scanId,
      jobId: job.id,
      mode,
      status: "pending",
      findingsCount: scan._count.findings,
    }, { status: 202 });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "P2002") {
      return NextResponse.json(
        { error: "A review is already running for this scan" },
        { status: 409 },
      );
    }
    console.error("LLM scan error:", error);
    return NextResponse.json(
      { error: "Review failed" },
      { status: 500 },
    );
  }
}
