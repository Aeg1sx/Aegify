import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { reviewScanFindings } from "@/lib/llm-scanner";

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

    // Fire async review (fire-and-forget)
    reviewScanFindings(scanId, mode).catch((err) =>
      console.error("LLM review failed", { scanId, error: err }),
    );

    return NextResponse.json({
      scanId,
      mode,
      status: "running",
      findingsCount: scan._count.findings,
    });
  } catch (error) {
    console.error("LLM scan error:", error);
    return NextResponse.json(
      { error: "Review failed" },
      { status: 500 },
    );
  }
}
