import { NextRequest, NextResponse } from "next/server";

import { validateCveInputs } from "@/lib/agent-contract";
import {
  createSecurityAgentRun,
  listAgentRuns,
  serializeAgentRun,
} from "@/lib/agent-operations";

const SCAN_ID = /^[a-z0-9-]{8,64}$/;

export async function GET(request: NextRequest) {
  const limit = Number(request.nextUrl.searchParams.get("limit") || "50");
  const runs = await listAgentRuns(Number.isFinite(limit) ? limit : 50);
  return NextResponse.json({ runs });
}

export async function POST(request: NextRequest) {
  try {
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > 100_000) {
      return NextResponse.json({ error: "Request exceeds 100 KB" }, { status: 413 });
    }
    const body = await request.json();
    const scanId = String(body.scanId || "");
    const mode = String(body.mode || "deep");
    if (!SCAN_ID.test(scanId)) {
      return NextResponse.json({ error: "A valid scanId is required" }, { status: 400 });
    }
    if (!['lite', 'deep'].includes(mode)) {
      return NextResponse.json({ error: "mode must be lite or deep" }, { status: 400 });
    }
    const cves = validateCveInputs(body.cves);
    const run = await createSecurityAgentRun(scanId, mode as "lite" | "deep", cves);
    return NextResponse.json(serializeAgentRun(run), { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Agent run failed";
    const status = message === "Scan not found" ? 404 : 400;
    return NextResponse.json({ error: message.slice(0, 1_000) }, { status });
  }
}
