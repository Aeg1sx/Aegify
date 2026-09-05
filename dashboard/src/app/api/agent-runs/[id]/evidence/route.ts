import { NextRequest, NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { ingestAgentEvidence } from "@/lib/agent-operations";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    if (!/^[a-z0-9-]{8,64}$/.test(id)) {
      return NextResponse.json({ error: "Invalid run ID" }, { status: 400 });
    }
    const contentLength = Number(request.headers.get("content-length") || "0");
    if (contentLength > 2_100_000) {
      return NextResponse.json({ error: "Evidence exceeds 2 MB" }, { status: 413 });
    }
    const body = await request.json();
    const approvalId = String(body.approvalId || "");
    if (!/^[a-z0-9-]{8,64}$/.test(approvalId)) {
      return NextResponse.json({ error: "Valid approvalId is required" }, { status: 400 });
    }
    const session = await auth();
    const actor = session?.user?.email || session?.user?.name || "local-operator";
    const evidence = await ingestAgentEvidence(id, approvalId, body.evidence, actor);
    return NextResponse.json({ evidence }, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Evidence import failed";
    return NextResponse.json({ error: message.slice(0, 1_000) }, { status: 409 });
  }
}
