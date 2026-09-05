import { NextRequest, NextResponse } from "next/server";

import { getAgentRun, serializeAgentRun } from "@/lib/agent-operations";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  if (!/^[a-z0-9-]{8,64}$/.test(id)) {
    return NextResponse.json({ error: "Invalid run ID" }, { status: 400 });
  }
  const run = await getAgentRun(id);
  if (!run) return NextResponse.json({ error: "Agent run not found" }, { status: 404 });
  return NextResponse.json(serializeAgentRun(run));
}
