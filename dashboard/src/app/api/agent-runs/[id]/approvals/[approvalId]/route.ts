import { NextRequest, NextResponse } from "next/server";

import { auth } from "@/lib/auth";
import { decideAgentApproval } from "@/lib/agent-operations";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; approvalId: string }> },
) {
  try {
    const { id, approvalId } = await params;
    if (!/^[a-z0-9-]{8,64}$/.test(id) || !/^[a-z0-9-]{8,64}$/.test(approvalId)) {
      return NextResponse.json({ error: "Invalid run or approval ID" }, { status: 400 });
    }
    const body = await request.json();
    const decision = String(body.decision || "");
    const note = String(body.note || "");
    if (!['approved', 'rejected'].includes(decision)) {
      return NextResponse.json({ error: "decision must be approved or rejected" }, { status: 400 });
    }
    if (decision === "approved" && note.trim().length < 8) {
      return NextResponse.json(
        { error: "Approval requires a meaningful scope note" },
        { status: 400 },
      );
    }
    const session = await auth();
    const actor = session?.user?.email || session?.user?.name || "local-operator";
    const approval = await decideAgentApproval(
      id,
      approvalId,
      decision as "approved" | "rejected",
      note,
      actor,
    );
    return NextResponse.json({ approval });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Approval failed";
    return NextResponse.json({ error: message.slice(0, 1_000) }, { status: 409 });
  }
}
