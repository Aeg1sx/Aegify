import { NextRequest, NextResponse } from "next/server";
import { requireAccess } from "@/lib/access";

export async function GET(request: NextRequest) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  return NextResponse.json({ userId: access.userId, workspaceAdmin: access.workspaceAdmin, development: access.development }, { headers: { "Cache-Control": "no-store" } });
}
