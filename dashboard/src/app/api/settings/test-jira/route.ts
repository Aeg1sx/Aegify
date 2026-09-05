import { NextResponse } from "next/server";

import { testJiraConnection } from "@/lib/jira";

export async function POST() {
  try {
    const displayName = await testJiraConnection();
    return NextResponse.json({ success: true, message: `Connected as ${displayName}` });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Jira connection failed";
    return NextResponse.json({ error: message.slice(0, 500) }, { status: 502 });
  }
}
