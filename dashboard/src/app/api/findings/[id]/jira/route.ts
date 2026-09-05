import { NextRequest, NextResponse } from "next/server";

import { createJiraFindingIssue } from "@/lib/jira";
import { prisma } from "@/lib/prisma";

export async function POST(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    if (!/^[a-z0-9-]{8,64}$/.test(id)) {
      return NextResponse.json({ error: "Invalid finding ID" }, { status: 400 });
    }
    const finding = await prisma.finding.findUnique({
      where: { id },
      include: { scan: { select: { repository: true, branch: true, commitSha: true } } },
    });
    if (!finding) return NextResponse.json({ error: "Finding not found" }, { status: 404 });
    const issue = await createJiraFindingIssue(finding);
    await prisma.finding.update({
      where: { id },
      data: {
        ticketProvider: "jira",
        ticketKey: issue.key,
        ticketUrl: issue.url,
        lastNotifiedAt: new Date(),
      },
    });
    return NextResponse.json(issue, { status: 201 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Jira issue creation failed";
    return NextResponse.json({ error: message.slice(0, 500) }, { status: 409 });
  }
}
