import { accessError, requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";

import { createJiraFindingIssue } from "@/lib/jira";
import { prisma } from "@/lib/prisma";
import { FindingWorkflowError, prepareFindingTicket, recordFindingTicket } from "@/lib/finding-workflow";
import { AccessDenied } from "@/lib/project-access";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const access = await requireResource(request, "finding", id, "triager");
    if (access instanceof Response) return access;
    if (!/^[a-z0-9-]{8,64}$/.test(id)) {
      return NextResponse.json({ error: "Invalid finding ID" }, { status: 400 });
    }
    const prepared = await prepareFindingTicket(prisma, access, id);
    if (prepared.finding.ticketKey) return NextResponse.json({ key: prepared.finding.ticketKey, url: prepared.finding.ticketUrl }, { headers: { "Cache-Control": "no-store" } });
    const issue = await createJiraFindingIssue(prepared.finding);
    const recorded = await recordFindingTicket(prisma, prepared.context, issue);
    if (!recorded.linked) return NextResponse.json({ error: `Jira ticket ${issue.key} was created, but its finding linkage needs review. The receipt is retained in the audit log.` }, { status: 409, headers: { "Cache-Control": "no-store" } });
    return NextResponse.json(issue, { status: 201, headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof AccessDenied) return accessError(error);
    if (error instanceof FindingWorkflowError) return NextResponse.json({ error: error.message }, { status: error.status });
    const message = error instanceof Error ? error.message : "Jira issue creation failed";
    return NextResponse.json({ error: message.slice(0, 500) }, { status: 409 });
  }
}
