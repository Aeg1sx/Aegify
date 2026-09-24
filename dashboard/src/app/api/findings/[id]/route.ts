import { accessError, projectScope, requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { findingContractContext } from "@/lib/openapi-context";
import { readAuthBody } from "@/lib/auth-request";
import { FindingWorkflowError, findingWorkflow, parseFindingWorkflowPatch, updateFindingWorkflow } from "@/lib/finding-workflow";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const access = await requireResource(request, "finding", id, "viewer");
  if (access instanceof Response) return access;

  const finding = await prisma.finding.findUnique({
    where: { id },
    include: { scan: true },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  const identity = finding.identityId
    ? await prisma.findingIdentity.findFirst({
        where: { id: finding.identityId, projectId: finding.scan.projectId || "" },
        include: { triageEvents: { orderBy: { createdAt: "desc" }, take: 50 } },
      })
    : null;

  const apiContractContext = await findingContractContext(prisma, finding);
  const canTriage = finding.scan.projectId ? Boolean(await prisma.project.findFirst({
    where: { AND: [{ id: finding.scan.projectId, archived: false }, projectScope(access, "triager")] }, select: { id: true },
  })) : access.workspaceAdmin;
  return NextResponse.json({ ...finding, identity, workflow: findingWorkflow(finding, identity), permissions: { canTriage }, apiContractContext }, { headers: { "Cache-Control": "no-store" } });
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const access = await requireResource(request, "finding", id, "triager");
  if (access instanceof Response) return access;
  try {
    const patch = parseFindingWorkflowPatch(await readAuthBody(request, 32 * 1024));
    const updated = await updateFindingWorkflow(prisma, access, id, patch);
    return NextResponse.json(updated, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof FindingWorkflowError) return NextResponse.json({ error: error.message }, {
      status: error.status, headers: { "Cache-Control": "no-store" },
    });
    return accessError(error);
  }
}
