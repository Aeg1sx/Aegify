import { NextRequest, NextResponse } from "next/server";
import { requireResource, accessError } from "@/lib/access";
import { prisma } from "@/lib/prisma";
import { readAuthBody } from "@/lib/auth-request";
import { cancelRuleFixture, enqueueRuleFixture, readRuleFixture } from "@/lib/rule-fixture-jobs";
import { AccessDenied } from "@/lib/project-access";

const headers = { "Cache-Control": "no-store" };
type Context = { params: Promise<{ id: string; jobId: string }> };
export async function GET(request: NextRequest, { params }: Context) {
  const { id, jobId } = await params;
  const access = await requireResource(request, "project", id);
  if (access instanceof Response) return access;
  try {
    const query = request.nextUrl.searchParams;
    if (jobId.length > 128 || [...query.keys()].some((key) => key !== "input") || query.getAll("input").length > 1 || (query.has("input") && query.get("input") !== "1")) throw new AccessDenied(400, "Use input=1 to load the retained authoring input.");
    return NextResponse.json(await readRuleFixture(prisma, access, id, jobId, process.env, query.has("input")), { headers });
  } catch (error) { return accessError(error); }
}
export async function POST(request: NextRequest, { params }: Context) {
  const { id, jobId } = await params;
  const access = await requireResource(request, "project", id, "maintainer");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request, 4096);
  try {
    if (!body || Object.keys(body).length !== 1 || jobId.length > 128) throw new AccessDenied(400, "Choose cancel or rerun.");
    if (body.action === "cancel") {
      await cancelRuleFixture(prisma, access, id, jobId, process.env);
      return NextResponse.json({ status: "cancelled" }, { headers });
    }
    if (body.action === "rerun") {
      const saved = await readRuleFixture(prisma, access, id, jobId, process.env, true);
      return NextResponse.json(await enqueueRuleFixture(prisma, access, id, saved.input, process.env), { status: 202, headers });
    }
    throw new AccessDenied(400, "Choose cancel or rerun.");
  } catch (error) { return accessError(error); }
}
