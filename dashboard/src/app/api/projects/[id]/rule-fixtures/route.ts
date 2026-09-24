import { NextRequest, NextResponse } from "next/server";
import { requireResource, accessError } from "@/lib/access";
import { prisma } from "@/lib/prisma";
import { readAuthBody } from "@/lib/auth-request";
import { enqueueRuleFixture, listRuleFixtures } from "@/lib/rule-fixture-jobs";
import { FIXTURE_INPUT_BYTES } from "@/lib/rule-fixture-contract";

const headers = { "Cache-Control": "no-store" };
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id);
  if (access instanceof Response) return access;
  try { return NextResponse.json(await listRuleFixtures(prisma, access, id, process.env), { headers }); }
  catch (error) { return accessError(error); }
}
export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "maintainer");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request, FIXTURE_INPUT_BYTES);
  try { return NextResponse.json(await enqueueRuleFixture(prisma, access, id, body, process.env), { status: 202, headers }); }
  catch (error) { return accessError(error); }
}
