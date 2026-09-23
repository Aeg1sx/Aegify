import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { accessError, requireResource } from "@/lib/access";
import { issueProjectToken, revokeProjectToken, tokenMetadata } from "@/lib/project-tokens";
import { readAuthBody } from "@/lib/auth-request";

type Context = { params: Promise<{ id: string }> };
const headers = { "Cache-Control": "no-store" };
export async function GET(request: NextRequest, { params }: Context) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const tokens = await prisma.projectServiceToken.findMany({ where: { projectId: id }, select: tokenMetadata, orderBy: { createdAt: "desc" }, take: 100 });
  return NextResponse.json({ tokens }, { headers });
}
export async function POST(request: NextRequest, { params }: Context) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request);
  if (typeof body?.name !== "string" || typeof body?.expiresAt !== "string") return NextResponse.json({ error: "Provide a token name and expiry." }, { status: 400, headers });
  try {
    const issued = await issueProjectToken(prisma, access, id, body.name, new Date(body.expiresAt));
    return NextResponse.json(issued, { status: 201, headers });
  } catch (error) { return accessError(error); }
}
export async function DELETE(request: NextRequest, { params }: Context) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request);
  if (typeof body?.tokenId !== "string") return NextResponse.json({ error: "Select a token." }, { status: 400, headers });
  try { await revokeProjectToken(prisma, access, id, body.tokenId); }
  catch (error) { return accessError(error); }
  return NextResponse.json({ success: true }, { headers });
}
