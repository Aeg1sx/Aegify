import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { accessError, requireResource } from "@/lib/access";
import { changeProjectMember, isProjectRole } from "@/lib/project-access";
import { emailAllowed, normalizeEmail } from "@/lib/auth-policy";
import { readAuthBody } from "@/lib/auth-request";

type Context = { params: Promise<{ id: string }> };
const headers = { "Cache-Control": "no-store" };
export async function GET(request: NextRequest, { params }: Context) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const members = await prisma.projectMember.findMany({ where: { projectId: id }, select: { userId: true, role: true, user: { select: { name: true, email: true, disabled: true } } }, orderBy: [{ role: "asc" }, { userId: "asc" }] });
  return NextResponse.json({ members }, { headers });
}
export async function PUT(request: NextRequest, { params }: Context) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request);
  const email = normalizeEmail(body?.email);
  if (!email || !isProjectRole(body?.role) || (!access.development && !emailAllowed(email, process.env))) return NextResponse.json({ error: "Enter an admitted account email and a valid role." }, { status: 400, headers });
  const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (!user) return NextResponse.json({ error: "The account must sign in to this workspace before it can be added." }, { status: 400, headers });
  try { await changeProjectMember(prisma, access, id, user.id, body!.role as "viewer" | "triager" | "maintainer" | "admin"); }
  catch (error) { return accessError(error); }
  return NextResponse.json({ success: true }, { headers });
}
export async function DELETE(request: NextRequest, { params }: Context) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const body = await readAuthBody(request);
  if (typeof body?.userId !== "string") return NextResponse.json({ error: "Select a project member." }, { status: 400, headers });
  try { await changeProjectMember(prisma, access, id, body.userId, null); }
  catch (error) { return accessError(error); }
  return NextResponse.json({ success: true }, { headers });
}
