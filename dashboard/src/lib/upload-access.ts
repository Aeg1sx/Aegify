import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAccess } from "./access.ts";
import { authenticateUploadToken } from "./project-tokens.ts";
import type { AccessPrincipal } from "./project-access.ts";
import { anonymousUploadAllowed } from "./security-config.ts";

export type UploadPrincipal = { kind: "user"; access: AccessPrincipal } | { kind: "service"; projectId: string; actorId: string };
export async function requireUploadAccess(request: Request): Promise<UploadPrincipal | Response> {
  const authorization = request.headers.get("authorization");
  const oldHeader = request.headers.get("x-aegify-token");
  if (authorization !== null || oldHeader !== null) {
    const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : authorization === null ? oldHeader || "" : "";
    const service = await authenticateUploadToken(prisma, token, process.env);
    if (!service) return NextResponse.json({ error: "Invalid or expired project upload token." }, { status: 401, headers: { "Cache-Control": "no-store" } });
    const requestedProject = new URL(request.url).searchParams.get("projectId");
    if (requestedProject && requestedProject !== service.projectId) return NextResponse.json({ error: "Resource not found." }, { status: 404 });
    return { kind: "service", ...service };
  }
  const access = await requireAccess(request);
  if (!(access instanceof Response) && access.development && !anonymousUploadAllowed(process.env)) return NextResponse.json({ error: "Project upload token required." }, { status: 401 });
  return access instanceof Response ? access : { kind: "user", access };
}
