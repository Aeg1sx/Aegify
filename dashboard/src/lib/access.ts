import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { sameAuthOrigin } from "./auth-request.ts";
import { AccessDenied, authorizeResource, resolvePrincipal, type ProjectRole, type ResourceKind } from "./project-access.ts";
export { projectScope, scanScope, findingScope } from "./project-access.ts";

export function accessError(error: unknown): NextResponse {
  if (!(error instanceof AccessDenied)) throw error;
  return NextResponse.json({ error: error.message }, { status: error.status, headers: { "Cache-Control": "no-store" } });
}
export async function requireAccess(request?: Request, adminOnly = false) {
  try {
    // Bearer service credentials are accepted only by the dedicated upload path.
    if (request?.headers.has("authorization") || request?.headers.has("x-aegify-token")) throw new AccessDenied(401, "Use service tokens only for project uploads.");
    const session = await auth();
    const principal = await resolvePrincipal(prisma, session?.user?.id, process.env);
    if (request && !["GET", "HEAD", "OPTIONS"].includes(request.method) && !principal.development && !sameAuthOrigin(request, process.env)) throw new AccessDenied(403, "Same-origin request required.");
    if (adminOnly && !principal.workspaceAdmin) throw new AccessDenied(403, "Workspace administrator access required.");
    return principal;
  } catch (error) { return accessError(error); }
}
export async function requireResource(request: Request, kind: ResourceKind, id: unknown, minimum: ProjectRole = "viewer") {
  const principal = await requireAccess(request);
  if (principal instanceof Response) return principal;
  try { await authorizeResource(prisma, principal, kind, id, minimum); return principal; }
  catch (error) { return accessError(error); }
}
