import type { Prisma, PrismaClient } from "@prisma/client";
import { emailAllowed, normalizeEmail, type AuthEnvironment } from "./auth-policy.ts";

export const PROJECT_ROLES = ["viewer", "triager", "maintainer", "admin"] as const;
export type ProjectRole = typeof PROJECT_ROLES[number];
export interface AccessPrincipal { userId: string | null; email: string | null; workspaceAdmin: boolean; development: boolean }
export class AccessDenied extends Error {
  status: number;
  constructor(status = 404, message = "Resource not found.") { super(message); this.status = status; }
}
export function isProjectRole(value: unknown): value is ProjectRole { return PROJECT_ROLES.includes(value as ProjectRole); }
export function workspaceAdminEmails(env: AuthEnvironment): string[] {
  return (env.AUTH_ADMIN_EMAILS || "").split(",").map(normalizeEmail).filter((value): value is string => value !== null);
}
export async function resolvePrincipal(db: PrismaClient, userId: string | undefined, env: AuthEnvironment): Promise<AccessPrincipal> {
  if (env.NODE_ENV !== "production" && !env.AUTH_SECRET) return { userId: null, email: null, workspaceAdmin: true, development: true };
  if (!userId) throw new AccessDenied(401, "Authentication required.");
  const user = await db.user.findUnique({ where: { id: userId }, select: { id: true, email: true, disabled: true } });
  if (!user || user.disabled || !emailAllowed(user.email, env)) throw new AccessDenied(401, "Authentication required.");
  const email = normalizeEmail(user.email);
  return { userId: user.id, email, workspaceAdmin: Boolean(email && workspaceAdminEmails(env).includes(email)), development: false };
}
export function projectScope(principal: AccessPrincipal, minimum: ProjectRole = "viewer"): Prisma.ProjectWhereInput {
  if (principal.workspaceAdmin) return {};
  if (!principal.userId) return { id: { in: [] } };
  return { members: { some: { userId: principal.userId, role: { in: PROJECT_ROLES.slice(PROJECT_ROLES.indexOf(minimum)) } } } };
}
export function scanScope(principal: AccessPrincipal, minimum: ProjectRole = "viewer"): Prisma.ScanWhereInput {
  return principal.workspaceAdmin ? {} : { project: { is: projectScope(principal, minimum) } };
}
export function findingScope(principal: AccessPrincipal, minimum: ProjectRole = "viewer"): Prisma.FindingWhereInput {
  return { scan: scanScope(principal, minimum) };
}
export async function authorizeProject(db: PrismaClient | Prisma.TransactionClient, principal: AccessPrincipal, projectId: string, minimum: ProjectRole = "viewer") {
  const project = await db.project.findFirst({ where: { AND: [{ id: projectId }, projectScope(principal, minimum)] }, select: { id: true, archived: true } });
  if (!project) throw new AccessDenied();
  return project;
}
export type ResourceKind = "project" | "scan" | "finding" | "endpoint" | "llmJob" | "agentRun";
export async function authorizeResource(db: PrismaClient, principal: AccessPrincipal, kind: ResourceKind, id: unknown, minimum: ProjectRole = "viewer") {
  if (typeof id !== "string" || !id || id.length > 128) throw new AccessDenied();
  if (kind === "project") { await authorizeProject(db, principal, id, minimum); return; }
  const item = kind === "scan"
    ? await db.scan.findUnique({ where: { id }, select: { projectId: true } })
    : kind === "finding" ? (await db.finding.findUnique({ where: { id }, select: { scan: { select: { projectId: true } } } }))?.scan
    : kind === "endpoint" ? (await db.endpoint.findUnique({ where: { id }, select: { scan: { select: { projectId: true } } } }))?.scan
    : kind === "llmJob" ? (await db.llmJob.findUnique({ where: { id }, select: { scan: { select: { projectId: true } } } }))?.scan
    : (await db.agentRun.findUnique({ where: { id }, select: { scan: { select: { projectId: true } } } }))?.scan;
  if (!item || (!item.projectId && !principal.workspaceAdmin)) throw new AccessDenied();
  if (item.projectId) await authorizeProject(db, principal, item.projectId, minimum);
}
export async function changeProjectMember(db: PrismaClient, principal: AccessPrincipal, projectId: string, userId: string, role: ProjectRole | null) {
  return db.$transaction(async (tx) => {
    await authorizeProject(tx, principal, projectId, "admin");
    if (role !== null && !isProjectRole(role)) throw new AccessDenied(400, "Invalid project role.");
    const user = await tx.user.findUnique({ where: { id: userId }, select: { disabled: true } });
    if (role !== null && (!user || user.disabled)) throw new AccessDenied(400, "Choose an active workspace account.");
    const current = await tx.projectMember.findUnique({ where: { projectId_userId: { projectId, userId } } });
    if (current?.role === "admin" && user && !user.disabled && role !== "admin") {
      const admins = await tx.projectMember.count({ where: { projectId, role: "admin", user: { disabled: false } } });
      if (admins <= 1) throw new AccessDenied(409, "Assign another project administrator before removing the last administrator.");
    }
    if (role === null) await tx.projectMember.deleteMany({ where: { projectId, userId } });
    else await tx.projectMember.upsert({ where: { projectId_userId: { projectId, userId } }, create: { projectId, userId, role }, update: { role } });
    await tx.auditEvent.create({ data: { projectId, actorId: principal.userId || "development", action: role ? "project.member.set" : "project.member.remove", targetId: userId, details: JSON.stringify({ from: current?.role || null, to: role }) } });
  });
}
