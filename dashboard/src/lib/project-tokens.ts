import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Prisma, PrismaClient } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { AccessDenied, authorizeProject, type AccessPrincipal } from "./project-access.ts";

export const tokenMetadata = { id: true, projectId: true, name: true, prefix: true, scope: true, createdBy: true, createdAt: true, expiresAt: true, revokedAt: true, lastUsedAt: true } as const;
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
export async function issueProjectToken(db: PrismaClient, principal: AccessPrincipal, projectId: string, name: string, expiresAt: Date, now = new Date()) {
  if (!name.trim() || name.length > 80 || !Number.isFinite(expiresAt.getTime()) || expiresAt <= now || expiresAt.getTime() - now.getTime() > 90 * 86_400_000) throw new AccessDenied(400, "Name the token and choose an expiry within 90 days.");
  return db.$transaction(async (tx) => {
    const project = await authorizeProject(tx, principal, projectId, "admin");
    if (project.archived) throw new AccessDenied(409, "Restore the project before issuing a token.");
    if (await tx.projectServiceToken.count({ where: { projectId, revokedAt: null, expiresAt: { gt: now } } }) >= 50) throw new AccessDenied(409, "Revoke an existing token before issuing more than 50 active credentials.");
    const token = "aegify_ci_" + randomBytes(32).toString("base64url");
    const record = await tx.projectServiceToken.create({ data: { projectId, name: name.trim(), tokenHash: hash(token), prefix: token.slice(0, 18), createdBy: principal.userId || "development", expiresAt }, select: tokenMetadata });
    await tx.auditEvent.create({ data: { projectId, actorId: principal.userId || "development", action: "service_token.create", targetId: record.id, details: JSON.stringify({ scope: "scan:upload", expiresAt: expiresAt.toISOString() }) } });
    return { token, record }; // The only response containing the raw credential.
  });
}
export async function revokeProjectToken(db: PrismaClient, principal: AccessPrincipal, projectId: string, tokenId: string) {
  return db.$transaction(async (tx) => {
    await authorizeProject(tx, principal, projectId, "admin");
    const token = await tx.projectServiceToken.findFirst({ where: { id: tokenId, projectId } });
    if (!token) throw new AccessDenied();
    if (token.revokedAt) return;
    await tx.projectServiceToken.update({ where: { id: tokenId }, data: { revokedAt: new Date() } });
    await tx.auditEvent.create({ data: { projectId, actorId: principal.userId || "development", action: "service_token.revoke", targetId: tokenId } });
  });
}
export async function authenticateUploadToken(db: PrismaClient | Prisma.TransactionClient, token: string, env: AuthEnvironment, now = new Date()): Promise<{ projectId: string; actorId: string } | null> {
  if (!token || token.length > 512) return null;
  const digest = hash(token);
  if (env.AEGIFY_UPLOAD_TOKEN && env.AEGIFY_UPLOAD_PROJECT_ID && timingSafeEqual(Buffer.from(digest, "hex"), Buffer.from(hash(env.AEGIFY_UPLOAD_TOKEN), "hex"))) {
    const project = await db.project.findFirst({ where: { id: env.AEGIFY_UPLOAD_PROJECT_ID, archived: false }, select: { id: true } });
    return project ? { projectId: project.id, actorId: "legacy-upload-token" } : null;
  }
  const record = await db.projectServiceToken.findUnique({ where: { tokenHash: digest }, select: { id: true, projectId: true, scope: true, revokedAt: true, expiresAt: true, project: { select: { archived: true } } } });
  if (!record || record.revokedAt || record.expiresAt <= now || record.scope !== "scan:upload" || record.project.archived) return null;
  // Recheck revocation in the write so an already-revoked credential is not accepted.
  const used = await db.projectServiceToken.updateMany({ where: { id: record.id, revokedAt: null, expiresAt: { gt: now } }, data: { lastUsedAt: now } });
  return used.count === 1 ? { projectId: record.projectId, actorId: `service-token:${record.id}` } : null;
}
