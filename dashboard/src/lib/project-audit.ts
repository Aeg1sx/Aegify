import { randomUUID } from "node:crypto";
import { open, unlink, type FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Prisma, PrismaClient } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { AccessDenied, authorizeProject, resolvePrincipal } from "./project-access.ts";

export function auditPageOptions(query: URLSearchParams) {
  const raw = query.get("limit") ?? "100";
  const cursor = query.get("cursor");
  if (query.getAll("limit").length > 1 || !/^(?:[1-9]\d?|100)$/.test(raw)) {
    throw new AccessDenied(400, "Choose an audit page size from 1 to 100.");
  }
  if (query.getAll("cursor").length > 1 || (cursor !== null && (!cursor || cursor.length > 128))) {
    throw new AccessDenied(400, "Invalid audit cursor.");
  }
  return { limit: Number(raw), cursor };
}

async function checkAdmin(tx: Prisma.TransactionClient, projectId: string, userId: string | null, env: AuthEnvironment) {
  const principal = await resolvePrincipal(tx, userId ?? undefined, env);
  await authorizeProject(tx, principal, projectId, "admin");
}

function readEvents(tx: Prisma.TransactionClient, projectId: string, take: number, cursor: string | null) {
  return tx.auditEvent.findMany({
    where: { projectId }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take,
    ...(cursor && { cursor: { id: cursor }, skip: 1 }),
  });
}

export function readAuditPage(db: PrismaClient, projectId: string, userId: string | null, env: AuthEnvironment, query: URLSearchParams) {
  return db.$transaction(async (tx) => {
    await checkAdmin(tx, projectId, userId, env);
    const { limit, cursor } = auditPageOptions(query);
    if (cursor && !await tx.auditEvent.findFirst({ where: { id: cursor, projectId }, select: { id: true } })) {
      throw new AccessDenied(400, "Invalid audit cursor.");
    }
    const events = await readEvents(tx, projectId, limit + 1, cursor);
    const hasMore = events.length > limit;
    if (hasMore) events.pop();
    return { events, nextCursor: hasMore ? events[events.length - 1].id : null };
  });
}

async function temporarySnapshot(): Promise<FileHandle> {
  const path = join(tmpdir(), `aegify-audit-${randomUUID()}`);
  const file = await open(path, "wx+", 0o600);
  try {
    // The descriptor is the only reference while records are written and downloaded.
    await unlink(path);
    return file;
  } catch (error) {
    await file.close();
    throw error;
  }
}

export async function exportAuditSnapshot(db: PrismaClient, projectId: string, userId: string | null, env: AuthEnvironment, signal: AbortSignal) {
  const file = await temporarySnapshot();
  try {
    const count = await db.$transaction(async (tx) => {
      await checkAdmin(tx, projectId, userId, env);
      let count = 0;
      let cursor: string | null = null;
      for (;;) {
        signal.throwIfAborted();
        const events = await readEvents(tx, projectId, 100, cursor);
        if (events.length) {
          await file.writeFile(events.map((event) => JSON.stringify(event) + "\n").join(""));
          count += events.length;
        }
        if (events.length < 100) return count;
        cursor = events[events.length - 1].id;
      }
    }, { timeout: 120_000 });
    signal.throwIfAborted();
    return { file, count, bytes: (await file.stat()).size };
  } catch (error) {
    await file.close();
    throw error;
  }
}
