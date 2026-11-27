import { randomInt } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import type { Prisma, PrismaClient } from "@prisma/client";

/** Configure the shared local database before dashboard/worker traffic starts. */
export async function configureDatabase(db: PrismaClient): Promise<void> {
  const rows = await db.$queryRaw<Array<{ journal_mode: string }>>`PRAGMA journal_mode = WAL`;
  if (rows[0]?.journal_mode?.toLowerCase() !== "wal")
    throw new Error("Aegify requires a local SQLite database with WAL enabled.");
}

function isDatabaseBusy(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const { code, meta } = error as {
    code?: string;
    meta?: { driverAdapterError?: { cause?: { originalCode?: string } } };
  };
  if (code === "P2010") {
    // Raw queries wrap the SQLite extended result code in the pinned adapter.
    const sqliteCode = Number(meta?.driverAdapterError?.cause?.originalCode);
    return Number.isSafeInteger(sqliteCode) && sqliteCode > 0 && (sqliteCode & 0xff) === 5;
  }
  return code === "SQLITE_BUSY" || code === "SQLITE_BUSY_SNAPSHOT" || code === "P1008";
}

/** Retry an entire rolled-back transaction, never an individual statement. */
export async function writeTransaction<T>(
  db: PrismaClient,
  action: (tx: Prisma.TransactionClient) => Promise<T>,
  options?: { timeout?: number; maxWait?: number },
): Promise<T> {
  const until = performance.now() + (options?.maxWait ?? 5000);
  for (let attempt = 0; ; attempt++) {
    try {
      return await db.$transaction(async (tx) => {
        // The libSQL Prisma adapter opens a DEFERRED transaction. Reserve the
        // SQLite writer before reading application state. No rows or triggers
        // are touched, and a competing writer can back off before doing work.
        await tx.$executeRaw`UPDATE "Setting" SET "value" = "value" WHERE 0`;
        return action(tx);
      }, options);
    } catch (error) {
      const remaining = until - performance.now();
      if (remaining <= 0 || !isDatabaseBusy(error)) throw error;
      await delay(Math.min(remaining, 25 * 2 ** Math.min(attempt, 4) + randomInt(25, 125)));
    }
  }
}

export function queuedOrExpired(now: Date) {
  return {
    OR: [
      { status: "queued", nextAttemptAt: { lte: now } },
      { status: "running", leaseExpiresAt: { lte: now } },
      { status: "running", leaseExpiresAt: null },
    ],
  };
}
