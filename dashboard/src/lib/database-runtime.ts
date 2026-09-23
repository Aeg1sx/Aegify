import { randomInt } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import type { Prisma, PrismaClient } from "@prisma/client";

/** Configure the shared local database before dashboard/worker traffic starts. */
export async function configureDatabase(db: PrismaClient): Promise<void> {
  const rows = await db.$queryRaw<Array<{ journal_mode: string }>>`PRAGMA journal_mode = WAL`;
  if (rows[0]?.journal_mode?.toLowerCase() !== "wal") throw new Error("Aegify requires a local SQLite database with WAL enabled.");
}

/** Retry an entire rolled-back transaction, never an individual statement. */
export async function writeTransaction<T>(db: PrismaClient, action: (tx: Prisma.TransactionClient) => Promise<T>, options?: { timeout?: number; maxWait?: number }): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try { return await db.$transaction(action, options); }
    catch (error) {
      const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
      // Pinned adapter-libsql maps SQLite BUSY (including BUSY_SNAPSHOT) to
      // P1008; transaction start/commit can also expose native SQLITE_BUSY.
      // Authorization, validation, constraints and other errors are not retried.
      if (attempt >= 3 || !["SQLITE_BUSY", "SQLITE_BUSY_SNAPSHOT", "P1008"].includes(String(code))) throw error;
      await delay(50 * 2 ** attempt + randomInt(25, 125));
    }
  }
}
