import type { PrismaClient } from "@prisma/client";
import { writeTransaction } from "./database-runtime.ts";

export type WorkerQueue = "source" | "ai";
export const WORKER_FRESH_MS = 45_000;

export async function recordWorkerHeartbeat(db: PrismaClient, queue: WorkerQueue, id: string): Promise<void> {
  await writeTransaction(db, async (tx) => {
    const lastSeenAt = new Date();
    if (queue === "source") {
      const fields = { version: "0.3.0-beta.1", ruleFixturesVersion: 1, lastSeenAt };
      await tx.scanWorker.upsert({ where: { id }, create: { id, ...fields }, update: fields });
    } else {
      const fields = { version: "review-v2", lastSeenAt };
      await tx.llmWorker.upsert({ where: { id }, create: { id, ...fields }, update: fields });
    }
  });
}

export async function unregisterWorker(db: PrismaClient, queue: WorkerQueue, id: string): Promise<void> {
  await writeTransaction(db, async (tx) => {
    if (queue === "source") await tx.scanWorker.deleteMany({ where: { id } });
    else await tx.llmWorker.deleteMany({ where: { id } });
  });
}
