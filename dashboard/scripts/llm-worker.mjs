import process from "node:process";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { setInterval, clearInterval } from "node:timers";
import { log, error } from "node:console";
import { prisma } from "../src/lib/prisma.ts";
import { runLlmWorkerOnce } from "../src/lib/llm-worker.ts";
import { expireLlmInputs } from "../src/lib/llm-jobs.ts";
import { configureDatabase } from "../src/lib/database-runtime.ts";

if (!process.env.AUTH_SECRET || !process.env.ENCRYPTION_SECRET || !process.env.DATABASE_URL || !process.env.AUTH_ADMIN_EMAILS || (!process.env.AUTH_ALLOWED_EMAILS && !process.env.AUTH_ALLOWED_DOMAINS)) throw new Error("The AI worker requires the dashboard's database, encryption, authentication and admission configuration.");
const stopping = new globalThis.AbortController();
process.once("SIGTERM", () => stopping.abort());
process.once("SIGINT", () => stopping.abort());
const workerId = randomUUID();
let registration;
let lastMaintenance = 0;
function register() {
  if (registration) return registration;
  registration = (async () => {
    await prisma.llmWorker.upsert({ where: { id: workerId }, create: { id: workerId, version: "review-v2" }, update: { lastSeenAt: new Date(), version: "review-v2" } });
    await writeFile(join(tmpdir(), "aegify-ai-worker-health"), new Date().toISOString(), { mode: 0o600 });
  })().finally(() => { registration = undefined; });
  return registration;
}
const pulse = setInterval(() => { register().catch(() => error("AI worker heartbeat could not be stored.")); }, 15_000);
try {
  await configureDatabase(prisma);
  await register();
  log("Aegify AI review worker ready. Review input snapshots expire after seven days; receipts remain.");
  while (!stopping.signal.aborted) {
    try {
      if (Date.now() - lastMaintenance > 3_600_000) {
        await expireLlmInputs(prisma);
        await prisma.llmWorker.deleteMany({ where: { lastSeenAt: { lt: new Date(Date.now() - 86_400_000) } } });
        lastMaintenance = Date.now();
      }
      const worked = await runLlmWorkerOnce(prisma, workerId, process.env, stopping.signal);
      if (process.argv.includes("--once")) break;
      if (!worked) await delay(2000, undefined, { signal: stopping.signal });
    } catch {
      if (stopping.signal.aborted) break;
      error("AI worker cycle interrupted. Durable dispatch receipts prevent automatic provider replays.");
      await delay(5000, undefined, { signal: stopping.signal }).catch(() => {});
    }
  }
} finally {
  clearInterval(pulse);
  await registration?.catch(() => {});
  await prisma.llmWorker.deleteMany({ where: { id: workerId } }).catch(() => {});
  await prisma.$disconnect();
}
