import process from "node:process";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { setInterval, clearInterval } from "node:timers";
import { log, error } from "node:console";
import { prisma } from "../src/lib/prisma.ts";
import { runWorkerOnce } from "../src/lib/scan-worker.ts";
import { recordWorkerHeartbeat, unregisterWorker } from "../src/lib/worker-registry.ts";
import { configureDatabase } from "../src/lib/database-runtime.ts";
import { runRuleFixtureWorkerOnce } from "../src/lib/rule-fixture-worker.ts";
import { expireRuleFixtures } from "../src/lib/rule-fixture-jobs.ts";

if (!process.env.AUTH_SECRET || !process.env.ENCRYPTION_SECRET || !process.env.DATABASE_URL || !process.env.AUTH_ADMIN_EMAILS || (!process.env.AUTH_ALLOWED_EMAILS && !process.env.AUTH_ALLOWED_DOMAINS)) {
  throw new Error("The worker requires the dashboard's database, encryption, authentication and admission configuration.");
}
if (process.platform === "win32") throw new Error("Run the scan worker in its Linux container.");
const stopping = new globalThis.AbortController();
process.once("SIGTERM", () => stopping.abort());
process.once("SIGINT", () => stopping.abort());
const workerId = randomUUID();
let lastMaintenance = 0;
let registration;
let preferFixtures = false;
function register() {
  if (registration) return registration;
  registration = (async () => {
    await recordWorkerHeartbeat(prisma, "source", workerId);
    await writeFile(join(tmpdir(), "aegify-worker-health"), new Date().toISOString(), { mode: 0o600 });
  })().finally(() => { registration = undefined; });
  return registration;
}
const pulse = setInterval(() => { register().catch(() => error("Worker heartbeat could not be stored.")); }, 15_000);
try {
  await configureDatabase(prisma);
  await register();
  log("Aegify source scan and rule fixture worker ready. Source snapshots and fixture records expire after seven days.");
  while (!stopping.signal.aborted) {
    try {
      if (Date.now() - lastMaintenance > 3_600_000) {
        const cutoff = new Date(Date.now() - 7 * 86_400_000);
        await prisma.scanJob.updateMany({ where: { completedAt: { lt: cutoff }, sourceCiphertext: { not: null }, status: { in: ["completed", "partial", "failed", "cancelled"] } }, data: { sourceCiphertext: null } });
        await expireRuleFixtures(prisma);
        await prisma.scanWorker.deleteMany({ where: { lastSeenAt: { lt: new Date(Date.now() - 86_400_000) } } });
        lastMaintenance = Date.now();
      }
      const first = preferFixtures ? runRuleFixtureWorkerOnce : runWorkerOnce;
      const second = preferFixtures ? runWorkerOnce : runRuleFixtureWorkerOnce;
      const worked = await first(prisma, workerId, process.env, stopping.signal) || (!stopping.signal.aborted && await second(prisma, workerId, process.env, stopping.signal));
      preferFixtures = !preferFixtures;
      if (process.argv.includes("--once")) break;
      if (!worked) await delay(2000, undefined, { signal: stopping.signal });
    } catch {
      if (stopping.signal.aborted) break;
      error("Worker cycle failed; the durable lease will preserve recovery state.");
      await delay(5000, undefined, { signal: stopping.signal }).catch(() => {});
    }
  }
} finally {
  clearInterval(pulse);
  await registration?.catch(() => {});
  await unregisterWorker(prisma, "source", workerId).catch(() => {});
  await prisma.$disconnect();
}
