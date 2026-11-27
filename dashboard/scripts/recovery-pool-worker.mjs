// Child process for the disposable recovery rehearsal. The coordinator supplies its database over IPC.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { configureDatabase, writeTransaction } from "../src/lib/database-runtime.ts";
import { claimScanJob } from "../src/lib/scan-jobs.ts";
import { runClaimedScan } from "../src/lib/scan-worker.ts";
import { claimLlmJob } from "../src/lib/llm-jobs.ts";
import { runClaimedLlmJob } from "../src/lib/llm-worker.ts";
import { recordWorkerHeartbeat, unregisterWorker } from "../src/lib/worker-registry.ts";

if (!process.send) throw new Error("Start the recovery rehearsal through measure-worker-recovery.mjs.");
const [config] = await once(process, "message");
const db = new PrismaClient({ adapter: new PrismaLibSql({ url: "file:" + config.databasePath }) });
const stop = new globalThis.AbortController();
const send = (data) =>
  new Promise((resolve, reject) => process.send(data, (error) => (error ? reject(error) : resolve())));
const stopped = () => stop.abort();
process.on("disconnect", stopped);
process.on("message", (message) => {
  if (message === "stop") stopped();
});
let calls = 0;
let pulse;
let registration;

async function crashPoint(jobId) {
  await send({ type: "crash-point", jobId });
  // The claimed lease or dispatched call was committed before entering this checkpoint.
  await once(stop.signal, "abort");
  throw new Error("Rehearsal stopped before the planned process loss.");
}

async function transport(request, jobId) {
  calls++;
  const digest = createHash("sha256").update(request.body).digest("hex");
  await send({ type: "transport", jobId, digest });
  if (config.incident === "after-dispatch" && calls === 2) await crashPoint(jobId);
  const findings = JSON.parse(JSON.parse(request.body).messages[0].content).findings;
  const reviews = findings.map(({ id }) => ({
    findingId: id,
    verdict: "needs_review",
    confidence: 0.2,
    reasoning: "The formatter is supplied by the caller.",
    remediation: "Check the formatter contract.",
    adjustedSeverity: null,
    evidenceFor: [],
    evidenceAgainst: [],
    evidenceGaps: ["The formatter implementation is outside this source snapshot."],
  }));
  return {
    status: 200,
    text: JSON.stringify({
      id: "owned-response",
      model: "fixture-model",
      stop_reason: "end_turn",
      usage: { input_tokens: 100, output_tokens: 40 },
      content: [{ type: "text", text: JSON.stringify(reviews) }],
    }),
  };
}

async function publishActivity() {
  for (let sequence = 1; !stop.signal.aborted; sequence++) {
    const begin = Date.now();
    await writeTransaction(db, (tx) =>
      tx.auditEvent.createMany({
        data: ["opened", "closed"].map((action) => ({
          actorId: "rehearsal-concurrent-writer",
          action,
          targetId: String(sequence),
        })),
      }),
    );
    await send({ type: "commit", sequence, begin, end: Date.now() });
    await delay(3);
  }
}

try {
  await configureDatabase(db);
  if (config.queue !== "audit") {
    await recordWorkerHeartbeat(db, config.queue, config.worker);
    pulse = globalThis.setInterval(() => {
      if (!registration)
        registration = recordWorkerHeartbeat(db, config.queue, config.worker)
          .catch((error) => {
            process.stderr.write(String(error));
            stop.abort();
          })
          .finally(() => {
            registration = undefined;
          });
    }, 15_000);
  }
  const starting = once(process, "message");
  await send({ type: "ready" });
  const [command] = await starting;
  assert.equal(command, "start");
  const source = config.queue === "source";
  const claim = source ? claimScanJob : claimLlmJob;
  if (config.queue === "audit") await publishActivity();
  else
    while (!stop.signal.aborted) {
      const start = performance.now();
      const job = await claim(db, config.worker, process.env);
      if (!job) {
        await delay(200);
        continue;
      }
      const claimedAt = performance.now();
      await send({ type: "claim", jobId: job.id, attempt: job.attempts, claimMs: claimedAt - start });
      if (config.incident === "after-claim") await crashPoint(job.id);
      if (source) {
        // A seeded immutable source must always go through the normal Python worker and SARIF publisher.
        assert.ok(job.sourceCiphertext && job.sourceDigest);
        await runClaimedScan(db, job, process.env, stop.signal);
      } else {
        await runClaimedLlmJob(db, job, process.env, stop.signal, {
          transport: (request) => transport(request, job.id),
        });
      }
      await send({ type: "processed", jobId: job.id, serviceMs: performance.now() - claimedAt });
    }
} finally {
  globalThis.clearInterval(pulse);
  await registration;
  if (config.queue !== "audit") await unregisterWorker(db, config.queue, config.worker);
  await db.$disconnect();
  if (process.connected) process.disconnect();
}
