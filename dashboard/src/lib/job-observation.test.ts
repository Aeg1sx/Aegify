import assert from "node:assert/strict";
import test from "node:test";
import { observeJob } from "./job-observation.ts";

test("job observations distinguish first attempt, backoff, eligible retry, occupied and expired leases", () => {
  const now = new Date("2026-11-21T13:00:00Z");
  const future = new Date(+now + 1000);
  const source = { status: "queued", attempts: 0, leaseExpiresAt: null, nextAttemptAt: now };
  assert.deepEqual(observeJob(source, now), { phase: "waiting", at: null });
  assert.deepEqual(observeJob({ ...source, attempts: 1, nextAttemptAt: future }, now), {
    phase: "retry_scheduled",
    at: future.toISOString(),
  });
  assert.deepEqual(observeJob({ ...source, attempts: 1 }, now), {
    phase: "retry_ready",
    at: now.toISOString(),
  });
  const running = { ...source, status: "running", attempts: 1, leaseExpiresAt: future };
  assert.equal(observeJob(running, now)?.phase, "working");
  assert.equal(observeJob({ ...running, attempts: 2 }, now)?.phase, "retrying");
  assert.deepEqual(observeJob(running, future), { phase: "recovery_pending", at: future.toISOString() });
  assert.deepEqual(observeJob({ ...running, leaseExpiresAt: null }, now), {
    phase: "recovery_pending",
    at: null,
  });
  assert.deepEqual(observeJob({ ...running, deadlineAt: now }, now), {
    phase: "deadline_reached",
    at: now.toISOString(),
  });
  assert.equal(observeJob({ ...running, status: "partial", deadlineAt: now }, now), null);
});
