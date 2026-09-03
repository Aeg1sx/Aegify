import { prisma } from "@/lib/prisma";

// Next.js after-tasks are bounded by the route's five-minute max duration.
// Reconcile abandoned rows after a one-minute grace period so a terminated
// worker cannot block all future reviews indefinitely.
const STALE_LLM_JOB_AGE_MS = 6 * 60 * 1_000;

export async function failStaleLlmJobs(now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - STALE_LLM_JOB_AGE_MS);
  const result = await prisma.llmJob.updateMany({
    where: {
      status: { in: ["pending", "running"] },
      OR: [
        { startedAt: { lt: cutoff } },
        { startedAt: null, createdAt: { lt: cutoff } },
      ],
    },
    data: {
      status: "failed",
      activeKey: null,
      completedAt: now,
      errorMessage: "AI review worker exceeded its operational time bound",
    },
  });
  return result.count;
}
