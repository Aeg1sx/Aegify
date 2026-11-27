/** The queue worker also checks ownership, authorization and call receipts when it claims a job. */
export type QueuePhase =
  | "waiting"
  | "retry_scheduled"
  | "retry_ready"
  | "working"
  | "retrying"
  | "recovery_pending"
  | "deadline_reached";
export interface JobObservation {
  phase: QueuePhase;
  at: string | null;
}
interface ObservedJob {
  status: string;
  attempts: number;
  leaseExpiresAt: Date | null;
  nextAttemptAt?: Date | null;
  deadlineAt?: Date | null;
}

export function observeJob(job: ObservedJob, now = new Date()): JobObservation | null {
  if (!["queued", "pending", "running"].includes(job.status)) return null;
  if (job.deadlineAt && job.deadlineAt <= now)
    return { phase: "deadline_reached", at: job.deadlineAt.toISOString() };
  if (job.status !== "running") {
    if (job.nextAttemptAt && job.attempts > 0) {
      return {
        phase: job.nextAttemptAt > now ? "retry_scheduled" : "retry_ready",
        at: job.nextAttemptAt.toISOString(),
      };
    }
    return { phase: "waiting", at: null };
  }
  if (!job.leaseExpiresAt || job.leaseExpiresAt <= now) {
    return { phase: "recovery_pending", at: job.leaseExpiresAt?.toISOString() ?? null };
  }
  return { phase: job.attempts > 1 ? "retrying" : "working", at: null };
}

export const phaseLabels: Record<QueuePhase, string> = {
  waiting: "Waiting for a worker",
  retry_scheduled: "Retry scheduled",
  retry_ready: "Ready to retry",
  working: "In progress",
  retrying: "Retry in progress",
  recovery_pending: "Waiting for recovery",
  deadline_reached: "Deadline reached",
};
