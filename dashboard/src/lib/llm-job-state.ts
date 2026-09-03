export type LlmJobTerminalStatus = "completed" | "partial" | "failed";

export function llmJobTerminalStatus(
  totalFindings: number,
  reviewedCount: number,
  errorCount: number,
): LlmJobTerminalStatus {
  if (totalFindings === 0) return "completed";
  if (errorCount === 0 && reviewedCount >= totalFindings) return "completed";
  if (reviewedCount > 0) return "partial";
  return "failed";
}

export function isLlmJobTerminal(status: string): boolean {
  return status === "completed" || status === "partial" || status === "failed";
}
