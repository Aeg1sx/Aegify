export interface HarnessEvidence {
  contract_version: 1;
  id?: string;
  plan_name: string;
  status: "passed" | "failed" | "timeout" | "error";
  executed: true;
  image: string;
  approval_scope_sha256: string;
  workspace_sha256: string;
  policy_sha256: string;
  steps: Array<{
    id: string;
    status: string;
    command: string[];
    stdout_sha256: string;
    stderr_sha256: string;
    artifacts?: Array<{ relative_path: string; size_bytes: number; sha256: string }>;
  }>;
}

export function validateHarnessEvidence(value: unknown): HarnessEvidence {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Harness evidence must be an object");
  }
  const raw = value as Record<string, unknown>;
  if (raw.contract_version !== 1 || raw.executed !== true) {
    throw new Error("Only executed harness contract version 1 is accepted");
  }
  if (!["passed", "failed", "timeout", "error"].includes(String(raw.status))) {
    throw new Error("Invalid harness status");
  }
  if (!/^.+@sha256:[0-9a-f]{64}$/.test(String(raw.image || ""))) {
    throw new Error("Harness image must be pinned by SHA-256 digest");
  }
  for (const key of ["approval_scope_sha256", "workspace_sha256", "policy_sha256"] as const) {
    if (!/^(?:sha256:)?[0-9a-f]{64}$/.test(String(raw[key] || ""))) {
      throw new Error(`${key} must contain a SHA-256 digest`);
    }
  }
  if (!Array.isArray(raw.steps) || raw.steps.length === 0 || raw.steps.length > 100) {
    throw new Error("Harness evidence must contain 1-100 steps");
  }
  for (const step of raw.steps as Array<Record<string, unknown>>) {
    if (!step || typeof step !== "object" || !Array.isArray(step.command)) {
      throw new Error("Invalid harness step");
    }
    if (!/^[0-9a-f]{64}$/.test(String(step.stdout_sha256 || ""))
      || !/^[0-9a-f]{64}$/.test(String(step.stderr_sha256 || ""))) {
      throw new Error("Harness step output digests are required");
    }
  }
  const serialized = JSON.stringify(raw);
  if (serialized.length > 2_000_000) throw new Error("Harness evidence exceeds 2 MB");
  return raw as unknown as HarnessEvidence;
}
