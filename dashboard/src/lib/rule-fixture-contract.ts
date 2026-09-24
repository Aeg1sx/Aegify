/** Shared display types. Python owns DSL validation and detection semantics. */
export const FIXTURE_RULE_BYTES = 128 * 1024;
export const FIXTURE_SUITE_BYTES = 2 * 1024 * 1024;
export const FIXTURE_INPUT_BYTES = 3 * 1024 * 1024;
export const FIXTURE_REPORT_BYTES = 4 * 1024 * 1024;
export const FIXTURE_TIMEOUT_SECONDS = 30;
export const FIXTURE_RETENTION_MS = 7 * 86_400_000;
export interface FixtureInput { ruleYaml: string; suiteJson: string }
export interface FixtureMetrics {
  true_positives: number; false_positives: number; false_negatives: number;
  precision: number | null; recall: number | null;
}
export interface FixtureFinding {
  rule_id: string; file_path: string; line_start: number; line_end: number;
  message: string; severity: string; evidence_state: string; disposition: string;
  taint_flow?: { source: { file_path: string; line: number; variable: string; source_type: string }; sink: { file_path: string; line: number; function: string; sink_type: string }; path: Array<{ file_path: string; line: number; variable: string; propagation_type: string }>; sanitized: boolean; sanitizer: string | null } | null;
}
export interface FixtureCaseReport {
  id: string; status: "passed" | "failed" | "incomplete"; source_digest: string;
  duration_seconds: number; files_scanned: number; evaluated_rules: string[];
  issues: string[]; parse_diagnostics: Array<Record<string, unknown>>;
  actual: FixtureFinding[]; metrics: FixtureMetrics | null;
  unmatched_actual: string[]; unmatched_expected: string[];
}
export interface FixtureReport {
  schema_version: 1; status: "passed" | "failed" | "incomplete" | "error";
  issues: string[]; diagnostics: Array<Record<string, unknown>>;
  suite_id: string; rule_id: string; positive_cases: number; negative_cases: number;
  cases: FixtureCaseReport[]; metrics: FixtureMetrics | null;
  manifest: Record<string, unknown>; result_digest: string;
}
export interface FixtureJobView {
  id: string; projectId: string; contractVersion: number; inputDigest: string; resultDigest: string;
  status: string; outcome: string; attempts: number; maxAttempts: number; errorCode: string;
  heartbeatAt: string | null; createdAt: string; completedAt: string | null; expiresAt: string;
}
export interface FixtureDetail {
  job: FixtureJobView; report: FixtureReport | null; input?: FixtureInput;
  expired: boolean; canManage: boolean;
  events: Array<{ id: number; code: string; message: string; createdAt: string }>;
}
