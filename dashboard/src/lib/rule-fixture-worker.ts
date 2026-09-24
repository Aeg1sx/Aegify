import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import type { PrismaClient, RuleFixtureJob } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { AccessDenied } from "./project-access.ts";
import { FIXTURE_REPORT_BYTES, FIXTURE_TIMEOUT_SECONDS, type FixtureInput, type FixtureReport } from "./rule-fixture-contract.ts";
import { fixtureDigest, fixtureInput, fixtureWorkerInput, restoreFixtureInput } from "./rule-fixture-input.ts";
import { assertFixtureLease, claimRuleFixture, completeRuleFixture, failRuleFixture, FixtureLeaseLost, heartbeatRuleFixture } from "./rule-fixture-jobs.ts";

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  return JSON.stringify(value);
}
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every((item) => typeof item === "string");
const count = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
function validMetrics(value: FixtureReport["metrics"]): boolean {
  if (!value || !count(value.true_positives) || !count(value.false_positives) || !count(value.false_negatives)) return false;
  const tp = value.true_positives, fp = value.false_positives, fn = value.false_negatives;
  return value.precision === (tp + fp ? tp / (tp + fp) : null) && value.recall === (tp + fn ? tp / (tp + fn) : null);
}
export function parseFixtureReport(raw: string, input: FixtureInput): FixtureReport {
  if (Buffer.byteLength(raw) > FIXTURE_REPORT_BYTES) throw new Error("Fixture report exceeds its byte limit.");
  const report = JSON.parse(raw) as FixtureReport;
  if (!report || report.schema_version !== 1 || !["passed", "failed", "incomplete", "error"].includes(report.status) || !strings(report.issues) || !Array.isArray(report.diagnostics) || !Array.isArray(report.cases) || report.cases.length > 20) throw new Error("Invalid fixture report.");
  if (report.status === "error") {
    if (report.cases.length || report.metrics !== null || !report.issues.length) throw new Error("Invalid fixture error report.");
    return report;
  }
  const suite = JSON.parse(input.suiteJson);
  if (report.suite_id !== suite.suite_id || report.rule_id !== suite.rule_id || report.manifest?.rule_digest !== fixtureDigest(input.ruleYaml) || report.manifest.suite_digest !== fixtureDigest(canonical(suite)) || report.manifest.source_execution !== false || report.manifest.line_tolerance !== 0 || report.manifest.wall_timeout_seconds !== FIXTURE_TIMEOUT_SECONDS || !/^sha256:[a-f0-9]{64}$/.test(report.result_digest) || report.cases.length !== suite.cases.length || report.positive_cases !== suite.cases.filter((item: { expected: unknown[] }) => item.expected.length).length || report.negative_cases !== report.cases.length - report.positive_cases) throw new Error("Fixture report does not match the submitted input.");
  if (report.status === "incomplete" ? report.metrics !== null : !validMetrics(report.metrics)) throw new Error("Invalid suite metrics.");
  for (const [index, item] of report.cases.entries()) {
    const expected = suite.cases[index];
    const sourceDigest = fixtureDigest(canonical([...expected.files].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)));
    if (item.id !== expected.id || item.source_digest !== sourceDigest || !["passed", "failed", "incomplete"].includes(item.status) || !strings(item.issues) || !strings(item.evaluated_rules) || !strings(item.unmatched_actual) || !strings(item.unmatched_expected) || !Array.isArray(item.parse_diagnostics) || !Array.isArray(item.actual) || !count(item.files_scanned)) throw new Error("Invalid fixture case.");
    if (item.status === "incomplete" ? item.metrics !== null : !validMetrics(item.metrics)) throw new Error("Invalid case metrics.");
    if (item.status === "passed" && (item.metrics!.false_positives || item.metrics!.false_negatives || item.issues.length)) throw new Error("Fixture pass contradicts its evidence.");
    for (const finding of item.actual) {
      if (finding.rule_id !== report.rule_id || !expected.files.some((file: { path: string }) => file.path === finding.file_path) || !count(finding.line_start) || finding.line_start < 1 || !count(finding.line_end) || finding.line_end < finding.line_start || [finding.message, finding.severity, finding.evidence_state, finding.disposition].some((value) => typeof value !== "string")) throw new Error("Invalid fixture finding.");
    }
  }
  if (report.status !== "incomplete") {
    if (report.positive_cases < 1 || report.negative_cases < 2 || report.cases.some((item) => item.status === "incomplete") || ["true_positives", "false_positives", "false_negatives"].some((key) => report.metrics![key as "true_positives"] !== report.cases.reduce((sum, item) => sum + item.metrics![key as "true_positives"], 0))) throw new Error("Suite completeness contradicts its cases.");
    if ((report.status === "passed") !== report.cases.every((item) => item.status === "passed")) throw new Error("Suite status contradicts its cases.");
  }
  return report;
}
export class FixtureProcessError extends Error {
  code: string;
  constructor(code: string) { super("Rule fixture worker failed."); this.code = code; }
}
/** Fixed trusted module; source, rule patterns and fixtures are data only. */
export async function runPythonFixture(value: FixtureInput, stopping: AbortSignal) {
  const input = fixtureInput(value);
  const directory = await mkdtemp(join(tmpdir(), "aegify-rule-fixture-"));
  const deadline = AbortSignal.timeout(FIXTURE_TIMEOUT_SECONDS * 1000);
  const signal = AbortSignal.any([stopping, deadline]);
  let child: ReturnType<typeof spawn> | undefined;
  let closed = false;
  const stop = () => {
    if (child?.pid && !closed) { try { process.kill(-child.pid, "SIGKILL"); } catch { /* The owned process group already exited. */ } }
  };
  try {
    const path = join(directory, "input.json");
    await writeFile(path, fixtureWorkerInput(input), { flag: "wx", mode: 0o400 });
    signal.throwIfAborted();
    const interpreter = fileURLToPath(new URL("../../../scanner/.venv/bin/python", import.meta.url));
    child = spawn(interpreter, ["-I", "-m", "aegify.quality.rule_fixture_worker", path], {
      cwd: directory, detached: true, stdio: ["ignore", "pipe", "pipe"],
      env: { NODE_ENV: "production", PATH: "/usr/local/bin:/usr/bin:/bin", LANG: "C.UTF-8", PYTHONDONTWRITEBYTECODE: "1", TMPDIR: directory },
    });
    child.once("close", () => { closed = true; });
    signal.addEventListener("abort", stop, { once: true });
    if (signal.aborted) stop();
    let outputBytes = 0, errorBytes = 0, exceeded = false;
    const chunks: Buffer[] = [];
    child.stdout!.on("data", (chunk: Buffer) => { outputBytes += chunk.length; if (outputBytes > FIXTURE_REPORT_BYTES) { exceeded = true; stop(); } else chunks.push(chunk); });
    child.stderr!.on("data", (chunk: Buffer) => { errorBytes += chunk.length; if (errorBytes > 128 * 1024) { exceeded = true; stop(); } });
    const code = await new Promise<number | null>((resolve, reject) => { child!.once("error", reject); child!.once("close", resolve); });
    if (deadline.aborted) throw new FixtureProcessError("deadline_exceeded");
    stopping.throwIfAborted();
    if (code !== 0 || exceeded) throw new FixtureProcessError("worker_failed");
    const raw = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
    return { raw, report: parseFixtureReport(raw, input) };
  } finally {
    signal.removeEventListener("abort", stop);
    if (child?.pid && !closed) { stop(); await new Promise<void>((resolve) => child!.once("close", () => resolve())); }
    await rm(directory, { recursive: true, force: true });
  }
}
export async function runClaimedRuleFixture(db: PrismaClient, job: RuleFixtureJob, env: AuthEnvironment, stopping: AbortSignal) {
  const control = new AbortController();
  const signal = AbortSignal.any([control.signal, stopping]);
  let failureCode = "authorization_lost";
  let heartbeatPending: Promise<void> | null = null;
  const pulse = setInterval(() => {
    if (heartbeatPending || signal.aborted) return;
    heartbeatPending = heartbeatRuleFixture(db, job, env).catch((error) => {
      if (error instanceof AccessDenied) failureCode = "authorization_lost";
      control.abort(error);
    }).finally(() => { heartbeatPending = null; });
  }, 5000);
  try {
    await db.$transaction((tx) => assertFixtureLease(tx, job, env));
    failureCode = "input_unavailable";
    const input = restoreFixtureInput(job, env.ENCRYPTION_SECRET);
    failureCode = "worker_failed";
    const result = await runPythonFixture(input, signal);
    signal.throwIfAborted();
    await completeRuleFixture(db, job, result.raw, result.report, env);
  } catch (error) {
    if (error instanceof FixtureLeaseLost) return;
    const code = failureCode === "authorization_lost" || (error instanceof AccessDenied && failureCode !== "input_unavailable") ? "authorization_lost" : error instanceof FixtureProcessError ? error.code : failureCode;
    await failRuleFixture(db, job, code, stopping.aborted);
  } finally { clearInterval(pulse); await heartbeatPending; }
}
export async function runRuleFixtureWorkerOnce(db: PrismaClient, workerId: string, env: AuthEnvironment, stopping: AbortSignal): Promise<boolean> {
  const job = await claimRuleFixture(db, workerId, env);
  if (!job) return false;
  await runClaimedRuleFixture(db, job, env, stopping);
  return true;
}
