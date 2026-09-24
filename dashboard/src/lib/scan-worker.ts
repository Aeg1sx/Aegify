import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import type { PrismaClient, ScanJob } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { AccessDenied } from "./project-access.ts";
import { encrypt, decrypt } from "./crypto.ts";
import { fetchRepoCode, isPathSafe, type CodeBundle } from "./repo-fetcher.ts";
import { importSarif } from "./sarif-import.ts";
import { notifyImportedScan } from "./scan-notifications.ts";
import { writeTransaction } from "./database-runtime.ts";
import { assertJobLease, claimScanJob, completeScanJob, failScanJob, heartbeatScanJob, JOB_DEADLINE_MS, LeaseLost } from "./scan-jobs.ts";
import { sourceDigest, type SourceSnapshot } from "./source-snapshot.ts";

export { sourceDigest } from "./source-snapshot.ts";
export type { SourceSnapshot } from "./source-snapshot.ts";

const sha256 = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const MAX_REPORT_BYTES = 100 * 1024 * 1024;
export function makeSourceSnapshot(job: ScanJob, bundle: CodeBundle): SourceSnapshot {
  if (bundle.ref !== job.commitSha) throw new Error("Source commit changed after pinning.");
  const snapshot: Omit<SourceSnapshot, "sourceDigest"> = { version: 1, provider: job.provider, repository: job.ownerSlug, commit: bundle.ref, truncated: bundle.truncated, files: bundle.files.map((file) => {
    if (!isPathSafe(file.path)) throw new Error("Invalid source path.");
    return { path: file.path, content: file.content, sha256: sha256(file.content) };
  }) };
  return { ...snapshot, sourceDigest: sourceDigest(snapshot) };
}

export async function pinJobCommit(db: PrismaClient, job: ScanJob, commitSha: string, env: AuthEnvironment) {
  if (!/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i.test(commitSha)) throw new Error("Invalid immutable commit.");
  await writeTransaction(db, async (tx) => {
    const current = await assertJobLease(tx, job, env);
    if (current.commitSha && current.commitSha !== commitSha) throw new Error("Pinned source changed.");
    if (!current.commitSha) {
      await tx.scanJob.update({ where: { id: job.id }, data: { commitSha } });
      await tx.scan.update({ where: { id: job.scanId }, data: { commitSha } });
      await tx.scanJobEvent.create({ data: { jobId: job.id, code: "source_pinned", message: "Repository commit pinned", details: JSON.stringify({ commitSha }) } });
    }
  });
  job.commitSha = commitSha;
}

async function getSnapshot(db: PrismaClient, job: ScanJob, env: AuthEnvironment, signal: AbortSignal): Promise<SourceSnapshot> {
  if (job.sourceCiphertext) {
    const source: SourceSnapshot = JSON.parse(decrypt(job.sourceCiphertext));
    if (source.sourceDigest !== job.sourceDigest || sourceDigest(source) !== job.sourceDigest || source.commit !== job.commitSha || source.repository !== job.ownerSlug || source.provider !== job.provider) throw new Error("Stored source manifest mismatch.");
    return source;
  }
  const account = await db.account.findFirst({ where: { userId: job.requestedBy, provider: job.provider }, select: { access_token: true } });
  if (!account?.access_token) throw new AccessDenied(401);
  const bundle = await fetchRepoCode({
    provider: job.provider as "github" | "gitlab", ownerSlug: job.ownerSlug, providerRepoId: job.providerRepoId,
    ref: job.commitSha || job.requestedRef, accessToken: account.access_token, signal,
    maxFiles: 1000, maxFileSizeBytes: 500 * 1024, maxTotalBytes: 10 * 1024 * 1024,
    onResolved: (commit) => pinJobCommit(db, job, commit, env),
  });
  const source = makeSourceSnapshot(job, bundle);
  const manifest = { version: 1, commit: source.commit, sourceDigest: source.sourceDigest, selection: bundle.selection, truncated: bundle.truncated, omittedFiles: bundle.omittedFiles, skippedFiles: bundle.skippedFiles, files: source.files.map(({ path, sha256 }) => ({ path, sha256 })) };
  const sourceCiphertext = encrypt(JSON.stringify(source));
  await writeTransaction(db, async (tx) => {
    await assertJobLease(tx, job, env);
    await tx.scanJob.update({ where: { id: job.id }, data: { sourceDigest: source.sourceDigest, sourceManifest: JSON.stringify(manifest), sourceCiphertext } });
    await tx.scanJobEvent.create({ data: { jobId: job.id, code: "snapshot_stored", message: "Encrypted source snapshot stored for recovery", details: JSON.stringify({ sourceDigest: source.sourceDigest, files: source.files.length, truncated: bundle.truncated }) } });
  });
  job.sourceDigest = source.sourceDigest;
  return source;
}

/** Fixed engine executable and fixed argv. No target build/install/shell command. */
export async function runPythonSnapshot(source: SourceSnapshot, signal: AbortSignal, progress: (value: { phase: number; name: string; percent: number }) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), "aegify-worker-"));
  const input = join(directory, "input.json");
  const output = join(directory, "report.sarif");
  let child: ReturnType<typeof spawn> | undefined;
  let closed = false;
  const abort = () => {
    // The child only reads its private snapshot and produces disposable output.
    // Kill its entire owned group, including parser processes even if the parent
    // has exited while descendants still hold the output pipes open.
    if (child?.pid && !closed) {
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* The owned group already exited. */ }
    }
  };
  try {
    await writeFile(input, JSON.stringify(source), { mode: 0o600, flag: "wx" });
    signal.throwIfAborted();
    const interpreter = fileURLToPath(new URL("../../../scanner/.venv/bin/python", import.meta.url));
    child = spawn(interpreter, ["-I", "-m", "aegify.worker", "--input", input, "--output", output], {
      cwd: directory, detached: true, stdio: ["ignore", "pipe", "pipe"],
      env: { NODE_ENV: "production", PATH: "/usr/local/bin:/usr/bin:/bin", LANG: "C.UTF-8", PYTHONDONTWRITEBYTECODE: "1", TMPDIR: directory },
    });
    child.once("close", () => { closed = true; });
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    let bytes = 0; let buffer = ""; let invalidOutput = false;
    let pending = Promise.resolve();
    child.stdout!.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 512 * 1024) { invalidOutput = true; abort(); return; }
      buffer += chunk.toString("utf8");
      if (buffer.length > 16_384) { invalidOutput = true; abort(); return; }
      while (buffer.includes("\n")) {
        const end = buffer.indexOf("\n"); const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        try {
          const value = JSON.parse(line);
          if (!Number.isInteger(value.phase) || value.phase < 1 || value.phase > 9 || typeof value.name !== "string" || value.name.length > 100 || typeof value.percent !== "number" || !Number.isFinite(value.percent) || value.percent < 0 || value.percent > 1) continue;
          pending = pending.then(() => progress(value)).catch(() => { invalidOutput = true; abort(); });
        } catch { /* The worker contract accepts only bounded JSON progress events. */ }
      }
    });
    child.stderr!.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 512 * 1024) { invalidOutput = true; abort(); } });
    const code = await new Promise<number | null>((resolve, reject) => { child!.once("error", reject); child!.once("close", resolve); });
    await pending;
    signal.throwIfAborted();
    if (code !== 0 || invalidOutput) throw new Error("Scanner process did not finish successfully.");
    const handle = await open(output, "r");
    let raw: Buffer;
    try {
      const metadata = await handle.stat();
      if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_REPORT_BYTES) throw new Error("Worker report exceeds its size limit.");
      raw = await handle.readFile();
      if (raw.length > MAX_REPORT_BYTES) throw new Error("Worker report exceeds its size limit.");
    } finally { await handle.close(); }
    return { report: JSON.parse(raw.toString("utf8")), resultDigest: `sha256:${sha256(raw)}` };
  } finally {
    signal.removeEventListener("abort", abort);
    if (child?.pid && !closed) {
      abort();
      await new Promise<void>((resolve) => child!.once("close", () => resolve()));
    }
    await rm(directory, { recursive: true, force: true });
  }
}

export async function runClaimedScan(db: PrismaClient, job: ScanJob, env: AuthEnvironment, stopping: AbortSignal): Promise<void> {
  const control = new AbortController();
  const deadline = AbortSignal.timeout(JOB_DEADLINE_MS);
  const signal = AbortSignal.any([control.signal, stopping, deadline]);
  let heartbeatBusy = false;
  let failureCode = "fetch_failed";
  const heartbeat = setInterval(() => {
    if (heartbeatBusy || signal.aborted) return;
    heartbeatBusy = true;
    heartbeatScanJob(db, job, env).catch((error) => {
      if (error instanceof AccessDenied) failureCode = "authorization_lost";
      control.abort(error);
    }).finally(() => { heartbeatBusy = false; });
  }, 10_000);
  try {
    await db.$transaction((tx) => assertJobLease(tx, job, env));
    const source = await getSnapshot(db, job, env, signal);
    failureCode = "scanner_failed";
    let previousPhase = ""; let updatedAt = 0;
    const { report, resultDigest } = await runPythonSnapshot(source, signal, async (value) => {
      if (value.name === previousPhase && Date.now() - updatedAt < 5000) return;
      await writeTransaction(db, async (tx) => {
        await assertJobLease(tx, job, env);
        await tx.scan.update({ where: { id: job.scanId }, data: { progressPhase: value.phase, progressPhaseName: value.name, progressPercent: value.percent, progressMessage: value.name, progressUpdatedAt: new Date() } });
        if (value.name !== previousPhase) await tx.scanJobEvent.create({ data: { jobId: job.id, code: "phase", message: value.name, details: JSON.stringify({ percent: value.percent }) } });
      });
      previousPhase = value.name; updatedAt = Date.now();
    });
    signal.throwIfAborted();
    const manifest = report?.runs?.[0]?.properties?.workerManifest;
    if (manifest?.sourceDigest !== source.sourceDigest || manifest?.commit !== job.commitSha) throw new Error("Report source binding mismatch.");
    failureCode = "publication_failed";
    const receipt = await importSarif(db, report, {
      projectId: job.projectId, scanId: job.scanId, repository: job.ownerSlug, branch: job.requestedRef, commitSha: job.commitSha, actorId: `worker:${job.workerId}`,
      authorize: async (tx) => { await assertJobLease(tx, job, env); },
      onPublished: (tx, receipt) => completeScanJob(tx, job, receipt, resultDigest, env, JSON.stringify(manifest)),
    });
    clearInterval(heartbeat);
    await notifyImportedScan(db, receipt, job.ownerSlug, job.requestedRef).catch(() => {});
  } catch (error) {
    if (error instanceof LeaseLost) return;
    const code = error instanceof AccessDenied || failureCode === "authorization_lost" ? "authorization_lost" : deadline.aborted ? "deadline_exceeded" : failureCode;
    await failScanJob(db, job, code, code !== "authorization_lost" && code !== "deadline_exceeded");
  } finally { clearInterval(heartbeat); }
}

export async function runWorkerOnce(db: PrismaClient, workerId: string, env: AuthEnvironment, stopping: AbortSignal): Promise<boolean> {
  const job = await claimScanJob(db, workerId, env);
  if (!job) return false;
  await runClaimedScan(db, job, env, stopping);
  return true;
}
