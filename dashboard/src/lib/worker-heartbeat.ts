import { randomUUID } from "node:crypto";
import { open, rename, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Publish a complete heartbeat without writing through an existing directory entry. */
export async function publishWorkerHeartbeat(
  worker: "ai" | "scan",
  directory = tmpdir(),
): Promise<void> {
  const name = worker === "ai" ? "aegify-ai-worker-health" : "aegify-worker-health";
  const staging = join(directory, `.${name}.${randomUUID()}`);
  const file = await open(staging, "wx", 0o600);
  try {
    try {
      await file.writeFile(new Date().toISOString());
    } finally {
      await file.close();
    }
    await rename(staging, join(directory, name));
  } catch (error) {
    await unlink(staging).catch(() => {});
    throw error;
  }
}
